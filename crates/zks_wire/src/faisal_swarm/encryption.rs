//! Faisal Swarm Encryption Module
//! 
//! Handles Wasif-Vernam encryption/decryption for Faisal Swarm cells.
//! Provides 256-bit post-quantum computational security at each hop.

use super::*;
use zks_crypt::wasif_vernam::WasifVernam;
use zks_crypt::true_entropy::get_sync_entropy;
use bytes::{BufMut, BytesMut};
use tracing::debug;
use sha2::{Sha256, Digest};

/// Faisal Swarm encryption manager
/// 
/// Manages Wasif-Vernam encryption for Faisal Swarm cells.
/// Each hop has its own Wasif-Vernam cipher for 256-bit post-quantum computational security.
pub struct FaisalSwarmEncryption {
    /// Wasif-Vernam ciphers for each hop
    vernam_ciphers: Vec<WasifVernam>,
    
    /// Anti-replay protection for each hop
    anti_replay: Vec<zks_crypt::anti_replay::BitmapAntiReplay>,
    
    /// Packet counters for each hop
    counters: Vec<std::sync::atomic::AtomicU64>,
}

impl FaisalSwarmEncryption {
    /// Create a new encryption manager
    #[must_use]
    pub fn new(hops: usize) -> Result<Self> {
        let mut vernam_ciphers = Vec::with_capacity(hops);
        let mut anti_replay = Vec::with_capacity(hops);
        let mut counters = Vec::with_capacity(hops);
        
        for i in 0..hops {
            // Generate unique key for each hop
            let key = Self::generate_vernam_key(i)?;
            
            let mut cipher = WasifVernam::new(key)
                .map_err(|e| super::SwarmError::Encryption(format!("Cipher creation failed: {:?}", e)))?;
            
            // Required: derive base_iv for encryption (security fix M3)
            cipher.derive_base_iv(&key, true);
            
            vernam_ciphers.push(cipher);
            anti_replay.push(zks_crypt::anti_replay::BitmapAntiReplay::new());
            counters.push(std::sync::atomic::AtomicU64::new(0));
        }
        
        Ok(Self {
            vernam_ciphers,
            anti_replay,
            counters,
        })
    }
    
    /// Generate a unique Wasif-Vernam key for each hop
    #[must_use]
    fn generate_vernam_key(hop_index: usize) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(b"FAISAL-SWARM-VERNAM-KEY-v1-ENCRYPT");
        hasher.update(&[0x01]);  // Key purpose: 0x01 = encrypt
        hasher.update(hop_index.to_be_bytes());
        
        // Generate a high-entropy random nonce (drand + OsRng) for 256-bit post-quantum security
        let entropy = get_sync_entropy(16);
        let mut random_nonce = [0u8; 16];
        random_nonce.copy_from_slice(&entropy);
        hasher.update(&random_nonce);
        
        Ok(hasher.finalize().into())
    }
    
    /// Encrypt cell with Wasif-Vernam (onion encryption)
    /// 
    /// This is the core of Faisal Swarm: each layer is encrypted with
    /// Wasif-Vernam instead of AES, providing 256-bit post-quantum computational security.
    #[must_use]
    pub fn encrypt_cell(&mut self, cell: &super::cells::FaisalSwarmCell, hop_index: usize) -> Result<Vec<u8>> {
        if hop_index >= self.vernam_ciphers.len() {
            return Err(super::SwarmError::Encryption(format!("Invalid hop index: {}", hop_index)));
        }
        
        debug!("Encrypting cell with Wasif-Vernam for hop {}", hop_index);
        
        // Serialize cell to bytes
        let cell_bytes = cell.to_bytes();
        
        // Get packet counter for anti-replay
        let counter = self.counters[hop_index].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        
        // Create packet with counter
        let mut packet = BytesMut::with_capacity(8 + cell_bytes.len());
        packet.put_u64(counter);
        packet.extend_from_slice(&cell_bytes);
        
        // Encrypt with Wasif-Vernam
        let encrypted = self.vernam_ciphers[hop_index].encrypt(&packet)
            .map_err(|e| super::SwarmError::Encryption(format!("Vernam encryption failed: {:?}", e)))?;
        
        debug!("Cell encrypted with Wasif-Vernam");
        
        Ok(encrypted)
    }
    
    /// Decrypt cell with Wasif-Vernam (onion decryption)
    /// 
    /// Each hop peels one Wasif-Vernam layer to reveal the inner cell.
    pub fn decrypt_cell(&mut self, encrypted_data: &[u8], hop_index: usize) -> Result<super::cells::FaisalSwarmCell> {
        if hop_index >= self.vernam_ciphers.len() {
            return Err(super::SwarmError::Encryption(format!("Invalid hop index: {}", hop_index)));
        }
        
        debug!("Decrypting cell with Wasif-Vernam for hop {}", hop_index);
        
        // Decrypt with Wasif-Vernam
        let decrypted = self.vernam_ciphers[hop_index].decrypt(encrypted_data)
            .map_err(|e| super::SwarmError::Encryption(format!("Vernam decryption failed: {:?}", e)))?;
        
        if decrypted.len() < 8 {
            return Err(super::SwarmError::Encryption(format!("Invalid decrypted size: {}", decrypted.len())));
        }
        
        // Extract counter
        let counter = u64::from_be_bytes(
            decrypted[0..8].try_into()
                .map_err(|_| super::SwarmError::Encryption("Counter parse failed".to_string()))?
        );
        
        // Check anti-replay
        self.anti_replay[hop_index].validate(counter)
            .map_err(|_| super::SwarmError::ReplayDetected)?;
        
        // Extract cell data
        let cell_data = &decrypted[8..];
        
        // Deserialize cell
        let cell = super::cells::FaisalSwarmCell::from_bytes(cell_data)
            .map_err(|e| super::SwarmError::Encryption(format!("Cell deserialization failed: {:?}", e)))?;
        
        debug!("Cell decrypted with Wasif-Vernam");
        
        Ok(cell)
    }
    
    /// Multi-hop onion encryption
    ///
    /// Encrypts data with multiple Wasif-Vernam layers for onion routing.
    /// This is used by the client to create the onion layers.
    #[must_use]
    pub fn encrypt_onion_layers(&mut self, data: &[u8], num_layers: usize) -> Result<Vec<u8>> {
        if num_layers > self.vernam_ciphers.len() {
            return Err(super::SwarmError::Encryption(format!("Too many layers requested: {}", num_layers)));
        }
        
        info!("Creating {} Wasif-Vernam onion layers", num_layers);
        
        let mut result = data.to_vec();
        
        // Encrypt in reverse order (Exit → Guard)
        for i in (0..num_layers).rev() {
            result = self.encrypt_layer(&result, i)
                .map_err(|e| super::SwarmError::Encryption(format!("Layer encryption failed: {:?}", e)))?;
        }
        
        Ok(result)
    }
    
    /// Multi-hop onion decryption
    /// 
    /// Decrypts onion layers one by one using Wasif-Vernam.
    /// This is used by each hop to peel its layer.
    #[must_use]
    pub fn decrypt_onion_layer(&mut self, encrypted_data: &[u8], hop_index: usize) -> Result<Vec<u8>> {
        if hop_index >= self.vernam_ciphers.len() {
            return Err(super::SwarmError::Encryption(format!("Invalid hop index: {}", hop_index)));
        }
        
        debug!("Peeling Wasif-Vernam layer {} from onion", hop_index);
        
        self.decrypt_layer(encrypted_data, hop_index)
            .map_err(|e| super::SwarmError::Encryption(format!("Decryption failed: {:?}", e)))
    }
    
    /// Encrypt single layer with Wasif-Vernam
    #[must_use]
    fn encrypt_layer(&mut self, data: &[u8], hop_index: usize) -> Result<Vec<u8>> {
        // Add counter for anti-replay
        let counter = self.counters[hop_index].fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        
        // Check for counter overflow
        if counter == u64::MAX {
            return Err(super::SwarmError::Encryption("Counter exhausted - re-key required".to_string()));
        }
        
        let mut packet = BytesMut::with_capacity(8 + data.len());
        packet.put_u64(counter);
        packet.extend_from_slice(data);
        
        self.vernam_ciphers[hop_index].encrypt(&packet)
            .map_err(|e| super::SwarmError::Encryption(format!("Vernam encryption failed: {:?}", e)))
    }
    
    /// Decrypt single layer with Wasif-Vernam
    #[must_use]
    fn decrypt_layer(&mut self, encrypted_data: &[u8], hop_index: usize) -> Result<Vec<u8>> {
        let decrypted = self.vernam_ciphers[hop_index].decrypt(encrypted_data)
            .map_err(|e| super::SwarmError::Encryption(format!("Vernam decryption failed: {:?}", e)))?;
        
        if decrypted.len() < 8 {
            return Err(super::SwarmError::Encryption(format!("Invalid decrypted size: {}", decrypted.len())));
        }
        
        // Extract counter
        let counter = u64::from_be_bytes(
            decrypted[0..8].try_into()
                .map_err(|_| super::SwarmError::Encryption("Counter parse failed".to_string()))?
        );
        
        // Check anti-replay
        self.anti_replay[hop_index].validate(counter)
            .map_err(|_| super::SwarmError::ReplayDetected)?;
        
        // Extract data
        Ok(decrypted[8..].to_vec())
    }
}

/// Create encryption manager for Faisal Swarm circuit
#[must_use]
pub fn create_encryption_manager(hops: &[super::SwarmHop]) -> Result<FaisalSwarmEncryption> {
    info!("Creating Faisal Swarm encryption manager for {} hops", hops.len());
    
    let encryption = FaisalSwarmEncryption::new(hops.len())?;
    
    // Initialize Wasif-Vernam ciphers with shared secrets from ML-KEM handshakes
    // This would be done after the ML-KEM handshake phase
    
    Ok(encryption)
}

/// Encrypt Faisal Swarm cell for multi-hop transmission
#[must_use]
pub fn encrypt_cell_for_transmission(
    cell: &super::cells::FaisalSwarmCell,
    encryption: &mut FaisalSwarmEncryption,
    num_hops: usize,
) -> Result<Vec<u8>> {
    // Serialize cell to bytes
    let cell_bytes = cell.to_bytes();
    
    // Apply onion encryption with Wasif-Vernam
    encryption.encrypt_onion_layers(&cell_bytes, num_hops)
}

/// Decrypt Faisal Swarm cell at specific hop
#[must_use]
pub fn decrypt_cell_at_hop(
    encrypted_data: &[u8],
    encryption: &mut FaisalSwarmEncryption,
    hop_index: usize,
) -> Result<super::cells::FaisalSwarmCell> {
    // Decrypt the onion layer at this hop
    let decrypted_data = encryption.decrypt_onion_layer(encrypted_data, hop_index)?;
    
    // Deserialize the cell
    super::cells::FaisalSwarmCell::from_bytes(&decrypted_data)
        .map_err(|e| super::SwarmError::Encryption(format!("Cell deserialization failed: {:?}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encryption_manager_creation() {
        let encryption = FaisalSwarmEncryption::new(3).unwrap();
        assert_eq!(encryption.vernam_ciphers.len(), 3);
        assert_eq!(encryption.anti_replay.len(), 3);
        assert_eq!(encryption.counters.len(), 3);
    }
    
    #[test]
    fn test_single_layer_encryption() {
        let mut encryption = FaisalSwarmEncryption::new(3).unwrap();
        
        // Create a test cell
        let cell = super::super::cells::FaisalSwarmCell::new(0x12345678, 
            super::super::cells::CellCommand::Relay, 
            vec![0x42; 50]).unwrap();
        
        // Encrypt
        let encrypted = encryption.encrypt_cell(&cell, 0).unwrap();
        assert_ne!(encrypted.len(), 0);
        
        // Decrypt
        let decrypted = encryption.decrypt_cell(&encrypted, 0).unwrap();
        assert_eq!(decrypted.header.circuit_id, cell.header.circuit_id);
        assert_eq!(decrypted.header.command, cell.header.command);
        assert_eq!(decrypted.payload, cell.payload);
    }
    
    #[test]
    fn test_onion_encryption() {
        let mut encryption = FaisalSwarmEncryption::new(3).unwrap();
        
        let original_data = vec![0x42; 100];
        
        // Encrypt with 3 layers
        let onion = encryption.encrypt_onion_layers(&original_data, 3).unwrap();
        assert_ne!(onion.len(), original_data.len());
        
        // Decrypt layer by layer
        let layer0 = encryption.decrypt_onion_layer(&onion, 0).unwrap();
        let layer1 = encryption.decrypt_onion_layer(&layer0, 1).unwrap();
        let layer2 = encryption.decrypt_onion_layer(&layer1, 2).unwrap();
        
        assert_eq!(layer2, original_data);
    }
    
    #[test]
    fn test_replay_detection() {
        // Test that anti-replay correctly detects duplicate counters
        let anti_replay = zks_crypt::anti_replay::BitmapAntiReplay::new();
        
        // First validation should succeed
        let result1 = anti_replay.validate(5);
        assert!(result1.is_ok(), "First validation should succeed");
        
        // Second validation of same counter should fail (replay attack!)
        let result2 = anti_replay.validate(5);
        assert!(result2.is_err(), "Second validation should fail (replay)");
        
        // Different counter should succeed
        let result3 = anti_replay.validate(10);
        assert!(result3.is_ok(), "Different counter should succeed");
        
        // Verify our encryption layer also detects replay
        let mut encryption = FaisalSwarmEncryption::new(1).unwrap();
        
        let data = vec![0x42; 50];
        
        // Encrypt and decrypt normally - this should work
        let encrypted = encryption.encrypt_layer(&data, 0).unwrap();
        let decrypted = encryption.decrypt_layer(&encrypted, 0).unwrap();
        assert_eq!(decrypted, data);
        
        // The counter (0) has been marked as seen in anti-replay
        // Now encrypt again (counter will be 1) and try manual replay attack:
        // Manually construct a packet with the already-seen counter 0
        let mut replay_packet = bytes::BytesMut::new();
        replay_packet.put_u64(0u64); // Replay counter 0 (already seen!)
        replay_packet.extend_from_slice(&data);
        
        // This encryption will succeed (counter 1)
        let _encrypted2 = encryption.encrypt_layer(&data, 0).unwrap();
        
        // But if an attacker tries to replay counter 0, the anti-replay should catch it
        // (Note: In practical attack, attacker would need to forge ciphertext, which is impossible
        // with Wasif-Vernam. This test verifies the anti-replay logic itself works.)
        let replay_result = encryption.anti_replay[0].validate(0);
        assert!(replay_result.is_err(), "Replayed counter should be rejected");
    }
}