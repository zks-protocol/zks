//! Faisal Swarm Encryption Module
//!
//! Handles Wasif-Vernam encryption/decryption for Faisal Swarm cells.
//! Provides 256-bit post-quantum computational security at each hop.

use super::*;
use sha2::{Digest, Sha256};
use tracing::debug;
use zks_crypt::true_entropy::get_sync_entropy;
use zks_crypt::wasif_vernam::WasifVernam;

/// Faisal Swarm encryption manager
///
/// Manages Wasif-Vernam encryption for Faisal Swarm cells.
/// Each hop has its own Wasif-Vernam cipher for 256-bit post-quantum computational security.
pub struct FaisalSwarmEncryption {
    /// Wasif-Vernam ciphers for forward path (Client -> Relay)
    pub(crate) forward_ciphers: Vec<WasifVernam>,

    /// Wasif-Vernam ciphers for backward path (Relay -> Client)
    pub(crate) backward_ciphers: Vec<WasifVernam>,

    /// Anti-replay protection for each hop (backward path)
    anti_replay: Vec<zks_crypt::anti_replay::BitmapAntiReplay>,

    /// Packet counters for each hop (forward path)
    counters: Vec<std::sync::atomic::AtomicU64>,
}

impl std::fmt::Debug for FaisalSwarmEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaisalSwarmEncryption")
            .field("hops", &self.forward_ciphers.len())
            .finish_non_exhaustive()
    }
}

impl FaisalSwarmEncryption {
    /// Create a new encryption manager from ML-KEM negotiated shared secrets
    /// Each secret was derived via HKDF from the ML-KEM shared secret
    /// established with the corresponding relay peer.
    pub fn from_shared_secrets(shared_secrets: &[[u8; 32]]) -> Result<Self> {
        let mut forward_ciphers = Vec::with_capacity(shared_secrets.len());
        let mut backward_ciphers = Vec::with_capacity(shared_secrets.len());
        let mut anti_replay = Vec::with_capacity(shared_secrets.len());
        let mut counters = Vec::with_capacity(shared_secrets.len());

        for (_i, key) in shared_secrets.iter().enumerate() {
            // Forward cipher (Initiator role: true)
            let mut f_cipher = WasifVernam::new(*key).map_err(|e| {
                SwarmError::Encryption(format!("Forward cipher creation failed: {:?}", e))
            })?;
            f_cipher.derive_base_iv(key, true);
            f_cipher.enable_sequenced_vernam(*key);
            forward_ciphers.push(f_cipher);

            // Backward cipher (Responder role: false)
            // Used to decrypt responses from Relay
            let mut b_cipher = WasifVernam::new(*key).map_err(|e| {
                SwarmError::Encryption(format!("Backward cipher creation failed: {:?}", e))
            })?;
            b_cipher.derive_base_iv(key, false);
            b_cipher.enable_sequenced_vernam(*key);
            backward_ciphers.push(b_cipher);

            anti_replay.push(zks_crypt::anti_replay::BitmapAntiReplay::new());
            counters.push(std::sync::atomic::AtomicU64::new(0));
        }

        Ok(Self {
            forward_ciphers,
            backward_ciphers,
            anti_replay,
            counters,
        })
    }

    /// Create a new encryption manager (legacy - for tests only)
    #[cfg(test)]
    #[must_use]
    #[must_use]
    pub fn new(hops: usize) -> Result<Self> {
        let mut forward_ciphers = Vec::with_capacity(hops);
        let mut backward_ciphers = Vec::with_capacity(hops);
        let mut anti_replay = Vec::with_capacity(hops);
        let mut counters = Vec::with_capacity(hops);

        for i in 0..hops {
            // Generate unique key for each hop
            let key = Self::generate_vernam_key(i)?;

            // Forward cipher (Initiator: true)
            let mut f_cipher = WasifVernam::new(key).map_err(|e| {
                super::SwarmError::Encryption(format!("Cipher creation failed: {:?}", e))
            })?;
            f_cipher.derive_base_iv(&key, true);
            f_cipher.enable_sequenced_vernam(key);
            forward_ciphers.push(f_cipher);

            // Backward cipher (Responder: false)
            let mut b_cipher = WasifVernam::new(key).map_err(|e| {
                super::SwarmError::Encryption(format!("Cipher creation failed: {:?}", e))
            })?;
            b_cipher.derive_base_iv(&key, false);
            b_cipher.enable_sequenced_vernam(key);
            backward_ciphers.push(b_cipher);

            anti_replay.push(zks_crypt::anti_replay::BitmapAntiReplay::new());
            counters.push(std::sync::atomic::AtomicU64::new(0));
        }

        Ok(Self {
            forward_ciphers,
            backward_ciphers,
            anti_replay,
            counters,
        })
    }

    /// Generate a unique Wasif-Vernam key for each hop
    #[must_use]
    fn generate_vernam_key(hop_index: usize) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(b"FAISAL-SWARM-VERNAM-KEY-v1-ENCRYPT");
        hasher.update(&[0x01]); // Key purpose: 0x01 = encrypt
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
    pub fn encrypt_cell(
        &mut self,
        cell: &super::cells::FaisalSwarmCell,
        hop_index: usize,
    ) -> Result<Vec<u8>> {
        if hop_index >= self.forward_ciphers.len() {
            return Err(super::SwarmError::Encryption(format!(
                "Invalid hop index: {}",
                hop_index
            )));
        }

        debug!("Encrypting cell with Wasif-Vernam for hop {}", hop_index);

        // Serialize cell to bytes
        let cell_bytes = cell.to_bytes();

        // Encrypt with Wasif-Vernam (Forward Cipher) - Sequenced mode handles counters
        let encrypted = self.forward_ciphers[hop_index]
            .encrypt_sequenced(&cell_bytes)
            .map_err(|e| {
                super::SwarmError::Encryption(format!("Vernam encryption failed: {:?}", e))
            })?;

        debug!("Cell encrypted with Wasif-Vernam");

        Ok(encrypted)
    }

    /// Decrypt cell with Wasif-Vernam (onion decryption)
    ///
    /// Each hop peels one Wasif-Vernam layer to reveal the inner cell.
    pub fn decrypt_cell(
        &mut self,
        encrypted_data: &[u8],
        hop_index: usize,
    ) -> Result<super::cells::FaisalSwarmCell> {
        if hop_index >= self.backward_ciphers.len() {
            return Err(super::SwarmError::Encryption(format!(
                "Invalid hop index: {}",
                hop_index
            )));
        }

        debug!("Decrypting cell with Wasif-Vernam for hop {}", hop_index);

        // Decrypt with Wasif-Vernam (Backward Cipher) - Sequenced mode handles anti-replay
        let decrypted = self.backward_ciphers[hop_index]
            .decrypt_sequenced(encrypted_data)
            .map_err(|e| {
                super::SwarmError::Encryption(format!("Vernam decryption failed: {:?}", e))
            })?;

        // Deserialize cell
        let cell = super::cells::FaisalSwarmCell::from_bytes(&decrypted).map_err(|e| {
            super::SwarmError::Encryption(format!("Cell deserialization failed: {:?}", e))
        })?;

        debug!("Cell decrypted with Wasif-Vernam");

        Ok(cell)
    }

    /// Multi-hop onion encryption
    ///
    /// Encrypts data with multiple Wasif-Vernam layers for onion routing.
    /// This is used by the client to create the onion layers.
    #[must_use]
    pub fn encrypt_onion_layers(&mut self, data: &[u8], num_layers: usize) -> Result<Vec<u8>> {
        if num_layers > self.forward_ciphers.len() {
            return Err(super::SwarmError::Encryption(format!(
                "Too many layers requested: {}",
                num_layers
            )));
        }

        info!("Creating {} Wasif-Vernam onion layers", num_layers);

        let mut result = data.to_vec();

        // Encrypt in reverse order (Exit → Guard)
        for i in (0..num_layers).rev() {
            result = self.encrypt_layer(&result, i).map_err(|e| {
                super::SwarmError::Encryption(format!("Layer encryption failed: {:?}", e))
            })?;
        }

        Ok(result)
    }

    /// Multi-hop onion decryption
    ///
    /// Decrypts onion layers one by one using Wasif-Vernam.
    /// This is used by each hop to peel its layer.
    #[must_use]
    pub fn decrypt_onion_layer(
        &mut self,
        encrypted_data: &[u8],
        hop_index: usize,
    ) -> Result<Vec<u8>> {
        if hop_index >= self.backward_ciphers.len() {
            return Err(super::SwarmError::Encryption(format!(
                "Invalid hop index: {}",
                hop_index
            )));
        }

        debug!("Peeling Wasif-Vernam layer {} from onion", hop_index);

        self.decrypt_layer(encrypted_data, hop_index)
            .map_err(|e| super::SwarmError::Encryption(format!("Decryption failed: {:?}", e)))
    }

    /// Encrypt single layer with Wasif-Vernam
    #[must_use]
    fn encrypt_layer(&mut self, data: &[u8], hop_index: usize) -> Result<Vec<u8>> {
        self.forward_ciphers[hop_index]
            .encrypt_sequenced(data)
            .map_err(|e| {
                super::SwarmError::Encryption(format!("Vernam encryption failed: {:?}", e))
            })
    }

    /// Decrypt single layer with Wasif-Vernam
    #[must_use]
    fn decrypt_layer(&mut self, encrypted_data: &[u8], hop_index: usize) -> Result<Vec<u8>> {
        self.backward_ciphers[hop_index]
            .decrypt_sequenced(encrypted_data)
            .map_err(|e| {
                super::SwarmError::Encryption(format!("Vernam decryption failed: {:?}", e))
            })
    }
}

/// Create encryption manager for Faisal Swarm circuit from ML-KEM shared secrets
pub fn create_encryption_manager_from_secrets(
    shared_secrets: &[[u8; 32]],
) -> Result<FaisalSwarmEncryption> {
    FaisalSwarmEncryption::from_shared_secrets(shared_secrets)
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
    fn test_encryption_manager_from_shared_secrets() {
        let shared_secrets = [[1u8; 32], [2u8; 32], [3u8; 32]];

        let encryption = FaisalSwarmEncryption::from_shared_secrets(&shared_secrets).unwrap();
        assert_eq!(encryption.forward_ciphers.len(), 3);
        assert_eq!(encryption.backward_ciphers.len(), 3);
        assert_eq!(encryption.anti_replay.len(), 3);
        assert_eq!(encryption.counters.len(), 3);
    }

    #[test]
    fn test_encryption_manager_creation() {
        let encryption = FaisalSwarmEncryption::new(3).unwrap();
        assert_eq!(encryption.forward_ciphers.len(), 3);
        assert_eq!(encryption.backward_ciphers.len(), 3);
        assert_eq!(encryption.anti_replay.len(), 3);
        assert_eq!(encryption.counters.len(), 3);
    }

    #[test]
    fn test_onion_encryption_loop() {
        // Test complete loop: Client Encrypt (Fwd) -> Relay Decrypt (Fwd) -> Relay Encrypt (Bwd) -> Client Decrypt (Bwd)
        let key = [0x42u8; 32];
        let shared_secrets = [key];

        // Use from_shared_secrets to have known keys
        let mut client_enc = FaisalSwarmEncryption::from_shared_secrets(&shared_secrets).unwrap();

        // Setup Relay Ciphers manually (mirror of client)
        // Relay Decrypt (Fwd): Must match Client Encrypt (Fwd) = Initiator/True
        let mut relay_fwd_decrypt = WasifVernam::new(key).unwrap();
        relay_fwd_decrypt.derive_base_iv(&key, true);
        relay_fwd_decrypt.enable_sequenced_vernam(key);

        // Relay Encrypt (Bwd): Must match Client Decrypt (Bwd) = Responder/False
        let mut relay_bwd_encrypt = WasifVernam::new(key).unwrap();
        relay_bwd_encrypt.derive_base_iv(&key, false);
        relay_bwd_encrypt.enable_sequenced_vernam(key);

        let original_data = vec![0x42; 50];

        // 1. Client Encrypts (Forward)
        // Uses encrypt_layer (which now uses encrypt_sequenced)
        let fwd_encrypted = client_enc.encrypt_layer(&original_data, 0).unwrap();

        // 2. Relay Decrypts (Forward)
        // Relay must use decrypt_sequenced to match
        let fwd_decrypted = relay_fwd_decrypt.decrypt_sequenced(&fwd_encrypted).unwrap();
        assert_eq!(fwd_decrypted, original_data);

        // 3. Relay Encrypts (Backward)
        // Simulate response from relay using encrypt_sequenced
        let bwd_encrypted = relay_bwd_encrypt.encrypt_sequenced(&original_data).unwrap();

        // 4. Client Decrypts (Backward)
        // Uses decrypt_layer (which now uses decrypt_sequenced)
        let bwd_decrypted = client_enc.decrypt_layer(&bwd_encrypted, 0).unwrap();
        assert_eq!(bwd_decrypted, original_data);
    }

    #[test]
    fn test_replay_detection() {
        // Test that anti-replay correctly detects duplicate counters on Backward path
        let key = [0x99u8; 32];
        let shared_secrets = [key];

        let mut encryption = FaisalSwarmEncryption::from_shared_secrets(&shared_secrets).unwrap();

        // Setup Relay Encrypt (Bwd) as source of packets
        let mut relay_bwd_encrypt = WasifVernam::new(key).unwrap();
        relay_bwd_encrypt.derive_base_iv(&key, false); // Match backward_ciphers
        relay_bwd_encrypt.enable_sequenced_vernam(key);

        let data = vec![0x42; 50];

        // Create packet
        let encrypted1 = relay_bwd_encrypt.encrypt_sequenced(&data).unwrap();

        // First validation should succeed
        let decrypted1 = encryption.decrypt_layer(&encrypted1, 0);
        assert!(decrypted1.is_ok(), "First packet should succeed");

        // Create duplicate packet with counter 5 (Replay)
        // To properly simulate replay with WasifVernam (which is stateful), we must reuse the EXACT ciphertext
        // Attempting to re-encrypt producing different ciphertext due to counter increment is NOT a replay of same packet.
        // It is a NEW packet with SAME counter payload but DIFFERENT outer nonce/ciphertext?
        // Wait, WasifVernam encrypt() auto-increments ITS internal nonce.
        // So encrypted1 and encrypted2 will correspond to DIFFERENT outer nonces (if using same cipher instance).
        // BUT the inner payload counter (5) is what we are testing for anti-replay.

        // However, WasifVernam::decrypt derives the PID from the OUTER nonce.
        // "Check for replay attacks using counter from nonce bytes 4-12"
        // It XORs back with base_iv.

        // Replayed ciphertext should fail anti-replay check
        let decrypted2 = encryption.decrypt_layer(&encrypted1, 0);
        assert!(
            decrypted2.is_err(),
            "Replayed ciphertext should fail anti-replay check"
        );

        // Different packet should succeed
        let encrypted2 = relay_bwd_encrypt.encrypt_sequenced(&data).unwrap();

        let decrypted3 = encryption.decrypt_layer(&encrypted2, 0);
        assert!(decrypted3.is_ok(), "New packet should succeed");
    }
}
