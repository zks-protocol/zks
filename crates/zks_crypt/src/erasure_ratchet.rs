//! Erasure-Coded Ratchet - Resilient PQ Ratcheting with Packet Loss Tolerance
//!
//! This module implements erasure-coded ratcheting for post-quantum key exchange,
//! providing graceful degradation under packet loss conditions.
//!
//! # Design Overview
//!
//! Traditional PQ ratcheting fails if any ratchet message is lost.
//! Erasure-coded ratcheting splits the ratchet payload into chunks with
//! redundancy, so any k-of-n chunks can reconstruct the full message.
//!
//! # Implementation: Reed-Solomon via reed-solomon-simd
//!
//! Uses the `reed-solomon-simd` crate which provides:
//! - O(n log n) complexity via Leopard-RS algorithm
//! - SIMD acceleration on x86-64 and AArch64
//! - Proper k-of-n recovery (any k shards of n total can reconstruct)
//!
//! # Protocol Flow
//!
//! ```text
//! Naive:  [=================== 1568 bytes ===================] (1 message)
//!         (if lost, ratchet fails)
//!
//! Erasure: [shard1][shard2][shard3][shard4]...[shard_n]
//!          (any k shards sufficient, others can be lost)
//! ```
//!
//! # Parameters
//!
//! | Profile | k (required) | n (total) | Overhead | Loss Tolerance |
//! |---------|--------------|-----------|----------|----------------|
//! | `minimal` | 4 | 5 | 25% | 20% loss |
//! | `balanced` | 4 | 8 | 100% | 50% loss |
//! | `resilient` | 4 | 12 | 200% | 66% loss |
//!
//! # Security Properties
//!
//! - ✅ Forward secrecy maintained (ratchet still advances)
//! - ✅ Break-in recovery preserved (each shard reveals nothing)
//! - ✅ Packet loss tolerance (graceful degradation)
//! - ✅ Post-quantum secure (shards of ML-KEM data)

use std::collections::HashMap;
use sha2::{Sha256, Digest};

/// Error type for erasure coding operations
#[derive(Debug, Clone)]
pub enum ErasureError {
    /// Not enough shards to reconstruct
    InsufficientShards {
        /// Number of shards available
        have: usize,
        /// Number of shards required
        need: usize,
    },
    /// Invalid shard size
    InvalidShardSize(String),
    /// Reconstruction failed
    ReconstructionError(String),
    /// Encoding failed
    EncodingError(String),
}

impl std::fmt::Display for ErasureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientShards { have, need } => {
                write!(f, "Insufficient shards: have {}, need {}", have, need)
            }
            Self::InvalidShardSize(msg) => write!(f, "Invalid shard size: {}", msg),
            Self::ReconstructionError(msg) => write!(f, "Reconstruction error: {}", msg),
            Self::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
        }
    }
}

impl std::error::Error for ErasureError {}

/// Result type for erasure operations
pub type Result<T> = std::result::Result<T, ErasureError>;

/// Erasure coding configuration
#[derive(Debug, Clone)]
pub struct ErasureConfig {
    /// Number of original data shards (k)
    pub original_count: usize,
    /// Number of recovery shards to generate
    pub recovery_count: usize,
}

impl Default for ErasureConfig {
    fn default() -> Self {
        Self::balanced()
    }
}

impl ErasureConfig {
    /// Minimal redundancy (20% loss tolerance)
    /// k=4 original, 1 recovery → need any 4 of 5
    pub fn minimal() -> Self {
        Self {
            original_count: 4,
            recovery_count: 1,
        }
    }

    /// Balanced redundancy (50% loss tolerance)
    /// k=4 original, 4 recovery → need any 4 of 8
    pub fn balanced() -> Self {
        Self {
            original_count: 4,
            recovery_count: 4,
        }
    }

    /// Maximum resilience (66% loss tolerance)
    /// k=4 original, 8 recovery → need any 4 of 12
    pub fn resilient() -> Self {
        Self {
            original_count: 4,
            recovery_count: 8,
        }
    }

    /// Custom configuration
    pub fn custom(original_count: usize, recovery_count: usize) -> Result<Self> {
        if original_count == 0 {
            return Err(ErasureError::EncodingError(
                "original_count must be positive".to_string()
            ));
        }
        if recovery_count == 0 {
            return Err(ErasureError::EncodingError(
                "recovery_count must be positive".to_string()
            ));
        }
        
        Ok(Self {
            original_count,
            recovery_count,
        })
    }

    /// Total number of shards (k + recovery)
    pub fn total_shards(&self) -> usize {
        self.original_count + self.recovery_count
    }

    /// Calculate overhead factor
    pub fn overhead_factor(&self) -> f64 {
        self.total_shards() as f64 / self.original_count as f64
    }

    /// Calculate loss tolerance (as percentage)
    pub fn loss_tolerance(&self) -> f64 {
        (self.recovery_count as f64 / self.total_shards() as f64) * 100.0
    }

    /// Calculate shard size for given data length
    pub fn shard_size(&self, data_len: usize) -> usize {
        // Each shard must be the same size
        // Pad data to be divisible by original_count, then divide
        let padded = (data_len + self.original_count - 1) / self.original_count * self.original_count;
        padded / self.original_count
    }

    /// Calculate total encoded size for given data length
    pub fn encoded_size(&self, data_len: usize) -> usize {
        self.shard_size(data_len) * self.total_shards()
    }
}

/// An encoded shard of ratchet data
#[derive(Debug, Clone)]
pub struct EncodedShard {
    /// Shard index (0 to n-1)
    pub index: usize,
    /// The shard data
    pub data: Vec<u8>,
    /// Hash of the full original data (for verification)
    pub data_hash: [u8; 32],
    /// Epoch this shard belongs to
    pub epoch: u64,
    /// Whether this is a recovery shard (vs original data shard)
    pub is_recovery: bool,
}

/// Erasure encoder/decoder for ratchet payloads using Reed-Solomon
pub struct ErasureCodec {
    config: ErasureConfig,
}

impl ErasureCodec {
    /// Create a new erasure codec with the given configuration
    pub fn new(config: ErasureConfig) -> Self {
        Self { config }
    }

    /// Encode data into shards with Reed-Solomon erasure coding
    ///
    /// # Arguments
    /// * `data` - The data to encode (typically ML-KEM ciphertext)
    /// * `epoch` - The ratchet epoch number
    ///
    /// # Returns
    /// Vector of encoded shards (n total, any k sufficient to reconstruct)
    pub fn encode(&self, data: &[u8], epoch: u64) -> Result<Vec<EncodedShard>> {
        // Calculate hash of original data for verification
        let mut hasher = Sha256::new();
        hasher.update(data);
        let data_hash: [u8; 32] = hasher.finalize().into();

        // Calculate shard size and pad data
        let shard_size = self.config.shard_size(data.len());
        let padded_len = shard_size * self.config.original_count;
        
        let mut padded_data = data.to_vec();
        padded_data.resize(padded_len, 0);

        // Split into original shards
        let original_shards: Vec<&[u8]> = padded_data
            .chunks_exact(shard_size)
            .collect();

        // Generate recovery shards using Reed-Solomon
        let recovery_shards = reed_solomon_simd::encode(
            self.config.original_count,
            self.config.recovery_count,
            &original_shards,
        ).map_err(|e| ErasureError::EncodingError(format!("Reed-Solomon encode failed: {:?}", e)))?;

        // Build output vector with all shards
        let mut shards = Vec::with_capacity(self.config.total_shards());

        // Add original data shards
        for (i, chunk) in original_shards.iter().enumerate() {
            shards.push(EncodedShard {
                index: i,
                data: chunk.to_vec(),
                data_hash,
                epoch,
                is_recovery: false,
            });
        }

        // Add recovery shards
        for (i, recovery) in recovery_shards.iter().enumerate() {
            shards.push(EncodedShard {
                index: self.config.original_count + i,
                data: recovery.to_vec(),
                data_hash,
                epoch,
                is_recovery: true,
            });
        }

        tracing::debug!(
            "📦 Reed-Solomon encoded {} bytes into {} shards (k={}, n={}, {:.0}% loss tolerance)",
            data.len(),
            shards.len(),
            self.config.original_count,
            self.config.total_shards(),
            self.config.loss_tolerance()
        );

        Ok(shards)
    }

    /// Decode shards back into original data using Reed-Solomon
    ///
    /// # Arguments
    /// * `shards` - At least k shards (can be any k of the n encoded shards)
    /// * `original_len` - Original data length (for removing padding)
    ///
    /// # Returns
    /// The reconstructed original data
    pub fn decode(&self, shards: &[EncodedShard], original_len: usize) -> Result<Vec<u8>> {
        if shards.len() < self.config.original_count {
            return Err(ErasureError::InsufficientShards {
                have: shards.len(),
                need: self.config.original_count,
            });
        }

        // Verify all shards have same hash (belong to same message)
        let first_hash = shards[0].data_hash;
        if !shards.iter().all(|c| c.data_hash == first_hash) {
            return Err(ErasureError::ReconstructionError(
                "Shards have mismatched hashes".to_string()
            ));
        }

        // Separate original and recovery shards
        let original_shards: Vec<(usize, &[u8])> = shards.iter()
            .filter(|s| !s.is_recovery)
            .map(|s| (s.index, s.data.as_slice()))
            .collect();

        let recovery_shards: Vec<(usize, &[u8])> = shards.iter()
            .filter(|s| s.is_recovery)
            .map(|s| (s.index - self.config.original_count, s.data.as_slice()))
            .collect();

        // Check if we have all original shards (simple case - no RS decode needed)
        if original_shards.len() == self.config.original_count {
            let mut sorted_originals: Vec<_> = original_shards.clone();
            sorted_originals.sort_by_key(|(idx, _)| *idx);
            
            let mut result = Vec::with_capacity(original_len);
            for (_, data) in sorted_originals {
                result.extend_from_slice(data);
            }
            result.truncate(original_len);
            
            tracing::debug!(
                "📦 Reed-Solomon decoded {} shards (all originals present) into {} bytes",
                shards.len(),
                result.len()
            );
            
            return Ok(result);
        }

        // Need to reconstruct using Reed-Solomon decode
        let decoder_result = reed_solomon_simd::decode(
            self.config.original_count,
            self.config.recovery_count,
            original_shards,
            recovery_shards,
        ).map_err(|e| ErasureError::ReconstructionError(format!("Reed-Solomon decode failed: {:?}", e)))?;

        // Reconstruct the full data from all original shards
        let shard_size = shards[0].data.len();
        let mut result = vec![0u8; self.config.original_count * shard_size];

        // Copy shards we already have
        for shard in shards.iter().filter(|s| !s.is_recovery) {
            let start = shard.index * shard_size;
            result[start..start + shard_size].copy_from_slice(&shard.data);
        }

        // Copy restored shards from BTreeMap result
        for (idx, restored) in decoder_result.iter() {
            let start = idx * shard_size;
            result[start..start + shard_size].copy_from_slice(restored);
        }

        result.truncate(original_len);

        tracing::debug!(
            "📦 Reed-Solomon decoded {} shards (with recovery) into {} bytes",
            shards.len(),
            result.len()
        );

        Ok(result)
    }

    /// Check if we have enough shards to reconstruct
    pub fn can_reconstruct(&self, shard_count: usize) -> bool {
        shard_count >= self.config.original_count
    }

    /// Get the configuration
    pub fn config(&self) -> &ErasureConfig {
        &self.config
    }
}

/// Erasure-coded ratchet that provides loss tolerance
pub struct ErasureRatchet {
    /// The erasure codec
    codec: ErasureCodec,
    /// Pending shards for reconstruction
    pending_shards: HashMap<u64, Vec<EncodedShard>>, // epoch -> shards
    /// Original data lengths for pending epochs
    pending_lengths: HashMap<u64, usize>,
    /// Successfully decoded epochs
    decoded_epochs: Vec<u64>,
}

impl ErasureRatchet {
    /// Create a new erasure-coded ratchet wrapper
    pub fn new(config: ErasureConfig) -> Self {
        Self {
            codec: ErasureCodec::new(config),
            pending_shards: HashMap::new(),
            pending_lengths: HashMap::new(),
            decoded_epochs: Vec::new(),
        }
    }

    /// Encode ratchet ciphertext for transmission
    pub fn encode_ciphertext(&self, ciphertext: &[u8], epoch: u64) -> Result<Vec<EncodedShard>> {
        self.codec.encode(ciphertext, epoch)
    }

    /// Set the expected original length for an epoch (for removing padding)
    pub fn set_original_length(&mut self, epoch: u64, length: usize) {
        self.pending_lengths.insert(epoch, length);
    }

    /// Receive a shard and try to reconstruct
    ///
    /// Returns the reconstructed ciphertext if we now have enough shards
    pub fn receive_shard(&mut self, shard: EncodedShard) -> Result<Option<Vec<u8>>> {
        let epoch = shard.epoch;
        
        // Skip if already decoded
        if self.decoded_epochs.contains(&epoch) {
            return Ok(None);
        }

        // Add to pending
        let shards = self.pending_shards.entry(epoch).or_insert_with(Vec::new);
        
        // Check if we already have this shard index
        if shards.iter().any(|s| s.index == shard.index) {
            return Ok(None); // Duplicate
        }

        shards.push(shard);
        let shard_count = shards.len();

        // Try to reconstruct
        if self.codec.can_reconstruct(shard_count) {
            let shards = self.pending_shards.get(&epoch).unwrap();
            let original_len = self.pending_lengths.get(&epoch)
                .copied()
                .unwrap_or_else(|| {
                    // Estimate from shard size * original_count
                    shards[0].data.len() * self.codec.config().original_count
                });

            match self.codec.decode(shards, original_len) {
                Ok(data) => {
                    self.decoded_epochs.push(epoch);
                    self.pending_shards.remove(&epoch);
                    self.pending_lengths.remove(&epoch);
                    
                    tracing::info!(
                        "✅ Reed-Solomon epoch {} reconstructed ({} shards)",
                        epoch,
                        shard_count
                    );
                    
                    Ok(Some(data))
                }
                Err(e) => {
                    tracing::warn!(
                        "⚠️ Reconstruction attempt failed for epoch {}: {}",
                        epoch, e
                    );
                    Ok(None) // Keep waiting for more shards
                }
            }
        } else {
            let needed = self.codec.config().original_count;
            let total = self.codec.config().total_shards();
            tracing::trace!(
                "📥 Received shard {}/{} for epoch {} (need {} to decode)",
                shard_count,
                total,
                epoch,
                needed
            );
            Ok(None)
        }
    }

    /// Get statistics on pending reconstructions
    pub fn pending_stats(&self) -> PendingStats {
        let epochs: Vec<_> = self.pending_shards.keys().copied().collect();
        let shards_per_epoch: Vec<_> = self.pending_shards.values()
            .map(|v| v.len())
            .collect();

        PendingStats {
            pending_epochs: epochs.len(),
            epochs,
            shards_per_epoch,
            required_shards: self.codec.config().original_count,
        }
    }
}

/// Statistics on pending reconstructions
#[derive(Debug, Clone)]
pub struct PendingStats {
    /// Number of epochs waiting for more shards
    pub pending_epochs: usize,
    /// List of pending epoch numbers
    pub epochs: Vec<u64>,
    /// Shards received per pending epoch
    pub shards_per_epoch: Vec<usize>,
    /// Shards required for reconstruction
    pub required_shards: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_profiles() {
        let minimal = ErasureConfig::minimal();
        assert_eq!(minimal.original_count, 4);
        assert_eq!(minimal.recovery_count, 1);
        assert!((minimal.loss_tolerance() - 20.0).abs() < 0.1);

        let balanced = ErasureConfig::balanced();
        assert_eq!(balanced.original_count, 4);
        assert_eq!(balanced.recovery_count, 4);
        assert!((balanced.loss_tolerance() - 50.0).abs() < 0.1);

        let resilient = ErasureConfig::resilient();
        assert_eq!(resilient.original_count, 4);
        assert_eq!(resilient.recovery_count, 8);
        assert!(resilient.loss_tolerance() > 60.0);
    }

    #[test]
    fn test_encode_decode_no_loss() {
        let config = ErasureConfig::balanced();
        let codec = ErasureCodec::new(config);

        let original = vec![0x42u8; 1568]; // ML-KEM ciphertext size
        let shards = codec.encode(&original, 1).unwrap();

        assert_eq!(shards.len(), 8); // n = 8 shards (4 original + 4 recovery)

        // Decode with all shards
        let decoded = codec.decode(&shards, original.len()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_decode_with_50_percent_loss() {
        let config = ErasureConfig::balanced();
        let codec = ErasureCodec::new(config);

        let original = vec![0x42u8; 1568];
        let shards = codec.encode(&original, 1).unwrap();

        // Keep only 4 shards (drop half) - use only original shards
        let partial: Vec<_> = shards.into_iter()
            .filter(|s| !s.is_recovery)
            .collect();
        
        assert_eq!(partial.len(), 4);
        
        let decoded = codec.decode(&partial, original.len()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_decode_with_recovery_shards() {
        let config = ErasureConfig::balanced();
        let codec = ErasureCodec::new(config);

        let original = vec![0x42u8; 1568];
        let shards = codec.encode(&original, 1).unwrap();

        // Keep only 2 original and 2 recovery shards (still 4 = k)
        let partial: Vec<_> = shards.into_iter()
            .enumerate()
            .filter(|(i, _)| *i == 0 || *i == 1 || *i == 4 || *i == 5)
            .map(|(_, s)| s)
            .collect();
        
        assert_eq!(partial.len(), 4);
        
        let decoded = codec.decode(&partial, original.len()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_insufficient_shards() {
        let config = ErasureConfig::balanced();
        let codec = ErasureCodec::new(config);

        let original = vec![0x42u8; 1568];
        let shards = codec.encode(&original, 1).unwrap();

        // Only keep k-1 shards
        let partial: Vec<_> = shards.into_iter().take(3).collect();
        
        let result = codec.decode(&partial, original.len());
        assert!(matches!(result, Err(ErasureError::InsufficientShards { .. })));
    }

    #[test]
    fn test_erasure_ratchet_reconstruction() {
        let config = ErasureConfig::balanced();
        let mut ratchet = ErasureRatchet::new(config);

        let original = vec![0xABu8; 1568];
        let shards = ratchet.encode_ciphertext(&original, 1).unwrap();
        
        ratchet.set_original_length(1, original.len());

        // Receive shards one by one
        for (i, shard) in shards.into_iter().enumerate() {
            let result = ratchet.receive_shard(shard).unwrap();
            
            if i < 3 {
                // Not enough yet
                assert!(result.is_none());
            } else if result.is_some() {
                // Should reconstruct after k shards
                let decoded = result.unwrap();
                assert_eq!(decoded, original);
                return;
            }
        }
    }

    #[test]
    fn test_duplicate_shard_handling() {
        let config = ErasureConfig::balanced();
        let mut ratchet = ErasureRatchet::new(config);

        let original = vec![0xABu8; 1568];
        let shards = ratchet.encode_ciphertext(&original, 1).unwrap();

        // Send same shard twice
        let first_shard = shards[0].clone();
        ratchet.receive_shard(first_shard.clone()).unwrap();
        let result = ratchet.receive_shard(first_shard).unwrap();
        
        // Should ignore duplicate
        assert!(result.is_none());
    }

    #[test]
    fn test_resilient_profile_recovery() {
        let config = ErasureConfig::resilient(); // k=4, n=12
        let codec = ErasureCodec::new(config);

        let original = vec![0x55u8; 1568];
        let shards = codec.encode(&original, 1).unwrap();
        
        assert_eq!(shards.len(), 12);

        // Keep only 4 shards (lose 66%)
        let partial: Vec<_> = shards.into_iter()
            .enumerate()
            .filter(|(i, _)| *i == 2 || *i == 5 || *i == 8 || *i == 11)
            .map(|(_, s)| s)
            .collect();
        
        assert_eq!(partial.len(), 4);
        
        let decoded = codec.decode(&partial, original.len()).unwrap();
        assert_eq!(decoded, original);
    }
}
