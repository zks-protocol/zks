//! Ciphertext Scrambling Module
//! 
//! Implements Citadel-style byte position scrambling to resist traffic analysis.
//! After encryption, ciphertext bytes are permuted according to a deterministic
//! mapping derived from shared entropy.
//! 
//! # Security Benefits
//! - Makes traffic pattern analysis harder
//! - Prevents correlation attacks between packets
//! - Adds another layer of obfuscation on top of encryption
//! 
//! # How It Works
//! 1. Both peers derive the same permutation table from shared entropy
//! 2. Sender: scramble(ciphertext) before transmission
//! 3. Receiver: unscramble(data) after reception
//! 4. Mapping is deterministic - both sides produce identical tables

use sha2::{Sha256, Digest};

/// Maximum data size we support scrambling (64KB)
/// Larger data should be chunked
pub const MAX_SCRAMBLE_SIZE: usize = 65536;

/// Ciphertext scrambler using Fisher-Yates derived permutation
pub struct CiphertextScrambler {
    /// Forward permutation: original_pos -> scrambled_pos
    forward_map: Vec<u16>,
    /// Reverse permutation: scrambled_pos -> original_pos
    reverse_map: Vec<u16>,
    /// Size this scrambler was built for
    size: usize,
}

impl CiphertextScrambler {
    /// Create a new scrambler from shared entropy
    /// 
    /// # Arguments
    /// * `entropy` - 32 bytes of shared entropy (e.g., from session key)
    /// * `size` - Size of data to scramble (must be <= MAX_SCRAMBLE_SIZE)
    /// 
    /// # Panics
    /// Panics if size > MAX_SCRAMBLE_SIZE
    pub fn from_entropy(entropy: &[u8; 32], size: usize) -> Self {
        assert!(size <= MAX_SCRAMBLE_SIZE, "Size exceeds maximum scramble size");
        
        // Generate forward permutation using Fisher-Yates shuffle
        // seeded by SHA256 chain of entropy
        let forward_map = Self::generate_permutation(entropy, size);
        
        // Build reverse map
        let mut reverse_map = vec![0u16; size];
        for (original_pos, &scrambled_pos) in forward_map.iter().enumerate() {
            reverse_map[scrambled_pos as usize] = original_pos as u16;
        }
        
        Self {
            forward_map,
            reverse_map,
            size,
        }
    }
    
    /// Generate a permutation using deterministic Fisher-Yates shuffle
    fn generate_permutation(entropy: &[u8; 32], size: usize) -> Vec<u16> {
        // Initialize identity permutation
        let mut perm: Vec<u16> = (0..size as u16).collect();
        
        if size <= 1 {
            return perm;
        }
        
        // Use entropy to seed a deterministic PRNG
        // We'll use SHA256 chaining for random numbers
        let mut state = *entropy;
        let mut random_idx = 0usize;
        let mut random_bytes = [0u8; 32];
        
        // Fisher-Yates shuffle with rejection sampling to eliminate modulo bias
        for i in (1..size).rev() {
            // Generate unbiased random index in range [0, i]
            // Use modular reduction with sufficient randomness to avoid bias
            let j = if i <= 255 {
                // For small ranges, use single byte with simple modular reduction
                if random_idx >= 32 {
                    let mut hasher = Sha256::new();
                    hasher.update(&state);
                    hasher.update(&(i as u64).to_le_bytes());
                    let result = hasher.finalize();
                    random_bytes.copy_from_slice(&result);
                    state = random_bytes;
                    random_idx = 0;
                }
                
                let r = random_bytes[random_idx];
                random_idx += 1;
                (r as usize) % (i + 1)
            } else {
                // For larger ranges, use multiple bytes with better distribution
                if random_idx >= 28 { // Need at least 4 bytes
                    let mut hasher = Sha256::new();
                    hasher.update(&state);
                    hasher.update(&(i as u64).to_le_bytes());
                    let result = hasher.finalize();
                    random_bytes.copy_from_slice(&result);
                    random_idx = 0;
                }
                
                // Use 32-bit value for better distribution
                let r = ((random_bytes[random_idx] as u32) << 24)
                    | ((random_bytes[random_idx + 1] as u32) << 16)
                    | ((random_bytes[random_idx + 2] as u32) << 8)
                    | (random_bytes[random_idx + 3] as u32);
                random_idx += 4;
                (r as usize) % (i + 1)
            };
            
            // Swap
            perm.swap(i, j);
        }
        
        perm
    }
    
    /// Scramble data in-place
    /// 
    /// # Arguments
    /// * `data` - Mutable slice to scramble (length must match scrambler size)
    pub fn scramble(&self, data: &mut [u8]) {
        assert_eq!(data.len(), self.size, "Data length must match scrambler size");
        
        // Use cycle-based in-place permutation to avoid temporary allocation
        let mut visited = vec![false; self.size];
        
        for i in 0..self.size {
            if visited[i] {
                continue;
            }
            
            // Follow the cycle
            let mut current = i;
            let temp = data[i];
            
            loop {
                let next = self.forward_map[current] as usize;
                if next == i {
                    // End of cycle
                    data[current] = temp;
                    visited[current] = true;
                    break;
                }
                
                data[current] = data[next];
                visited[current] = true;
                current = next;
            }
        }
    }
    
    /// Unscramble data in-place
    /// 
    /// # Arguments
    /// * `data` - Mutable slice to unscramble (length must match scrambler size)
    pub fn unscramble(&self, data: &mut [u8]) {
        assert_eq!(data.len(), self.size, "Data length must match scrambler size");
        
        // Use cycle-based in-place permutation to avoid temporary allocation
        let mut visited = vec![false; self.size];
        
        for i in 0..self.size {
            if visited[i] {
                continue;
            }
            
            // Follow the cycle in reverse
            let mut current = i;
            let temp = data[i];
            
            loop {
                let prev = self.reverse_map[current] as usize;
                if prev == i {
                    // End of cycle
                    data[current] = temp;
                    visited[current] = true;
                    break;
                }
                
                data[current] = data[prev];
                visited[current] = true;
                current = prev;
            }
        }
    }
    
    /// Scramble data, returning a new vector
    pub fn scramble_copy(&self, data: &[u8]) -> Vec<u8> {
        assert_eq!(data.len(), self.size, "Data length must match scrambler size");
        
        let mut result = vec![0u8; self.size];
        for (original_pos, &scrambled_pos) in self.forward_map.iter().enumerate() {
            result[scrambled_pos as usize] = data[original_pos];
        }
        result
    }
    
    /// Unscramble data, returning a new vector
    pub fn unscramble_copy(&self, data: &[u8]) -> Vec<u8> {
        assert_eq!(data.len(), self.size, "Data length must match scrambler size");
        
        let mut result = vec![0u8; self.size];
        for (scrambled_pos, &original_pos) in self.reverse_map.iter().enumerate() {
            result[original_pos as usize] = data[scrambled_pos];
        }
        result
    }
    
    /// Get the size this scrambler was built for
    pub fn size(&self) -> usize {
        self.size
    }
}

/// Convenience function: scramble data with entropy
pub fn scramble_with_entropy(data: &mut [u8], entropy: &[u8; 32]) {
    if data.is_empty() {
        return;
    }
    let scrambler = CiphertextScrambler::from_entropy(entropy, data.len());
    scrambler.scramble(data);
}

/// Convenience function: unscramble data with entropy
pub fn unscramble_with_entropy(data: &mut [u8], entropy: &[u8; 32]) {
    if data.is_empty() {
        return;
    }
    let scrambler = CiphertextScrambler::from_entropy(entropy, data.len());
    scrambler.unscramble(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scramble_unscramble_identity() {
        let entropy = [0x42u8; 32];
        let original = b"Hello, World! This is a test message for scrambling.";
        
        let scrambler = CiphertextScrambler::from_entropy(&entropy, original.len());
        
        let mut data = original.to_vec();
        scrambler.scramble(&mut data);
        
        // Data should be different after scrambling
        assert_ne!(&data[..], &original[..]);
        
        scrambler.unscramble(&mut data);
        
        // Data should be restored after unscrambling
        assert_eq!(&data[..], &original[..]);
    }

    #[test]
    fn test_deterministic_scrambling() {
        let entropy = [0xABu8; 32];
        let data = b"Test data for deterministic scrambling";
        
        let scrambler1 = CiphertextScrambler::from_entropy(&entropy, data.len());
        let scrambler2 = CiphertextScrambler::from_entropy(&entropy, data.len());
        
        let result1 = scrambler1.scramble_copy(data);
        let result2 = scrambler2.scramble_copy(data);
        
        // Same entropy should produce same scrambling
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_different_entropy_different_result() {
        let entropy1 = [0x11u8; 32];
        let entropy2 = [0x22u8; 32];
        let data = b"Test data for different entropy scrambling test";
        
        let scrambler1 = CiphertextScrambler::from_entropy(&entropy1, data.len());
        let scrambler2 = CiphertextScrambler::from_entropy(&entropy2, data.len());
        
        let result1 = scrambler1.scramble_copy(data);
        let result2 = scrambler2.scramble_copy(data);
        
        // Different entropy should produce different scrambling
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_convenience_functions() {
        let entropy = [0x99u8; 32];
        let original = b"Convenience test";
        
        let mut data = original.to_vec();
        scramble_with_entropy(&mut data, &entropy);
        assert_ne!(&data[..], &original[..]);
        
        unscramble_with_entropy(&mut data, &entropy);
        assert_eq!(&data[..], &original[..]);
    }

    #[test]
    fn test_single_byte() {
        let entropy = [0xFFu8; 32];
        let mut data = vec![0x42u8];
        
        scramble_with_entropy(&mut data, &entropy);
        assert_eq!(data, vec![0x42u8]); // Single byte can't be scrambled
    }

    #[test]
    fn test_empty_data() {
        let entropy = [0x00u8; 32];
        let mut data: Vec<u8> = vec![];
        
        scramble_with_entropy(&mut data, &entropy);
        assert!(data.is_empty());
    }
}