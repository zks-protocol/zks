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



/// Maximum data size we support scrambling (64KB)
/// Larger data should be chunked
pub const MAX_SCRAMBLE_SIZE: usize = 65536;

/// Errors for ciphertext scrambling operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrambleError {
    /// Size exceeds maximum scramble size
    SizeExceeded(usize),
}

impl std::fmt::Display for ScrambleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScrambleError::SizeExceeded(size) => {
                write!(f, "Size {} exceeds maximum scramble size {}", size, MAX_SCRAMBLE_SIZE)
            }
        }
    }
}

impl std::error::Error for ScrambleError {}

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
    /// # Errors
    /// Returns `ScrambleError::SizeExceeded` if size > MAX_SCRAMBLE_SIZE
    pub fn from_entropy(entropy: &[u8; 32], size: usize) -> Result<Self, ScrambleError> {
        if size > MAX_SCRAMBLE_SIZE {
            return Err(ScrambleError::SizeExceeded(size));
        }
        
        // Generate forward permutation using Fisher-Yates shuffle
        // seeded by SHA256 chain of entropy
        let forward_map = Self::generate_permutation(entropy, size);
        
        // Build reverse map
        let mut reverse_map = vec![0u16; size];
        for (original_pos, &scrambled_pos) in forward_map.iter().enumerate() {
            reverse_map[scrambled_pos as usize] = original_pos as u16;
        }
        
        Ok(Self {
            forward_map,
            reverse_map,
            size,
        })
    }
    
    /// Generate a permutation using deterministic Fisher-Yates shuffle
    /// Uses ChaCha20Rng seeded by entropy for cryptographically secure, unbiased permutation
    fn generate_permutation(entropy: &[u8; 32], size: usize) -> Vec<u16> {
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaCha20Rng;
        
        // Initialize identity permutation
        let mut perm: Vec<u16> = (0..size as u16).collect();
        
        if size <= 1 {
            return perm;
        }
        
        // SECURITY: Use ChaCha20Rng seeded by entropy for deterministic but unbiased randomness
        // ChaCha20 is cryptographically secure and gen_range uses rejection sampling
        // This eliminates modulo bias that could theoretically leak permutation information
        let mut rng = ChaCha20Rng::from_seed(*entropy);
        
        // Fisher-Yates shuffle with rejection sampling via gen_range (no modulo bias)
        for i in (1..size).rev() {
            // gen_range uses rejection sampling internally for uniform distribution
            let j = rng.gen_range(0..=i);
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
pub fn scramble_with_entropy(data: &mut [u8], entropy: &[u8; 32]) -> Result<(), ScrambleError> {
    if data.is_empty() {
        return Ok(());
    }
    let scrambler = CiphertextScrambler::from_entropy(entropy, data.len())?;
    scrambler.scramble(data);
    Ok(())
}

/// Convenience function: unscramble data with entropy
pub fn unscramble_with_entropy(data: &mut [u8], entropy: &[u8; 32]) -> Result<(), ScrambleError> {
    if data.is_empty() {
        return Ok(());
    }
    let scrambler = CiphertextScrambler::from_entropy(entropy, data.len())?;
    scrambler.unscramble(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scramble_unscramble_identity() {
        let entropy = [0x42u8; 32];
        let original = b"Hello, World! This is a test message for scrambling.";
        
        let scrambler = CiphertextScrambler::from_entropy(&entropy, original.len()).unwrap();
        
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
        
        let scrambler1 = CiphertextScrambler::from_entropy(&entropy, data.len()).unwrap();
        let scrambler2 = CiphertextScrambler::from_entropy(&entropy, data.len()).unwrap();
        
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
        
        let scrambler1 = CiphertextScrambler::from_entropy(&entropy1, data.len()).unwrap();
        let scrambler2 = CiphertextScrambler::from_entropy(&entropy2, data.len()).unwrap();
        
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
        scramble_with_entropy(&mut data, &entropy).unwrap();
        assert_ne!(&data[..], &original[..]);
        
        unscramble_with_entropy(&mut data, &entropy).unwrap();
        assert_eq!(&data[..], &original[..]);
    }

    #[test]
    fn test_single_byte() {
        let entropy = [0xFFu8; 32];
        let mut data = vec![0x42u8];
        
        scramble_with_entropy(&mut data, &entropy).unwrap();
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