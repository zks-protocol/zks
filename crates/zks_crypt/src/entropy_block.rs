use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// A single drand round with metadata for verification and storage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DrandRound {
    /// The round number for this drand beacon output
    pub round: u64,
    /// The 32-byte randomness output from the drand beacon
    pub randomness: [u8; 32],
    /// The BLS signature for this round's randomness
    pub signature: Vec<u8>,
    /// The BLS signature from the previous round (for chaining verification)
    pub previous_signature: Vec<u8>,
}

/// A block of drand rounds for efficient storage and distribution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntropyBlock {
    /// The first round number included in this block
    pub start_round: u64,
    /// The last round number included in this block
    pub end_round: u64,
    /// The collection of drand rounds in this block
    pub rounds: Vec<DrandRound>,
    /// SHA-256 hash of all rounds in this block for integrity verification
    pub block_hash: [u8; 32],
}

impl DrandRound {
    /// Create a new DrandRound with all required fields
    pub fn new(round: u64, randomness: [u8; 32], signature: Vec<u8>, previous_signature: Vec<u8>) -> Self {
        Self {
            round,
            randomness,
            signature,
            previous_signature,
        }
    }

    /// Verify the integrity of this round by checking basic constraints
    pub fn verify_basic(&self) -> bool {
        // Basic validation: round number should be positive
        if self.round == 0 {
            return false;
        }
        
        // Randomness should be exactly 32 bytes
        if self.randomness.len() != 32 {
            return false;
        }
        
        // Signature should not be empty
        if self.signature.is_empty() {
            return false;
        }
        
        true
    }

    /// Calculate hash of this round for integrity verification
    pub fn calculate_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.round.to_be_bytes());
        hasher.update(&self.randomness);
        hasher.update(&self.signature);
        hasher.update(&self.previous_signature);
        hasher.finalize().into()
    }
}

impl EntropyBlock {
    /// Create a new empty EntropyBlock
    pub fn new(start_round: u64) -> Self {
        Self {
            start_round,
            end_round: start_round,
            rounds: Vec::new(),
            block_hash: [0u8; 32],
        }
    }

    /// Add a round to the block and update end_round
    pub fn add_round(&mut self, round: DrandRound) -> Result<(), String> {
        // Verify the round is sequential
        if !self.rounds.is_empty() && round.round != self.end_round + 1 {
            return Err(format!(
                "Round {} is not sequential. Expected round {}",
                round.round,
                self.end_round + 1
            ));
        }
        
        // Verify basic integrity of the round
        if !round.verify_basic() {
            return Err("Invalid round data".to_string());
        }
        
        self.rounds.push(round);
        self.end_round = self.start_round + self.rounds.len() as u64 - 1;
        self.update_block_hash();
        
        Ok(())
    }

    /// Add multiple rounds at once for efficiency
    pub fn add_rounds(&mut self, rounds: Vec<DrandRound>) -> Result<(), String> {
        for round in rounds {
            self.add_round(round)?;
        }
        Ok(())
    }

    /// Calculate the block hash based on all rounds
    fn update_block_hash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.start_round.to_be_bytes());
        hasher.update(self.end_round.to_be_bytes());
        
        for round in &self.rounds {
            let round_hash = round.calculate_hash();
            hasher.update(&round_hash);
        }
        
        self.block_hash = hasher.finalize().into();
    }

    /// Verify the integrity of the entire block
    pub fn verify_integrity(&self) -> bool {
        // Check that we have the expected number of rounds
        let expected_rounds = (self.end_round - self.start_round + 1) as usize;
        if self.rounds.len() != expected_rounds {
            return false;
        }
        
        // Verify each round is sequential and valid
        for (i, round) in self.rounds.iter().enumerate() {
            let expected_round = self.start_round + i as u64;
            if round.round != expected_round {
                return false;
            }
            
            if !round.verify_basic() {
                return false;
            }
        }
        
        // Verify the block hash matches
        let mut temp_block = self.clone();
        temp_block.update_block_hash();
        temp_block.block_hash == self.block_hash
    }

    /// Get the size of this block in bytes when serialized
    pub fn serialized_size(&self) -> Result<usize, bincode::Error> {
        bincode::serialized_size(self).map(|s| s as usize)
    }

    /// Serialize the block to bytes using bincode
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize the block from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    /// Save the block to a file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let bytes = self.to_bytes().map_err(|e| format!("Serialization error: {}", e))?;
        
        fs::write(&path, bytes).map_err(|e| format!("File write error: {}", e))?;
        
        Ok(())
    }

    /// Load the block from a file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let bytes = fs::read(&path).map_err(|e| format!("File read error: {}", e))?;
        
        let block = Self::from_bytes(&bytes).map_err(|e| format!("Deserialization error: {}", e))?;
        
        // Verify integrity after loading
        if !block.verify_integrity() {
            return Err("Block integrity verification failed".to_string());
        }
        
        Ok(block)
    }

    /// Get a specific round from the block
    pub fn get_round(&self, round_number: u64) -> Option<&DrandRound> {
        if round_number < self.start_round || round_number > self.end_round {
            return None;
        }
        
        let index = (round_number - self.start_round) as usize;
        self.rounds.get(index)
    }

    /// Check if this block contains a specific round
    pub fn contains_round(&self, round_number: u64) -> bool {
        round_number >= self.start_round && round_number <= self.end_round
    }

    /// Get the number of rounds in this block
    pub fn len(&self) -> usize {
        self.rounds.len()
    }

    /// Check if the block is empty
    pub fn is_empty(&self) -> bool {
        self.rounds.is_empty()
    }

    /// Create a block from a range of rounds
    pub fn from_rounds(rounds: Vec<DrandRound>) -> Result<Self, String> {
        if rounds.is_empty() {
            return Err("Cannot create block from empty rounds".to_string());
        }
        
        let start_round = rounds[0].round;
        let mut block = Self::new(start_round);
        block.add_rounds(rounds)?;
        
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_round(round_num: u64) -> DrandRound {
        DrandRound::new(
            round_num,
            [round_num as u8; 32],
            vec![round_num as u8; 96], // BLS signature is 96 bytes
            vec![(round_num - 1) as u8; 96],
        )
    }

    #[test]
    fn test_drand_round_creation() {
        let round = create_test_round(100);
        assert_eq!(round.round, 100);
        assert!(round.verify_basic());
    }

    #[test]
    fn test_entropy_block_creation() {
        let block = EntropyBlock::new(1000);
        assert_eq!(block.start_round, 1000);
        assert_eq!(block.end_round, 1000);
        assert!(block.is_empty());
    }

    #[test]
    fn test_add_round() {
        let mut block = EntropyBlock::new(1000);
        let round1 = create_test_round(1000);
        let round2 = create_test_round(1001);
        
        assert!(block.add_round(round1).is_ok());
        assert_eq!(block.len(), 1);
        assert_eq!(block.end_round, 1000);
        
        assert!(block.add_round(round2).is_ok());
        assert_eq!(block.len(), 2);
        assert_eq!(block.end_round, 1001);
    }

    #[test]
    fn test_sequential_round_validation() {
        let mut block = EntropyBlock::new(1000);
        let round1 = create_test_round(1000);
        let round3 = create_test_round(1002); // Skip round 1001
        
        assert!(block.add_round(round1).is_ok());
        assert!(block.add_round(round3).is_err()); // Should fail
    }

    #[test]
    fn test_serialization() {
        let mut block = EntropyBlock::new(1000);
        let round1 = create_test_round(1000);
        let round2 = create_test_round(1001);
        
        block.add_round(round1).unwrap();
        block.add_round(round2).unwrap();
        
        // Test serialization
        let bytes = block.to_bytes().unwrap();
        assert!(bytes.len() > 0);
        
        // Test deserialization
        let deserialized = EntropyBlock::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.start_round, block.start_round);
        assert_eq!(deserialized.end_round, block.end_round);
        assert_eq!(deserialized.len(), block.len());
        
        // Test integrity verification
        assert!(deserialized.verify_integrity());
    }

    #[test]
    fn test_file_operations() {
        let mut block = EntropyBlock::new(1000);
        let round1 = create_test_round(1000);
        let round2 = create_test_round(1001);
        
        block.add_round(round1).unwrap();
        block.add_round(round2).unwrap();
        
        let test_path = "test_entropy_block.bin";
        
        // Test save
        assert!(block.save_to_file(test_path).is_ok());
        
        // Test load
        let loaded = EntropyBlock::load_from_file(test_path).unwrap();
        assert_eq!(loaded.start_round, block.start_round);
        assert_eq!(loaded.end_round, block.end_round);
        assert_eq!(loaded.len(), block.len());
        
        // Cleanup
        std::fs::remove_file(test_path).unwrap();
    }

    #[test]
    fn test_get_round() {
        let mut block = EntropyBlock::new(1000);
        let round1 = create_test_round(1000);
        let round2 = create_test_round(1001);
        let round3 = create_test_round(1002);
        
        block.add_round(round1.clone()).unwrap();
        block.add_round(round2.clone()).unwrap();
        block.add_round(round3.clone()).unwrap();
        
        assert!(block.get_round(1000).is_some());
        assert!(block.get_round(1001).is_some());
        assert!(block.get_round(1002).is_some());
        assert!(block.get_round(999).is_none()); // Before start
        assert!(block.get_round(1003).is_none()); // After end
    }

    #[test]
    fn test_block_integrity() {
        let mut block = EntropyBlock::new(1000);
        let round1 = create_test_round(1000);
        let round2 = create_test_round(1001);
        
        block.add_round(round1).unwrap();
        block.add_round(round2).unwrap();
        
        assert!(block.verify_integrity());
        
        // Tamper with the block
        let mut tampered = block.clone();
        tampered.start_round = 999; // Invalid start round
        assert!(!tampered.verify_integrity());
    }

    #[test]
    fn test_empty_block_integrity() {
        let block = EntropyBlock::new(1000);
        assert!(!block.verify_integrity()); // Empty block should fail integrity check
    }

    #[test]
    fn test_single_round_block() {
        let mut block = EntropyBlock::new(1000);
        let round = create_test_round(1000);
        
        block.add_round(round).unwrap();
        assert_eq!(block.len(), 1);
        assert_eq!(block.start_round, 1000);
        assert_eq!(block.end_round, 1000);
        assert!(block.verify_integrity());
    }

    #[test]
    fn test_large_block() {
        let mut block = EntropyBlock::new(1);
        
        // Add 100 rounds
        for i in 1..=100 {
            let round = create_test_round(i);
            block.add_round(round).unwrap();
        }
        
        assert_eq!(block.len(), 100);
        assert_eq!(block.start_round, 1);
        assert_eq!(block.end_round, 100);
        assert!(block.verify_integrity());
        
        // Test serialization of large block
        let bytes = block.to_bytes().unwrap();
        let deserialized = EntropyBlock::from_bytes(&bytes).unwrap();
        assert!(deserialized.verify_integrity());
        assert_eq!(deserialized.len(), 100);
    }

    #[test]
    fn test_block_hash_consistency() {
        let mut block1 = EntropyBlock::new(1000);
        let mut block2 = EntropyBlock::new(1000);
        
        let round1 = create_test_round(1000);
        let round2 = create_test_round(1001);
        
        block1.add_round(round1.clone()).unwrap();
        block1.add_round(round2.clone()).unwrap();
        
        block2.add_round(round1).unwrap();
        block2.add_round(round2).unwrap();
        
        // Blocks with same rounds should have same hash
        assert_eq!(block1.block_hash, block2.block_hash);
    }

    #[test]
    fn test_contains_round() {
        let mut block = EntropyBlock::new(1000);
        let round1 = create_test_round(1000);
        let round2 = create_test_round(1001);
        
        block.add_round(round1).unwrap();
        block.add_round(round2).unwrap();
        
        assert!(block.contains_round(1000));
        assert!(block.contains_round(1001));
        assert!(!block.contains_round(999));
        assert!(!block.contains_round(1002));
    }

    #[test]
    fn test_from_rounds() {
        let rounds = vec![
            create_test_round(1000),
            create_test_round(1001),
            create_test_round(1002),
        ];
        
        let block = EntropyBlock::from_rounds(rounds).unwrap();
        assert_eq!(block.len(), 3);
        assert_eq!(block.start_round, 1000);
        assert_eq!(block.end_round, 1002);
        assert!(block.verify_integrity());
    }

    #[test]
    fn test_from_rounds_empty() {
        let rounds: Vec<DrandRound> = vec![];
        let result = EntropyBlock::from_rounds(rounds);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialized_size() {
        let mut block = EntropyBlock::new(1000);
        let round = create_test_round(1000);
        block.add_round(round).unwrap();
        
        let size = block.serialized_size().unwrap();
        assert!(size > 0);
        
        let bytes = block.to_bytes().unwrap();
        assert_eq!(size, bytes.len());
    }

    #[test]
    fn test_invalid_round_data() {
        let round = DrandRound::new(
            1000,
            [0u8; 32], // Valid randomness
            vec![],   // Empty signature - invalid
            vec![0u8; 96],
        );
        
        assert!(!round.verify_basic()); // Should fail basic verification
    }

    #[test]
    fn test_block_corruption_detection() {
        let mut block = EntropyBlock::new(1000);
        let round1 = create_test_round(1000);
        let round2 = create_test_round(1001);
        
        block.add_round(round1).unwrap();
        block.add_round(round2).unwrap();
        
        // Test various corruption scenarios
        let mut corrupted = block.clone();
        
        // Corrupt end round
        corrupted.end_round = 1002;
        assert!(!corrupted.verify_integrity());
        
        // Corrupt by removing a round
        let mut corrupted2 = block.clone();
        corrupted2.rounds.pop();
        assert!(!corrupted2.verify_integrity());
        
        // Corrupt by changing round data
        let mut corrupted3 = block.clone();
        if let Some(round) = corrupted3.rounds.get_mut(0) {
            round.round = 999; // Invalid round number
        }
        assert!(!corrupted3.verify_integrity());
    }

    #[test]
    fn test_file_operations_error_handling() {
        let block = EntropyBlock::new(1000);
        
        // Test saving to invalid path
        let invalid_path = "/invalid/path/that/does/not/exist.bin";
        assert!(block.save_to_file(invalid_path).is_err());
        
        // Test loading from non-existent file
        let non_existent = "this_file_does_not_exist.bin";
        assert!(EntropyBlock::load_from_file(non_existent).is_err());
    }
}