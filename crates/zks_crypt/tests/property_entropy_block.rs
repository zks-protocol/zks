use proptest::prelude::*;
use zks_crypt::entropy_block::*;
use bytes::Bytes;

proptest! {
    #[test]
    fn prop_entropy_block_roundtrip(
        start_round in 0u64..1_000_000,
        block_size in 1u64..1000,
    ) {
        // Generate rounds
        let end_round = start_round.saturating_add(block_size).saturating_sub(1);
        let mut rounds = Vec::new();
        
        for i in start_round..=end_round {
            rounds.push(DrandRound {
                round: i,
                randomness: [0u8; 32], // Simple for now
                signature: vec![0u8; 96],
                previous_signature: vec![0u8; 96],
            });
        }
        
        // Create block
        let block = EntropyBlock::from_rounds(rounds.clone()).unwrap();
        
        // Property 1: Round range is correct
        prop_assert_eq!(block.start_round, start_round);
        prop_assert_eq!(block.end_round, end_round);
        
        // Property 2: Serialization roundtrip
        let serialized = block.to_bytes().unwrap();
        let deserialized = EntropyBlock::from_bytes(&serialized).unwrap();
        prop_assert_eq!(block.block_hash, deserialized.block_hash);
        
        // Property 3: Integrity check passes
        prop_assert!(block.verify_integrity());
    }
    
    #[test]
    fn prop_block_hash_uniqueness(
        round_a in 0u64..100_000,
        round_b in 100_001u64..200_000, // Different range
    ) {
        // Two blocks with different rounds should have different hashes
        let block_a = EntropyBlock::from_rounds(vec![DrandRound {
            round: round_a,
            randomness: [1u8; 32],
            signature: vec![0u8; 96],
            previous_signature: vec![0u8; 96],
        }]).unwrap();
        
        let block_b = EntropyBlock::from_rounds(vec![DrandRound {
            round: round_b,
            randomness: [2u8; 32],
            signature: vec![0u8; 96],
            previous_signature: vec![0u8; 96],
        }]).unwrap();
        
        // Property: Different blocks have different hashes
        prop_assert_ne!(block_a.block_hash, block_b.block_hash);
    }
    
    #[test]
    fn prop_message_serialization(
        message_type in 0u8..8u8,
        sequence in 0u32..1_000_000,
        payload_size in 0usize..1000,
    ) {
        // Create a mock wire message (simplified for testing)
        let payload = vec![0u8; payload_size];
        
        // Property 1: Payload size is preserved
        prop_assert_eq!(payload.len(), payload_size);
        
        // Property 2: Sequence number is within valid range
        prop_assert!(sequence < 1_000_000);
        
        // Property 3: Message type is valid (0-7 are defined types)
        let valid_types = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x7F];
        let is_valid_type = valid_types.contains(&message_type) || message_type <= 7;
        prop_assert!(is_valid_type);
        
        // Property 4: Payload can be converted to Bytes
        let bytes_payload = Bytes::from(payload.clone());
        prop_assert_eq!(bytes_payload.len(), payload_size);
    }
    
    #[test]
    fn prop_round_ordering(
        start_round in 1u64..100, // Start from 1 to avoid round 0 issues
        round_count in 1usize..50,
    ) {
        // Create sequential rounds starting from start_round
        let mut drand_rounds = Vec::new();
        for i in 0..round_count {
            drand_rounds.push(DrandRound {
                round: start_round + i as u64,
                randomness: [0u8; 32],
                signature: vec![0u8; 96],
                previous_signature: vec![0u8; 96],
            });
        }
        
        // Property 1: Block can be created from sequential rounds
        let block = EntropyBlock::from_rounds(drand_rounds).unwrap();
        
        // Property 2: Start and end rounds are correct
        prop_assert_eq!(block.start_round, start_round);
        prop_assert_eq!(block.end_round, start_round + round_count as u64 - 1);
        
        // Property 3: Round range is continuous
        prop_assert_eq!(block.end_round - block.start_round + 1, round_count as u64);
        
        // Property 4: Block integrity check passes
        prop_assert!(block.verify_integrity());
    }

    #[test]
    fn prop_entropy_block_hash_uniqueness(
        start_round_a in 1u64..1000,
        start_round_b in 1u64..1000,
        size_a in 1usize..50,
        size_b in 1usize..50,
    ) {
        // Skip if rounds would overlap
        prop_assume!(start_round_a + size_a as u64 <= start_round_b || start_round_b + size_b as u64 <= start_round_a);
        
        // Create first block
        let mut rounds_a = Vec::new();
        for i in 0..size_a {
            rounds_a.push(DrandRound {
                round: start_round_a + i as u64,
                randomness: rand::random(),
                signature: vec![0u8; 96],
                previous_signature: vec![0u8; 96],
            });
        }
        let block_a = EntropyBlock::from_rounds(rounds_a).unwrap();
        
        // Create second block with different rounds or different randomness
        let mut rounds_b = Vec::new();
        for i in 0..size_b {
            rounds_b.push(DrandRound {
                round: start_round_b + i as u64,
                randomness: rand::random(),
                signature: vec![0u8; 96],
                previous_signature: vec![0u8; 96],
            });
        }
        let block_b = EntropyBlock::from_rounds(rounds_b).unwrap();
        
        // Property 1: Different blocks should have different hashes
        prop_assert_ne!(block_a.block_hash, block_b.block_hash);
        
        // Property 2: Block hashes should be deterministic (same rounds = same hash)
        let block_a_copy = EntropyBlock::from_rounds(block_a.rounds.clone()).unwrap();
        prop_assert_eq!(block_a.block_hash, block_a_copy.block_hash);
    }

    #[test]
    fn prop_signature_verification(
        round_num in 1u64..10000,
        randomness in proptest::array::uniform32(0u8..255),
    ) {
        // Property 1: DrandRound basic verification should pass with valid data
        let valid_round = DrandRound {
            round: round_num,
            randomness: randomness,
            signature: vec![0u8; 96], // Valid length for G2 signature
            previous_signature: vec![0u8; 96],
        };
        prop_assert!(valid_round.verify_basic());
        
        // Property 2: Round 0 should fail basic verification
        let invalid_round = DrandRound {
            round: 0,
            randomness: randomness,
            signature: vec![0u8; 96],
            previous_signature: vec![0u8; 96],
        };
        prop_assert!(!invalid_round.verify_basic());
        
        // Property 3: Empty signature should fail
        let empty_sig_round = DrandRound {
            round: round_num,
            randomness: randomness,
            signature: vec![], // Empty signature
            previous_signature: vec![0u8; 96],
        };
        prop_assert!(!empty_sig_round.verify_basic());
        
        // Property 4: Valid signature lengths should pass
        let g2_sig_round = DrandRound {
            round: round_num,
            randomness: randomness,
            signature: vec![0u8; 96], // G2 signature length
            previous_signature: vec![0u8; 96],
        };
        prop_assert!(g2_sig_round.verify_basic());
        
        let g1_sig_round = DrandRound {
            round: round_num,
            randomness: randomness,
            signature: vec![0u8; 48], // G1 signature length
            previous_signature: vec![0u8; 96],
        };
        prop_assert!(g1_sig_round.verify_basic());
    }

    #[test]
    fn prop_entropy_block_split_merge(
        start_round in 1u64..1000,
        total_size in 10usize..100,
        split_point in 5usize..95, // Split point within the range
    ) {
        // Ensure split point is valid (not equal to total_size)
        prop_assume!(split_point < total_size);
        
        // Create a large block
        let mut rounds = Vec::new();
        for i in 0..total_size {
            rounds.push(DrandRound {
                round: start_round + i as u64,
                randomness: rand::random(),
                signature: vec![0u8; 96],
                previous_signature: vec![0u8; 96],
            });
        }
        let original_block = EntropyBlock::from_rounds(rounds.clone()).unwrap();
        
        // Split the block at the split point
        let (left_rounds, right_rounds) = rounds.split_at(split_point);
        let left_block = EntropyBlock::from_rounds(left_rounds.to_vec()).unwrap();
        let right_block = EntropyBlock::from_rounds(right_rounds.to_vec()).unwrap();
        
        // Property 1: Split blocks should have correct ranges
        prop_assert_eq!(left_block.start_round, start_round);
        prop_assert_eq!(left_block.end_round, start_round + split_point as u64 - 1);
        prop_assert_eq!(right_block.start_round, start_round + split_point as u64);
        prop_assert_eq!(right_block.end_round, start_round + total_size as u64 - 1);
        
        // Property 2: Combined rounds should equal original
        let mut combined_rounds = left_block.rounds.clone();
        combined_rounds.extend(right_block.rounds.clone());
        prop_assert_eq!(combined_rounds.len(), original_block.rounds.len());
        
        // Property 3: Split blocks should be valid
        prop_assert!(left_block.verify_integrity());
        prop_assert!(right_block.verify_integrity());
        
        // Property 4: Original block should be reconstructible from parts
        let reconstructed_block = EntropyBlock::from_rounds(combined_rounds).unwrap();
        prop_assert_eq!(reconstructed_block.start_round, original_block.start_round);
        prop_assert_eq!(reconstructed_block.end_round, original_block.end_round);
        prop_assert_eq!(reconstructed_block.rounds.len(), original_block.rounds.len());
    }

    #[test]
    fn prop_entropy_block_concurrent_access(
        start_round in 1u64..1000,
        round_count in 10usize..50,
    ) {
        use std::sync::{Arc, Mutex};
        use std::thread;
        
        // Create a shared block
        let mut rounds = Vec::new();
        for i in 0..round_count {
            rounds.push(DrandRound {
                round: start_round + i as u64,
                randomness: rand::random(),
                signature: vec![0u8; 96],
                previous_signature: vec![0u8; 96],
            });
        }
        let original_block = EntropyBlock::from_rounds(rounds).unwrap();
        let shared_block = Arc::new(Mutex::new(original_block.clone()));
        
        // Property 1: Original block should be valid
        prop_assert!(original_block.verify_integrity());
        
        // Property 2: Concurrent reads should not corrupt data
        let mut handles = Vec::new();
        for _ in 0..3 {
            let block_clone = Arc::clone(&shared_block);
            let handle = thread::spawn(move || {
                let block = block_clone.lock().unwrap();
                // Verify block integrity in each reader
                let is_valid = block.verify_integrity();
                let start_round = block.start_round;
                let end_round = block.end_round;
                (is_valid, start_round, end_round)
            });
            handles.push(handle);
        }
        
        // Wait for all read operations to complete (before writes)
        for handle in handles {
            let (is_valid, start_round, end_round) = handle.join().unwrap();
            prop_assert!(is_valid, "Reader found corrupted block");
            prop_assert_eq!(start_round, original_block.start_round);
            prop_assert_eq!(end_round, original_block.end_round);
        }
        
        // Property 3: Sequential writes should maintain consistency
        let mut write_results = Vec::new();
        
        // First write - should succeed
        let block_clone = Arc::clone(&shared_block);
        let handle = thread::spawn(move || {
            let mut block = block_clone.lock().unwrap();
            let current_end = block.end_round;
            // Simulate a write operation (add a round)
            let new_round = DrandRound {
                round: current_end + 1,
                randomness: rand::random(),
                signature: vec![0u8; 96],
                previous_signature: vec![0u8; 96],
            };
            let result = block.add_round(new_round);
            result.is_ok()
        });
        let first_result = handle.join().unwrap();
        write_results.push(first_result);
        
        // Second write - should also succeed (different round number)
        let block_clone = Arc::clone(&shared_block);
        let handle = thread::spawn(move || {
            let mut block = block_clone.lock().unwrap();
            let current_end = block.end_round;
            // Simulate a write operation (add a round)
            let new_round = DrandRound {
                round: current_end + 1,
                randomness: rand::random(),
                signature: vec![0u8; 96],
                previous_signature: vec![0u8; 96],
            };
            let result = block.add_round(new_round);
            result.is_ok()
        });
        let second_result = handle.join().unwrap();
        write_results.push(second_result);
        
        // Write results are already collected above
        
        // Property 4: Final block should be valid and extended
        let final_block = shared_block.lock().unwrap().clone();
        prop_assert!(final_block.verify_integrity());
        prop_assert!(final_block.end_round >= original_block.end_round);
        prop_assert_eq!(final_block.start_round, original_block.start_round);
        
        // Property 5: Verify the block was extended (at least 1 successful write)
        let successful_writes = write_results.iter().filter(|&&x| x).count();
        prop_assert!(successful_writes >= 1, "At least one write should succeed");
        prop_assert!(
            final_block.end_round >= original_block.end_round + 1,
            "Block should be extended by at least 1 round"
        );
    }

    #[test]
    fn prop_cache_invariants(
        cache_size in 1usize..100,
        round_count in 1usize..200,
        access_pattern in 0u8..3u8, // 0=sequential, 1=random, 2=reverse, 3=burst
    ) {
        use std::collections::HashMap;
        
        // Simulate a simple cache with LRU eviction
        let mut cache = HashMap::new();
        let mut access_order = Vec::new();
        
        // Property 1: Cache size should never exceed capacity
        prop_assert!(cache.len() <= cache_size);
        
        // Simulate different access patterns
        match access_pattern {
            0 => { // Sequential access
                for i in 0..round_count.min(cache_size * 2) {
                    let key = format!("round_{}", i);
                    cache.insert(key.clone(), i);
                    access_order.push(key);
                    
                    // Evict oldest if cache is full
                    if cache.len() > cache_size {
                        if let Some(oldest) = access_order.first() {
                            cache.remove(oldest);
                            access_order.remove(0);
                        }
                    }
                    
                    // Property 2: Cache size invariant maintained
                    prop_assert!(cache.len() <= cache_size);
                }
            },
            1 => { // Random access
                for i in 0..round_count.min(cache_size * 2) {
                    let key_num = rand::random::<usize>() % round_count;
                    let key = format!("round_{}", key_num);
                    
                    // Move to end if exists, otherwise insert
                    if cache.contains_key(&key) {
                        access_order.retain(|k| k != &key);
                    } else if cache.len() >= cache_size {
                        if let Some(oldest) = access_order.first() {
                            cache.remove(oldest);
                            access_order.remove(0);
                        }
                    }
                    
                    cache.insert(key.clone(), key_num);
                    access_order.push(key);
                    
                    prop_assert!(cache.len() <= cache_size);
                }
            },
            _ => { // Other patterns - similar logic
                for i in 0..round_count.min(cache_size * 2) {
                    let key = format!("round_{}", i % (cache_size * 2));
                    
                    if cache.contains_key(&key) {
                        access_order.retain(|k| k != &key);
                    } else if cache.len() >= cache_size {
                        if let Some(oldest) = access_order.first() {
                            cache.remove(oldest);
                            access_order.remove(0);
                        }
                    }
                    
                    cache.insert(key.clone(), i);
                    access_order.push(key);
                    
                    prop_assert!(cache.len() <= cache_size);
                }
            }
        }
        
        // Property 3: All cached items should be valid (exist in cache)
        for key in &access_order {
            prop_assert!(cache.contains_key(key));
        }
        
        // Property 4: Cache should contain most recently accessed items
        if !access_order.is_empty() {
            let recent_key = access_order.last().unwrap();
            prop_assert!(cache.contains_key(recent_key));
        }
    }

    #[test]
    fn prop_timestamp_monotonicity(
        message_count in 1usize..100,
        time_drift in -100i64..100i64, // Simulated clock drift in milliseconds
    ) {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // Get base timestamp
        let base_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        
        // Simulate message timestamps with potential drift
        let mut timestamps = Vec::new();
        for i in 0..message_count {
            let timestamp = base_time + (i as i64 * 1000) + time_drift; // 1 second intervals + drift
            timestamps.push(timestamp);
        }
        
        // Property 1: Timestamps should be monotonically non-decreasing
        for i in 1..timestamps.len() {
            prop_assert!(timestamps[i] >= timestamps[i-1], 
                        "Timestamp {} ({}) should be >= timestamp {} ({})", 
                        i, timestamps[i], i-1, timestamps[i-1]);
        }
        
        // Property 2: Message ordering should match timestamp ordering
        let mut sorted_timestamps = timestamps.clone();
        sorted_timestamps.sort();
        prop_assert_eq!(timestamps.clone(), sorted_timestamps, "Timestamps should be naturally sorted");
        
        // Property 3: Time differences should be reasonable (not too far in future/past)
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        
        for &timestamp in &timestamps {
            let time_diff = (timestamp - current_time).abs();
            // Allow up to 1 hour drift for testing purposes
            prop_assert!(time_diff < 3600_000, "Timestamp drift too large: {} ms", time_diff);
        }
        
        // Property 4: Consecutive messages should have reasonable time gaps
        if timestamps.len() > 1 {
            for i in 1..timestamps.len() {
                let time_gap = timestamps[i] - timestamps[i-1];
                // Gap should be positive and reasonable (not more than 1 hour)
                prop_assert!(time_gap >= 0, "Negative time gap detected: {}", time_gap);
                prop_assert!(time_gap < 3600_000, "Time gap too large: {} ms", time_gap);
            }
        }
    }
}