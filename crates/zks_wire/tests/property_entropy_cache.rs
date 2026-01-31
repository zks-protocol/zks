use proptest::prelude::*;
use zks_wire::entropy_cache::{EntropyCache, EntropyCacheConfig};
use zks_crypt::entropy_block::{EntropyBlock, DrandRound};

proptest! {
    #[test]
    fn prop_cache_max_blocks_invariant(
        max_blocks in 1usize..100,
        block_count in 1usize..200,
    ) {
        // Property: Cache should never exceed max_blocks
        let config = EntropyCacheConfig {
            max_blocks,
            ttl_seconds: 86400, // 24 hours to avoid expiration during test
            ..Default::default()
        };
        
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cache = EntropyCache::new(config);
            
            // Store more blocks than max_blocks
            for i in 0..block_count {
                let start_round = (i + 1) as u64 * 100; // Start from 100 to avoid round 0 issues
                let block = create_test_block(start_round, 99);
                cache.store_block(block).await.expect("Failed to store block");
            }
            
            // Check cache size
            let stats = cache.get_stats().await;
            prop_assert!(stats.total_blocks <= max_blocks);
            Ok::<(), proptest::test_runner::TestCaseError>(())
        })?;
    }
    
    #[test]
    fn prop_cache_lru_eviction_order(
        max_blocks in 3usize..10,
        additional_blocks in 1usize..5,
    ) {
        // Property: LRU eviction should maintain correct order
        let config = EntropyCacheConfig {
            max_blocks,
            ..Default::default()
        };
        
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cache = EntropyCache::new(config);
            
            // Store exactly max_blocks
            for i in 0..max_blocks {
                let start_round = (i + 1) as u64 * 100; // Start from 100 to avoid round 0 issues
                let block = create_test_block(start_round, 99);
                cache.store_block(block).await.expect("Failed to store block");
            }
            
            // Access first block to make it recently used
            cache.get_block(100).await.expect("Failed to get block");
            
            // Store additional blocks to trigger eviction
            for i in max_blocks..(max_blocks + additional_blocks) {
                let start_round = (i + 1) as u64 * 100;
                let block = create_test_block(start_round, 99);
                cache.store_block(block).await.expect("Failed to store block");
            }
            
            // Verify cache size is maintained at max_blocks
            let stats = cache.get_stats().await;
            prop_assert_eq!(stats.total_blocks, max_blocks);
            Ok::<(), proptest::test_runner::TestCaseError>(())
        })?;
    }
    
    #[test]
    fn prop_cache_block_size_limit(
        _block_size in 1usize..1000,
        max_block_size in 1000usize..10000,
    ) {
        // Property: Blocks exceeding max_block_size should be rejected
        let config = EntropyCacheConfig {
            max_block_size,
            ..Default::default()
        };
        
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cache = EntropyCache::new(config);
            
            // Create a block with many rounds to exceed size limit
            let rounds_count = (max_block_size / std::mem::size_of::<DrandRound>()) + 10;
            let block = create_large_block(1000, rounds_count as u64);
            
            // Should fail due to size limit
            let result = cache.store_block(block).await;
            prop_assert!(result.is_err());
            Ok::<(), proptest::test_runner::TestCaseError>(())
        })?;
    }
}

// Helper function to create test blocks
fn create_test_block(start_round: u64, round_count: u64) -> EntropyBlock {
    let end_round = start_round + round_count - 1;
    let rounds: Vec<DrandRound> = (start_round..=end_round)
        .map(|i| DrandRound {
            round: i,
            randomness: [0u8; 32],
            signature: vec![0u8; 96],
            previous_signature: vec![0u8; 96],
        })
        .collect();
    
    EntropyBlock::from_rounds(rounds).unwrap()
}

// Helper function to create large blocks
fn create_large_block(start_round: u64, rounds_count: u64) -> EntropyBlock {
    let end_round = start_round + rounds_count - 1;
    let rounds: Vec<DrandRound> = (start_round..=end_round)
        .map(|i| DrandRound {
            round: i,
            randomness: [0u8; 32],
            signature: vec![0u8; 96],
            previous_signature: vec![0u8; 96],
        })
        .collect();
    
    EntropyBlock::from_rounds(rounds).unwrap()
}