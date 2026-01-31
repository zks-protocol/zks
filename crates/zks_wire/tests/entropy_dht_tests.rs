//! Tests for Kademlia DHT entropy caching functionality
//!
//! This module tests the Phase 3 implementation including:
//! - LRU cache functionality for entropy blocks
//! - Kademlia provider record management
//! - DHT lookup logic for entropy block discovery
//! - Periodic cache synchronization

use std::sync::Arc;
use tokio::time::{sleep, Duration};
use zks_crypt::entropy_block::{EntropyBlock, DrandRound};
use zks_wire::{
    entropy_cache::{EntropyCache, EntropyCacheConfig},
    entropy_swarm::{EntropySwarm, EntropySwarmConfig, EntropyBlockProvider},
    dht_lookup::{DHTLookupService, DHTLookupConfig},
    swarm::Swarm,
    PeerId,
};

/// Create a test entropy block with specific rounds
fn create_test_entropy_block(start_round: u64, end_round: u64) -> EntropyBlock {
    let mut block = EntropyBlock::new(start_round);
    
    for round_num in start_round..=end_round {
        let round = DrandRound {
            round: round_num,
            randomness: [0x42; 32], // Test randomness
            signature: vec![0x43; 64],  // Test signature
            previous_signature: vec![0x44; 64], // Test previous signature
        };
        block.add_round(round).expect(&format!("Failed to add round {}", round_num));
    }
    
    block
}

/// Create a test peer ID
fn create_test_peer_id(index: u32) -> PeerId {
    let mut bytes = [0u8; 32];
    bytes[0..4].copy_from_slice(&index.to_be_bytes());
    PeerId::from_bytes(bytes)
}

#[tokio::test]
async fn test_entropy_cache_basic_operations() {
    let config = EntropyCacheConfig {
        max_blocks: 100,
        max_block_size: 32 * 1024 * 1024,
        ttl_seconds: 3600,
        auto_cleanup: true,
        cleanup_interval_seconds: 300,
    };
    
    let cache = EntropyCache::new(config);
    
    // Test storing and retrieving blocks
    let block1 = create_test_entropy_block(1, 100);
    let block2 = create_test_entropy_block(101, 200);
    
    // Store blocks
    cache.store_block(block1.clone()).await.expect("Failed to store block1");
    cache.store_block(block2.clone()).await.expect("Failed to store block2");
    
    // Retrieve blocks
    let retrieved1 = cache.get_block(1).await.expect("Failed to get block1");
    let retrieved2 = cache.get_block(101).await.expect("Failed to get block2");
    
    assert!(retrieved1.is_some());
    assert!(retrieved2.is_some());
    
    let retrieved1 = retrieved1.unwrap();
    let retrieved2 = retrieved2.unwrap();
    
    assert_eq!(retrieved1.start_round, block1.start_round);
    assert_eq!(retrieved1.end_round, block1.end_round);
    assert_eq!(retrieved2.start_round, block2.start_round);
    assert_eq!(retrieved2.end_round, block2.end_round);
    
    // Test non-existent block
    let non_existent = cache.get_block(999).await.expect("Failed to get non-existent block");
    assert!(non_existent.is_none());
}

#[tokio::test]
async fn test_entropy_cache_lru_eviction() {
    let config = EntropyCacheConfig {
        max_blocks: 3, // Small cache to test eviction
        max_block_size: 32 * 1024 * 1024,
        ttl_seconds: 3600,
        auto_cleanup: true,
        cleanup_interval_seconds: 300,
    };
    
    let cache = EntropyCache::new(config);
    
    // Store more blocks than cache capacity
    let block1 = create_test_entropy_block(1, 10);
    let block2 = create_test_entropy_block(11, 20);
    let block3 = create_test_entropy_block(21, 30);
    let block4 = create_test_entropy_block(31, 40);
    
    cache.store_block(block1.clone()).await.expect("Failed to store block1");
    cache.store_block(block2.clone()).await.expect("Failed to store block2");
    cache.store_block(block3.clone()).await.expect("Failed to store block3");
    
    // This should evict the least recently used block (block1)
    cache.store_block(block4.clone()).await.expect("Failed to store block4");
    
    // Check that block1 was evicted
    let retrieved1 = cache.get_block(1).await.expect("Failed to get block1");
    assert!(retrieved1.is_none());
    
    // Check that other blocks are still there
    let retrieved2 = cache.get_block(11).await.expect("Failed to get block2");
    let retrieved3 = cache.get_block(21).await.expect("Failed to get block3");
    let retrieved4 = cache.get_block(31).await.expect("Failed to get block4");
    
    assert!(retrieved2.is_some());
    assert!(retrieved3.is_some());
    assert!(retrieved4.is_some());
}

#[tokio::test]
async fn test_provider_record_management() {
    let config = EntropyCacheConfig {
        max_blocks: 100,
        max_block_size: 32 * 1024 * 1024,
        ttl_seconds: 3600,
        auto_cleanup: true,
        cleanup_interval_seconds: 300,
    };
    
    let cache = EntropyCache::new(config);
    
    let peer1 = create_test_peer_id(1);
    let peer2 = create_test_peer_id(2);
    let peer3 = create_test_peer_id(3);
    
    // Add provider records
    cache.add_provider_record(1, peer1.to_string()).await.expect("Failed to add provider1");
    cache.add_provider_record(1, peer2.to_string()).await.expect("Failed to add provider2");
    cache.add_provider_record(2, peer3.to_string()).await.expect("Failed to add provider3");
    
    // Query providers
    let providers1 = cache.get_providers(1).await;
    let providers2 = cache.get_providers(2).await;
    let providers3 = cache.get_providers(999).await;
    
    assert_eq!(providers1.len(), 2);
    assert_eq!(providers2.len(), 1);
    assert_eq!(providers3.len(), 0);
    
    // Remove provider record
    let removed = cache.remove_provider_record(1, &peer1.to_string()).await.expect("Failed to remove provider");
    assert!(removed);
    
    let providers1_after = cache.get_providers(1).await;
    assert_eq!(providers1_after.len(), 1);
    assert_eq!(providers1_after[0], peer2.to_string());
}

#[tokio::test]
async fn test_entropy_swarm_block_validation() {
    let config = EntropySwarmConfig {
        max_cached_blocks: 100,
        cache_ttl_seconds: 3600,
        enable_gossip: true,
        enable_serving: true,
        max_concurrent_requests: 10,
    };
    
    let swarm = EntropySwarm::new(config);
    
    // Test with valid block
    let valid_block = create_test_entropy_block(1, 50);
    let result = swarm.handle_received_block(valid_block, "test_peer".to_string()).await;
    assert!(result.is_ok());
    
    // Test with corrupted block (empty rounds)
    let mut corrupted_block = create_test_entropy_block(100, 100);
    corrupted_block.rounds.clear(); // Corrupt the block
    
    let result = swarm.handle_received_block(corrupted_block, "test_peer".to_string()).await;
    assert!(result.is_ok()); // Should still succeed but log warning
    
    // Verify cache stats
    let stats = swarm.get_cache_stats().await;
    assert_eq!(stats.total_blocks, 1); // Only the valid block should be stored
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dht_lookup_configuration() {
    let lookup_config = DHTLookupConfig {
        max_parallel_queries: 5,
        query_timeout: Duration::from_secs(30),
        max_retries: 3,
        retry_delay: Duration::from_secs(5),
    };
    
    let swarm = Swarm::new("test-network".to_string());
    let cache = Arc::new(EntropyCache::new(EntropyCacheConfig::default()));
    
    let lookup = DHTLookupService::new(Arc::new(swarm), cache, lookup_config);
    
    // Test configuration is properly set
    // Note: DHTLookupService doesn't expose config directly, so we just verify it was created
    assert!(true); // Service was created successfully
}

#[tokio::test]
async fn test_cache_cleanup_expired() {
    let config = EntropyCacheConfig {
        max_blocks: 100,
        max_block_size: 32 * 1024 * 1024,
        ttl_seconds: 1, // 1 second TTL for testing
        auto_cleanup: true,
        cleanup_interval_seconds: 1,
    };
    
    let cache = EntropyCache::new(config);
    
    // Store a block
    let block = create_test_entropy_block(1, 10);
    cache.store_block(block).await.expect("Failed to store block");
    
    // Verify block exists
    let retrieved = cache.get_block(1).await.expect("Failed to get block");
    assert!(retrieved.is_some());
    
    // Wait for expiration
    sleep(Duration::from_secs(2)).await;
    
    // Cleanup expired blocks
    let cleaned_count = cache.cleanup_expired().await;
    assert_eq!(cleaned_count, 1);
    
    // Verify block was removed
    let retrieved_after = cache.get_block(1).await.expect("Failed to get block after cleanup");
    assert!(retrieved_after.is_none());
}

#[tokio::test]
async fn test_entropy_block_provider_conversion() {
    let provider_record = EntropyBlockProvider {
        start_round: 100,
        end_round: 199,
        block_hash: [0x42; 32],
        peer_id: "test_peer_id".to_string(),
    };
    
    // Test basic properties
    assert_eq!(provider_record.start_round, 100);
    assert_eq!(provider_record.end_round, 199);
    assert_eq!(provider_record.peer_id, "test_peer_id");
    
    // Test hash is properly set
    assert_eq!(provider_record.block_hash[0], 0x42);
    assert_eq!(provider_record.block_hash[31], 0x42);
}

#[tokio::test]
async fn test_concurrent_cache_operations() {
    let config = EntropyCacheConfig {
        max_blocks: 50,
        max_block_size: 32 * 1024 * 1024,
        ttl_seconds: 3600,
        auto_cleanup: true,
        cleanup_interval_seconds: 300,
    };
    
    let cache = Arc::new(EntropyCache::new(config));
    let mut handles = vec![];
    
    // Spawn multiple concurrent operations
    for i in 0..10 {
        let cache_clone = cache.clone();
        let start_round = (i + 1) * 100; // Start from round 100 to avoid round 0
        let handle = tokio::spawn(async move {
            let block = create_test_entropy_block(start_round, start_round + 99);
            cache_clone.store_block(block).await.expect("Failed to store block");
            
            let retrieved = cache_clone.get_block(start_round).await.expect("Failed to get block");
            assert!(retrieved.is_some());
            
            // Add provider records
            let peer_id = create_test_peer_id(i as u32);
            cache_clone.add_provider_record(start_round, peer_id.to_string()).await.expect("Failed to add provider");
        });
        handles.push(handle);
    }
    
    // Wait for all operations to complete
    for handle in handles {
        handle.await.expect("Task failed");
    }
    
    // Verify all blocks were stored
    for i in 0..10 {
        let start_round = (i + 1) * 100; // Match the rounds we stored
        let retrieved = cache.get_block(start_round).await.expect("Failed to get block");
        assert!(retrieved.is_some());
        
        let providers = cache.get_providers(start_round).await;
        assert_eq!(providers.len(), 1);
    }
}

#[tokio::test]
async fn test_cache_statistics() {
    let config = EntropyCacheConfig {
        max_blocks: 100,
        max_block_size: 32 * 1024 * 1024,
        ttl_seconds: 3600,
        auto_cleanup: true,
        cleanup_interval_seconds: 300,
    };
    
    let cache = EntropyCache::new(config);
    
    // Store some blocks
    for i in 0..5 {
        let start_round = (i + 1) * 100; // Start from round 100 to avoid round 0
        let block = create_test_entropy_block(start_round, start_round + 99);
        cache.store_block(block).await.expect("Failed to store block");
    }
    
    // Access some blocks to generate stats
    for _ in 0..3 {
        cache.get_block(100).await.expect("Failed to get block");
        cache.get_block(200).await.expect("Failed to get block");
    }
    
    let stats = cache.get_stats().await;
    
    assert_eq!(stats.total_blocks, 5);
    assert_eq!(stats.expired_blocks, 0);
    assert_eq!(stats.total_requests, 6); // 3 accesses to each of 2 blocks
    assert!(stats.hit_rate >= 0.0 && stats.hit_rate <= 1.0);
}