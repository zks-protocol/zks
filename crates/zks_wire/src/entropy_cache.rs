//! Entropy Block Cache - LRU cache for entropy blocks with Kademlia DHT integration
//!
//! This module provides efficient caching of entropy blocks with automatic cleanup
//! and Kademlia DHT integration for distributed discovery.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use lru::LruCache;
use serde::{Serialize, Deserialize};
use tracing::{debug, info};

use zks_crypt::entropy_block::EntropyBlock;
use crate::{Result, WireError};

/// Configuration for the entropy block cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyCacheConfig {
    /// Maximum number of blocks to cache (default: 100)
    pub max_blocks: usize,
    /// Maximum size of each block in bytes (32 MB)
    pub max_block_size: usize,
    /// Cache TTL in seconds (default: 3600 = 1 hour)
    pub ttl_seconds: u64,
    /// Whether to automatically cleanup expired blocks
    pub auto_cleanup: bool,
    /// Cleanup interval in seconds (default: 300 = 5 minutes)
    pub cleanup_interval_seconds: u64,
}

impl Default for EntropyCacheConfig {
    fn default() -> Self {
        Self {
            max_blocks: 100,              // 100 blocks = ~3.2 GB max
            max_block_size: 32 * 1024 * 1024, // 32 MB per block
            ttl_seconds: 3600,            // 1 hour TTL
            auto_cleanup: true,           // Auto cleanup expired blocks
            cleanup_interval_seconds: 300, // 5 minutes cleanup interval
        }
    }
}

/// Cached entropy block with metadata
#[derive(Debug, Clone)]
struct CachedEntropyBlock {
    /// The entropy block data
    block: EntropyBlock,
    /// Timestamp when the block was cached
    cached_at: u64,
    /// Last access timestamp
    last_accessed: u64,
    /// Access count for LRU eviction
    access_count: u64,
    /// Whether this block is currently being served to other peers
    is_serving: bool,
}

impl CachedEntropyBlock {
    /// Create a new cached block
    fn new(block: EntropyBlock) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            block,
            cached_at: now,
            last_accessed: now,
            access_count: 0,
            is_serving: false,
        }
    }

    /// Check if the block has expired
    fn is_expired(&self, ttl_seconds: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now - self.cached_at > ttl_seconds
    }

    /// Update access metadata
    fn access(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.last_accessed = now;
        self.access_count += 1;
    }
}

/// Statistics about the entropy cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyCacheStats {
    /// Total number of cached blocks
    pub total_blocks: usize,
    /// Total size of cached data in bytes
    pub total_size_bytes: u64,
    /// Number of expired blocks
    pub expired_blocks: usize,
    /// Cache hit rate (0.0 to 1.0)
    pub hit_rate: f64,
    /// Total number of cache requests
    pub total_requests: u64,
    /// Number of cache hits
    pub cache_hits: u64,
    /// Number of cache misses
    pub cache_misses: u64,
    /// Average block size in bytes
    pub avg_block_size_bytes: u64,
    /// Oldest block timestamp
    pub oldest_block_timestamp: u64,
    /// Newest block timestamp
    pub newest_block_timestamp: u64,
}

/// Main entropy cache with LRU eviction and Kademlia DHT integration
#[derive(Debug)]
pub struct EntropyCache {
    /// LRU cache for entropy blocks
    blocks: Arc<RwLock<LruCache<u64, CachedEntropyBlock>>>,
    /// Configuration
    config: EntropyCacheConfig,
    /// Cache statistics
    stats: Arc<RwLock<CacheStatsInternal>>,
    /// Kademlia provider records for blocks we're serving
    provider_records: Arc<RwLock<HashMap<u64, Vec<String>>>>, // peer IDs as strings
}

#[derive(Debug, Default)]
struct CacheStatsInternal {
    total_requests: u64,
    cache_hits: u64,
    cache_misses: u64,
    total_size_bytes: u64,
}

impl EntropyCache {
    /// Create a new entropy cache with the given configuration
    pub fn new(config: EntropyCacheConfig) -> Self {
        let blocks = Arc::new(RwLock::new(LruCache::new(
            std::num::NonZeroUsize::new(config.max_blocks).unwrap_or(std::num::NonZeroUsize::new(100).unwrap())
        )));

        let stats = Arc::new(RwLock::new(CacheStatsInternal::default()));
        let provider_records = Arc::new(RwLock::new(HashMap::new()));

        Self {
            blocks,
            config,
            stats,
            provider_records,
        }
    }

    /// Create a new entropy cache with default configuration
    pub fn with_defaults() -> Self {
        Self::new(EntropyCacheConfig::default())
    }

    /// Store an entropy block in the cache
    pub async fn store_block(&self, block: EntropyBlock) -> Result<()> {
        // Validate block size
        let block_size = std::mem::size_of_val(&block) + (block.rounds.len() * std::mem::size_of::<zks_crypt::entropy_block::DrandRound>());
        if block_size > self.config.max_block_size {
            return Err(WireError::other(&format!(
                "Block size {} exceeds maximum allowed size {}",
                block_size, self.config.max_block_size
            )));
        }

        let start_round = block.start_round;
        
        // Create cached block
        let cached_block = CachedEntropyBlock::new(block);

        // Store in cache
        let mut blocks = self.blocks.write().await;
        blocks.put(start_round, cached_block);

        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_size_bytes += block_size as u64;

        info!("Stored entropy block {} in cache", start_round);
        debug!("Cache now contains {} blocks", blocks.len());

        Ok(())
    }

    /// Retrieve an entropy block from the cache
    pub async fn get_block(&self, start_round: u64) -> Result<Option<EntropyBlock>> {
        let mut blocks = self.blocks.write().await;
        
        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;

        if let Some(cached_block) = blocks.get_mut(&start_round) {
            // Check if expired
            if cached_block.is_expired(self.config.ttl_seconds) {
                // Remove expired block
                blocks.pop(&start_round);
                stats.cache_misses += 1;
                debug!("Block {} expired and removed from cache", start_round);
                return Ok(None);
            }

            // Update access metadata
            cached_block.access();
            stats.cache_hits += 1;

            info!("Retrieved entropy block {} from cache (hit)", start_round);
            Ok(Some(cached_block.block.clone()))
        } else {
            stats.cache_misses += 1;
            debug!("Entropy block {} not found in cache (miss)", start_round);
            Ok(None)
        }
    }

    /// Get multiple blocks by range
    pub async fn get_blocks_range(&self, start_round: u64, end_round: u64) -> Result<Vec<EntropyBlock>> {
        let mut result = Vec::new();
        let blocks = self.blocks.read().await;

        for round in (start_round..=end_round).step_by(1_000_000) {
            if let Some(cached_block) = blocks.peek(&round) {
                // Check if expired
                if !cached_block.is_expired(self.config.ttl_seconds) {
                    result.push(cached_block.block.clone());
                }
            }
        }

        Ok(result)
    }

    /// Check if we have a specific block
    pub async fn has_block(&self, start_round: u64) -> bool {
        let blocks = self.blocks.read().await;
        
        if let Some(cached_block) = blocks.peek(&start_round) {
            !cached_block.is_expired(self.config.ttl_seconds)
        } else {
            false
        }
    }

    /// Remove a block from the cache
    pub async fn remove_block(&self, start_round: u64) -> Result<bool> {
        let mut blocks = self.blocks.write().await;
        
        if blocks.pop(&start_round).is_some() {
            info!("Removed entropy block {} from cache", start_round);
            Ok(true)
        } else {
            debug!("Entropy block {} not found in cache for removal", start_round);
            Ok(false)
        }
    }

    /// Clear all blocks from the cache
    pub async fn clear(&self) -> Result<()> {
        let mut blocks = self.blocks.write().await;
        let mut stats = self.stats.write().await;
        
        let removed_count = blocks.len();
        blocks.clear();
        stats.total_size_bytes = 0;

        info!("Cleared {} blocks from cache", removed_count);
        Ok(())
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> EntropyCacheStats {
        let blocks = self.blocks.read().await;
        let stats = self.stats.read().await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut expired_blocks = 0;
        let mut oldest_timestamp = now;
        let mut newest_timestamp = 0;

        for cached_block in blocks.iter() {
            if cached_block.1.is_expired(self.config.ttl_seconds) {
                expired_blocks += 1;
            }

            if cached_block.1.cached_at < oldest_timestamp {
                oldest_timestamp = cached_block.1.cached_at;
            }
            if cached_block.1.cached_at > newest_timestamp {
                newest_timestamp = cached_block.1.cached_at;
            }
        }

        let hit_rate = if stats.total_requests > 0 {
            stats.cache_hits as f64 / stats.total_requests as f64
        } else {
            0.0
        };

        let avg_block_size = if blocks.len() > 0 {
            stats.total_size_bytes / blocks.len() as u64
        } else {
            0
        };

        EntropyCacheStats {
            total_blocks: blocks.len(),
            total_size_bytes: stats.total_size_bytes,
            expired_blocks,
            hit_rate,
            total_requests: stats.total_requests,
            cache_hits: stats.cache_hits,
            cache_misses: stats.cache_misses,
            avg_block_size_bytes: avg_block_size,
            oldest_block_timestamp: oldest_timestamp,
            newest_block_timestamp: newest_timestamp,
        }
    }

    /// Clean up expired blocks
    pub async fn cleanup_expired(&self) -> usize {
        let mut blocks = self.blocks.write().await;
        let mut removed_count = 0;

        // Collect keys of expired blocks
        let expired_keys: Vec<u64> = blocks
            .iter()
            .filter(|(_, cached_block)| cached_block.is_expired(self.config.ttl_seconds))
            .map(|(k, _)| *k)
            .collect();

        // Remove expired blocks
        for key in expired_keys {
            if blocks.pop(&key).is_some() {
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            info!("Cleaned up {} expired blocks", removed_count);
        }

        removed_count
    }

    /// Start automatic cleanup task
    pub async fn start_cleanup_task(&self) -> Result<tokio::task::JoinHandle<()>> {
        if !self.config.auto_cleanup {
            return Err(WireError::other("Auto cleanup is disabled"));
        }

        let cache = Arc::new(self.clone());
        let interval = self.config.cleanup_interval_seconds;

        let handle = tokio::spawn(async move {
            let mut cleanup_interval = tokio::time::interval(
                std::time::Duration::from_secs(interval)
            );

            loop {
                cleanup_interval.tick().await;
                
                let removed = cache.cleanup_expired().await;
                if removed > 0 {
                    debug!("Auto cleanup removed {} expired blocks", removed);
                }
            }
        });

        info!("Started entropy cache cleanup task with {} second interval", interval);
        Ok(handle)
    }

    /// Add a provider record for an entropy block
    pub async fn add_provider_record(&self, start_round: u64, peer_id: String) -> Result<()> {
        let mut providers = self.provider_records.write().await;
        providers.entry(start_round).or_insert_with(Vec::new).push(peer_id.clone());
        
        debug!("Added provider record for block {}: {}", start_round, peer_id);
        Ok(())
    }

    /// Get provider records for an entropy block
    pub async fn get_providers(&self, start_round: u64) -> Vec<String> {
        let providers = self.provider_records.read().await;
        providers.get(&start_round).cloned().unwrap_or_default()
    }

    /// Remove a provider record
    pub async fn remove_provider_record(&self, start_round: u64, peer_id: &str) -> Result<bool> {
        let mut providers = self.provider_records.write().await;
        
        if let Some(peer_list) = providers.get_mut(&start_round) {
            let initial_len = peer_list.len();
            peer_list.retain(|id| id != peer_id);
            let changed = initial_len != peer_list.len();
            
            if peer_list.is_empty() {
                providers.remove(&start_round);
            }
            
            Ok(changed)
        } else {
            Ok(false)
        }
    }

    /// Mark a block as being served
    pub async fn mark_serving(&self, start_round: u64, is_serving: bool) -> Result<bool> {
        let mut blocks = self.blocks.write().await;
        
        if let Some(cached_block) = blocks.get_mut(&start_round) {
            cached_block.is_serving = is_serving;
            debug!("Marked block {} as serving: {}", start_round, is_serving);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if we're currently serving a block
    pub async fn is_serving(&self, start_round: u64) -> bool {
        let blocks = self.blocks.read().await;
        
        if let Some(cached_block) = blocks.peek(&start_round) {
            cached_block.is_serving
        } else {
            false
        }
    }
}

impl Clone for EntropyCache {
    fn clone(&self) -> Self {
        Self {
            blocks: Arc::new(RwLock::new(LruCache::new(
                std::num::NonZeroUsize::new(self.config.max_blocks).unwrap_or(std::num::NonZeroUsize::new(100).unwrap())
            ))),
            config: self.config.clone(),
            stats: Arc::new(RwLock::new(CacheStatsInternal::default())),
            provider_records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zks_crypt::entropy_block::{EntropyBlock, DrandRound};

    fn create_test_block(start_round: u64) -> EntropyBlock {
        let rounds: Vec<DrandRound> = (0..1000).map(|i| DrandRound {
            round: start_round + i,
            randomness: [0u8; 32],
            signature: vec![1, 2, 3, 4],
            previous_signature: vec![0, 1, 2, 3],
        }).collect();

        // Use with_rounds to ensure proper hash calculation
        EntropyBlock::with_rounds(start_round, rounds)
    }

    #[tokio::test]
    async fn test_cache_store_and_retrieve() {
        let cache = EntropyCache::with_defaults();
        let block = create_test_block(1_000_000);

        // Store block
        cache.store_block(block.clone()).await.unwrap();

        // Retrieve block
        let retrieved = cache.get_block(1_000_000).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().start_round, 1_000_000);
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = EntropyCache::with_defaults();

        let result = cache.get_block(1_000_000).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let mut config = EntropyCacheConfig::default();
        config.ttl_seconds = 1; // 1 second TTL for testing

        let cache = EntropyCache::new(config);
        let block = create_test_block(1_000_000);

        // Store block
        cache.store_block(block).await.unwrap();

        // Wait for expiration
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Should be expired
        let result = cache.get_block(1_000_000).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = EntropyCache::with_defaults();
        let block = create_test_block(1_000_000);

        // Store and retrieve to generate stats
        cache.store_block(block).await.unwrap();
        cache.get_block(1_000_000).await.unwrap();
        cache.get_block(2_000_000).await.unwrap(); // miss

        let stats = cache.get_stats().await;
        assert_eq!(stats.total_blocks, 1);
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.hit_rate, 0.5);
    }

    #[tokio::test]
    async fn test_provider_records() {
        let cache = EntropyCache::with_defaults();

        // Add provider records
        cache.add_provider_record(1_000_000, "peer1".to_string()).await.unwrap();
        cache.add_provider_record(1_000_000, "peer2".to_string()).await.unwrap();

        let providers = cache.get_providers(1_000_000).await;
        assert_eq!(providers.len(), 2);
        assert!(providers.contains(&"peer1".to_string()));
        assert!(providers.contains(&"peer2".to_string()));
    }
}