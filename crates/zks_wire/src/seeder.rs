//! Entropy Seeder Module
//! 
//! This module implements the seeder node logic for the ZKS Protocol Entropy Grid.
//! The seeder daemon polls the drand API, bulk-fetches rounds, creates EntropyBlocks,
//! and publishes them to the swarm for distribution across the network.
//! 
//! ## Key Features
//! - **Automated Drand Polling**: Continuously fetches latest drand rounds
//! - **Bulk Round Fetching**: Efficiently fetches ranges of rounds using fetch_range
//! - **EntropyBlock Creation**: Creates optimized blocks for network distribution
//! - **Swarm Publishing**: Publishes blocks to the Kademlia DHT for peer discovery
//! - **Configurable Parameters**: Flexible configuration for polling intervals, block sizes, etc.
//! - **Health Monitoring**: Tracks seeder performance and network connectivity
//! 
//! ## Usage
//! ```rust,no_run
//! use zks_wire::seeder::{EntropySeeder, SeederConfig};
//! use std::time::Duration;
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = SeederConfig {
//!         poll_interval: Duration::from_secs(30),
//!         block_size: 100,
//!         max_retry_attempts: 3,
//!         ..Default::default()
//!     };
//!     
//!     let mut seeder = EntropySeeder::new(config).await?;
//!     seeder.start().await?;
//!     
//!     Ok(())
//! }
//! ```

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{info, warn, error, debug};

use zks_crypt::drand::DrandEntropy;
use zks_crypt::entropy_block::{DrandRound, EntropyBlock};
use crate::EntropySwarm;
use crate::entropy_cache::EntropyCache;

/// Configuration for the entropy seeder
#[derive(Debug, Clone)]
pub struct SeederConfig {
    /// How often to poll for new drand rounds
    pub poll_interval: Duration,
    /// Number of rounds to include in each EntropyBlock
    pub block_size: u64,
    /// Maximum number of retry attempts for failed operations
    pub max_retry_attempts: u32,
    /// Whether to start from the current round or from a specific round
    pub start_from_current: bool,
    /// Specific round to start from (if start_from_current is false)
    pub start_round: Option<u64>,
    /// Whether to publish blocks to the swarm immediately
    pub auto_publish: bool,
    /// Whether to cache blocks locally before publishing
    pub cache_blocks: bool,
    /// Maximum number of blocks to cache locally
    pub max_cached_blocks: usize,
}

impl Default for SeederConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(30),
            block_size: 100,
            max_retry_attempts: 3,
            start_from_current: true,
            start_round: None,
            auto_publish: true,
            cache_blocks: true,
            max_cached_blocks: 1000,
        }
    }
}

/// Errors that can occur during seeder operation
#[derive(Debug, thiserror::Error)]
pub enum SeederError {
    /// Failed to fetch rounds from drand
    #[error("Failed to fetch drand rounds: {0}")]
    FetchError(String),
    
    /// Failed to create EntropyBlock
    #[error("Failed to create EntropyBlock: {0}")]
    BlockCreationError(String),
    
    /// Failed to publish to swarm
    #[error("Failed to publish to swarm: {0}")]
    PublishError(String),
    
    /// Network connectivity error
    #[error("Network error: {0}")]
    NetworkError(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    /// Seeder is already running
    #[error("Seeder is already running: {0}")]
    AlreadyRunning(String),
    
    /// Failed to initialize seeder
    #[error("Initialization error: {0}")]
    InitializationError(String),
}

/// Statistics about seeder operation
#[derive(Debug, Default, Clone)]
pub struct SeederStats {
    /// Total number of rounds fetched
    pub rounds_fetched: u64,
    /// Total number of blocks created
    pub blocks_created: u64,
    /// Total number of blocks published
    pub blocks_published: u64,
    /// Number of successful operations
    pub successful_operations: u64,
    /// Number of failed operations
    pub failed_operations: u64,
    /// Current round being processed
    pub current_round: u64,
    /// Timestamp when seeder started
    pub start_time: Option<std::time::Instant>,
    /// Timestamp of last successful operation
    pub last_success_time: Option<std::time::Instant>,
}

/// Runtime statistics for monitoring seeder health
#[derive(Debug, Clone)]
pub struct RuntimeStats {
    /// Whether the seeder is currently running
    pub is_running: bool,
    /// Uptime duration since start
    pub uptime: Option<std::time::Duration>,
    /// Time elapsed since last successful operation
    pub time_since_last_success: Option<std::time::Duration>,
    /// Average rounds fetched per second
    pub rounds_per_second: f64,
    /// Success rate of operations (0.0 to 1.0)
    pub success_rate: f64,
}

/// The main seeder component that manages entropy generation and distribution
pub struct EntropySeeder {
    config: SeederConfig,
    drand_client: Arc<DrandEntropy>,
    swarm: Option<Arc<EntropySwarm>>,
    cache: Option<Arc<EntropyCache>>,
    stats: Arc<RwLock<SeederStats>>,
    running: Arc<RwLock<bool>>,
}

type SeederResult<T> = std::result::Result<T, SeederError>;

impl EntropySeeder {
    /// Create a new entropy seeder with the given configuration
    pub async fn new(config: SeederConfig) -> SeederResult<Self> {
        let drand_client = Arc::new(DrandEntropy::new());
        
        let cache = if config.cache_blocks {
            Some(Arc::new(EntropyCache::new(crate::entropy_cache::EntropyCacheConfig::default())))
        } else {
            None
        };
        
        Ok(Self {
            config,
            drand_client,
            swarm: None,
            cache,
            stats: Arc::new(RwLock::new(SeederStats::default())),
            running: Arc::new(RwLock::new(false)),
        })
    }
    
    /// Attach a swarm for publishing blocks
    pub fn attach_swarm(&mut self, swarm: Arc<EntropySwarm>) {
        self.swarm = Some(swarm);
    }
    
    /// Start the seeder daemon
    pub async fn start(&mut self) -> SeederResult<()> {
        // Check if already running
        if *self.running.read().await {
            return Err(SeederError::AlreadyRunning("Seeder is already running".to_string()));
        }
        
        info!("Starting entropy seeder daemon");
        
        // Get current round from drand
        let current_round = match self.get_current_round().await {
            Ok(round) => {
                info!("Current drand round: {}", round);
                round
            }
            Err(e) => {
                error!("Failed to get current drand round: {}", e);
                // Fallback to estimated round
                match self.estimate_current_round() {
                    Ok(estimated) => {
                        warn!("Using estimated round: {}", estimated);
                        estimated
                    }
                    Err(e) => {
                        return Err(SeederError::InitializationError(format!("Failed to determine starting round: {}", e)));
                    }
                }
            }
        };
        
        // Determine starting round with catch-up logic
        let start_round = if self.config.start_from_current {
            current_round
        } else {
            let configured_start = self.config.start_round.unwrap_or(1);
            // If configured start is behind current, catch up to current
            if configured_start < current_round {
                info!("Configured start round {} is behind current round {}, catching up to current", configured_start, current_round);
                current_round
            } else {
                configured_start
            }
        };
        
        info!("Starting seeder from round: {}", start_round);
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.current_round = start_round;
            stats.start_time = Some(std::time::Instant::now());
        }
        
        // Set running flag
        *self.running.write().await = true;
        
        // Start the main polling loop
        self.run_polling_loop(start_round).await;
        
        Ok(())
    }
    
    /// Check if the seeder is currently running
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
    
    /// Stop the seeder daemon
    pub async fn stop(&self) -> SeederResult<()> {
        info!("Stopping entropy seeder daemon");
        
        // Set running flag to false to signal shutdown
        *self.running.write().await = false;
        
        // Wait a short time for any ongoing operations to complete
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Log final statistics
        let stats = self.get_stats().await;
        info!("Seeder stopped. Final stats: rounds_fetched={}, blocks_created={}, blocks_published={}, successful_ops={}, failed_ops={}",
              stats.rounds_fetched, stats.blocks_created, stats.blocks_published,
              stats.successful_operations, stats.failed_operations);
        
        Ok(())
    }
    
    /// Get current seeder statistics
    pub async fn get_stats(&self) -> SeederStats {
        self.stats.read().await.clone()
    }
    
    /// Get runtime statistics including uptime
    pub async fn get_runtime_stats(&self) -> RuntimeStats {
        let stats = self.stats.read().await;
        let uptime = stats.start_time.map(|start| start.elapsed());
        let time_since_last_success = stats.last_success_time.map(|last| last.elapsed());
        
        RuntimeStats {
            is_running: *self.running.read().await,
            uptime,
            time_since_last_success,
            rounds_per_second: if let Some(uptime) = uptime {
                if uptime.as_secs() > 0 {
                    stats.rounds_fetched as f64 / uptime.as_secs() as f64
                } else {
                    0.0
                }
            } else {
                0.0
            },
            success_rate: if stats.successful_operations + stats.failed_operations > 0 {
                stats.successful_operations as f64 / (stats.successful_operations + stats.failed_operations) as f64
            } else {
                0.0
            },
        }
    }
    
    /// Get the current round number from drand
    async fn get_current_round(&self) -> SeederResult<u64> {
        // First try to get the cached round
        if let Some(round) = self.drand_client.cached_round().await {
            return Ok(round);
        }
        
        // If no cached round, fetch the latest entropy to populate cache
        match self.drand_client.get_entropy().await {
            Ok(_) => {
                // Now try to get the round from cache again
                if let Some(round) = self.drand_client.cached_round().await {
                    Ok(round)
                } else {
                    // Fallback: estimate current round based on time
                    self.estimate_current_round()
                }
            }
            Err(e) => {
                warn!("Failed to fetch drand entropy: {}", e);
                // Fallback: estimate current round based on time
                self.estimate_current_round()
            }
        }
    }
    
    /// Estimate current round based on time (fallback method)
    fn estimate_current_round(&self) -> SeederResult<u64> {
        // drand updates every 30 seconds, starting from genesis
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| SeederError::ConfigError(format!("System clock error: {}", e)))?
            .as_secs();
        
        let genesis_time = 1595431050; // drand mainnet genesis (approximate)
        let round_duration = 30;
        
        // Prevent underflow - validate system clock
        if now < genesis_time {
            return Err(SeederError::ConfigError(format!(
                "System clock ({}) is before drand genesis ({}). Please check system time.",
                now, genesis_time
            )));
        }
        
        let estimated_round = (now - genesis_time) / round_duration;
        Ok(estimated_round)
    }
    
    /// The main polling loop that fetches and processes rounds
    async fn run_polling_loop(&self, mut current_round: u64) {
        let mut interval = interval(self.config.poll_interval);
        let mut consecutive_errors = 0;
        const MAX_CONSECUTIVE_ERRORS: usize = 5;
        
        info!("Starting polling loop from round {}", current_round);
        
        while *self.running.read().await {
            // Check if we should continue due to too many consecutive errors
            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                error!("Too many consecutive errors ({}), stopping seeder", consecutive_errors);
                *self.running.write().await = false;
                break;
            }
            
            interval.tick().await;
            
            // Check if we need to catch up with the current round
            match self.get_current_round().await {
                Ok(latest_round) => {
                    // Reset consecutive errors on successful operation
                    consecutive_errors = 0;
                    
                    if current_round < latest_round {
                        // We're behind, catch up immediately without waiting for next interval
                        info!("Seeder is behind (current: {}, latest: {}), catching up...", current_round, latest_round);
                        
                        // Process multiple ranges in quick succession to catch up
                        while current_round < latest_round && *self.running.read().await {
                            match self.process_round_range(current_round).await {
                                Ok(next_round) => {
                                    current_round = next_round;
                                    let mut stats = self.stats.write().await;
                                    stats.current_round = current_round;
                                    stats.successful_operations += 1;
                                    stats.last_success_time = Some(std::time::Instant::now());
                                    consecutive_errors = 0; // Reset on success
                                }
                                Err(e) => {
                                    error!("Failed to process round range during catch-up: {}", e);
                                    let mut stats = self.stats.write().await;
                                    stats.failed_operations += 1;
                                    consecutive_errors += 1;
                                    current_round += self.config.block_size;
                                    break; // Break catch-up loop on error
                                }
                            }
                        }
                    } else {
                        // We're up to date, process normally
                        match self.process_round_range(current_round).await {
                            Ok(next_round) => {
                                current_round = next_round;
                                let mut stats = self.stats.write().await;
                                stats.current_round = current_round;
                                stats.successful_operations += 1;
                                stats.last_success_time = Some(std::time::Instant::now());
                                consecutive_errors = 0; // Reset on success
                            }
                            Err(e) => {
                                error!("Failed to process round range: {}", e);
                                let mut stats = self.stats.write().await;
                                stats.failed_operations += 1;
                                consecutive_errors += 1;
                                
                                // Continue to next round even on failure to avoid getting stuck
                                current_round += self.config.block_size;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get current round: {}", e);
                    let mut stats = self.stats.write().await;
                    stats.failed_operations += 1;
                    consecutive_errors += 1;
                    
                    // Continue with current round even on error
                    current_round += self.config.block_size;
                }
            }
        }
    }
    
    /// Process a range of rounds and create an EntropyBlock
    async fn process_round_range(&self, start_round: u64) -> SeederResult<u64> {
        // Validate block_size configuration
        if self.config.block_size == 0 {
            return Err(SeederError::ConfigError("block_size must be > 0".to_string()));
        }
        
        // Use checked arithmetic to prevent overflow
        let end_round = start_round
            .checked_add(self.config.block_size)
            .and_then(|r| r.checked_sub(1))
            .ok_or_else(|| SeederError::ConfigError(format!(
                "Round overflow: start_round={}, block_size={}",
                start_round, self.config.block_size
            )))?;
        
        debug!("Processing round range {}-{}", start_round, end_round);
        
        // Fetch the rounds using the bulk fetch method
        let rounds = self.drand_client.fetch_range(start_round, end_round).await
            .map_err(|e| SeederError::FetchError(format!("Failed to fetch rounds: {}", e)))?;
        
        // Validate that we got rounds - seeder might be ahead of beacon
        if rounds.is_empty() {
            debug!("No rounds available for range {}-{} (seeder ahead of beacon)", start_round, end_round);
            // Don't treat as error - this is expected when seeder catches up
            return Ok(end_round + 1); // Move to next range
        }
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.rounds_fetched += rounds.len() as u64;
        }
        
        // Create EntropyBlock from the rounds
        let block = self.create_entropy_block(rounds).await?;
        
        // Cache the block if caching is enabled
        if let Some(ref cache) = self.cache {
            cache.store_block(block.clone()).await
                .map_err(|e| SeederError::BlockCreationError(format!("Failed to cache block: {}", e)))?;
        }
        
        // Publish to swarm if auto-publishing is enabled
        if self.config.auto_publish {
            if let Some(ref swarm) = self.swarm {
                swarm.publish_entropy_block(block.clone()).await
                    .map_err(|e| SeederError::PublishError(format!("Failed to publish block: {}", e)))?;
                
                // Update stats
                {
                    let mut stats = self.stats.write().await;
                    stats.blocks_published += 1;
                }
            } else {
                warn!("Auto-publish enabled but no swarm attached");
            }
        }
        
        Ok(end_round + 1)
    }
    
    /// Create an EntropyBlock from a list of DrandRounds
    async fn create_entropy_block(&self, rounds: Vec<DrandRound>) -> SeederResult<EntropyBlock> {
        if rounds.is_empty() {
            return Err(SeederError::BlockCreationError("No rounds provided".to_string()));
        }
        
        let start_round = rounds.first().unwrap().round;
        let end_round = rounds.last().unwrap().round;
        
        let block = EntropyBlock::from_rounds(rounds)
            .map_err(|e| SeederError::BlockCreationError(format!("Failed to create block: {}", e)))?;
        
        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.blocks_created += 1;
        }
        
        info!("Created EntropyBlock {} with rounds {}-{}", 
              hex::encode(&block.block_hash[..8]), start_round, end_round);
        
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_seeder_config_default() {
        let config = SeederConfig::default();
        assert_eq!(config.block_size, 100);
        assert_eq!(config.poll_interval, Duration::from_secs(30));
        assert!(config.auto_publish);
        assert!(config.cache_blocks);
    }
    
    #[tokio::test]
    async fn test_seeder_creation() {
        let config = SeederConfig::default();
        let seeder = EntropySeeder::new(config).await;
        assert!(seeder.is_ok());
    }
    
    #[tokio::test]
    async fn test_seeder_stats() {
        let config = SeederConfig::default();
        let seeder = EntropySeeder::new(config).await.unwrap();
        
        let stats = seeder.get_stats().await;
        assert_eq!(stats.rounds_fetched, 0);
        assert_eq!(stats.blocks_created, 0);
        assert_eq!(stats.blocks_published, 0);
        assert_eq!(stats.current_round, 0);
        assert!(stats.start_time.is_none());
        assert!(stats.last_success_time.is_none());
    }
    
    #[tokio::test]
    async fn test_seeder_start_stop() {
        let config = SeederConfig::default();
        let seeder = EntropySeeder::new(config).await.unwrap();
        
        // Initially not running
        assert!(!seeder.is_running().await);
        
        // Test stop functionality (should work even if not started)
        let stop_result = seeder.stop().await;
        assert!(stop_result.is_ok());
        
        // Verify stop doesn't break anything
        assert!(!seeder.is_running().await);
    }
    
    #[tokio::test]
    async fn test_runtime_stats() {
        let config = SeederConfig::default();
        let seeder = EntropySeeder::new(config).await.unwrap();
        
        let runtime_stats = seeder.get_runtime_stats().await;
        assert!(!runtime_stats.is_running);
        assert!(runtime_stats.uptime.is_none());
        assert_eq!(runtime_stats.rounds_per_second, 0.0);
        assert_eq!(runtime_stats.success_rate, 0.0);
    }
    
    #[tokio::test]
    async fn test_estimate_current_round() {
        let config = SeederConfig::default();
        let seeder = EntropySeeder::new(config).await.unwrap();
        
        // This should return a reasonable estimate
        let estimated = seeder.estimate_current_round();
        assert!(estimated.is_ok(), "Estimate should succeed");
        let round = estimated.unwrap();
        assert!(round > 0, "Estimated round should be positive");
        
        // Should be a reasonable value (not too far in the future)
        let max_reasonable = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - 1595431050) / 30 + 10000; // +10000 for buffer
        assert!(round < max_reasonable, "Estimated round seems too high");
    }
}