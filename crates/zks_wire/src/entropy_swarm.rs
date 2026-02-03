//! Entropy Swarm - GossipSub-based P2P entropy sharing for ZKS Protocol
//!
//! This module implements a gossip-based protocol for distributing drand entropy blocks
//! across the ZKS P2P swarm, enabling high-entropy encryption at low cost.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn, error};

use zks_crypt::entropy_block::EntropyBlock;
use crate::{PeerId, Result, WireError};

#[cfg(not(target_arch = "wasm32"))]
use crate::p2p::NativeP2PTransport;

/// GossipSub topic for entropy block sharing
pub const ENTROPY_TOPIC: &str = "zks/entropy/v1";

/// Maximum entropy block size in bytes (32 MB)
pub const MAX_BLOCK_SIZE: usize = 32 * 1024 * 1024;

/// Request types for entropy sharing protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntropyRequest {
    /// Request a specific entropy block by start round
    GetBlock {
        /// Starting round number of the block to retrieve
        start_round: u64
    },
    /// Request multiple entropy blocks by range
    GetBlocks {
        /// Starting round number of the range
        start_round: u64,
        /// Ending round number of the range
        end_round: u64
    },
    /// Request latest available entropy block
    GetLatest,
}

/// Response types for entropy sharing protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntropyResponse {
    /// Entropy block data
    Block {
        /// The entropy block
        block: EntropyBlock
    },
    /// Multiple entropy blocks
    Blocks {
        /// List of entropy blocks
        blocks: Vec<EntropyBlock>
    },
    /// Block not found
    NotFound {
        /// Starting round number of the requested block
        start_round: u64
    },
    /// Error response
    Error {
        /// Error message describing what went wrong
        message: String
    },
}

/// Message types for GossipSub entropy gossip
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntropyGossipMessage {
    /// Announce availability of new entropy block
    BlockAvailable {
        /// Starting round number of the entropy block
        start_round: u64,
        /// Ending round number of the entropy block
        end_round: u64,
        /// SHA-256 hash of the entropy block
        block_hash: [u8; 32],
        /// Peer ID of the node announcing the block
        peer_id: String,
    },
    /// Request entropy block from specific peer
    BlockRequest {
        /// Starting round number of the requested block
        start_round: u64,
        /// Peer ID of the node requesting the block
        requester: String,
    },
    /// Response to block request
    BlockResponse {
        /// Starting round number of the response block
        start_round: u64,
        /// The entropy block data (None if not found)
        block: Option<EntropyBlock>,
    },
}

/// Provider information for an entropy block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyBlockProvider {
    /// Start round of the entropy block
    pub start_round: u64,
    /// End round of the entropy block
    pub end_round: u64,
    /// Hash of the entropy block
    pub block_hash: [u8; 32],
    /// Peer ID of the provider
    pub peer_id: String,
}

/// Configuration for entropy swarm
#[derive(Debug, Clone)]
pub struct EntropySwarmConfig {
    /// Maximum number of entropy blocks to cache locally
    pub max_cached_blocks: usize,
    /// Maximum age of cached blocks in seconds
    pub cache_ttl_seconds: u64,
    /// Whether to participate in entropy gossip
    pub enable_gossip: bool,
    /// Whether to serve entropy blocks to other peers
    pub enable_serving: bool,
    /// Maximum number of concurrent block requests
    pub max_concurrent_requests: usize,
}

impl Default for EntropySwarmConfig {
    fn default() -> Self {
        Self {
            max_cached_blocks: 100,  // ~3.2 GB max cache
            cache_ttl_seconds: 3600, // 1 hour TTL
            enable_gossip: true,
            enable_serving: true,
            max_concurrent_requests: 10,
        }
    }
}

/// Entropy block cache for local storage
#[derive(Debug)]
pub struct EntropyCache {
    /// Cached entropy blocks indexed by start round
    blocks: Arc<RwLock<HashMap<u64, CachedBlock>>>,
    /// Configuration
    config: EntropySwarmConfig,
}

#[derive(Debug, Clone)]
struct CachedBlock {
    block: EntropyBlock,
    timestamp: u64,
    access_count: u64,
}

impl EntropyCache {
    /// Create a new entropy cache
    pub fn new(config: EntropySwarmConfig) -> Self {
        Self {
            blocks: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Store an entropy block in cache
    pub async fn store_block(&self, block: EntropyBlock) -> Result<()> {
        let start_round = block.start_round;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cached_block = CachedBlock {
            block,
            timestamp,
            access_count: 0,
        };

        let mut blocks: tokio::sync::RwLockWriteGuard<HashMap<u64, CachedBlock>> = self.blocks.write().await;
        
        // Check cache size limit
        if blocks.len() >= self.config.max_cached_blocks {
            // Remove oldest block
            let oldest_key = blocks
                .iter()
                .min_by_key(|(_, cb)| cb.timestamp)
                .map(|(k, _)| *k)
                .unwrap_or(start_round);
            blocks.remove(&oldest_key);
            debug!("Removed oldest block {} to make room", oldest_key);
        }

        blocks.insert(start_round, cached_block);
        info!("Stored entropy block {}-{} in cache", start_round, start_round + 1_000_000);
        Ok(())
    }

    /// Retrieve an entropy block from cache
    pub async fn get_block(&self, start_round: u64) -> Result<Option<EntropyBlock>> {
        let mut blocks: tokio::sync::RwLockWriteGuard<HashMap<u64, CachedBlock>> = self.blocks.write().await;
        
        if let Some(cached_block) = blocks.get_mut(&start_round) {
            // Check if block is expired
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if now - cached_block.timestamp > self.config.cache_ttl_seconds {
                blocks.remove(&start_round);
                debug!("Removed expired block {}", start_round);
                return Ok(None);
            }

            // Update access count
            cached_block.access_count += 1;
            Ok(Some(cached_block.block.clone()))
        } else {
            Ok(None)
        }
    }

    /// Get multiple blocks by range
    pub async fn get_blocks_range(&self, start_round: u64, end_round: u64) -> Result<Vec<EntropyBlock>> {
        let blocks: tokio::sync::RwLockReadGuard<HashMap<u64, CachedBlock>> = self.blocks.read().await;
        let mut result = Vec::new();

        for round in (start_round..=end_round).step_by(1_000_000) {
            if let Some(cached_block) = blocks.get(&round) {
                // Check expiration
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if now - cached_block.timestamp <= self.config.cache_ttl_seconds {
                    result.push(cached_block.block.clone());
                }
            }
        }

        Ok(result)
    }

    /// Check if we have a specific block
    pub async fn has_block(&self, start_round: u64) -> bool {
        let blocks: tokio::sync::RwLockReadGuard<'_, HashMap<u64, CachedBlock>> = self.blocks.read().await;
        blocks.contains_key(&start_round)
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        let blocks: tokio::sync::RwLockReadGuard<'_, HashMap<u64, CachedBlock>> = self.blocks.read().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut total_accesses = 0;
        let mut expired_blocks = 0;

        for cached_block in blocks.values() {
            total_accesses += cached_block.access_count;
            if now - cached_block.timestamp > self.config.cache_ttl_seconds {
                expired_blocks += 1;
            }
        }

        CacheStats {
            total_blocks: blocks.len(),
            expired_blocks,
            total_accesses,
            cache_hit_rate: if total_accesses > 0 { 
                (total_accesses - expired_blocks as u64) as f64 / total_accesses as f64 
            } else { 0.0 },
        }
    }

    /// Clean up expired blocks
    pub async fn cleanup_expired(&self) -> usize {
        let mut blocks: tokio::sync::RwLockWriteGuard<'_, HashMap<u64, CachedBlock>> = self.blocks.write().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired_keys: Vec<u64> = blocks
            .iter()
            .filter(|(_, cb)| now - cb.timestamp > self.config.cache_ttl_seconds)
            .map(|(k, _)| *k)
            .collect();

        let removed_count = expired_keys.len();
        for key in expired_keys {
            blocks.remove(&key);
        }

        if removed_count > 0 {
            debug!("Cleaned up {} expired blocks from cache", removed_count);
        }

        removed_count
    }

    /// Clear all blocks from cache
    pub async fn clear(&self) -> Result<()> {
        let mut blocks = self.blocks.write().await;
        blocks.clear();
        debug!("Cleared all blocks from cache");
        Ok(())
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of blocks in cache
    pub total_blocks: usize,
    /// Number of expired blocks
    pub expired_blocks: usize,
    /// Total number of cache accesses
    pub total_accesses: u64,
    /// Cache hit rate (0.0 to 1.0)
    pub cache_hit_rate: f64,
}

/// Main entropy swarm component for P2P entropy sharing
#[derive(Debug)]
pub struct EntropySwarm {
    /// Local entropy cache
    pub cache: EntropyCache,
    /// Configuration
    pub config: EntropySwarmConfig,
    /// Connected peers that support entropy sharing
    pub entropy_peers: Arc<RwLock<HashSet<PeerId>>>,
    /// Channel for sending entropy requests (reserved for async request-response pattern)
    #[allow(dead_code)]
    request_tx: mpsc::Sender<EntropyRequest>,
    /// Channel for receiving entropy responses (reserved for async request-response pattern)
    #[allow(dead_code)]
    response_rx: Arc<RwLock<mpsc::Receiver<EntropyResponse>>>,
    /// Optional transport for GossipSub operations (native platforms only)
    #[cfg(not(target_arch = "wasm32"))]
    transport: Arc<RwLock<Option<Arc<RwLock<NativeP2PTransport>>>>>,
    /// Channel for receiving GossipSub messages from NativeP2PTransport
    #[cfg(not(target_arch = "wasm32"))]
    message_rx: Arc<RwLock<mpsc::UnboundedReceiver<(EntropyGossipMessage, PeerId)>>>,
    /// Optional reference to swarm for DHT operations
    swarm: Arc<RwLock<Option<Arc<crate::swarm::Swarm>>>>,
}

impl EntropySwarm {
    /// Create a new entropy swarm with message channel
    pub fn new_with_channel(config: EntropySwarmConfig) -> (Self, mpsc::UnboundedSender<(EntropyGossipMessage, PeerId)>) {
        let (request_tx, _) = mpsc::channel(100);
        let (_response_tx, response_rx) = mpsc::channel(100);
        let (message_tx, message_rx) = mpsc::unbounded_channel();
        
        let swarm = Self {
            cache: EntropyCache::new(config.clone()),
            config,
            entropy_peers: Arc::new(RwLock::new(HashSet::new())),
            request_tx,
            response_rx: Arc::new(RwLock::new(response_rx)),
            #[cfg(not(target_arch = "wasm32"))]
            transport: Arc::new(RwLock::new(None)),
            #[cfg(not(target_arch = "wasm32"))]
            message_rx: Arc::new(RwLock::new(message_rx)),
            swarm: Arc::new(RwLock::new(None)),
        };
        
        (swarm, message_tx)
    }

    /// Create a new entropy swarm
    pub fn new(config: EntropySwarmConfig) -> Self {
        let (swarm, _) = Self::new_with_channel(config);
        swarm
    }
    
    /// Set the swarm reference for DHT operations
    pub async fn set_swarm(&self, swarm: Arc<crate::swarm::Swarm>) {
        let mut swarm_guard = self.swarm.write().await;
        *swarm_guard = Some(swarm);
    }

    /// Set the transport for GossipSub operations (native platforms only)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn set_transport(&self, transport: Arc<RwLock<NativeP2PTransport>>) {
        let mut transport_guard = self.transport.write().await;
        *transport_guard = Some(transport);
    }

    /// Subscribe to the entropy GossipSub topic (native platforms only)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn subscribe_entropy_topic(&self) -> Result<()> {
        let transport_guard = self.transport.read().await;
        if let Some(transport) = transport_guard.as_ref() {
            let mut transport_lock = transport.write().await;
            transport_lock.subscribe_entropy_topic().await
                .map_err(|e| WireError::other(&format!("Failed to subscribe to entropy topic: {}", e)))
        } else {
            Err(WireError::other("No transport available for topic subscription"))
        }
    }

    /// Unsubscribe from the entropy GossipSub topic (native platforms only)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn unsubscribe_entropy_topic(&self) -> Result<()> {
        let transport_guard = self.transport.read().await;
        if let Some(transport) = transport_guard.as_ref() {
            let mut transport_lock = transport.write().await;
            transport_lock.unsubscribe_entropy_topic().await
                .map_err(|e| WireError::other(&format!("Failed to unsubscribe from entropy topic: {}", e)))
        } else {
            Err(WireError::other("No transport available for topic unsubscription"))
        }
    }

    /// Add a peer that supports entropy sharing
    pub async fn add_entropy_peer(&self, peer_id: PeerId) -> Result<()> {
        let mut peers = self.entropy_peers.write().await;
        peers.insert(peer_id);
        info!("Added entropy peer: {}", peer_id);
        Ok(())
    }

    /// Remove an entropy peer
    pub async fn remove_entropy_peer(&self, peer_id: PeerId) -> Result<()> {
        let mut peers = self.entropy_peers.write().await;
        peers.remove(&peer_id);
        info!("Removed entropy peer: {}", peer_id);
        Ok(())
    }

    /// Get list of entropy peers
    pub async fn get_entropy_peers(&self) -> Vec<PeerId> {
        let peers = self.entropy_peers.read().await;
        peers.iter().cloned().collect()
    }


    /// Request entropy block from swarm
    pub async fn request_entropy_block(&self, start_round: u64) -> Result<Option<EntropyBlock>> {
        // First check local cache
        if let Some(block) = self.cache.get_block(start_round).await? {
            debug!("Found entropy block {} in local cache", start_round);
            return Ok(Some(block));
        }

        // Check if we have DHT access through swarm
        let swarm_guard = self.swarm.read().await;
        if let Some(swarm) = swarm_guard.as_ref() {
            // Query DHT for providers of this entropy block
            let providers = swarm.query_entropy_block_providers(start_round).await;
            
            if !providers.is_empty() {
                info!("Found {} providers for entropy block {} in DHT", providers.len(), start_round);
                
                // Request from all providers (they'll respond if they have it)
                for provider in providers.iter().take(3) { // Limit to first 3 providers
                    debug!("Requesting block {} from provider {}", start_round, provider.provider);
                    
                    // Add provider to our entropy peers list
                    let mut entropy_peers = self.entropy_peers.write().await;
                    entropy_peers.insert(provider.provider);
                    drop(entropy_peers); // Release lock before async operation
                    
                    // Send BlockRequest via GossipSub
                    let request_msg = EntropyGossipMessage::BlockRequest {
                        start_round,
                        requester: swarm.local_peer_id().to_string(),
                    };
                    
                    // Serialize and publish the request
                    let message_data = bincode::serialize(&request_msg)
                        .map_err(|e| WireError::other(&format!("Failed to serialize block request: {}", e)))?;
                    
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        let transport_guard = self.transport.read().await;
                        if let Some(transport) = transport_guard.as_ref() {
                            let mut transport_lock = transport.write().await;
                            if let Err(e) = transport_lock.publish_entropy_message(message_data).await {
                                warn!("Failed to publish block request to provider {}: {}", provider.provider, e);
                            } else {
                                info!("Sent block request for {} to provider {}", start_round, provider.provider);
                            }
                        }
                    }
                }
                
                // Requests sent - block will arrive asynchronously via handle_gossip_message
                // and be stored in cache. For now, return None and let caller retry from cache.
                debug!("Block requests sent for {} to {} providers - will arrive asynchronously", 
                       start_round, providers.len().min(3));
                return Ok(None);
            } else {
                debug!("No providers found for entropy block {} in DHT", start_round);
            }
        } else {
            debug!("No swarm available for DHT queries");
        }

        // Fallback: Broadcast request to all known entropy peers
        let peers = self.get_entropy_peers().await;
        if !peers.is_empty() {
            debug!("Broadcasting block request for {} to {} known peers", start_round, peers.len());
            
            let request_msg = EntropyGossipMessage::BlockRequest {
                start_round,
                requester: "local".to_string(), // TODO: Use actual peer ID
            };
            
            let message_data = bincode::serialize(&request_msg)
                .map_err(|e| WireError::other(&format!("Failed to serialize block request: {}", e)))?;
            
            #[cfg(not(target_arch = "wasm32"))]
            {
                let transport_guard = self.transport.read().await;
                if let Some(transport) = transport_guard.as_ref() {
                    let mut transport_lock = transport.write().await;
                    if let Err(e) = transport_lock.publish_entropy_message(message_data).await {
                        warn!("Failed to broadcast block request: {}", e);
                    } else {
                        info!("Broadcast block request for {} to all known peers", start_round);
                    }
                }
            }
            
            return Ok(None); // Request sent, will arrive async
        }

        warn!("No entropy peers available for block {}", start_round);
        Ok(None)
    }


    /// Publish entropy block to swarm via gossip
    pub async fn publish_entropy_block(&self, block: EntropyBlock) -> Result<()> {
        if !self.config.enable_gossip {
            debug!("Gossip disabled, not publishing block {}-{}", block.start_round, block.end_round);
            return Ok(());
        }

        // Store in local cache first
        self.cache.store_block(block.clone()).await?;

        // Announce to DHT if swarm is available
        let swarm_guard = self.swarm.read().await;
        if let Some(swarm) = swarm_guard.as_ref() {
            match swarm.announce_entropy_block(block.start_round).await {
                Ok(_) => info!("Announced entropy block {} to DHT", block.start_round),
                Err(e) => warn!("Failed to announce entropy block {} to DHT: {}", block.start_round, e),
            }
        } else {
            debug!("No swarm available for DHT announcement");
        }

        // Create gossip message
        let gossip_msg = EntropyGossipMessage::BlockAvailable {
            start_round: block.start_round,
            end_round: block.end_round,
            block_hash: block.block_hash,
            peer_id: "local".to_string(), // TODO: Use actual peer ID
        };

        // Serialize the gossip message
        let message_data = bincode::serialize(&gossip_msg)
            .map_err(|e| WireError::other(&format!("Failed to serialize gossip message: {}", e)))?;

        // Publish via GossipSub if transport is available
        #[cfg(not(target_arch = "wasm32"))]
        {
            let transport_guard = self.transport.read().await;
            if let Some(transport) = transport_guard.as_ref() {
                let mut transport_lock = transport.write().await;
                transport_lock.publish_entropy_message(message_data).await
                    .map_err(|e| WireError::other(&format!("Failed to publish gossip message: {}", e)))?;
            } else {
                debug!("No transport available for gossip publishing");
            }
        }

        info!("Published entropy block {}-{} to swarm", block.start_round, block.end_round);
        Ok(())
    }

    /// Handle received entropy block from peer
    pub async fn handle_received_block(&self, block: EntropyBlock, from_peer: String) -> Result<()> {
        // Validate the block using the proper verify_integrity method
        if block.verify_integrity() {
            let start_round = block.start_round;
            let end_round = block.end_round;
            
            info!("Received valid entropy block {}-{} from peer {}", 
                  start_round, end_round, from_peer);
            
            // Store in cache
            self.cache.store_block(block).await?;
            info!("Stored received block {}-{} in cache", 
                  start_round, end_round);
        } else {
            warn!("Received corrupted block {}-{} from peer {}, discarding", 
                  block.start_round, block.end_round, from_peer);
        }
        
        Ok(())
    }

    /// Announce an entropy block to the DHT
    pub async fn announce_entropy_block_to_dht(&self, start_round: u64) -> Result<()> {
        let swarm_guard = self.swarm.read().await;
        if let Some(swarm) = swarm_guard.as_ref() {
            swarm.announce_entropy_block(start_round).await
                .map_err(|e| WireError::other(&format!("Failed to announce entropy block to DHT: {}", e)))
        } else {
            Err(WireError::other("No swarm available for DHT operations"))
        }
    }

    /// Query DHT for providers of an entropy block
    pub async fn query_entropy_block_providers(&self, start_round: u64) -> Result<Vec<EntropyBlockProvider>> {
        let swarm_guard = self.swarm.read().await;
        if let Some(swarm) = swarm_guard.as_ref() {
            let providers = swarm.query_entropy_block_providers(start_round).await;
            
            // Convert ProviderRecord to EntropyBlockProvider
            let mut result = Vec::new();
            for provider in providers {
                // SECURITY FIX: Use provider's key as block hash (DHT key is content-addressed)
                // The key in Kademlia DHT should be the SHA-256 of the block content
                let mut block_hash = [0u8; 32];
                if provider.key.len() >= 32 {
                    block_hash.copy_from_slice(&provider.key[..32]);
                }
                
                result.push(EntropyBlockProvider {
                    start_round,
                    end_round: start_round + 999, // Approximate end round
                    block_hash,
                    peer_id: provider.provider.to_string(),
                });
            }
            
            Ok(result)
        } else {
            Err(WireError::other("No swarm available for DHT operations"))
        }
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> CacheStats {
        self.cache.get_stats().await
    }

    /// Cleanup old entries from cache
    pub async fn cleanup_cache(&self) -> Result<usize> {
        Ok(self.cache.cleanup_expired().await)
    }

    /// Get the number of entropy peers
    pub async fn get_entropy_peer_count(&self) -> usize {
        let peers = self.entropy_peers.read().await;
        peers.len()
    }

    /// Check if a peer is an entropy peer
    pub async fn is_entropy_peer(&self, peer_id: &PeerId) -> bool {
        let peers = self.entropy_peers.read().await;
        peers.contains(peer_id)
    }

    /// Get the transport (native platforms only)

    /// Get the transport
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn transport(&self) -> Option<Arc<RwLock<NativeP2PTransport>>> {
        let transport = self.transport.read().await;
        transport.clone()
    }
    
    /// Get the configuration
    pub fn config(&self) -> &EntropySwarmConfig {
        &self.config
    }

    /// Update the configuration
    pub fn update_config(&mut self, config: EntropySwarmConfig) {
        self.config = config;
    }

    /// Shutdown the entropy swarm
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down entropy swarm");
        
        // Clear cache
        self.cache.clear().await?;
        
        // Clear peers
        let mut peers = self.entropy_peers.write().await;
        peers.clear();
        
        // Clear transport
        let mut transport = self.transport.write().await;
        *transport = None;
        
        // Clear swarm
        let mut swarm = self.swarm.write().await;
        *swarm = None;
        
        info!("Entropy swarm shutdown complete");
        Ok(())
    }

    /// Handle incoming gossip message
    pub async fn handle_gossip_message(&self, message: EntropyGossipMessage, from_peer: PeerId) -> Result<()> {
        debug!("Received gossip message from {}: {:?}", from_peer, message);

        match message {
            EntropyGossipMessage::BlockAvailable { start_round, end_round, block_hash: _, .. } => {
                info!("Peer {} has block {}-{} available", from_peer, start_round, end_round);
                
                // Add peer to entropy peers if not already present
                self.add_entropy_peer(from_peer).await?;
                
                // TODO: Request block if needed
            }
            EntropyGossipMessage::BlockRequest { start_round, requester } => {
                debug!("Peer {} requested block {} (requested by {})", from_peer, start_round, requester);
                
                // Serve block if we have it and serving is enabled
                if self.config.enable_serving {
                    if let Some(block) = self.cache.get_block(start_round).await? {
                        let response_msg = EntropyGossipMessage::BlockResponse {
                            start_round,
                            block: Some(block),
                        };
                        
                        // Serialize the response message
                        let message_data = bincode::serialize(&response_msg)
                            .map_err(|e| WireError::other(&format!("Failed to serialize response message: {}", e)))?;
                        
                        // Send response back to requester via GossipSub if transport is available
                        #[cfg(not(target_arch = "wasm32"))]
                        {
                            let transport_guard = self.transport.read().await;
                            if let Some(transport) = transport_guard.as_ref() {
                                let mut transport_lock = transport.write().await;
                                transport_lock.publish_entropy_message(message_data).await
                                    .map_err(|e| WireError::other(&format!("Failed to publish response message: {}", e)))?;
                                info!("Serving block {} to peer {} via GossipSub", start_round, from_peer);
                            } else {
                                debug!("No transport available to serve block");
                            }
                        }
                    }
                }
            }
            EntropyGossipMessage::BlockResponse { start_round, block } => {
                if let Some(block) = block {
                    let end_round = block.end_round;
                    
                    info!("Received block {}-{} from peer {}", 
                          start_round, end_round, from_peer);
                
                    // Verify block integrity before storing
                    if block.verify_integrity() {
                        self.cache.store_block(block.clone()).await?;
                        info!("Stored received block {}-{} in cache", 
                              start_round, end_round);
                    } else {
                        warn!("Received corrupted block {}-{} from peer {}, discarding", 
                              block.start_round, block.end_round, from_peer);
                    }
                } else {
                    warn!("Received empty block response from peer {}", from_peer);
                }
            }
        }
        
        Ok(())
    }

    /// Process incoming GossipSub messages (native platforms only)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn process_messages(&self) -> Result<()> {
        let mut message_rx = self.message_rx.write().await;
        
        // Process all available messages
        while let Ok((message, peer_id)) = message_rx.try_recv() {
            debug!("Processing GossipSub message from {}: {:?}", peer_id, message);
            
            // Handle the message
            if let Err(e) = self.handle_gossip_message(message, peer_id).await {
                error!("Failed to handle GossipSub message from {}: {}", peer_id, e);
            }
        }
        
        Ok(())
    }

    /// Run the entropy swarm message loop (native platforms only)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn run(&self) -> Result<()> {
        info!("Starting entropy swarm message processing loop");
        
        loop {
            // Process incoming GossipSub messages
            self.process_messages().await?;
            
            // Small delay to prevent busy waiting
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zks_crypt::entropy_block::DrandRound;

    fn create_test_entropy_block(start_round: u64) -> EntropyBlock {
        let mut block = EntropyBlock::new(start_round);
        
        // Add a few test rounds
        for i in 0..10 {
            let round = DrandRound::new(
                start_round + i,
                [i as u8; 32],
                vec![i as u8; 96],
                vec![(i + 1) as u8; 96],
            );
            block.add_round(round).unwrap();
        }
        
        block
    }

    #[tokio::test]
    async fn test_entropy_cache_basic() {
        let config = EntropySwarmConfig::default();
        let cache = EntropyCache::new(config);
        
        let block = create_test_entropy_block(1000);
        let start_round = block.start_round;
        
        // Store block
        cache.store_block(block.clone()).await.unwrap();
        
        // Retrieve block
        let retrieved = cache.get_block(start_round).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().start_round, start_round);
        
        // Check stats
        let stats = cache.get_stats().await;
        assert_eq!(stats.total_blocks, 1);
        assert_eq!(stats.total_accesses, 1);
    }

    #[tokio::test]
    async fn test_entropy_swarm_creation() {
        let config = EntropySwarmConfig::default();
        let swarm = EntropySwarm::new(config);
        
        assert!(swarm.get_entropy_peers().await.is_empty());
        
        let stats = swarm.get_cache_stats().await;
        assert_eq!(stats.total_blocks, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_entropy_peer_management() {
        let config = EntropySwarmConfig::default();
        let swarm = EntropySwarm::new(config);
        
        let peer_id = PeerId::new();
        
        // Add peer
        swarm.add_entropy_peer(peer_id).await.unwrap();
        assert_eq!(swarm.get_entropy_peers().await.len(), 1);
        
        // Remove peer
        swarm.remove_entropy_peer(peer_id).await.unwrap();
        assert!(swarm.get_entropy_peers().await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_gossip_message_handling() {
        let config = EntropySwarmConfig::default();
        let swarm = EntropySwarm::new(config);
        
        let peer_id = PeerId::new();
        let block = create_test_entropy_block(1000);
        
        // Test BlockAvailable message
        let gossip_msg = EntropyGossipMessage::BlockAvailable {
            start_round: block.start_round,
            end_round: block.end_round,
            block_hash: block.block_hash,
            peer_id: peer_id.to_string(),
        };
        
        swarm.handle_gossip_message(gossip_msg, peer_id).await.unwrap();
        
        // Peer should be added to entropy peers
        assert_eq!(swarm.get_entropy_peers().await.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "Requires DHT swarm setup for proper testing"]
    async fn test_dht_entropy_block_announcement() {
        let config = EntropySwarmConfig::default();
        let swarm = EntropySwarm::new(config);
        
        let block = create_test_entropy_block(1000);
        let start_round = block.start_round;
        
        // Store block in cache
        swarm.cache.store_block(block.clone()).await.unwrap();
        
        // Announce block to DHT
        swarm.announce_entropy_block_to_dht(start_round).await.unwrap();
        
        // Query DHT for providers
        let providers = swarm.query_entropy_block_providers(start_round).await.unwrap();
        
        // Should find at least one provider (ourselves)
        assert!(!providers.is_empty());
        
        // Verify provider information
        let provider = &providers[0];
        assert_eq!(provider.start_round, start_round);
        assert_eq!(provider.end_round, block.end_round);
        assert_eq!(provider.block_hash, block.block_hash);
    }
}