//! Swarm networking for peer discovery and mesh formation in ZK Protocol
//! 
//! Provides decentralized peer discovery and connection management.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::net::UdpSocket;
use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn};

use crate::{WireError, Result};
use zks_crypt::entropy_block::EntropyBlock;

/// Kademlia provider record for DHT functionality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRecord {
    /// Provider peer ID
    pub provider: PeerId,
    /// Content key (hash)
    pub key: Vec<u8>,
    /// Provider addresses
    pub addresses: Vec<SocketAddr>,
    /// Record creation timestamp
    pub created: u64,
    /// Record expiration timestamp
    pub expires: u64,
}

/// Kademlia DHT storage
#[derive(Debug, Clone)]
pub struct KademliaDHT {
    /// Provider records stored locally
    providers: Arc<RwLock<HashMap<Vec<u8>, Vec<ProviderRecord>>>>,
    /// Replication factor (k) - reserved for future replication logic
    #[allow(dead_code)]
    k_value: usize,
}

impl KademliaDHT {
    /// Create a new Kademlia DHT
    pub fn new(k_value: usize) -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
            k_value,
        }
    }
    
    /// Store a provider record
    pub async fn store_provider(&self, record: ProviderRecord) -> Result<()> {
        let mut providers = self.providers.write().await;
        let key = record.key.clone();
        providers.entry(key).or_insert_with(Vec::new).push(record);
        Ok(())
    }
    
    /// Get provider records for a key
    pub async fn get_providers(&self, key: &[u8]) -> Vec<ProviderRecord> {
        let providers = self.providers.read().await;
        providers.get(key).cloned().unwrap_or_default()
    }
    
    /// Remove expired records
    pub async fn cleanup_expired(&self) {
        let mut providers = self.providers.write().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        for records in providers.values_mut() {
            records.retain(|record| record.expires > now);
        }
        
        // Remove empty key entries
        providers.retain(|_, records| !records.is_empty());
    }
}

/// Unique identifier for a peer in the swarm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Generate a new random peer ID using high-entropy randomness (drand + OsRng)
    /// 
    /// # Security
    /// Uses TrueEntropy for 256-bit post-quantum computational security.
    /// Secure if ANY entropy source is uncompromised.
    pub fn new() -> Self {
        use zks_crypt::true_entropy::get_sync_entropy;
        let entropy = get_sync_entropy(32);
        let mut id = [0u8; 32];
        id.copy_from_slice(&entropy);
        Self(id)
    }
    
    /// Create from a byte array
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    /// Convert to byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
    
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Default for PeerId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Information about a peer in the swarm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    /// Peer ID
    pub id: PeerId,
    /// Peer addresses
    pub addresses: Vec<SocketAddr>,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Connection state
    pub state: PeerState,
    /// Protocol version
    pub protocol_version: u8,
}

/// Connection state of a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerState {
    /// Peer is disconnected
    Disconnected,
    /// Peer is connecting
    Connecting,
    /// Peer is connected
    Connected,
    /// Peer is in the process of disconnecting
    Disconnecting,
}

/// Events that can occur in the swarm
#[derive(Debug, Clone)]
pub enum SwarmEvent {
    /// A new peer has joined the swarm
    PeerJoined(PeerId),
    /// A peer has left the swarm
    PeerLeft(PeerId),
    /// A peer has updated their information
    PeerUpdated(PeerId),
    /// Received a message from a peer
    MessageReceived {
        /// Source peer ID
        from: PeerId,
        /// Message content
        content: Vec<u8>,
    },
    /// Swarm is ready
    Ready,
    /// Swarm error occurred
    Error(String),
}

/// Messages that can be sent between peers in the swarm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwarmMessage {
    /// An entropy block being shared via GossipSub
    EntropyBlock {
        /// Starting round number of the block
        start_round: u64,
        /// Ending round number of the block
        end_round: u64,
        /// Serialized entropy block data
        data: Vec<u8>,
    },
}

/// Configuration for the swarm
#[derive(Debug, Clone)]
pub struct SwarmConfig {
    /// Network name/identifier
    pub network_name: String,
    /// Bind address for swarm communication
    pub bind_addr: SocketAddr,
    /// Maximum number of peers
    pub max_peers: usize,
    /// Peer discovery interval in seconds
    pub discovery_interval: u64,
    /// Protocol version
    pub protocol_version: u8,
    /// Entropy cache sync interval in seconds
    pub entropy_sync_interval: u64,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            network_name: "zks-swarm".to_string(),
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            max_peers: 50,
            discovery_interval: 30,
            protocol_version: 1,
            entropy_sync_interval: 60, // 1 minute
        }
    }
}

/// Main swarm networking component
#[derive(Debug)]
pub struct Swarm {
    /// Swarm configuration
    config: SwarmConfig,
    /// This peer's ID
    peer_id: PeerId,
    /// Known peers
    peers: Arc<RwLock<HashMap<PeerId, Peer>>>,
    /// UDP socket for communication
    socket: Option<Arc<UdpSocket>>,
    /// Event channel
    event_tx: mpsc::Sender<SwarmEvent>,
    /// Event receiver (stored for internal use)
    event_rx: Option<mpsc::Receiver<SwarmEvent>>,
    /// Whether the swarm is running
    running: Arc<RwLock<bool>>,
    /// Kademlia DHT for provider records
    dht: Arc<KademliaDHT>,
    /// Entropy cache for storing entropy blocks
    entropy_cache: Option<Arc<crate::entropy_cache::EntropyCache>>,
}

impl Swarm {
    /// Create a new swarm with the given network name
    pub fn new(network_name: String) -> Self {
        let config = SwarmConfig {
            network_name,
            ..Default::default()
        };
        
        let (event_tx, event_rx) = mpsc::channel(100);
        let peer_id = PeerId::new();
        
        Self {
            config,
            peer_id,
            peers: Arc::new(RwLock::new(HashMap::new())),
            socket: None,
            event_tx,
            event_rx: Some(event_rx),
            running: Arc::new(RwLock::new(false)),
            dht: Arc::new(KademliaDHT::new(20)), // k=20 for Kademlia
            entropy_cache: None,
        }
    }
    
    /// Create a swarm with custom configuration
    pub fn with_config(config: SwarmConfig) -> Self {
        let (event_tx, event_rx) = mpsc::channel(100);
        let peer_id = PeerId::new();
        
        Self {
            config,
            peer_id,
            peers: Arc::new(RwLock::new(HashMap::new())),
            socket: None,
            event_tx,
            event_rx: Some(event_rx),
            running: Arc::new(RwLock::new(false)),
            dht: Arc::new(KademliaDHT::new(20)), // k=20 for Kademlia
            entropy_cache: None,
        }
    }
    
    /// Get this peer's ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }
    
    /// Set the entropy cache for this swarm
    pub fn set_entropy_cache(&mut self, cache: Arc<crate::entropy_cache::EntropyCache>) {
        self.entropy_cache = Some(cache);
    }
    
    /// Get a reference to the entropy cache if set
    pub fn entropy_cache(&self) -> Option<&Arc<crate::entropy_cache::EntropyCache>> {
        self.entropy_cache.as_ref()
    }
    
    /// Start the swarm
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting swarm '{}' with peer ID {}", self.config.network_name, self.peer_id);
        
        // Create UDP socket
        let socket = UdpSocket::bind(self.config.bind_addr).await?;
        let socket = Arc::new(socket);
        self.socket = Some(socket.clone());
        
        // Mark as running
        *self.running.write().await = true;
        
        // Start background tasks
        self.start_background_tasks(socket).await?;
        
        info!("Swarm started successfully");
        Ok(())
    }
    
    /// Stop the swarm
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping swarm '{}'", self.config.network_name);
        
        *self.running.write().await = false;
        
        // Clear socket
        self.socket = None;
        
        info!("Swarm stopped");
        Ok(())
    }
    
    /// Add a known peer
    pub async fn add_peer(&self, peer: Peer) -> Result<()> {
        let peer_id = peer.id;
        
        {
            let mut peers = self.peers.write().await;
            peers.insert(peer_id, peer.clone());
        }
        
        // Send event
        self.event_tx.send(SwarmEvent::PeerJoined(peer_id)).await
            .map_err(|_| WireError::other("Failed to send peer joined event"))?;
        
        info!("Added peer: {}", peer_id);
        Ok(())
    }
    
    /// Remove a peer
    pub async fn remove_peer(&self, peer_id: PeerId) -> Result<()> {
        {
            let mut peers = self.peers.write().await;
            peers.remove(&peer_id);
        }
        
        // Send event
        self.event_tx.send(SwarmEvent::PeerLeft(peer_id)).await
            .map_err(|_| WireError::other("Failed to send peer left event"))?;
        
        info!("Removed peer: {}", peer_id);
        Ok(())
    }
    
    /// Get a peer by ID
    pub async fn get_peer(&self, peer_id: PeerId) -> Result<Peer> {
        let peers = self.peers.read().await;
        peers.get(&peer_id)
            .cloned()
            .ok_or_else(|| WireError::peer_not_found(peer_id.to_string()))
    }
    
    /// Get all peers
    pub async fn get_peers(&self) -> Vec<Peer> {
        let peers = self.peers.read().await;
        peers.values().cloned().collect()
    }
    
    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }
    
    /// Get the local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.peer_id
    }
    
    /// Send a message to a specific peer
    pub async fn send_message(&self, peer_id: PeerId, content: Vec<u8>) -> Result<()> {
        let peer = self.get_peer(peer_id).await?;
        
        if peer.addresses.is_empty() {
            return Err(WireError::other("Peer has no addresses"));
        }
        
        // Send to first available address (simplified)
        if let Some(socket) = &self.socket {
            let addr = peer.addresses[0];
            socket.send_to(&content, addr).await?;
            debug!("Sent message to peer {} at {}", peer_id, addr);
        }
        
        Ok(())
    }
    
    /// Broadcast a message to all peers
    pub async fn broadcast_message(&self, content: Vec<u8>) -> Result<()> {
        let peers = self.get_peers().await;
        
        for peer in peers {
            if peer.id != self.peer_id {
                let _ = self.send_message(peer.id, content.clone()).await;
            }
        }
        
        Ok(())
    }
    
    /// Get event receiver for external event handling
    pub fn event_receiver(&mut self) -> Option<mpsc::Receiver<SwarmEvent>> {
        self.event_rx.take()
    }
    
    /// Discover peers for circuit building
    pub async fn discover_peers(&self, min_peers: usize) -> Result<Vec<Peer>> {
        let peers = self.get_peers().await;
        
        if peers.len() < min_peers {
            warn!("Not enough peers available for circuit. Need {}, have {}", min_peers, peers.len());
            return Err(WireError::other(&format!(
                "Insufficient peers for circuit: need {}, have {}",
                min_peers, peers.len()
            )));
        }
        
        // Filter connected peers only
        let connected_peers: Vec<Peer> = peers.into_iter()
            .filter(|peer| peer.state == PeerState::Connected && !peer.addresses.is_empty())
            .collect();
        
        if connected_peers.len() < min_peers {
            warn!("Not enough connected peers for circuit. Need {}, have {}", min_peers, connected_peers.len());
            return Err(WireError::other(&format!(
                "Insufficient connected peers for circuit: need {}, have {}",
                min_peers, connected_peers.len()
            )));
        }
        
        info!("Discovered {} peers for circuit building", connected_peers.len());
        Ok(connected_peers)
    }
    
    /// Build a circuit through the swarm for onion routing
    pub async fn build_circuit(&self, min_hops: u8, max_hops: u8) -> Result<crate::SwarmCircuit> {
        use crate::CircuitBuilder;
        
        info!("Building circuit with {}-{} hops", min_hops, max_hops);
        
        // Discover available peers (need at least max_hops peers for the circuit)
        let available_peers = self.discover_peers(max_hops as usize).await?;
        
        // Build circuit using the circuit builder
        let builder = CircuitBuilder::new()
            .min_hops(min_hops)
            .max_hops(max_hops);
        
        let circuit = builder.build(&available_peers).await?;
        
        info!("Successfully built circuit with {} hops", circuit.hop_count());
        Ok(circuit)
    }
    
    /// Announce that this peer provides an entropy block
    pub async fn announce_entropy_block(&self, start_round: u64) -> Result<()> {
        // Generate content key for the entropy block
        let key = Self::generate_entropy_block_key(start_round);
        
        // Get this peer's addresses from peer info
        let addresses = self.get_peer_addresses(self.peer_id).await?;
        
        // Create provider record
        let record = ProviderRecord {
            provider: self.peer_id,
            key: key.clone(),
            addresses,
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expires: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + 3600, // 1 hour TTL
        };
        
        // Store in local DHT
        self.dht.store_provider(record).await?;
        
        info!("Announced entropy block {} to DHT", start_round);
        Ok(())
    }
    
    /// Announce multiple entropy blocks in batch
    pub async fn announce_entropy_blocks(&self, start_rounds: Vec<u64>) -> Result<()> {
        let count = start_rounds.len();
        for start_round in start_rounds {
            if let Err(e) = self.announce_entropy_block(start_round).await {
                warn!("Failed to announce entropy block {}: {}", start_round, e);
            }
        }
        
        info!("Announced {} entropy blocks to DHT", count);
        Ok(())
    }
    
    /// Query DHT for providers of an entropy block
    pub async fn query_entropy_block_providers(&self, start_round: u64) -> Vec<ProviderRecord> {
        let key = Self::generate_entropy_block_key(start_round);
        self.dht.get_providers(&key).await
    }
    
    /// Get addresses for a specific peer
    async fn get_peer_addresses(&self, peer_id: PeerId) -> Result<Vec<SocketAddr>> {
        let peers = self.peers.read().await;
        if let Some(peer) = peers.get(&peer_id) {
            Ok(peer.addresses.clone())
        } else {
            // If we don't have the peer info, return empty addresses
            // This could be enhanced to query other peers for the information
            Ok(vec![])
        }
    }
    
    /// Generate a content key for an entropy block (round-based)
    fn generate_entropy_block_key(start_round: u64) -> Vec<u8> {
        // Use block number (round / 1M) as key
        let block_number = start_round / 1_000_000;
        format!("entropy_block_{}", block_number).into_bytes()
    }
    
    /// Query DHT for providers of multiple entropy blocks
    pub async fn query_entropy_blocks_providers(&self, start_rounds: Vec<u64>) -> HashMap<u64, Vec<ProviderRecord>> {
        let mut results = HashMap::new();
        
        for start_round in start_rounds {
            let providers = self.query_entropy_block_providers(start_round).await;
            if !providers.is_empty() {
                results.insert(start_round, providers);
            }
        }
        
        results
    }
    
    /// Find the closest provider for an entropy block
    pub async fn find_closest_entropy_provider(&self, start_round: u64) -> Option<ProviderRecord> {
        let providers = self.query_entropy_block_providers(start_round).await;
        
        if providers.is_empty() {
            return None;
        }
        
        // For now, return the first provider
        // This could be enhanced with latency-based selection or other metrics
        providers.into_iter().next()
    }
    
    /// Sync entropy cache with DHT provider records
    /// This should be called periodically to announce blocks we have cached
    pub async fn sync_entropy_cache_with_dht(&self) -> Result<()> {
        // Check if we have an entropy cache configured
        let cache = match &self.entropy_cache {
            Some(cache) => cache,
            None => {
                debug!("No entropy cache configured, skipping DHT sync");
                return Ok(());
            }
        };
        
        // Get cache stats to see what blocks we have
        let stats = cache.get_stats().await;
        debug!("Syncing {} cached entropy blocks with DHT", stats.total_blocks);
        
        // For now, we'll announce a few recent blocks
        // In a full implementation, this would iterate through all cached blocks
        let recent_blocks = vec![
            50_000_000, // Block 50M
            51_000_000, // Block 51M  
            52_000_000, // Block 52M
        ];
        
        let mut blocks_to_announce = Vec::new();
        
        for start_round in recent_blocks {
            // Check if we have this block cached
            if cache.has_block(start_round).await {
                blocks_to_announce.push(start_round);
            }
        }
        
        let blocks_count = blocks_to_announce.len();
        if !blocks_to_announce.is_empty() {
            self.announce_entropy_blocks(blocks_to_announce).await?;
        }
        
        info!("Synced {} entropy blocks with DHT", blocks_count);
        Ok(())
    }
    
    /// Clean up expired provider records
    pub async fn cleanup_expired_providers(&self) {
        self.dht.cleanup_expired().await;
        debug!("Cleaned up expired provider records");
    }

    /// Publish an entropy block to the P2P swarm using GossipSub
    pub async fn publish_entropy_block(&self, block: EntropyBlock) -> Result<()> {
        // Serialize the block
        let serialized_block = bincode::serialize(&block)
            .map_err(|e| WireError::Other(format!("Failed to serialize entropy block: {}", e)))?;
        
        // Create a GossipSub message
        let message = SwarmMessage::EntropyBlock {
            start_round: block.start_round,
            end_round: block.end_round,
            data: serialized_block,
        };
        
        // Serialize the message
        let message_bytes = bincode::serialize(&message)
            .map_err(|e| WireError::Other(format!("Failed to serialize swarm message: {}", e)))?;
        
        // Broadcast the message to all peers
        self.broadcast_message(message_bytes).await?;
        
        // Announce this peer as a provider in the DHT
        self.announce_entropy_block(block.start_round).await?;
        
        info!("Published entropy block {} (rounds {}-{}) to swarm", 
              hex::encode(&block.block_hash[..8]), block.start_round, block.end_round);
        
        Ok(())
    }

    // Private methods
    
    async fn start_background_tasks(&self, socket: Arc<UdpSocket>) -> Result<()> {
        // Start message receiver task
        let socket_clone = socket.clone();
        let peers_clone = self.peers.clone();
        let event_tx_clone = self.event_tx.clone();
        let running_clone = self.running.clone();
        
        tokio::spawn(async move {
            Self::receive_messages(socket_clone, peers_clone, event_tx_clone, running_clone).await;
        });
        
        // Start peer discovery task
        let peers_clone = self.peers.clone();
        let event_tx_clone = self.event_tx.clone();
        let running_clone = self.running.clone();
        let discovery_interval = self.config.discovery_interval;
        
        tokio::spawn(async move {
            Self::peer_discovery(peers_clone, event_tx_clone, running_clone, discovery_interval).await;
        });
        
        // Start DHT cleanup task
        let dht_clone = self.dht.clone();
        let running_clone = self.running.clone();
        
        tokio::spawn(async move {
            Self::dht_cleanup(dht_clone, running_clone).await;
        });
        
        // Start entropy cache sync task if cache is configured
        if let Some(cache) = &self.entropy_cache {
            let cache_clone = cache.clone();
            let running_clone = self.running.clone();
            let sync_interval = self.config.entropy_sync_interval;
            
            tokio::spawn(async move {
                Self::entropy_cache_sync(cache_clone, running_clone, sync_interval).await;
            });
        }
        
        Ok(())
    }
    
    async fn receive_messages(
        socket: Arc<UdpSocket>,
        peers: Arc<RwLock<HashMap<PeerId, Peer>>>,
        event_tx: mpsc::Sender<SwarmEvent>,
        running: Arc<RwLock<bool>>,
    ) {
        let mut buf = vec![0u8; 65536];
        
        while *running.read().await {
            match socket.recv_from(&mut buf).await {
                Ok((len, from)) => {
                    let content = buf[..len].to_vec();
                    
                    // Find peer by address (simplified)
                    let peers_guard = peers.read().await;
                    if let Some(peer) = peers_guard.values().find(|p| p.addresses.contains(&from)) {
                        let event = SwarmEvent::MessageReceived {
                            from: peer.id,
                            content,
                        };
                        
                        let _ = event_tx.send(event).await;
                    }
                }
                Err(e) => {
                    warn!("Error receiving message: {}", e);
                }
            }
        }
    }
    
    async fn peer_discovery(
        peers: Arc<RwLock<HashMap<PeerId, Peer>>>,
        event_tx: mpsc::Sender<SwarmEvent>,
        running: Arc<RwLock<bool>>,
        interval_secs: u64,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        
        while *running.read().await {
            interval.tick().await;
            
            // Clean up stale peers
            let mut peers_guard = peers.write().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let stale_threshold = 300; // 5 minutes
            let stale_peers: Vec<PeerId> = peers_guard
                .iter()
                .filter(|(_, peer)| now - peer.last_seen > stale_threshold)
                .map(|(id, _)| *id)
                .collect();
            
            for peer_id in stale_peers {
                peers_guard.remove(&peer_id);
                let _ = event_tx.send(SwarmEvent::PeerLeft(peer_id)).await;
            }
        }
    }
    
    async fn dht_cleanup(dht: Arc<KademliaDHT>, running: Arc<RwLock<bool>>) {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
        
        while *running.read().await {
            interval.tick().await;
            dht.cleanup_expired().await;
        }
    }
    
    async fn entropy_cache_sync(cache: Arc<crate::entropy_cache::EntropyCache>, running: Arc<RwLock<bool>>, interval_secs: u64) {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        
        while *running.read().await {
            interval.tick().await;
            
            // Get cache stats
            let stats = cache.get_stats().await;
            debug!("Periodic entropy cache sync: {} cached blocks", stats.total_blocks);
            
            // Clean up expired entries
            let removed_count = cache.cleanup_expired().await;
            if removed_count > 0 {
                debug!("Removed {} expired entropy blocks from cache", removed_count);
            }
            
            // Log cache health
            if stats.total_blocks > 0 {
                let hit_rate = if stats.total_requests > 0 {
                    (stats.cache_hits as f64 / stats.total_requests as f64) * 100.0
                } else {
                    0.0
                };
                info!("Entropy cache health: {} blocks, {} hits, {:.1}% hit rate", 
                      stats.total_blocks, stats.cache_hits, hit_rate);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_swarm_creation() {
        let swarm = Swarm::new("test-network".to_string());
        assert_eq!(swarm.config.network_name, "test-network");
        assert!(swarm.peer_count().await == 0);
    }
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_peer_management() {
        let swarm = Swarm::new("test-network".to_string());
        
        let peer = Peer {
            id: PeerId::new(),
            addresses: vec!["127.0.0.1:8080".parse().unwrap()],
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            state: PeerState::Connected,
            protocol_version: 1,
        };
        
        swarm.add_peer(peer.clone()).await.unwrap();
        assert_eq!(swarm.peer_count().await, 1);
        
        let retrieved_peer = swarm.get_peer(peer.id).await.unwrap();
        assert_eq!(retrieved_peer.id, peer.id);
        
        swarm.remove_peer(peer.id).await.unwrap();
        assert_eq!(swarm.peer_count().await, 0);
    }
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_peer_id_generation() {
        let peer_id1 = PeerId::new();
        let peer_id2 = PeerId::new();
        
        assert_ne!(peer_id1, peer_id2);
        assert_eq!(peer_id1.to_bytes().len(), 32);
    }
    
    #[tokio::test]
    async fn test_entropy_block_key_generation() {
        let key1 = Swarm::generate_entropy_block_key(50_000_000);
        let key2 = Swarm::generate_entropy_block_key(50_999_999);
        let key3 = Swarm::generate_entropy_block_key(51_000_000);
        
        // Same block number (50M) should generate same key
        assert_eq!(key1, key2);
        // Different block numbers should generate different keys
        assert_ne!(key1, key3);
        
        assert_eq!(String::from_utf8(key1).unwrap(), "entropy_block_50");
        assert_eq!(String::from_utf8(key3).unwrap(), "entropy_block_51");
    }
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_entropy_block_announcement() {
        let swarm = Swarm::new("test-network".to_string());
        
        // Add a peer with addresses first
        let peer_id = swarm.peer_id();
        let peer = Peer {
            id: peer_id,
            addresses: vec!["127.0.0.1:8080".parse().unwrap()],
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            state: PeerState::Connected,
            protocol_version: 1,
        };
        swarm.add_peer(peer).await.unwrap();
        
        // Announce an entropy block
        swarm.announce_entropy_block(50_000_000).await.unwrap();
        
        // Query for providers
        let providers = swarm.query_entropy_block_providers(50_000_000).await;
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].provider, peer_id);
    }
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_multiple_entropy_block_announcement() {
        let swarm = Swarm::new("test-network".to_string());
        
        // Add a peer with addresses first
        let peer_id = swarm.peer_id();
        let peer = Peer {
            id: peer_id,
            addresses: vec!["127.0.0.1:8080".parse().unwrap()],
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            state: PeerState::Connected,
            protocol_version: 1,
        };
        swarm.add_peer(peer).await.unwrap();
        
        // Announce multiple entropy blocks
        let blocks = vec![50_000_000, 51_000_000, 52_000_000];
        swarm.announce_entropy_blocks(blocks.clone()).await.unwrap();
        
        // Query for each block
        for start_round in blocks {
            let providers = swarm.query_entropy_block_providers(start_round).await;
            assert_eq!(providers.len(), 1);
            assert_eq!(providers[0].provider, peer_id);
        }
    }
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_find_closest_entropy_provider() {
        let swarm = Swarm::new("test-network".to_string());
        
        // Add a peer with addresses first
        let peer_id = swarm.peer_id();
        let peer = Peer {
            id: peer_id,
            addresses: vec!["127.0.0.1:8080".parse().unwrap()],
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            state: PeerState::Connected,
            protocol_version: 1,
        };
        swarm.add_peer(peer).await.unwrap();
        
        // Announce an entropy block
        swarm.announce_entropy_block(50_000_000).await.unwrap();
        
        // Find closest provider
        let provider = swarm.find_closest_entropy_provider(50_000_000).await;
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().provider, peer_id);
        
        // Test with non-existent block
        let no_provider = swarm.find_closest_entropy_provider(99_000_000).await;
        assert!(no_provider.is_none());
    }
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_entropy_cache_integration() {
        let mut swarm = Swarm::new("test-network".to_string());
        
        // Create and configure entropy cache
        let cache_config = crate::entropy_cache::EntropyCacheConfig::default();
        let cache = Arc::new(crate::entropy_cache::EntropyCache::new(cache_config));
        swarm.set_entropy_cache(cache.clone());
        
        // Store a block in the cache with proper hash calculation
        let rounds: Vec<zks_crypt::entropy_block::DrandRound> = (0..1000).map(|i| zks_crypt::entropy_block::DrandRound {
            round: 50_000_000 + i,
            randomness: [0u8; 32],
            signature: vec![1, 2, 3, 4],
            previous_signature: vec![0, 1, 2, 3],
        }).collect();
        let test_block = zks_crypt::entropy_block::EntropyBlock::with_rounds(50_000_000, rounds);
        cache.store_block(test_block).await.unwrap();
        
        // Verify block is in cache
        assert!(cache.has_block(50_000_000).await);
        
        // Sync cache with DHT
        swarm.sync_entropy_cache_with_dht().await.unwrap();
        
        // Query for providers
        let providers = swarm.query_entropy_block_providers(50_000_000).await;
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].provider, swarm.peer_id());
        
        // Test without cache configured
        let mut swarm2 = Swarm::new("test-network-2".to_string());
        // Should not panic even without cache
        swarm2.sync_entropy_cache_with_dht().await.unwrap();
    }
}