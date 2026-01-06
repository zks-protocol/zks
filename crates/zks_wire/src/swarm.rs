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
use rand::Rng;

use crate::{WireError, Result};

/// Unique identifier for a peer in the swarm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Generate a new random peer ID using cryptographically secure random
    pub fn new() -> Self {
        let mut id = [0u8; 32];
        getrandom::getrandom(&mut id).expect("Failed to generate random peer ID");
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
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            network_name: "zks-swarm".to_string(),
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            max_peers: 50,
            discovery_interval: 30,
            protocol_version: 1,
        }
    }
}

/// Main swarm networking component
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
        }
    }
    
    /// Get this peer's ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
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
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_swarm_creation() {
        let swarm = Swarm::new("test-network".to_string());
        assert_eq!(swarm.config.network_name, "test-network");
        assert!(swarm.peer_count().await == 0);
    }
    
    #[tokio::test]
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
    
    #[tokio::test]
    async fn test_peer_id_generation() {
        let peer_id1 = PeerId::new();
        let peer_id2 = PeerId::new();
        
        assert_ne!(peer_id1, peer_id2);
        assert_eq!(peer_id1.to_bytes().len(), 32);
    }
}