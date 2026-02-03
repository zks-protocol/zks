//! Native P2P transport using libp2p for desktop/mobile platforms
//! 
//! This module provides full peer-to-peer networking capabilities for native
//! platforms (not WASM), including:
//! - Direct TCP/UDP connections
//! - NAT traversal with DCUtR (Direct Connection Upgrade through Relay)
//! - Full libp2p protocol support
//! - Hole punching capabilities

#[cfg(not(target_arch = "wasm32"))]
use libp2p::{
    identity::Keypair,
    swarm::{SwarmEvent, Swarm},
    tcp::{tokio::Transport as TcpTransport, Config as TcpConfig},
    noise,
    yamux,
    relay,
    dcutr,
    ping,
    request_response,
    gossipsub,
    kad,
    PeerId,
    Multiaddr,
    Transport,
};



use crate::entropy_swarm::{EntropyGossipMessage, ENTROPY_TOPIC};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn, error};
use futures_util::StreamExt;

use serde::{Deserialize, Serialize};
use std::io;
use async_trait::async_trait;

/// Request type for Faisal Swarm protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaisalSwarmRequest {
    /// Circuit identifier for routing the request through the swarm
    pub circuit_id: u32,
    /// Encrypted payload data for the circuit
    pub data: Vec<u8>,
}

/// Response type for Faisal Swarm protocol  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaisalSwarmResponse {
    /// Whether the request was successful
    pub success: bool,
    /// Response data from the circuit
    pub data: Vec<u8>,
}

/// Codec for Faisal Swarm request-response protocol
#[derive(Clone)]
pub struct FaisalSwarmCodec;

#[async_trait]
impl request_response::Codec for FaisalSwarmCodec {
    type Protocol = libp2p::StreamProtocol;
    type Request = FaisalSwarmRequest;
    type Response = FaisalSwarmResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        futures::AsyncReadExt::read_to_end(io, &mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        futures::AsyncReadExt::read_to_end(io, &mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        futures::AsyncWriteExt::write_all(io, &data).await?;
        futures::AsyncWriteExt::flush(io).await?;
        Ok(())
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Self::Response) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&res).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        futures::AsyncWriteExt::write_all(io, &data).await?;
        futures::AsyncWriteExt::flush(io).await?;
        Ok(())
    }
}

/// Custom event type for NativeSwarmBehaviour
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub enum NativeSwarmEvent {
    /// Ping protocol event for connectivity testing
    Ping(ping::Event),
    /// Relay protocol event for NAT traversal
    Relay(relay::Event),
    /// DCUtR protocol event for hole punching
    Dcutr(dcutr::Event),
    /// Faisal Swarm request-response event for circuit communication
    FaisalSwarm(request_response::Event<FaisalSwarmRequest, FaisalSwarmResponse>),
    /// Entropy gossip protocol event for block sharing
    EntropyGossip(gossipsub::Event),
    /// Kademlia DHT event for entropy block discovery
    Kademlia(kad::Event),
}

impl From<ping::Event> for NativeSwarmEvent {
    fn from(event: ping::Event) -> Self {
        NativeSwarmEvent::Ping(event)
    }
}

impl From<relay::Event> for NativeSwarmEvent {
    fn from(event: relay::Event) -> Self {
        NativeSwarmEvent::Relay(event)
    }
}

impl From<dcutr::Event> for NativeSwarmEvent {
    fn from(event: dcutr::Event) -> Self {
        NativeSwarmEvent::Dcutr(event)
    }
}

impl From<request_response::Event<FaisalSwarmRequest, FaisalSwarmResponse>> for NativeSwarmEvent {
    fn from(event: request_response::Event<FaisalSwarmRequest, FaisalSwarmResponse>) -> Self {
        NativeSwarmEvent::FaisalSwarm(event)
    }
}

impl From<gossipsub::Event> for NativeSwarmEvent {
    fn from(event: gossipsub::Event) -> Self {
        NativeSwarmEvent::EntropyGossip(event)
    }
}

impl From<kad::Event> for NativeSwarmEvent {
    fn from(event: kad::Event) -> Self {
        NativeSwarmEvent::Kademlia(event)
    }
}

/// Native P2P swarm behavior combining all necessary protocols
#[cfg(not(target_arch = "wasm32"))]
#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(to_swarm = "NativeSwarmEvent")]
pub struct NativeSwarmBehaviour {
    /// Ping protocol for connectivity testing
    ping: ping::Behaviour,
    /// Relay protocol for NAT traversal
    relay: relay::Behaviour,
    /// DCUtR protocol for hole punching
    dcutr: dcutr::Behaviour,
    /// Request-response protocol for Faisal Swarm circuit communication
    faisal_swarm: request_response::Behaviour<FaisalSwarmCodec>,
    /// GossipSub protocol for entropy block sharing
    entropy_gossip: gossipsub::Behaviour,
    /// Kademlia DHT for entropy block discovery
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeSwarmBehaviour {
    /// Create a new NativeSwarmBehaviour instance
    pub fn new(local_peer_id: libp2p::PeerId) -> Self {
        let faisal_swarm_codec = FaisalSwarmCodec;
        let faisal_swarm = request_response::Behaviour::with_codec(
            faisal_swarm_codec,
            [(libp2p::StreamProtocol::new("/faisal-swarm/1.0.0"), request_response::ProtocolSupport::Full)],
            request_response::Config::default(),
        );
        
        // Configure GossipSub for entropy sharing
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .max_transmit_size(32 * 1024 * 1024) // 32 MB max message size
            .build()
            .expect("Valid gossipsub config");
        
        let entropy_gossip = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(Keypair::generate_ed25519()),
            gossipsub_config,
        ).expect("Valid gossipsub behaviour");
        
        // Configure Kademlia for entropy block discovery
        let kademlia = kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));
        
        // Bootstrap with some well-known peers (can be extended later)
        // For now, we'll add bootstrap nodes when the swarm starts
        
        NativeSwarmBehaviour {
            ping: ping::Behaviour::new(ping::Config::new()),
            relay: relay::Behaviour::new(local_peer_id, Default::default()),
            dcutr: dcutr::Behaviour::new(local_peer_id),
            faisal_swarm,
            entropy_gossip,
            kademlia,
        }
    }
}

/// Native P2P transport for desktop/mobile platforms
#[cfg(not(target_arch = "wasm32"))]
pub struct NativeP2PTransport {
    /// libp2p swarm instance managing all protocols
    swarm: Swarm<NativeSwarmBehaviour>,
    /// Local peer ID for this transport
    local_peer_id: PeerId,
    /// Map of connected peers to their network addresses
    connected_peers: Arc<Mutex<HashMap<PeerId, Vec<Multiaddr>>>>,
    /// Channel receiver for swarm events (currently unused but kept for future event processing)
    #[allow(dead_code)]
    event_receiver: mpsc::UnboundedReceiver<SwarmEvent<NativeSwarmEvent>>,
    /// Channel sender for forwarding GossipSub messages to EntropySwarm
    entropy_message_sender: Option<mpsc::UnboundedSender<(EntropyGossipMessage, PeerId)>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl std::fmt::Debug for NativeP2PTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeP2PTransport")
            .field("local_peer_id", &self.local_peer_id)
            .field("connected_peers", &self.connected_peers)
            .field("entropy_message_sender", &self.entropy_message_sender.is_some())
            .field("swarm", &"<Swarm>")
            .finish()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeP2PTransport {
    /// Create a new native P2P transport
    pub async fn new(keypair: Option<Keypair>) -> Result<Self, NativeP2PError> {
        let keypair = keypair.unwrap_or_else(Keypair::generate_ed25519);
        let local_peer_id = PeerId::from(keypair.public());
        
        info!("Creating native P2P transport with peer ID: {}", local_peer_id);
        
        // Create transport with TCP, noise, and yamux
        let _transport = TcpTransport::new(TcpConfig::default())
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::Config::new(&keypair).map_err(|e| NativeP2PError::Noise(e.to_string()))?)
            .multiplex(yamux::Config::default())
            .boxed();
        
        // Create swarm behavior
        let faisal_swarm_protocol = request_response::ProtocolSupport::Full;
        let faisal_swarm_codec = FaisalSwarmCodec;
        let faisal_swarm_config = request_response::Config::default();
        
        let faisal_swarm = request_response::Behaviour::with_codec(
            faisal_swarm_codec,
            vec![(libp2p::StreamProtocol::new("/faisal-swarm/1.0.0"), faisal_swarm_protocol)],
            faisal_swarm_config,
        );

        // Create GossipSub configuration for entropy sharing
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .max_transmit_size(1024 * 1024) // 1MB max message size
            .build()
            .map_err(|e| NativeP2PError::GossipSubConfig(e.to_string()))?;
        
        let entropy_gossip = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Anonymous,
            gossipsub_config,
        ).map_err(|e| NativeP2PError::GossipSubInit(e.to_string()))?;

        // Configure Kademlia for entropy block discovery
        let kademlia = kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));
        
        let behaviour = NativeSwarmBehaviour {
            ping: ping::Behaviour::new(ping::Config::new()),
            relay: relay::Behaviour::new(local_peer_id, Default::default()),
            dcutr: dcutr::Behaviour::new(local_peer_id),
            faisal_swarm,
            entropy_gossip,
            kademlia,
        };
        
        // Create swarm
        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                TcpConfig::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|_| behaviour)?
            .build();
        
        let (_event_sender, event_receiver) = mpsc::unbounded_channel();
        
        Ok(Self {
            swarm,
            local_peer_id,
            connected_peers: Arc::new(Mutex::new(HashMap::new())),
            event_receiver,
            entropy_message_sender: None,
        })
    }
    
    /// Listen on a local address
    pub async fn listen_on(&mut self, addr: Multiaddr) -> Result<(), NativeP2PError> {
        self.swarm.listen_on(addr)?;
        info!("Native P2P transport listening on swarm addresses");
        Ok(())
    }
    
    /// Dial a peer at the given address
    pub async fn dial(&mut self, peer_addr: Multiaddr) -> Result<(), NativeP2PError> {
        info!("Dialing peer at: {}", peer_addr);
        self.swarm.dial(peer_addr)?;
        Ok(())
    }
    
    /// Subscribe to the entropy topic for GossipSub
    pub async fn subscribe_entropy_topic(&mut self) -> Result<(), NativeP2PError> {
        let topic = gossipsub::IdentTopic::new(ENTROPY_TOPIC);
        self.swarm.behaviour_mut().entropy_gossip.subscribe(&topic)?;
        info!("Subscribed to entropy topic: {}", ENTROPY_TOPIC);
        Ok(())
    }
    
    /// Unsubscribe from the entropy topic
    pub async fn unsubscribe_entropy_topic(&mut self) -> Result<(), NativeP2PError> {
        let topic = gossipsub::IdentTopic::new(ENTROPY_TOPIC);
        self.swarm.behaviour_mut().entropy_gossip.unsubscribe(&topic)?;
        info!("Unsubscribed from entropy topic: {}", ENTROPY_TOPIC);
        Ok(())
    }
    
    /// Publish an entropy message to the GossipSub topic
    pub async fn publish_entropy_message(&mut self, message: Vec<u8>) -> Result<(), NativeP2PError> {
        let topic = gossipsub::IdentTopic::new(ENTROPY_TOPIC);
        self.swarm.behaviour_mut().entropy_gossip.publish(topic, message)
            .map_err(|e| NativeP2PError::GossipSubPublish(format!("Failed to publish entropy message: {:?}", e)))?;
        debug!("Published entropy message to topic");
        Ok(())
    }
    
    /// Set the entropy message sender for forwarding GossipSub messages to EntropySwarm
    pub fn set_entropy_message_sender(&mut self, sender: mpsc::UnboundedSender<(EntropyGossipMessage, PeerId)>) {
        self.entropy_message_sender = Some(sender);
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }
    
    /// Get swarm addresses
    pub fn listen_addresses(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().cloned().collect()
    }
    
    /// Start the event loop
    pub async fn run(mut self) -> Result<(), NativeP2PError> {
        info!("Starting native P2P transport event loop");
        
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Listening on {}", address);
                }
                SwarmEvent::Behaviour(event) => {
                    match event {
                        NativeSwarmEvent::Ping(ping_event) => {
                            debug!("Ping event: {:?}", ping_event);
                        }
                        NativeSwarmEvent::Relay(relay_event) => {
                            debug!("Relay event: {:?}", relay_event);
                        }
                        NativeSwarmEvent::Dcutr(dcutr_event) => {
                            debug!("DCUtR event: {:?}", dcutr_event);
                        }
                        NativeSwarmEvent::FaisalSwarm(faisal_event) => {
                            debug!("FaisalSwarm event: {:?}", faisal_event);
                        }
                        NativeSwarmEvent::EntropyGossip(gossip_event) => {
                            debug!("EntropyGossip event: {:?}", gossip_event);
                            
                            // Handle incoming GossipSub messages
                            if let gossipsub::Event::Message { propagation_source, message, .. } = gossip_event {
                                match bincode::deserialize::<EntropyGossipMessage>(&message.data) {
                                    Ok(entropy_msg) => {
                                        debug!("Received entropy message from {}: {:?}", propagation_source, entropy_msg);
                                        
                                        // Forward to EntropySwarm if sender is available
                                        if let Some(sender) = &self.entropy_message_sender {
                                            if let Err(e) = sender.send((entropy_msg, propagation_source)) {
                                                error!("Failed to forward entropy message to EntropySwarm: {}", e);
                                            }
                                        } else {
                                            debug!("No entropy message sender configured");
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to deserialize entropy message: {}", e);
                                    }
                                }
                            }
                        }
                        NativeSwarmEvent::Kademlia(kad_event) => {
                            debug!("Kademlia event: {:?}", kad_event);
                            
                            // Handle Kademlia events for entropy block discovery
                            match kad_event {
                                kad::Event::OutboundQueryProgressed { result, .. } => {
                                    match result {
                                        kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { providers, .. })) => {
                                            debug!("Found {} providers for entropy block", providers.len());
                                            for provider in providers {
                                                debug!("Entropy block provider: {}", provider);
                                                // TODO: Connect to provider and request entropy block
                                            }
                                        }
                                        kad::QueryResult::GetProviders(Err(e)) => {
                                            error!("Failed to get providers for entropy block: {:?}", e);
                                        }
                                        kad::QueryResult::StartProviding(Ok(kad::AddProviderOk { key })) => {
                                            debug!("Successfully started providing entropy block: {:?}", hex::encode(key.as_ref()));
                                        }
                                        kad::QueryResult::StartProviding(Err(e)) => {
                                            error!("Failed to start providing entropy block: {:?}", e);
                                        }
                                        _ => {
                                            debug!("Other Kademlia query result: {:?}", result);
                                        }
                                    }
                                }
                                kad::Event::RoutingUpdated { peer, .. } => {
                                    debug!("Routing table updated with peer: {}", peer);
                                }
                                _ => {
                                    debug!("Other Kademlia event: {:?}", kad_event);
                                }
                            }
                        }
                    }
                }
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    info!("Connected to {} via {}", peer_id, endpoint.get_remote_address());
                    
                    let mut peers = self.connected_peers.lock().await;
                    peers.entry(peer_id).or_default().push(endpoint.get_remote_address().clone());
                }
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    warn!("Connection closed to {}: {:?}", peer_id, cause);
                    
                    let mut peers = self.connected_peers.lock().await;
                    peers.remove(&peer_id);
                }
                SwarmEvent::IncomingConnection { local_addr, send_back_addr, .. } => {
                    debug!("Incoming connection from {} to {}", send_back_addr, local_addr);
                }
                SwarmEvent::IncomingConnectionError { local_addr, send_back_addr, error, .. } => {
                    error!("Incoming connection error from {} to {}: {}", send_back_addr, local_addr, error);
                }
                SwarmEvent::Dialing { peer_id, .. } => {
                    debug!("Dialing peer {:?}", peer_id);
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    error!("Outgoing connection error to {:?}: {}", peer_id, error);
                }
                _ => {}
            }
        }
    }
    
    /// Get connected peers
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        let peers = self.connected_peers.lock().await;
        peers.keys().cloned().collect()
    }
    
    /// Check if connected to a specific peer
    pub async fn is_connected(&self, peer_id: &PeerId) -> bool {
        let peers = self.connected_peers.lock().await;
        peers.contains_key(peer_id)
    }
    
    /// Add a peer as a provider for an entropy block
    pub async fn add_entropy_block_provider(&mut self, block_key: &[u8], peer_id: PeerId) -> Result<(), NativeP2PError> {
        // Note: In libp2p-kad, we don't manually add providers. 
        // Providers are discovered through the DHT when they announce themselves via start_providing
        debug!("Note: Provider {} for entropy block key {:?} should announce via start_providing", peer_id, hex::encode(block_key));
        Ok(())
    }
    
    /// Start providing an entropy block (announce that we have it)
    pub async fn start_providing_entropy_block(&mut self, block_key: &[u8]) -> Result<(), NativeP2PError> {
        let key = kad::RecordKey::new(&block_key);
        self.swarm.behaviour_mut().kademlia.start_providing(key)
            .map_err(|e| NativeP2PError::Kademlia(format!("Failed to start providing entropy block: {:?}", e)))?;
        debug!("Started providing entropy block key: {:?}", hex::encode(block_key));
        Ok(())
    }
    
    /// Stop providing an entropy block
    pub async fn stop_providing_entropy_block(&mut self, block_key: &[u8]) -> Result<(), NativeP2PError> {
        let key = kad::RecordKey::new(&block_key);
        self.swarm.behaviour_mut().kademlia.stop_providing(&key);
        debug!("Stopped providing entropy block key: {:?}", hex::encode(block_key));
        Ok(())
    }
    
    /// Get providers for an entropy block
    pub async fn get_entropy_block_providers(&mut self, block_key: &[u8]) -> Result<Vec<PeerId>, NativeP2PError> {
        let key = kad::RecordKey::new(&block_key);
        let query_id = self.swarm.behaviour_mut().kademlia.get_providers(key);
        debug!("Started provider query {:?} for entropy block key: {:?}", query_id, hex::encode(block_key));
        
        // For now, return empty vector - in a real implementation, we'd wait for the query to complete
        // and return the actual providers. This is a simplified version.
        Ok(vec![])
    }
    
    /// Add a bootstrap node for Kademlia
    pub async fn add_kademlia_bootstrap(&mut self, peer_id: PeerId, addr: Multiaddr) -> Result<(), NativeP2PError> {
        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
        debug!("Added Kademlia bootstrap node {} at {}", peer_id, addr);
        Ok(())
    }
    
    /// Bootstrap the Kademlia DHT
    pub async fn bootstrap_kademlia(&mut self) -> Result<(), NativeP2PError> {
        match self.swarm.behaviour_mut().kademlia.bootstrap() {
            Ok(query_id) => {
                debug!("Started Kademlia bootstrap with query ID: {:?}", query_id);
                Ok(())
            }
            Err(e) => {
                error!("Failed to bootstrap Kademlia: {:?}", e);
                Err(NativeP2PError::Kademlia(format!("Bootstrap failed: {:?}", e)))
            }
        }
    }
}

/// Errors that can occur in native P2P transport
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, thiserror::Error)]
pub enum NativeP2PError {
    /// Transport layer error (TCP/UDP connection issues)
    #[error("Transport error: {0}")]
    Transport(#[from] libp2p::TransportError<std::io::Error>),
    
    /// Swarm management error
    #[error("Swarm error: {0}")]
    Swarm(String),
    
    /// Failed to dial/connect to peer
    #[error("Dial error: {0}")]
    Dial(String),
    
    /// libp2p dial error
    #[error("Dial error: {0}")]
    DialError(#[from] libp2p::swarm::DialError),
    
    /// Noise protocol encryption error
    #[error("Noise error: {0}")]
    NoiseError(#[from] libp2p::noise::Error),
    
    /// Infallible error (should never occur)
    #[error("Infallible error")]
    Infallible(#[from] std::convert::Infallible),
    
    /// I/O operation error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Noise protocol error with custom message
    #[error("Noise error: {0}")]
    Noise(String),
    
    /// GossipSub publish error
    #[error("GossipSub publish error: {0}")]
    GossipSubPublish(String),
    
    /// GossipSub subscription error
    #[error("GossipSub subscription error: {0}")]
    GossipSubSubscription(String),
    
    /// GossipSub configuration error
    #[error("GossipSub configuration error: {0}")]
    GossipSubConfig(String),
    
    /// GossipSub initialization error
    #[error("GossipSub initialization error: {0}")]
    GossipSubInit(String),
    
    /// Kademlia DHT error
    #[error("Kademlia error: {0}")]
    Kademlia(String),
}

impl From<libp2p::gossipsub::SubscriptionError> for NativeP2PError {
    fn from(error: libp2p::gossipsub::SubscriptionError) -> Self {
        NativeP2PError::GossipSubSubscription(error.to_string())
    }
}

impl From<libp2p::gossipsub::PublishError> for NativeP2PError {
    fn from(error: libp2p::gossipsub::PublishError) -> Self {
        NativeP2PError::GossipSubPublish(error.to_string())
    }
}

/// Stub implementation for WASM targets
#[cfg(target_arch = "wasm32")]
pub struct NativeP2PTransport;

#[cfg(target_arch = "wasm32")]
impl NativeP2PTransport {
    pub async fn new(_keypair: Option<()>) -> Result<Self, String> {
        Err("Native P2P transport not available in WASM".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(not(target_arch = "wasm32"))]
    #[ignore = "Requires gossipsub configuration for local testing"]
    async fn test_native_p2p_creation() {
        let transport = NativeP2PTransport::new(None).await.unwrap();
        let peer_id = transport.local_peer_id();
        assert!(!peer_id.to_string().is_empty());
    }
}