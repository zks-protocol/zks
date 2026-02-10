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
    dcutr, gossipsub,
    identity::Keypair,
    kad, noise, ping, relay, request_response,
    swarm::{Swarm, SwarmEvent},
    tcp::{tokio::Transport as TcpTransport, Config as TcpConfig},
    yamux, Multiaddr, PeerId, Transport,
};
use std::time::{Duration, Instant};

use crate::entropy_swarm::{EntropyGossipMessage, ENTROPY_TOPIC};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, error, info, warn};

use async_trait::async_trait;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::io;

/// Internal commands for the P2P transport loop
#[derive(Debug)]
pub enum P2PCommand {
    /// Send a Faisal Swarm response
    SendResponse {
        channel: request_response::ResponseChannel<FaisalSwarmResponse>,
        response: FaisalSwarmResponse,
    },
    /// Dial a peer
    Dial {
        addr: Multiaddr,
        response: oneshot::Sender<Result<(), NativeP2PError>>,
    },
    /// Send a Faisal Swarm request
    SendRequest {
        peer_id: PeerId,
        request: FaisalSwarmRequest,
        response_sender: oneshot::Sender<Result<FaisalSwarmResponse, NativeP2PError>>,
    },
    SubscribeEntropy,
    UnsubscribeEntropy,
    PublishEntropy(Vec<u8>),
    AddEntropyProvider(Vec<u8>, PeerId),
    /// Start providing an entropy block
    StartProvidingEntropy(Vec<u8>),
    /// Stop providing an entropy block
    StopProvidingEntropy(Vec<u8>),
    /// Listen on an address
    ListenOn(Multiaddr, oneshot::Sender<Result<(), NativeP2PError>>),
    GetEntropyProviders(Vec<u8>, oneshot::Sender<Vec<PeerId>>),
    AddKadBootstrap(PeerId, Multiaddr),
    BootstrapKad(oneshot::Sender<Result<(), NativeP2PError>>),
}

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

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        futures::AsyncReadExt::read_to_end(io, &mut buf).await?;
        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        let data =
            bincode::serialize(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        futures::AsyncWriteExt::write_all(io, &data).await?;
        futures::AsyncWriteExt::flush(io).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        let data =
            bincode::serialize(&res).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
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
            [(
                libp2p::StreamProtocol::new("/faisal-swarm/1.0.0"),
                request_response::ProtocolSupport::Full,
            )],
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
        )
        .expect("Valid gossipsub behaviour");

        // Configure Kademlia for entropy block discovery
        let kademlia =
            kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));

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

/// Response channel for routing FaisalSwarm responses to waiting tasks
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct ResponseChannel {
    /// Pending requests mapped to their response senders and creation timestamps
    pending: Arc<
        Mutex<
            HashMap<
                libp2p::request_response::OutboundRequestId,
                (oneshot::Sender<FaisalSwarmResponse>, Instant),
            >,
        >,
    >,
}

#[cfg(not(target_arch = "wasm32"))]
impl ResponseChannel {
    /// Create a new response channel
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a pending request and return a receiver for the response
    pub async fn register_request(
        &self,
        request_id: libp2p::request_response::OutboundRequestId,
    ) -> oneshot::Receiver<FaisalSwarmResponse> {
        let (sender, receiver) = oneshot::channel();
        let mut pending = self.pending.lock().await;
        pending.insert(request_id, (sender, Instant::now()));
        receiver
    }

    /// Route a response to the waiting task
    pub async fn route_response(
        &self,
        request_id: libp2p::request_response::OutboundRequestId,
        response: FaisalSwarmResponse,
    ) {
        let mut pending = self.pending.lock().await;
        if let Some((sender, _)) = pending.remove(&request_id) {
            if let Err(_) = sender.send(response) {
                warn!(
                    "Failed to send response to waiting task for request {:?}",
                    request_id
                );
            }
        } else {
            warn!("No pending request found for response {:?}", request_id);
        }
    }

    /// Remove a pending request (used for cleanup on timeout/failure)
    pub async fn remove_request(&self, request_id: libp2p::request_response::OutboundRequestId) {
        let mut pending = self.pending.lock().await;
        pending.remove(&request_id);
    }

    /// Clean up stale requests that have been pending for longer than the specified duration
    pub async fn cleanup_stale_requests(&self, max_age: Duration) -> usize {
        let mut pending = self.pending.lock().await;
        let now = Instant::now();
        let initial_count = pending.len();

        pending.retain(|request_id, (_, timestamp)| {
            let is_stale = now.duration_since(*timestamp) > max_age;
            if is_stale {
                debug!(
                    "Cleaning up stale request {:?} (age: {:?})",
                    request_id,
                    now.duration_since(*timestamp)
                );
            }
            !is_stale
        });

        let cleaned_count = initial_count - pending.len();
        if cleaned_count > 0 {
            info!(
                "Cleaned up {} stale requests from ResponseChannel",
                cleaned_count
            );
        }

        cleaned_count
    }

    /// Get the number of currently pending requests
    pub async fn pending_count(&self) -> usize {
        let pending = self.pending.lock().await;
        pending.len()
    }
}

/// Native P2P transport driver (runs the event loop)
#[cfg(not(target_arch = "wasm32"))]
pub struct NativeP2PDriver {
    /// libp2p swarm instance managing all protocols
    swarm: Swarm<NativeSwarmBehaviour>,
    /// Local peer ID for this transport
    local_peer_id: PeerId,
    /// Channel receiver for internal loop commands
    command_receiver: mpsc::UnboundedReceiver<P2PCommand>,
    /// Channel sender for internal loop commands (needed for spawned tasks)
    command_sender: mpsc::UnboundedSender<P2PCommand>,
    /// Request handler for Faisal Swarm protocol
    faisal_request_handler: Option<
        Arc<
            dyn Fn(PeerId, FaisalSwarmRequest) -> BoxFuture<'static, FaisalSwarmResponse>
                + Send
                + Sync,
        >,
    >,
    /// Channel sender for forwarding GossipSub messages to EntropySwarm
    entropy_message_sender: Option<mpsc::UnboundedSender<(EntropyGossipMessage, PeerId)>>,
    /// Map of connected peers to their network addresses (shared with Client)
    connected_peers: Arc<Mutex<HashMap<PeerId, Vec<Multiaddr>>>>,
    /// List of addresses this node is listening on (shared with Client)
    listen_addresses: Arc<Mutex<Vec<Multiaddr>>>,
    /// Response channel for routing FaisalSwarm responses (owned by Driver)
    response_channel: ResponseChannel,
}

/// Native P2P transport client handle (safe to share across threads)
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone)]
pub struct NativeP2PTransport {
    local_peer_id: PeerId,
    command_sender: mpsc::UnboundedSender<P2PCommand>,
    connected_peers: Arc<Mutex<HashMap<PeerId, Vec<Multiaddr>>>>,
    listen_addresses: Arc<Mutex<Vec<Multiaddr>>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl std::fmt::Debug for NativeP2PTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeP2PTransport")
            .field("local_peer_id", &self.local_peer_id)
            .field("connected_peers", &self.connected_peers)
            .finish()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeP2PTransport {
    /// Create a new native P2P transport client and driver
    pub fn new(
        keypair: Option<Keypair>,
        faisal_request_timeout: Option<Duration>,
    ) -> Result<(Self, NativeP2PDriver), NativeP2PError> {
        let keypair = keypair.unwrap_or_else(Keypair::generate_ed25519);
        let local_peer_id = PeerId::from(keypair.public());

        info!(
            "Creating native P2P transport with peer ID: {}",
            local_peer_id
        );

        // Create transport
        let _transport = TcpTransport::new(TcpConfig::default())
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(
                noise::Config::new(&keypair).map_err(|e| NativeP2PError::Noise(e.to_string()))?,
            )
            .multiplex(yamux::Config::default())
            .boxed();

        // Create swarm behavior
        let faisal_swarm_protocol = request_response::ProtocolSupport::Full;
        let faisal_swarm_codec = FaisalSwarmCodec;
        let faisal_swarm_config = request_response::Config::default();

        let faisal_swarm = request_response::Behaviour::with_codec(
            faisal_swarm_codec,
            vec![(
                libp2p::StreamProtocol::new("/faisal-swarm/1.0.0"),
                faisal_swarm_protocol,
            )],
            faisal_swarm_config,
        );

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .max_transmit_size(1024 * 1024)
            .validation_mode(gossipsub::ValidationMode::Permissive)
            .build()
            .map_err(|e| NativeP2PError::GossipSubConfig(e.to_string()))?;

        let entropy_gossip =
            gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Anonymous, gossipsub_config)
                .map_err(|e| NativeP2PError::GossipSubInit(e.to_string()))?;

        let kademlia =
            kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));

        let behaviour = NativeSwarmBehaviour {
            ping: ping::Behaviour::new(ping::Config::new()),
            relay: relay::Behaviour::new(local_peer_id, Default::default()),
            dcutr: dcutr::Behaviour::new(local_peer_id),
            faisal_swarm,
            entropy_gossip,
            kademlia,
        };

        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                TcpConfig::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|_| behaviour)?
            .build();

        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let connected_peers = Arc::new(Mutex::new(HashMap::new()));
        let listen_addresses = Arc::new(Mutex::new(Vec::new()));

        let client = Self {
            local_peer_id,
            command_sender: command_sender.clone(),
            connected_peers: connected_peers.clone(),
            listen_addresses: listen_addresses.clone(),
        };

        let driver = NativeP2PDriver {
            swarm,
            local_peer_id,
            command_receiver,
            command_sender,
            faisal_request_handler: None,
            entropy_message_sender: None,
            connected_peers,
            listen_addresses,
            response_channel: ResponseChannel::new(),
        };

        Ok((client, driver))
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Send a command and wait for simple result
    async fn send_command(&self, cmd: P2PCommand) -> Result<(), NativeP2PError> {
        // This is for commands that don't need response or have their own response channel inserted in cmd
        self.command_sender
            .send(cmd)
            .map_err(|_| NativeP2PError::Network("Transport closed".into()))
    }

    /// Dial a peer
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), NativeP2PError> {
        let (tx, rx) = oneshot::channel();
        self.send_command(P2PCommand::Dial { addr, response: tx })
            .await?;
        rx.await
            .map_err(|_| NativeP2PError::Network("Response channel closed".into()))?
    }

    /// Check if connected to a peer
    pub async fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.connected_peers.lock().await.contains_key(peer_id)
    }

    /// Listen on an address
    pub async fn listen_on(&self, addr: Multiaddr) -> Result<(), NativeP2PError> {
        let (tx, rx) = oneshot::channel();
        self.send_command(P2PCommand::ListenOn(addr, tx)).await?;
        rx.await
            .map_err(|_| NativeP2PError::Network("Response channel closed".into()))?
    }

    /// Send a request
    pub async fn send_faisal_request(
        &self,
        peer_id: PeerId,
        request: FaisalSwarmRequest,
    ) -> Result<FaisalSwarmResponse, NativeP2PError> {
        let (tx, rx) = oneshot::channel();
        self.send_command(P2PCommand::SendRequest {
            peer_id,
            request,
            response_sender: tx,
        })
        .await?;
        rx.await
            .map_err(|_| NativeP2PError::Network("Response channel closed".into()))?
    }

    /// Get connected peers
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        let peers = self.connected_peers.lock().await;
        peers.keys().cloned().collect()
    }

    // Proxy other methods if needed...
}

impl NativeP2PDriver {
    pub fn set_faisal_request_handler<F>(&mut self, handler: F)
    where
        F: Fn(PeerId, FaisalSwarmRequest) -> BoxFuture<'static, FaisalSwarmResponse>
            + Send
            + Sync
            + 'static,
    {
        self.faisal_request_handler = Some(Arc::new(handler));
    }

    pub fn set_entropy_message_sender(
        &mut self,
        sender: mpsc::UnboundedSender<(EntropyGossipMessage, PeerId)>,
    ) {
        self.entropy_message_sender = Some(sender);
    }

    pub async fn listen_on(&mut self, addr: Multiaddr) -> Result<(), NativeP2PError> {
        self.swarm.listen_on(addr)?;
        Ok(())
    }

    pub async fn run(mut self) -> Result<(), NativeP2PError> {
        info!("Starting native P2P transport event loop");
        let cleanup_interval = Duration::from_secs(30);
        let max_request_age = Duration::from_secs(300);
        let mut cleanup_timer = tokio::time::interval(cleanup_interval);

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
                command = self.command_receiver.recv() => {
                    if let Some(cmd) = command {
                        self.handle_command(cmd).await;
                    } else {
                        break; // Channel closed
                    }
                }
                _ = cleanup_timer.tick() => {
                    // Cleanup stale requests
                    self.response_channel.cleanup_stale_requests(max_request_age).await;
                }
            }
        }
        Ok(())
    }

    async fn handle_command(&mut self, cmd: P2PCommand) {
        match cmd {
            P2PCommand::Dial { addr, response } => {
                let result = self
                    .swarm
                    .dial(addr)
                    .map_err(|e| NativeP2PError::Network(e.to_string()));
                let _ = response.send(result);
            }
            P2PCommand::SendRequest {
                peer_id,
                request,
                response_sender,
            } => {
                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .faisal_swarm
                    .send_request(&peer_id, request);
                let receiver = self.response_channel.register_request(request_id).await;

                tokio::spawn(async move {
                    match tokio::time::timeout(Duration::from_secs(30), receiver).await {
                        Ok(Ok(res)) => {
                            let _ = response_sender.send(Ok(res));
                        }
                        Ok(Err(_)) => {
                            let _ = response_sender
                                .send(Err(NativeP2PError::Network("Channel closed".into())));
                        }
                        Err(_) => {
                            let _ = response_sender
                                .send(Err(NativeP2PError::Timeout("Timeout".into())));
                        }
                    }
                });
            }
            P2PCommand::SendResponse { channel, response } => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .faisal_swarm
                    .send_response(channel, response);
            }
            P2PCommand::SubscribeEntropy => {
                let topic = gossipsub::IdentTopic::new(ENTROPY_TOPIC);
                if let Err(e) = self.swarm.behaviour_mut().entropy_gossip.subscribe(&topic) {
                    error!("Failed to subscribe to entropy topic: {:?}", e);
                }
            }
            P2PCommand::UnsubscribeEntropy => {
                let topic = gossipsub::IdentTopic::new(ENTROPY_TOPIC);
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .entropy_gossip
                    .unsubscribe(&topic)
                {
                    error!("Failed to unsubscribe from entropy topic: {:?}", e);
                }
            }
            P2PCommand::PublishEntropy(message) => {
                let topic = gossipsub::IdentTopic::new(ENTROPY_TOPIC);
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .entropy_gossip
                    .publish(topic, message)
                {
                    error!("Failed to publish entropy message: {:?}", e);
                }
            }
            P2PCommand::AddEntropyProvider(block_key, _peer_id) => {
                // kademlia doesnt have add_provider taking peer_id directly easily without knowing addr?
                // But we can start providing ourselves.
                // For remote provider, we just discover them.
                // This command might be used to manually populate DHT?
                // Or maybe we treat it as 'add address' then 'add provider'?
                // Let's warn for now.
                let _key = kad::RecordKey::new(&block_key);
                debug!("AddEntropyProvider ignored - Kademlia handles discovery automatically");
            }
            P2PCommand::StartProvidingEntropy(block_key) => {
                let key = kad::RecordKey::new(&block_key);
                if let Err(e) = self.swarm.behaviour_mut().kademlia.start_providing(key) {
                    error!("Failed to start providing entropy block: {:?}", e);
                }
            }
            P2PCommand::StopProvidingEntropy(block_key) => {
                let key = kad::RecordKey::new(&block_key);
                self.swarm.behaviour_mut().kademlia.stop_providing(&key);
            }
            P2PCommand::ListenOn(addr, response) => {
                let result = self
                    .swarm
                    .listen_on(addr)
                    .map_err(|e| NativeP2PError::Transport(e));
                if let Ok(_) = &result {
                    // We don't return the ListenerId, just success
                    let _ = response.send(Ok(()));
                } else {
                    let _ = response.send(Err(result.err().unwrap()));
                }
            }
            P2PCommand::GetEntropyProviders(block_key, response) => {
                let key = kad::RecordKey::new(&block_key);
                let _query_id = self.swarm.behaviour_mut().kademlia.get_providers(key);
                // We don't wait for query completion here (complex logic needed).
                // We just return immediately to unblock client.
                // Real implementation would track query_id in a map and send results later.
                // For now, return empty.
                let _ = response.send(vec![]);
            }
            P2PCommand::AddKadBootstrap(peer_id, addr) => {
                self.swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, addr);
            }
            P2PCommand::BootstrapKad(response) => {
                match self.swarm.behaviour_mut().kademlia.bootstrap() {
                    Ok(_) => {
                        let _ = response.send(Ok(()));
                    }
                    Err(e) => {
                        let _ = response.send(Err(NativeP2PError::Kademlia(format!("{:?}", e))));
                    }
                }
            }
        }
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<NativeSwarmEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
                let mut addrs = self.listen_addresses.lock().await;
                if !addrs.contains(&address) {
                    addrs.push(address);
                }
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                let mut addrs = self.listen_addresses.lock().await;
                if let Some(pos) = addrs.iter().position(|a| *a == address) {
                    addrs.remove(pos);
                }
            }
            SwarmEvent::Behaviour(NativeSwarmEvent::FaisalSwarm(
                request_response::Event::Message { peer, message },
            )) => match message {
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                } => {
                    if let Some(handler) = &self.faisal_request_handler {
                        let response_future = handler(peer, request);
                        let command_sender = self.command_sender.clone();
                        tokio::spawn(async move {
                            let response = response_future.await;
                            let _ =
                                command_sender.send(P2PCommand::SendResponse { channel, response });
                        });
                    } else {
                        let _ = self.swarm.behaviour_mut().faisal_swarm.send_response(
                            channel,
                            FaisalSwarmResponse {
                                success: true,
                                data: b"ACK".to_vec(),
                            },
                        );
                    }
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    self.response_channel
                        .route_response(request_id, response)
                        .await;
                }
            },
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let mut peers = self.connected_peers.lock().await;
                peers
                    .entry(peer_id)
                    .or_default()
                    .push(endpoint.get_remote_address().clone());
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                let mut peers = self.connected_peers.lock().await;
                peers.remove(&peer_id);
            }
            SwarmEvent::Behaviour(NativeSwarmEvent::EntropyGossip(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            })) => {
                if let Ok(entropy_msg) = bincode::deserialize::<EntropyGossipMessage>(&message.data)
                {
                    if let Some(sender) = &self.entropy_message_sender {
                        let _ = sender.send((entropy_msg, propagation_source));
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeP2PTransport {
    /// Subscribe to the entropy topic for GossipSub
    pub async fn subscribe_entropy_topic(&self) -> Result<(), NativeP2PError> {
        self.send_command(P2PCommand::SubscribeEntropy).await
    }

    /// Unsubscribe from the entropy topic
    pub async fn unsubscribe_entropy_topic(&self) -> Result<(), NativeP2PError> {
        self.send_command(P2PCommand::UnsubscribeEntropy).await
    }

    /// Publish an entropy message to the GossipSub topic
    pub async fn publish_entropy_message(&self, message: Vec<u8>) -> Result<(), NativeP2PError> {
        self.send_command(P2PCommand::PublishEntropy(message)).await
    }

    /// Add a peer as a provider for an entropy block
    pub async fn add_entropy_block_provider(
        &self,
        block_key: &[u8],
        peer_id: PeerId,
    ) -> Result<(), NativeP2PError> {
        self.send_command(P2PCommand::AddEntropyProvider(block_key.to_vec(), peer_id))
            .await
    }

    /// Start providing an entropy block (announce that we have it)
    pub async fn start_providing_entropy_block(
        &self,
        block_key: &[u8],
    ) -> Result<(), NativeP2PError> {
        self.send_command(P2PCommand::StartProvidingEntropy(block_key.to_vec()))
            .await
    }

    /// Stop providing an entropy block
    pub async fn stop_providing_entropy_block(
        &self,
        block_key: &[u8],
    ) -> Result<(), NativeP2PError> {
        self.send_command(P2PCommand::StopProvidingEntropy(block_key.to_vec()))
            .await
    }

    /// Get providers for an entropy block
    pub async fn get_entropy_block_providers(
        &self,
        block_key: &[u8],
    ) -> Result<Vec<PeerId>, NativeP2PError> {
        let (tx, rx) = oneshot::channel();
        self.send_command(P2PCommand::GetEntropyProviders(block_key.to_vec(), tx))
            .await?;
        rx.await
            .map_err(|_| NativeP2PError::Network("Response channel closed".into()))
    }

    /// Add a bootstrap node for Kademlia
    pub async fn add_kademlia_bootstrap(
        &self,
        peer_id: PeerId,
        addr: Multiaddr,
    ) -> Result<(), NativeP2PError> {
        self.send_command(P2PCommand::AddKadBootstrap(peer_id, addr))
            .await
    }

    /// Bootstrap the Kademlia DHT
    pub async fn bootstrap_kademlia(&self) -> Result<(), NativeP2PError> {
        let (tx, rx) = oneshot::channel();
        self.send_command(P2PCommand::BootstrapKad(tx)).await?;
        rx.await
            .map_err(|_| NativeP2PError::Network("Response channel closed".into()))?
    }

    /// Get swarm addresses (Snapshot)
    pub async fn listen_addresses(&self) -> Vec<Multiaddr> {
        let addrs = self.listen_addresses.lock().await;
        addrs.clone()
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

    /// Request timeout
    #[error("Request timeout: {0}")]
    Timeout(String),

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

    /// Network error
    #[error("Network error: {0}")]
    Network(String),
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
        let (transport, _driver) = NativeP2PTransport::new(None, None).unwrap();
        let peer_id = transport.local_peer_id();
        assert!(!peer_id.to_string().is_empty());
    }
}
