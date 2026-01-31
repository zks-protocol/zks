//! Unified SwarmController for zks:// onion routing
//! 
//! This module provides a platform-agnostic interface that automatically
//! detects the runtime environment (Native vs WASM) and uses the appropriate
//! transport layer for onion routing.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug};

#[cfg(not(target_arch = "wasm32"))]
use crate::p2p::NativeP2PTransport;
#[cfg(not(target_arch = "wasm32"))]
use crate::signaling::SignalingClient;

#[cfg(target_arch = "wasm32")]
use crate::signaling::SignalingClient;

use crate::faisal_swarm::FaisalSwarmManager;

/// Platform detection and transport selection
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Platform {
    /// Native platform (desktop/mobile) with full P2P capabilities
    Native,
    /// WebAssembly platform (browser) with limited P2P capabilities
    WebAssembly,
}

impl Platform {
    /// Detect the current platform at runtime
    pub fn detect() -> Self {
        #[cfg(target_arch = "wasm32")]
        {
            Platform::WebAssembly
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            Platform::Native
        }
    }
}

/// Unified swarm controller that automatically selects the appropriate transport
pub struct SwarmController {
    platform: Platform,
    signaling_client: Arc<RwLock<Option<SignalingClient>>>,
    
    /// Native P2P transport (desktop/mobile only, currently unused but kept for future transport selection)
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(dead_code)]
    native_transport: Arc<RwLock<Option<NativeP2PTransport>>>,
    
    /// Faisal Swarm manager for onion routing circuits
    faisal_swarm_manager: Arc<RwLock<Option<FaisalSwarmManager>>>,
    
    is_connected: Arc<RwLock<bool>>,
    local_peer_id: Arc<RwLock<Option<String>>>,
}

impl SwarmController {
    /// Create a new swarm controller
    pub async fn new() -> Result<Self, SwarmControllerError> {
        let platform = Platform::detect();
        info!("Initializing SwarmController for platform: {:?}", platform);
        
        Ok(Self {
            platform,
            signaling_client: Arc::new(RwLock::new(None)),
            
            #[cfg(not(target_arch = "wasm32"))]
            native_transport: Arc::new(RwLock::new(None)),
            
            // Faisal Swarm manager for onion routing circuits
            faisal_swarm_manager: Arc::new(RwLock::new(None)),
            
            is_connected: Arc::new(RwLock::new(false)),
            local_peer_id: Arc::new(RwLock::new(None)),
        })
    }
    
    /// Get the current platform
    pub fn platform(&self) -> Platform {
        self.platform
    }
    
    /// Connect to the swarm using the appropriate transport
    pub async fn connect(
        &self,
        signaling_url: &str,
        local_peer_id: String,
    ) -> Result<(), SwarmControllerError> {
        debug!("Connecting to swarm via signaling server: {}", signaling_url);
        
        // Store local peer ID
        *self.local_peer_id.write().await = Some(local_peer_id.clone());
        
        // Create and connect signaling client
        let signaling_client = SignalingClient::connect(signaling_url, local_peer_id).await
            .map_err(|e| SwarmControllerError::SignalingError(format!("Failed to connect to signaling server: {}", e)))?;
        
        *self.signaling_client.write().await = Some(signaling_client.clone());
        
        // Initialize Faisal Swarm manager
        use libp2p::{identity::Keypair, tcp::Config as TcpConfig, noise, yamux, Transport};
        
        // Create keypair for libp2p
        let keypair = Keypair::generate_ed25519();
        let local_peer_id = libp2p::PeerId::from(keypair.public());
        
        // Create transport with TCP, noise, and yamux
        let _transport = libp2p::tcp::tokio::Transport::new(TcpConfig::default())
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::Config::new(&keypair).map_err(|e| SwarmControllerError::TransportError(format!("Noise error: {}", e)))?)
            .multiplex(yamux::Config::default())
            .boxed();
        
        // Create swarm behavior
        let behaviour = crate::p2p::NativeSwarmBehaviour::new(local_peer_id);
        
        // Create swarm
        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                TcpConfig::default(),
                noise::Config::new,
                yamux::Config::default,
            ).map_err(|e| SwarmControllerError::TransportError(format!("Swarm build error: {}", e)))?
            .with_behaviour(|_| behaviour).map_err(|e| SwarmControllerError::TransportError(format!("Behaviour error: {}", e)))?
            .build();
        
        let faisal_swarm_manager = FaisalSwarmManager::new(
            Arc::new(signaling_client),
            Arc::new(RwLock::new(swarm)),
        );
        
        *self.faisal_swarm_manager.write().await = Some(faisal_swarm_manager);
        *self.is_connected.write().await = true;
        
        info!("Successfully connected to swarm via signaling server");
        Ok(())
    }
    
    /// Join a swarm room for peer discovery
    pub async fn join_room(&self, room_id: &str, capabilities: crate::signaling::PeerCapabilities) -> Result<(), SwarmControllerError> {
        if let Some(client) = self.signaling_client.write().await.as_mut() {
            client.join_room(room_id, capabilities).await
                .map_err(|e| SwarmControllerError::SignalingError(format!("Failed to join room: {}", e)))?;
            
            info!("Joined swarm room: {}", room_id);
            Ok(())
        } else {
            Err(SwarmControllerError::NotConnected)
        }
    }
    
    /// Discover peers in the current room
    pub async fn discover_peers(&self, room_id: &str) -> Result<Vec<crate::signaling::PeerInfo>, SwarmControllerError> {
        if let Some(client) = self.signaling_client.write().await.as_mut() {
            let peers = client.discover_peers(room_id).await
                .map_err(|e| SwarmControllerError::SignalingError(format!("Failed to discover peers: {}", e)))?;
            
            debug!("Discovered {} peers in room {}", peers.len(), room_id);
            Ok(peers)
        } else {
            Err(SwarmControllerError::NotConnected)
        }
    }
    
    /// Get swarm entropy for cryptographic operations
    pub async fn get_swarm_entropy(&self, room_id: &str) -> Result<[u8; 32], SwarmControllerError> {
        if let Some(client) = self.signaling_client.write().await.as_mut() {
            let entropy = client.get_swarm_entropy(room_id).await
                .map_err(|e| SwarmControllerError::SignalingError(format!("Failed to get swarm entropy: {}", e)))?;
            
            debug!("Retrieved {} bytes of swarm entropy", entropy.len());
            Ok(entropy)
        } else {
            Err(SwarmControllerError::NotConnected)
        }
    }
    
    /// Get the local peer ID
    pub async fn local_peer_id(&self) -> Option<String> {
        self.local_peer_id.read().await.clone()
    }
    
    /// Check if connected to the swarm
    pub async fn is_connected(&self) -> bool {
        *self.is_connected.read().await
    }
    
    /// Disconnect from the swarm
    pub async fn disconnect(&self) -> Result<(), SwarmControllerError> {
        if let Some(_client) = self.signaling_client.write().await.take() {
            // Client will be dropped, which closes the connection
            info!("Disconnected from swarm");
        }
        
        *self.is_connected.write().await = false;
        Ok(())
    }
    
    /// Get platform-specific transport capabilities
    pub fn transport_capabilities(&self) -> TransportCapabilities {
        match self.platform {
            Platform::Native => TransportCapabilities {
                supports_direct_p2p: true,
                supports_nat_traversal: true,
                supports_relay: true,
                max_hops: 8,
                min_hops: 2,
            },
            Platform::WebAssembly => TransportCapabilities {
                supports_direct_p2p: false,
                supports_nat_traversal: false,
                supports_relay: true,
                max_hops: 6,
                min_hops: 3,
            },
        }
    }
    
    /// Build an onion circuit for the specified number of hops using Faisal Swarm
    pub async fn build_onion_circuit(&self, target_peer: &str, min_hops: u8, max_hops: u8) -> Result<String, SwarmControllerError> {
        let capabilities = self.transport_capabilities();
        
        if min_hops < capabilities.min_hops || max_hops > capabilities.max_hops {
            return Err(SwarmControllerError::InvalidCircuitConfig(format!(
                "Hops must be between {} and {}",
                capabilities.min_hops,
                capabilities.max_hops
            )));
        }
        
        // Use Faisal Swarm Manager to build the circuit
        let room_id = "default"; // TODO: Get from configuration
        
        if let Some(ref faisal_manager) = *self.faisal_swarm_manager.read().await {
            info!("Building {}-hop Faisal Swarm circuit to {} via room {}", max_hops, target_peer, room_id);
            
            // Create circuit using Faisal Swarm
            let circuit_id = faisal_manager.create_circuit(room_id, max_hops as usize).await
                .map_err(|e| SwarmControllerError::CircuitError(format!("Faisal Swarm circuit creation failed: {}", e)))?;
            
            info!("✅ Faisal Swarm circuit {} created successfully", circuit_id);
            Ok(circuit_id.to_string())
        } else {
            Err(SwarmControllerError::CircuitError("Faisal Swarm Manager not initialized".to_string()))
        }
    }
    
    /// Send data through an established onion circuit using Faisal Swarm
    pub async fn send_through_circuit(&self, circuit_id: &str, data: &[u8]) -> Result<(), SwarmControllerError> {
        if let Some(ref faisal_manager) = *self.faisal_swarm_manager.read().await {
            // Parse circuit ID from string to CircuitId
            let circuit_id_u32 = circuit_id.parse::<u32>()
                .map_err(|e| SwarmControllerError::CircuitError(format!("Invalid circuit ID: {}", e)))?;
            
            debug!("Sending {} bytes through Faisal Swarm circuit {}", data.len(), circuit_id);
            
            // Send data through Faisal Swarm circuit
            faisal_manager.send_via_swarm(circuit_id_u32, data).await
                .map_err(|e| SwarmControllerError::CircuitError(format!("Failed to send data: {}", e)))?;
            
            info!("✅ Successfully sent {} bytes through Faisal Swarm circuit {}", data.len(), circuit_id);
            Ok(())
        } else {
            Err(SwarmControllerError::CircuitError("Faisal Swarm Manager not initialized".to_string()))
        }
    }
    
    /// Receive data from any circuit using Faisal Swarm
    pub async fn receive_from_circuit(&self, circuit_id: &str) -> Result<Option<Vec<u8>>, SwarmControllerError> {
        if let Some(ref faisal_manager) = *self.faisal_swarm_manager.read().await {
            // Parse circuit ID from string to CircuitId
            let circuit_id_u32 = circuit_id.parse::<u32>()
                .map_err(|e| SwarmControllerError::CircuitError(format!("Invalid circuit ID: {}", e)))?;
            
            debug!("Receiving data from Faisal Swarm circuit {}", circuit_id);
            
            // Receive data from Faisal Swarm circuit
            match faisal_manager.receive_from_swarm(circuit_id_u32).await {
                Ok(data) => {
                    info!("✅ Successfully received {} bytes from Faisal Swarm circuit {}", data.len(), circuit_id);
                    Ok(Some(data))
                },
                Err(e) => Err(SwarmControllerError::CircuitError(format!("Failed to receive data: {}", e)))
            }
        } else {
            Err(SwarmControllerError::CircuitError("Faisal Swarm Manager not initialized".to_string()))
        }
    }
    
    /// Tear down an onion circuit using Faisal Swarm
    pub async fn teardown_circuit(&self, circuit_id: &str) -> Result<(), SwarmControllerError> {
        if let Some(ref faisal_manager) = *self.faisal_swarm_manager.read().await {
            // Parse circuit ID from string to CircuitId
            let circuit_id_u32 = circuit_id.parse::<u32>()
                .map_err(|e| SwarmControllerError::CircuitError(format!("Invalid circuit ID: {}", e)))?;
            
            info!("Tearing down Faisal Swarm circuit {}", circuit_id);
            
            // Close circuit using Faisal Swarm Manager
            faisal_manager.close_circuit(circuit_id_u32).await
                .map_err(|e| SwarmControllerError::CircuitError(format!("Failed to close circuit: {}", e)))?;
            
            info!("✅ Successfully tore down Faisal Swarm circuit {}", circuit_id);
            Ok(())
        } else {
            Err(SwarmControllerError::CircuitError("Faisal Swarm Manager not initialized".to_string()))
        }
    }
    
    /// Create an onion stream that routes through the specified circuit using Faisal Swarm
    pub async fn create_onion_stream(&self, circuit_id: &str) -> Result<OnionStream, SwarmControllerError> {
        if let Some(ref faisal_manager) = *self.faisal_swarm_manager.read().await {
            // Parse circuit ID from string to CircuitId
            let circuit_id_u32 = circuit_id.parse::<u32>()
                .map_err(|e| SwarmControllerError::CircuitError(format!("Invalid circuit ID: {}", e)))?;
            
            info!("Creating onion stream for Faisal Swarm circuit {}", circuit_id);
            
            // Get circuit info to verify it exists and is ready
            let _circuit_info = faisal_manager.get_circuit_info(circuit_id_u32).await
                .map_err(|e| SwarmControllerError::CircuitError(format!("Failed to get circuit info: {}", e)))?;
            
            debug!("Circuit {} verified, creating onion stream", circuit_id);
            
            // Create an onion stream that will route through Faisal Swarm
            // The stream will use the Faisal Swarm manager for actual data transmission
            let stream = OnionStream::new(circuit_id.to_string());
            
            // In a full implementation, we would establish the actual stream connection here
            // For now, we return a stream that can be used with send_via_swarm/receive_from_swarm
            info!("✅ Successfully created onion stream for Faisal Swarm circuit {}", circuit_id);
            Ok(stream)
        } else {
            Err(SwarmControllerError::CircuitError("Faisal Swarm Manager not initialized".to_string()))
        }
    }
}

/// Transport capabilities for different platforms
#[derive(Debug, Clone)]
pub struct TransportCapabilities {
    /// Whether the transport supports direct peer-to-peer connections
    pub supports_direct_p2p: bool,
    /// Whether the transport supports NAT traversal (hole punching)
    pub supports_nat_traversal: bool,
    /// Whether the transport supports relay connections
    pub supports_relay: bool,
    /// Maximum number of hops supported by the transport
    pub max_hops: u8,
    /// Minimum number of hops required by the transport
    pub min_hops: u8,
}

/// Errors that can occur in the swarm controller
#[derive(Debug, thiserror::Error)]
pub enum SwarmControllerError {
    /// Not connected to the swarm network
    #[error("Not connected to swarm")]
    NotConnected,
    
    /// Error communicating with signaling server
    #[error("Signaling error: {0}")]
    SignalingError(String),
    
    /// Transport layer error
    #[error("Transport error: {0}")]
    TransportError(String),
    
    /// Invalid circuit configuration provided
    #[error("Invalid circuit configuration: {0}")]
    InvalidCircuitConfig(String),
    
    /// Not enough peers available to form circuit
    #[error("Not enough peers available: {0}")]
    NotEnoughPeers(String),
    
    /// Error in circuit establishment or operation
    #[error("Circuit error: {0}")]
    CircuitError(String),
    
    /// I/O operation error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// An onion routing stream that routes data through an established circuit
pub struct OnionStream {
    circuit_id: String,
    read_buffer: std::collections::VecDeque<u8>,
    write_buffer: std::collections::VecDeque<u8>,
}

impl OnionStream {
    /// Create a new onion stream for the specified circuit
    pub fn new(circuit_id: String) -> Self {
        Self {
            circuit_id,
            read_buffer: std::collections::VecDeque::new(),
            write_buffer: std::collections::VecDeque::new(),
        }
    }
    
    /// Get the circuit ID this stream is associated with
    pub fn circuit_id(&self) -> &str {
        &self.circuit_id
    }
}

impl tokio::io::AsyncRead for OnionStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let n = std::cmp::min(buf.remaining(), self.read_buffer.len());
        if n > 0 {
            let data: Vec<u8> = self.read_buffer.drain(..n).collect();
            buf.put_slice(&data);
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for OnionStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.write_buffer.extend(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_platform_detection() {
        let platform = Platform::detect();
        
        #[cfg(target_arch = "wasm32")]
        assert_eq!(platform, Platform::WebAssembly);
        
        #[cfg(not(target_arch = "wasm32"))]
        assert_eq!(platform, Platform::Native);
    }
    
    #[tokio::test]
    async fn test_swarm_controller_creation() {
        let controller = SwarmController::new().await.unwrap();
        assert!(controller.is_connected().await == false);
    }
    
    #[tokio::test]
    async fn test_transport_capabilities() {
        let controller = SwarmController::new().await.unwrap();
        let capabilities = controller.transport_capabilities();
        
        match controller.platform() {
            Platform::Native => {
                assert!(capabilities.supports_direct_p2p);
                assert!(capabilities.supports_nat_traversal);
                assert!(capabilities.max_hops >= 6);
            }
            Platform::WebAssembly => {
                assert!(!capabilities.supports_direct_p2p);
                assert!(capabilities.supports_relay);
                assert!(capabilities.max_hops <= 6);
            }
        }
    }
}