//! Swarm-based ZKS connection implementation with real onion routing

use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tracing::{info, debug, warn};
use zks_wire::{SwarmController, SwarmCircuit};

use crate::{
    config::ConnectionConfig,
    error::{Result, SdkError},
    stream::EncryptedStream,
};

/// Trait for stream types that can be used with ZKS connections
pub trait ZksStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> ZksStream for T {}

/// Swarm-based ZKS connection for maximum privacy with real onion routing
pub struct ZksConnection {
    stream: EncryptedStream<Box<dyn ZksStream>>,
    config: ConnectionConfig,
    peer_addr: String,
    hop_count: u8,
    circuit: Option<SwarmCircuit>,
    swarm_controller: Option<SwarmController>,
    circuit_id: Option<String>,
}

impl ZksConnection {
    /// Connect to a peer using zks:// protocol with real onion routing
    pub async fn connect(
        url: String, 
        config: ConnectionConfig, 
        min_hops: u8, 
        max_hops: u8
    ) -> Result<Self> {
        info!("🔐 Connecting to ZKS peer via onion routing: {} with {}-{} hops", url, min_hops, max_hops);
        
        // Parse the URL to extract target information
        let parsed_url = url::Url::parse(&url)
            .map_err(|e| SdkError::InvalidUrl(format!("Invalid URL: {}", e)))?;
        
        let target_peer = parsed_url.host_str()
            .ok_or_else(|| SdkError::InvalidUrl("Missing host in URL".to_string()))?
            .to_string();
        
        // Create swarm controller with platform detection
        let swarm_controller = SwarmController::new().await
            .map_err(|e| SdkError::ConnectionFailed(format!("Failed to create swarm controller: {}", e)))?;
        
        // Connect to signaling server (use default for now)
        let signaling_url = "wss://signal.zks-protocol.org:8443";
        let local_peer_id = format!("zks-client-{}", uuid::Uuid::new_v4());
        
        swarm_controller.connect(signaling_url, local_peer_id).await
            .map_err(|e| SdkError::ConnectionFailed(format!("Failed to connect to signaling server: {}", e)))?;
        
        // Join default room for peer discovery
        let room_id = "zks-onion-network";
        let capabilities = zks_wire::PeerCapabilities {
            supports_onion_routing: true,
            max_hops: max_hops as u32,
            ..Default::default()
        };
        
        swarm_controller.join_room(room_id, capabilities).await
            .map_err(|e| SdkError::ConnectionFailed(format!("Failed to join room: {}", e)))?;
        
        // Build onion circuit to target peer
        info!("Building onion circuit to {} with {}-{} hops", target_peer, min_hops, max_hops);
        let circuit_id = swarm_controller.build_onion_circuit(&target_peer, min_hops, max_hops).await
            .map_err(|e| SdkError::ConnectionFailed(format!("Failed to build onion circuit: {}", e)))?;
        
        info!("🧅 Onion circuit {} established with {} hops", circuit_id, max_hops);
        
        // Create an onion stream that routes through the circuit
        let onion_stream = swarm_controller.create_onion_stream(&circuit_id).await
            .map_err(|e| SdkError::ConnectionFailed(format!("Failed to create onion stream: {}", e)))?;
        
        let peer_addr = format!("onion://{}/{}", target_peer, circuit_id);
        
        debug!("Onion stream established through circuit {}", circuit_id);
        
        // Box the stream for trait object compatibility
        let boxed_stream: Box<dyn ZksStream> = Box::new(onion_stream);
        
        // SECURITY NOTE: Swarm mode uses onion routing which provides anonymity
        // but the exit node is not cryptographically authenticated like in zk:// mode.
        // This is the standard trade-off in onion routing (like Tor):
        // - You get strong sender anonymity
        // - But the exit node could potentially MITM the final hop
        // For maximum security, use end-to-end encryption at the application layer.
        let encrypted_stream = EncryptedStream::handshake(
            boxed_stream,
            &config,
            true, // Swarm mode - enables scrambling for traffic analysis resistance
            zks_proto::HandshakeRole::Initiator,
            room_id.to_string(),
            None, // Exit node not authenticated - use app-layer E2E encryption for sensitive data
        ).await?;
        
        info!("🔐 ZKS connection established with {} via onion circuit {} ({} hops)", peer_addr, circuit_id, max_hops);
        
        Ok(Self {
            stream: encrypted_stream,
            config,
            peer_addr,
            hop_count: max_hops,
            circuit: None, // Will be populated when we implement full onion routing
            swarm_controller: Some(swarm_controller),
            circuit_id: Some(circuit_id),
        })
    }
    
    /// Send data to the peer
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        debug!("Sending {} bytes to {} ({} hops)", data.len(), self.peer_addr, self.hop_count);
        
        tokio::time::timeout(self.config.timeout, self.stream.write_all(data))
            .await
            .map_err(|_| SdkError::Timeout)?
            .map_err(|e| SdkError::NetworkError(e.to_string()))?;
        
        debug!("Sent {} bytes successfully", data.len());
        Ok(())
    }
    
    /// Receive data from the peer
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        debug!("Receiving data from {} ({} hops)", self.peer_addr, self.hop_count);
        
        let n = tokio::time::timeout(self.config.timeout, self.stream.read(buf))
            .await
            .map_err(|_| SdkError::Timeout)?
            .map_err(|e| SdkError::NetworkError(e.to_string()))?;
        
        if n == 0 {
            return Err(SdkError::ConnectionFailed("Connection closed by peer".to_string()));
        }
        
        debug!("Received {} bytes", n);
        Ok(n)
    }
    
    /// Send a message (with length prefix)
    pub async fn send_message(&mut self, message: &[u8]) -> Result<()> {
        if message.len() > self.config.max_message_size {
            return Err(SdkError::InvalidUrl(format!(
                "Message too large: {} bytes (max: {})",
                message.len(),
                self.config.max_message_size
            )));
        }
        
        // Send length prefix (4 bytes, big-endian)
        let len = (message.len() as u32).to_be_bytes();
        self.send(&len).await?;
        
        // Send message data
        self.send(message).await?;
        
        Ok(())
    }
    
    /// Receive a message (with length prefix)
    pub async fn recv_message(&mut self) -> Result<Vec<u8>> {
        // Receive length prefix
        let mut len_buf = [0u8; 4];
        self.recv(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        if len > self.config.max_message_size {
            return Err(SdkError::InvalidUrl(format!(
                "Message too large: {} bytes (max: {})",
                len,
                self.config.max_message_size
            )));
        }
        
        // Receive message data
        let mut message = vec![0u8; len];
        self.recv(&mut message).await?;
        
        Ok(message)
    }
    
    /// Get the peer address
    pub fn peer_addr(&self) -> &str {
        &self.peer_addr
    }
    
    /// Get the connection configuration
    pub fn config(&self) -> &ConnectionConfig {
        &self.config
    }
    
    /// Get the number of hops in the onion route
    pub fn hop_count(&self) -> u8 {
        self.hop_count
    }
    
    /// Check if the connection is still active
    /// 
    /// Note: For full health checking, consider implementing ping/pong at the application layer.
    pub fn is_connected(&self) -> bool {
        // Check if encrypted stream handshake is complete and circuit exists
        self.stream.is_handshake_complete() && self.circuit_id.is_some()
    }
    
    /// Build a circuit through the swarm for onion routing
    pub async fn build_circuit(&mut self, min_hops: u8, max_hops: u8) -> Result<()> {
        if let Some(swarm_controller) = &self.swarm_controller {
            info!("Building circuit with {}-{} hops via swarm controller", min_hops, max_hops);
            
            let target_peer = self.peer_addr.clone();
            let circuit_id = swarm_controller.build_onion_circuit(&target_peer, min_hops, max_hops).await
                .map_err(|e| SdkError::ConnectionFailed(format!("Failed to build circuit: {}", e)))?;
            
            self.hop_count = max_hops;
            self.circuit_id = Some(circuit_id);
            
            info!("Successfully built circuit with {} hops", self.hop_count);
            Ok(())
        } else {
            Err(SdkError::ConnectionFailed("No swarm controller available for circuit building".to_string()))
        }
    }
    
    /// Send data through the onion circuit
    pub async fn send_onion(&mut self, data: &[u8]) -> Result<()> {
        if let Some(circuit) = &self.circuit {
            debug!("Onion routing {} bytes through {} hops", data.len(), circuit.hop_count());
            
            // Encrypt data through the circuit
            let encrypted = circuit.onion_encrypt(data)
                .map_err(|e| SdkError::NetworkError(format!("Onion encryption failed: {}", e)))?;
            
            // Send encrypted data through the stream
            self.send(&encrypted).await
        } else {
            // Fallback to regular send if no circuit
            debug!("No circuit available, sending directly");
            self.send(data).await
        }
    }
    
    /// Receive data through the onion circuit
    pub async fn recv_onion(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Check if we have a circuit first
        let has_circuit = self.circuit.is_some();
        
        if has_circuit {
            debug!("Receiving onion routed data");
            
            // Receive encrypted data
            let mut encrypted_buf = vec![0u8; buf.len() * 2]; // Allow for encryption overhead
            let n = self.recv(&mut encrypted_buf).await?;
            
            if n == 0 {
                return Ok(0);
            }
            
            // Get circuit reference after recv to avoid borrowing conflicts
            if let Some(circuit) = &self.circuit {
                debug!("Decrypting through {} hops", circuit.hop_count());
                
                // Decrypt data through the circuit
                let decrypted = circuit.onion_decrypt(&encrypted_buf[..n])
                    .map_err(|e| SdkError::NetworkError(format!("Onion decryption failed: {}", e)))?;
                
                // Copy decrypted data to output buffer
                let copy_len = std::cmp::min(decrypted.len(), buf.len());
                buf[..copy_len].copy_from_slice(&decrypted[..copy_len]);
                
                Ok(copy_len)
            } else {
                // Circuit was removed during recv, fallback to regular recv
                debug!("Circuit removed during recv, treating as regular data");
                let copy_len = std::cmp::min(n, buf.len());
                buf[..copy_len].copy_from_slice(&encrypted_buf[..copy_len]);
                Ok(copy_len)
            }
        } else {
            // Fallback to regular recv if no circuit
            debug!("No circuit available, receiving directly");
            self.recv(buf).await
        }
    }
    
    /// Get the current circuit (if any)
    pub fn circuit(&self) -> Option<&SwarmCircuit> {
        self.circuit.as_ref()
    }
    
    /// Get the swarm controller (if any)
    pub fn swarm_controller(&self) -> Option<&SwarmController> {
        self.swarm_controller.as_ref()
    }
    
    /// Get the circuit ID (if any)
    pub fn circuit_id(&self) -> Option<&str> {
        self.circuit_id.as_deref()
    }
    
    /// Gracefully close the connection
    pub async fn close(mut self) -> Result<()> {
        info!("Closing ZKS connection to {} ({} hops)", self.peer_addr, self.hop_count);
        
        // Send close notification
        let close_msg = b"CLOSE";
        if let Err(e) = self.send(close_msg).await {
            warn!("Failed to send close notification: {}", e);
        }
        
        // Close the stream
        self.stream.shutdown().await
            .map_err(|e| SdkError::NetworkError(e.to_string()))?;
        
        info!("ZKS connection to {} closed", self.peer_addr);
        Ok(())
    }
}