//! WebSocket-based signaling client for peer discovery and swarm coordination
//! 
//! This module provides a unified signaling mechanism that works in both
//! native environments (Rust) and browsers (WASM) via WebSocket connections
//! to Cloudflare Workers.

use tokio_tungstenite::{connect_async, tungstenite::Message, WebSocketStream};
use futures_util::{SinkExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Information about a discovered peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Unique identifier for the peer
    pub peer_id: String,
    /// Public key for secure communication
    pub public_key: Vec<u8>,
    /// Capabilities and supported features of the peer
    pub capabilities: PeerCapabilities,
    /// Timestamp when the peer was last seen (Unix timestamp)
    pub last_seen: u64,
    /// Network addresses where the peer can be reached
    pub addresses: Vec<String>,
}

/// Peer capabilities and supported features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Whether the peer supports direct P2P connections
    pub supports_p2p: bool,
    /// Whether the peer supports relay connections
    pub supports_relay: bool,
    /// Whether the peer supports onion routing
    pub supports_onion_routing: bool,
    /// Maximum message size the peer can handle
    pub max_message_size: usize,
    /// List of protocols supported by the peer
    pub supported_protocols: Vec<String>,
    /// Maximum number of hops the peer supports
    pub max_hops: u32,
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            supports_p2p: true,
            supports_relay: true,
            supports_onion_routing: false,
            max_message_size: 65536,
            supported_protocols: vec!["zks/1.0".to_string()],
            max_hops: 3,
        }
    }
}

/// Signaling messages exchanged between peers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignalingMessage {
    /// Join a swarm room
    Join {
        /// Room identifier to join
        room_id: String,
        /// Peer information for the joining peer
        peer_info: PeerInfo,
    },
    /// Leave a swarm room
    Leave {
        /// Room identifier to leave
        room_id: String,
    },
    /// Discover peers in a room
    Discover {
        /// Room identifier to discover peers in
        room_id: String,
    },
    /// Response with peer list
    Peers {
        /// List of peers discovered in the room
        peers: Vec<PeerInfo>,
    },
    /// Request entropy from swarm
    EntropyRequest {
        /// Room identifier for entropy request
        room_id: String,
        /// Unique request identifier
        request_id: String,
    },
    /// Response with entropy
    EntropyResponse {
        /// Request identifier for matching responses
        request_id: String,
        /// Random entropy data
        entropy: Vec<u8>,
        /// Cryptographic signature of the entropy
        signature: Vec<u8>,
    },
    /// Error message
    Error {
        /// Error code
        code: String,
        /// Human-readable error message
        message: String,
    },
}

/// WebSocket-based signaling client
#[derive(Clone)]
pub struct SignalingClient {
    ws_stream: Arc<Mutex<WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>>,
    peer_id: String,
    is_connected: Arc<Mutex<bool>>,
}

impl SignalingClient {
    /// Connect to a signaling server
    pub async fn connect(url: &str, peer_id: String) -> Result<Self, SignalingError> {
        info!("Connecting to signaling server at {}", url);
        
        let ws_url = if url.starts_with("ws://") || url.starts_with("wss://") {
            url.to_string()
        } else {
            format!("wss://{}/signaling", url.trim_end_matches('/'))
        };
        
        let (ws_stream, _) = connect_async(&ws_url).await
            .map_err(|e| SignalingError::ConnectionFailed(format!("WebSocket connection failed: {}", e)))?;
        
        info!("Connected to signaling server");
        
        Ok(Self {
            ws_stream: Arc::new(Mutex::new(ws_stream)),
            peer_id,
            is_connected: Arc::new(Mutex::new(true)),
        })
    }
    
    /// Join a swarm room for peer discovery
    pub async fn join_room(&self, room_id: &str, capabilities: PeerCapabilities) -> Result<(), SignalingError> {
        let peer_info = PeerInfo {
            peer_id: self.peer_id.clone(),
            public_key: vec![], // Will be populated with actual key
            capabilities,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            addresses: vec![],
        };
        
        let message = SignalingMessage::Join {
            room_id: room_id.to_string(),
            peer_info,
        };
        
        self.send_message(message).await?;
        debug!("Joined room: {}", room_id);
        Ok(())
    }
    
    /// Discover peers in a room
    pub async fn discover_peers(&self, room_id: &str) -> Result<Vec<PeerInfo>, SignalingError> {
        let message = SignalingMessage::Discover {
            room_id: room_id.to_string(),
        };
        
        self.send_message(message).await?;
        
        // Wait for response
        let response = self.receive_message().await?;
        
        match response {
            SignalingMessage::Peers { peers } => {
                debug!("Discovered {} peers in room {}", peers.len(), room_id);
                Ok(peers)
            }
            SignalingMessage::Error { code, message } => {
                Err(SignalingError::ServerError(format!("{}: {}", code, message)))
            }
            _ => Err(SignalingError::UnexpectedMessage("Expected Peers response")),
        }
    }
    
    /// Request entropy from the swarm
    pub async fn get_swarm_entropy(&self, room_id: &str) -> Result<[u8; 32], SignalingError> {
        let request_id = uuid::Uuid::new_v4().to_string();
        
        let message = SignalingMessage::EntropyRequest {
            room_id: room_id.to_string(),
            request_id: request_id.clone(),
        };
        
        self.send_message(message).await?;
        
        // Wait for entropy response
        let response = self.receive_message().await?;
        
        match response {
            SignalingMessage::EntropyResponse { request_id: resp_id, entropy, .. } => {
                if resp_id != request_id {
                    return Err(SignalingError::UnexpectedMessage("Request ID mismatch"));
                }
                
                if entropy.len() != 32 {
                    return Err(SignalingError::InvalidEntropy("Entropy must be 32 bytes"));
                }
                
                let mut result = [0u8; 32];
                result.copy_from_slice(&entropy);
                Ok(result)
            }
            SignalingMessage::Error { code, message } => {
                Err(SignalingError::ServerError(format!("{}: {}", code, message)))
            }
            _ => Err(SignalingError::UnexpectedMessage("Expected EntropyResponse")),
        }
    }
    
    /// Leave a room
    pub async fn leave_room(&self, room_id: &str) -> Result<(), SignalingError> {
        let message = SignalingMessage::Leave {
            room_id: room_id.to_string(),
        };
        
        self.send_message(message).await?;
        debug!("Left room: {}", room_id);
        Ok(())
    }
    
    /// Send a signaling message
    async fn send_message(&self, message: SignalingMessage) -> Result<(), SignalingError> {
        let json = serde_json::to_string(&message)
            .map_err(|e| SignalingError::SerializationFailed(format!("Failed to serialize message: {}", e)))?;
        
        let ws_message = Message::Text(json);
        
        let mut stream = self.ws_stream.lock().await;
        stream.send(ws_message).await
            .map_err(|e| SignalingError::SendFailed(format!("Failed to send message: {}", e)))?;
        
        Ok(())
    }
    
    /// Receive a signaling message
    async fn receive_message(&self) -> Result<SignalingMessage, SignalingError> {
        let mut stream = self.ws_stream.lock().await;
        
        loop {
            match stream.try_next().await {
                Ok(Some(Message::Text(text))) => {
                    let message: SignalingMessage = serde_json::from_str(&text)
                        .map_err(|e| SignalingError::DeserializationFailed(format!("Failed to deserialize message: {}", e)))?;
                    return Ok(message);
                }
                Ok(Some(Message::Binary(_))) => {
                    // Ignore binary messages for now
                    continue;
                }
                Ok(Some(Message::Ping(_))) => {
                    // Ignore ping messages for now
                    continue;
                }
                Ok(Some(Message::Pong(_))) => {
                    // Ignore pong messages for now
                    continue;
                }
                Ok(Some(Message::Frame(_))) => {
                    // Ignore frame messages for now
                    continue;
                }
                Ok(Some(Message::Close(_))) => {
                    *self.is_connected.lock().await = false;
                    return Err(SignalingError::ConnectionClosed);
                }
                Ok(None) => {
                    *self.is_connected.lock().await = false;
                    return Err(SignalingError::ConnectionClosed);
                }
                Err(e) => {
                    return Err(SignalingError::ReceiveFailed(format!("WebSocket error: {}", e)));
                }
            }
        }
    }
    
    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.is_connected.lock().await
    }
    
    /// Close the connection
    pub async fn close(self) -> Result<(), SignalingError> {
        let message = Message::Close(None);
        let mut stream = self.ws_stream.lock().await;
        stream.send(message).await
            .map_err(|e| SignalingError::SendFailed(format!("Failed to send close message: {}", e)))?;
        Ok(())
    }
}

/// Errors that can occur during signaling
#[derive(Debug, thiserror::Error)]
pub enum SignalingError {
    /// Failed to establish connection to signaling server
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    /// Connection to signaling server was closed
    #[error("Connection closed")]
    ConnectionClosed,
    
    /// Failed to send message to signaling server
    #[error("Send failed: {0}")]
    SendFailed(String),
    
    /// Failed to receive message from signaling server
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),
    
    /// Failed to serialize message for transmission
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    
    /// Failed to deserialize received message
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
    
    /// Server returned an error response
    #[error("Server error: {0}")]
    ServerError(String),
    
    /// Received unexpected message type
    #[error("Unexpected message: {0}")]
    UnexpectedMessage(&'static str),
    
    /// Invalid entropy data received
    #[error("Invalid entropy: {0}")]
    InvalidEntropy(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    #[ignore] // Requires running signaling server
    async fn test_signaling_client() {
        let mut client = SignalingClient::connect("localhost:8080", "test-peer".to_string()).await.unwrap();
        
        let capabilities = PeerCapabilities {
            supports_p2p: true,
            supports_relay: true,
            supports_onion_routing: false,
            max_message_size: 1024 * 1024,
            supported_protocols: vec!["zks-v1".to_string()],
            max_hops: 3,
        };
        
        client.join_room("test-room", capabilities).await.unwrap();
        
        let peers = client.discover_peers("test-room").await.unwrap();
        println!("Discovered {} peers", peers.len());
        
        client.leave_room("test-room").await.unwrap();
        client.close().await.unwrap();
    }
}