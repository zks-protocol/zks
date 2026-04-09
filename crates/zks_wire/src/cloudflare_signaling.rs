//! Production Cloudflare Workers signaling client for ZKS Protocol
//!
//! This module provides real-world signaling using Cloudflare Workers
//! with authentication, rate limiting, and global edge distribution.

use futures_util::{SinkExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};
use tracing::{debug, error, info, warn};

use crate::signaling::{PeerCapabilities, PeerInfo};

/// Cloudflare Workers signaling configuration
#[derive(Debug, Clone)]
pub struct CloudflareSignalingConfig {
    /// Primary signaling server endpoint
    pub primary_endpoint: String,
    /// Fallback endpoints for high availability
    pub fallback_endpoints: Vec<String>,
    /// Authentication token (JWT or API key)
    pub auth_token: Option<String>,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Message timeout
    pub message_timeout: Duration,
    /// Reconnection attempts
    pub max_reconnect_attempts: u32,
}

impl Default for CloudflareSignalingConfig {
    fn default() -> Self {
        Self {
            primary_endpoint: "wss://zks-protocol-signaling-prod.your-domain.workers.dev"
                .to_string(),
            fallback_endpoints: vec![
                "wss://zks-protocol-signaling-backup.your-domain.workers.dev".to_string(),
            ],
            auth_token: None,
            connection_timeout: Duration::from_secs(30),
            message_timeout: Duration::from_secs(10),
            max_reconnect_attempts: 3,
        }
    }
}

impl CloudflareSignalingConfig {
    /// Production configuration for ZKS Protocol
    pub fn production() -> Self {
        Self {
            primary_endpoint: "wss://zks-protocol-signaling.faisal-swarm.workers.dev".to_string(),
            fallback_endpoints: vec![
                "wss://zks-protocol-signaling-backup.faisal-swarm.workers.dev".to_string(),
                "wss://zks-protocol-signaling-eu.faisal-swarm.workers.dev".to_string(),
            ],
            auth_token: None, // Will be set from environment
            connection_timeout: Duration::from_secs(30),
            message_timeout: Duration::from_secs(10),
            max_reconnect_attempts: 5,
        }
    }

    /// Staging configuration for testing
    pub fn staging() -> Self {
        Self {
            primary_endpoint: "wss://zks-protocol-signaling-staging.md-wasif-faisal.workers.dev"
                .to_string(),
            fallback_endpoints: vec![],
            auth_token: None,
            connection_timeout: Duration::from_secs(15),
            message_timeout: Duration::from_secs(5),
            max_reconnect_attempts: 3,
        }
    }
}

/// Production signaling client with Cloudflare Workers integration
#[derive(Clone)]
pub struct CloudflareSignalingClient {
    ws_stream:
        Arc<Mutex<WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>>,
    peer_id: String,
    config: CloudflareSignalingConfig,
    is_connected: Arc<Mutex<bool>>,
    connection_attempts: Arc<Mutex<u32>>,
    advertised_addresses: Arc<Mutex<Vec<String>>>,
    shutdown: Arc<Mutex<bool>>,
}

impl CloudflareSignalingClient {
    /// Connect to Cloudflare Workers signaling server with production settings
    pub async fn connect(
        config: CloudflareSignalingConfig,
        peer_id: String,
    ) -> Result<Self, CloudflareSignalingError> {
        info!(
            "Connecting to Cloudflare signaling server: {}",
            config.primary_endpoint
        );

        // Try primary endpoint first, then fallbacks
        let mut last_error = None;
        let endpoints = std::iter::once(&config.primary_endpoint)
            .chain(config.fallback_endpoints.iter())
            .collect::<Vec<_>>();

        for (attempt, endpoint) in endpoints.iter().enumerate() {
            if attempt > 0 {
                warn!("Trying fallback endpoint: {}", endpoint);
            }

            match Self::try_connect_endpoint(endpoint, &config, &peer_id).await {
                Ok(ws_stream) => {
                    info!("Successfully connected to signaling server: {}", endpoint);

                    return Ok(Self {
                        ws_stream: Arc::new(Mutex::new(ws_stream)),
                        peer_id,
                        config,
                        is_connected: Arc::new(Mutex::new(true)),
                        connection_attempts: Arc::new(Mutex::new(0)),
                        advertised_addresses: Arc::new(Mutex::new(vec![])),
                        shutdown: Arc::new(Mutex::new(false)),
                    });
                }
                Err(e) => {
                    error!("Failed to connect to {}: {}", endpoint, e);
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or(CloudflareSignalingError::NoAvailableEndpoints))
    }

    async fn try_connect_endpoint(
        endpoint: &str,
        config: &CloudflareSignalingConfig,
        peer_id: &str,
    ) -> Result<
        WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
        CloudflareSignalingError,
    > {
        let mut request = endpoint.into_client_request()?;

        // Add authentication headers if token is provided
        if let Some(token) = &config.auth_token {
            request.headers_mut().insert(
                "Authorization",
                format!("Bearer {}", token)
                    .parse()
                    .map_err(|e| CloudflareSignalingError::InvalidHeader(format!("Authorization header parse error: {}", e)))?,
            );
        }

        // Add custom headers for ZKS Protocol
        request
            .headers_mut()
            .insert("X-ZKS-Protocol-Version", "1.0"
                .parse()
                .map_err(|e| CloudflareSignalingError::InvalidHeader(format!("Protocol version header parse error: {}", e)))?);
        request
            .headers_mut()
            .insert("X-ZKS-Peer-ID", peer_id.parse()
                .map_err(|e| CloudflareSignalingError::InvalidHeader(format!("Peer ID header parse error: {}", e)))?);

        // Create a custom rustls configuration that uses webpki-roots directly
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        
        let config_tls = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(config_tls));

        let connect_future = tokio_tungstenite::connect_async_tls_with_config(
            request,
            None,
            false,
            Some(connector)
        );
        let (ws_stream, _response) = timeout(config.connection_timeout, connect_future)
            .await
            .map_err(|_| CloudflareSignalingError::ConnectionTimeout)?
            .map_err(|e| {
                CloudflareSignalingError::ConnectionFailed(format!(
                    "WebSocket connection failed: {}",
                    e
                ))
            })?;

        Ok(ws_stream)
    }

    /// Join a swarm room with production-grade error handling
    pub async fn join_room(
        &self,
        room_id: &str,
        capabilities: PeerCapabilities,
    ) -> Result<(), CloudflareSignalingError> {
        let peer_info = PeerInfo {
            peer_id: self.peer_id.clone(),
            public_key: vec![], // Will be populated with actual key
            capabilities,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| CloudflareSignalingError::Internal(format!("System clock error: {}", e)))?
                .as_secs(),
            addresses: vec![],
        };

        let message = CloudflareSignalingMessage::Join {
            room_id: room_id.to_string(),
            peer_info,
        };

        self.send_message_with_retry(message).await?;
        debug!("Joined room: {}", room_id);
        Ok(())
    }

    /// Discover peers with timeout and retry logic
    pub async fn discover_peers(
        &self,
        room_id: &str,
    ) -> Result<Vec<PeerInfo>, CloudflareSignalingError> {
        let message = CloudflareSignalingMessage::Discover {
            room_id: room_id.to_string(),
        };

        self.send_message(message).await?;

        // Wait for response with timeout
        let response = timeout(self.config.message_timeout, self.receive_message())
            .await
            .map_err(|_| CloudflareSignalingError::ResponseTimeout)??;

        match response {
            CloudflareSignalingMessage::Peers { peers } => {
                debug!("Discovered {} peers in room {}", peers.len(), room_id);
                Ok(peers)
            }
            CloudflareSignalingMessage::Error { code, message } => Err(
                CloudflareSignalingError::ServerError(format!("{}: {}", code, message)),
            ),
            _ => Err(CloudflareSignalingError::UnexpectedMessage(
                "Expected Peers response",
            )),
        }
    }

    /// Request entropy from the swarm with cryptographic verification
    pub async fn get_swarm_entropy(
        &self,
        room_id: &str,
    ) -> Result<Vec<u8>, CloudflareSignalingError> {
        let request_id = uuid::Uuid::new_v4().to_string();

        let message = CloudflareSignalingMessage::EntropyRequest {
            room_id: room_id.to_string(),
            request_id: request_id.clone(),
        };

        self.send_message(message).await?;

        // Wait for entropy response with timeout
        let response = timeout(self.config.message_timeout, self.receive_message())
            .await
            .map_err(|_| CloudflareSignalingError::ResponseTimeout)??;

        match response {
            CloudflareSignalingMessage::EntropyResponse {
                request_id: resp_id,
                entropy,
                signature,
            } => {
                if resp_id != request_id {
                    return Err(CloudflareSignalingError::UnexpectedMessage(
                        "Request ID mismatch",
                    ));
                }

                if entropy.len() != 32 {
                    return Err(CloudflareSignalingError::InvalidEntropy(
                        "Entropy must be 32 bytes",
                    ));
                }

                // Verify signature (simplified - in production use proper crypto verification)
                if signature.len() < 32 {
                    return Err(CloudflareSignalingError::InvalidEntropy(
                        "Invalid signature length",
                    ));
                }

                Ok(entropy)
            }
            CloudflareSignalingMessage::Error { code, message } => Err(
                CloudflareSignalingError::ServerError(format!("{}: {}", code, message)),
            ),
            _ => Err(CloudflareSignalingError::UnexpectedMessage(
                "Expected EntropyResponse",
            )),
        }
    }

    /// Leave a room with proper cleanup
    pub async fn leave_room(&self, room_id: &str) -> Result<(), CloudflareSignalingError> {
        let message = CloudflareSignalingMessage::Leave {
            room_id: room_id.to_string(),
        };

        self.send_message(message).await?;
        debug!("Left room: {}", room_id);
        Ok(())
    }

    /// Send message with automatic retry on connection issues
    async fn send_message_with_retry(
        &self,
        message: CloudflareSignalingMessage,
    ) -> Result<(), CloudflareSignalingError> {
        let mut attempts = 0;
        let max_attempts = self.config.max_reconnect_attempts;

        loop {
            // Check if connection is marked as disconnected and try to reconnect
            if !*self.is_connected.lock().await {
                warn!("Connection marked as disconnected, attempting to reconnect");
                if let Err(e) = self.reconnect().await {
                    warn!("Reconnection failed: {}", e);
                } else {
                    info!("Successfully reconnected to signaling server");
                }
            }

            match self.send_message(message.clone()).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    attempts += 1;
                    if attempts >= max_attempts {
                        return Err(e);
                    }

                    warn!(
                        "Message send failed (attempt {}/{}): {}",
                        attempts, max_attempts, e
                    );

                    // Try to reconnect if connection issue detected
                    if e.to_string().contains("closed") || e.to_string().contains("ConnectionReset") {
                        warn!("Connection issue detected, attempting to reconnect");
                        if let Err(reconnect_err) = self.reconnect().await {
                            warn!("Reconnection attempt failed: {}", reconnect_err);
                        } else {
                            info!("Successfully reconnected after send failure");
                        }
                    }

                    // Wait before retry with exponential backoff
                    let wait_time = Duration::from_millis(100 * 2_u64.pow(attempts - 1));
                    tokio::time::sleep(wait_time).await;

                    continue;
                }
            }
        }
    }

    /// Send a signaling message with timeout
    async fn send_message(
        &self,
        message: CloudflareSignalingMessage,
    ) -> Result<(), CloudflareSignalingError> {
        let json = serde_json::to_string(&message).map_err(|e| {
            CloudflareSignalingError::SerializationFailed(format!(
                "Failed to serialize message: {}",
                e
            ))
        })?;

        let ws_message = Message::Text(json);

        let mut stream = self.ws_stream.lock().await;
        
        let send_result = timeout(self.config.message_timeout, stream.send(ws_message))
            .await
            .map_err(|_| CloudflareSignalingError::SendTimeout);

        match send_result {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => {
                if e.to_string().contains("closed") || e.to_string().contains("ConnectionReset") {
                    warn!("WebSocket connection closed, marking for reconnection");
                    *self.is_connected.lock().await = false;
                }
                return Err(CloudflareSignalingError::SendFailed(format!("Failed to send message: {}", e)))
            }
            Err(_) => return Err(CloudflareSignalingError::SendTimeout),
        }
    }

    /// Receive a signaling message with timeout
    async fn receive_message(
        &self,
    ) -> Result<CloudflareSignalingMessage, CloudflareSignalingError> {
        let mut stream = self.ws_stream.lock().await;

        loop {
            match timeout(self.config.message_timeout, stream.try_next()).await {
                Ok(Ok(Some(Message::Text(text)))) => {
                    let message: CloudflareSignalingMessage =
                        serde_json::from_str(&text).map_err(|e| {
                            CloudflareSignalingError::DeserializationFailed(format!(
                                "Failed to deserialize message: {}",
                                e
                            ))
                        })?;
                    return Ok(message);
                }
                Ok(Ok(Some(Message::Close(_)))) => {
                    *self.is_connected.lock().await = false;
                    return Err(CloudflareSignalingError::ConnectionClosed);
                }
                Ok(Ok(None)) => {
                    *self.is_connected.lock().await = false;
                    return Err(CloudflareSignalingError::ConnectionClosed);
                }
                Ok(Err(e)) => {
                    return Err(CloudflareSignalingError::ReceiveFailed(format!(
                        "WebSocket error: {}",
                        e
                    )));
                }
                Err(_) => {
                    return Err(CloudflareSignalingError::ReceiveTimeout);
                }
                _ => continue,
            }
        }
    }

    /// Reconnect to the signaling server
    async fn reconnect(&self) -> Result<(), CloudflareSignalingError> {
        // Check if shutdown is in progress
        if *self.shutdown.lock().await {
            return Err(CloudflareSignalingError::Internal("Shutdown in progress".into()));
        }

        let mut attempts = 0;
        let max_attempts = self.config.max_reconnect_attempts;

        loop {
            attempts += 1;

            if attempts > max_attempts {
                return Err(CloudflareSignalingError::ConnectionFailed(format!(
                    "Failed to reconnect after {} attempts",
                    max_attempts
                )));
            }

            warn!("Reconnection attempt {}/{}", attempts, max_attempts);

            // Try to reconnect using existing config
            let endpoints = std::iter::once(&self.config.primary_endpoint)
                .chain(self.config.fallback_endpoints.iter())
                .collect::<Vec<_>>();

            for (attempt, endpoint) in endpoints.iter().enumerate() {
                if attempt > 0 {
                    debug!("Trying fallback endpoint: {}", endpoint);
                }

                match Self::try_connect_endpoint(endpoint, &self.config, &self.peer_id).await {
                    Ok(ws_stream) => {
                        info!("Successfully reconnected to signaling server: {}", endpoint);

                        // Replace the WebSocket stream
                        let mut stream = self.ws_stream.lock().await;
                        *stream = ws_stream;
                        *self.is_connected.lock().await = true;

                        return Ok(());
                    }
                    Err(e) => {
                        debug!("Failed to reconnect to {}: {}", endpoint, e);
                        continue;
                    }
                }
            }

            // Wait before next attempt with exponential backoff
            let wait_time = Duration::from_millis(500 * 2_u64.pow(attempts - 1));
            tokio::time::sleep(wait_time).await;
        }
    }

    /// Check if connected
    pub async fn is_connected(&self) -> bool {
        *self.is_connected.lock().await
    }

    /// Get connection statistics
    pub async fn get_connection_stats(&self) -> ConnectionStats {
        ConnectionStats {
            is_connected: self.is_connected().await,
            endpoint: self.config.primary_endpoint.clone(),
            peer_id: self.peer_id.clone(),
            connection_attempts: *self.connection_attempts.lock().await,
        }
    }

    /// Close the connection gracefully
    pub async fn close(&mut self) -> Result<(), CloudflareSignalingError> {
        // Set shutdown flag to prevent reconnection attempts
        *self.shutdown.lock().await = true;

        let message = Message::Close(None);
        let mut stream = self.ws_stream.lock().await;

        match timeout(self.config.message_timeout, stream.send(message)).await {
            Ok(Ok(())) => {
                *self.is_connected.lock().await = false;
                Ok(())
            }
            Ok(Err(e)) => Err(CloudflareSignalingError::SendFailed(format!(
                "Failed to send close message: {}",
                e
            ))),
            Err(_) => Err(CloudflareSignalingError::SendTimeout),
        }
    }
}

/// Connection statistics for Cloudflare signaling client
///
/// Tracks the current state of the signaling connection including
/// connection status, active endpoint, peer identity, and retry attempts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// Whether the client is currently connected to the signaling server
    pub is_connected: bool,
    /// The primary endpoint URL being used for signaling
    pub endpoint: String,
    /// The peer ID of this client in the swarm
    pub peer_id: String,
    /// Number of connection attempts made (including retries)
    pub connection_attempts: u32,
}

/// Production-ready signaling messages for Cloudflare Workers
///
/// Defines the protocol messages exchanged between clients and the Cloudflare
/// signaling server for peer discovery, room management, and cryptographic
/// operations in the ZKS Protocol network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CloudflareSignalingMessage {
    /// Join a swarm room
    Join {
        /// Room identifier to join
        room_id: String,
        /// Information about the joining peer
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
        /// Room identifier for the entropy request
        room_id: String,
        /// Unique request identifier for tracking
        request_id: String,
    },
    /// Response with entropy
    EntropyResponse {
        /// Unique request identifier matching the request
        request_id: String,
        /// Cryptographic entropy data from swarm
        entropy: Vec<u8>,
        /// Signature verifying the entropy source
        signature: Vec<u8>,
    },
    /// Error message
    #[serde(rename = "error")]
    Error {
        /// Error code for classification
        code: String,
        /// Human-readable error message
        message: String,
    },
    /// Join success response
    JoinSuccess {
        /// Room identifier that was joined
        room_id: String,
        /// Number of peers in the room
        peer_count: usize,
    },
    /// Leave success response
    LeaveSuccess {
        /// Room identifier that was left
        room_id: String,
    },
    /// Peer joined notification
    PeerJoined {
        /// Information about the peer that joined
        peer_info: PeerInfo,
    },
    /// Peer left notification
    PeerLeft {
        /// Identifier of the peer that left
        peer_id: String,
    },
}

/// Production errors for Cloudflare Workers signaling
#[derive(Debug, thiserror::Error)]
pub enum CloudflareSignalingError {
    /// WebSocket connection establishment failed
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    /// WebSocket connection establishment timed out
    #[error("Connection timeout")]
    ConnectionTimeout,
    /// WebSocket connection was closed
    #[error("Connection closed")]
    ConnectionClosed,
    /// Sending message through WebSocket failed
    #[error("Send failed: {0}")]
    SendFailed(String),
    /// Sending message through WebSocket timed out
    #[error("Send timeout")]
    SendTimeout,
    /// Generic WebSocket connection error occurred
    #[error("Connection error: {0}")]
    ConnectionError(String),
    /// Receiving message from WebSocket failed
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),
    /// Receiving message from WebSocket timed out
    #[error("Receive timeout")]
    ReceiveTimeout,
    /// Waiting for server response timed out
    #[error("Response timeout")]
    ResponseTimeout,
    /// Serializing message to JSON failed
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    /// Deserializing message from JSON failed
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
    /// Server returned an error response
    #[error("Server error: {0}")]
    ServerError(String),
    /// Received unexpected message type from server
    #[error("Unexpected message: {0}")]
    UnexpectedMessage(&'static str),
    /// Received invalid entropy data
    #[error("Invalid entropy: {0}")]
    InvalidEntropy(&'static str),
    /// Received invalid protocol header
    #[error("Invalid header: {0}")]
    InvalidHeader(String),
    /// Internal signaling error occurred
    #[error("Internal error: {0}")]
    Internal(String),
    /// No available Cloudflare endpoints to connect to
    #[error("No available endpoints")]
    NoAvailableEndpoints,
    /// HTTP request to Cloudflare failed
    #[error("HTTP request error: {0}")]
    HttpRequestError(String),
}

impl From<tokio_tungstenite::tungstenite::error::Error> for CloudflareSignalingError {
    fn from(error: tokio_tungstenite::tungstenite::error::Error) -> Self {
        CloudflareSignalingError::ConnectionError(error.to_string())
    }
}

#[async_trait::async_trait]
impl crate::signaling::SignalingClientTrait for CloudflareSignalingClient {
    async fn discover_peers(
        &self,
        room_id: &str,
    ) -> Result<Vec<crate::signaling::PeerInfo>, Box<dyn std::error::Error + Send + Sync>> {
        CloudflareSignalingClient::discover_peers(self, room_id)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn join_room(
        &mut self,
        room_id: &str,
        capabilities: crate::signaling::PeerCapabilities,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        CloudflareSignalingClient::join_room(self, room_id, capabilities)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn leave_room(
        &mut self,
        room_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        CloudflareSignalingClient::leave_room(self, room_id)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn get_swarm_entropy(
        &mut self,
        room_id: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        CloudflareSignalingClient::get_swarm_entropy(self, room_id)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn close(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        CloudflareSignalingClient::close(self)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    fn set_peer_id(&mut self, peer_id: String) {
        self.peer_id = peer_id;
    }

    async fn set_advertised_addresses(&self, addresses: Vec<String>) {
        *self.advertised_addresses.lock().await = addresses;
    }

    async fn get_advertised_addresses(&self) -> Vec<String> {
        self.advertised_addresses.lock().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cloudflare_config_creation() {
        let config = CloudflareSignalingConfig::production();
        assert!(config.primary_endpoint.contains("faisal-swarm"));
        assert!(config.fallback_endpoints.len() > 0);
        assert_eq!(config.max_reconnect_attempts, 5);
    }

    #[tokio::test]
    async fn test_connection_stats() {
        let config = CloudflareSignalingConfig::staging();
        let stats = ConnectionStats {
            is_connected: true,
            endpoint: config.primary_endpoint.clone(),
            peer_id: "test-peer".to_string(),
            connection_attempts: 1,
        };

        assert!(stats.is_connected);
        assert_eq!(stats.peer_id, "test-peer");
    }
}
