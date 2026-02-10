use crate::error::{Result, SdkError};
use crate::identity::ZksIdentity;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

/// Configuration for a ZKS Node
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Address to bind for incoming connections
    pub bind_addr: SocketAddr,
    /// Identity (Signing Key) for this node
    pub identity: Option<Arc<ZksIdentity>>,
    /// Network name (for separation of testnets)
    pub network_name: String,
    /// Mode settings
    pub is_relay: bool,
    pub is_hidden_service: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8443".parse().unwrap(),
            identity: None,
            network_name: "zks-mainnet".to_string(),
            is_relay: true,
            is_hidden_service: false,
        }
    }
}

impl NodeConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    pub fn identity(mut self, identity: ZksIdentity) -> Self {
        self.identity = Some(Arc::new(identity));
        self
    }

    pub fn network_name(mut self, name: String) -> Self {
        self.network_name = name;
        self
    }
}

/// A ZKS Protocol Node (Relay, Client, or Exit)
pub struct ZksNode {
    config: NodeConfig,
    shutdown_tx: broadcast::Sender<()>,
}

impl ZksNode {
    /// Create a new node instance
    pub fn new(config: NodeConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            config,
            shutdown_tx,
        }
    }

    /// Start the node in the background
    pub async fn start(&self) -> Result<JoinHandle<()>> {
        let config = self.config.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        info!("🚀 ZksNode Starting on {}", config.bind_addr);
        if let Some(id) = &config.identity {
            info!("🆔 Identity Fingerprint: {}", id.fingerprint()?);
        } else {
            info!("⚠️ No identity provided - running in anonymous mode");
        }

        let listener = TcpListener::bind(config.bind_addr)
            .await
            .map_err(|e| SdkError::IoError(e))?;

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((socket, addr)) => {
                                debug!("Inbound connection from {}", addr);
                                let config_clone = config.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_connection(socket, config_clone).await {
                                        error!("Connection error: {}", e);
                                    }
                                });
                            }
                            Err(e) => error!("Accept error: {}", e),
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("🛑 Node shutting down...");
                        break;
                    }
                }
            }
        });

        Ok(task)
    }

    /// Stop the node
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }

    async fn handle_connection(mut socket: TcpStream, config: NodeConfig) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use zks_proto::handshake::{Handshake, HandshakeFinish, HandshakeInit};

        info!("🔐 Starting ZKS post-quantum handshake with peer");

        // Get node identity for handshake
        let identity = config
            .identity
            .as_ref()
            .ok_or_else(|| SdkError::ConfigError("No identity provided for handshake".into()))?;

        // Create responder handshake with node's identity
        let mut handshake = Handshake::new_responder(config.network_name.clone());

        // Read HandshakeInit (Message 1)
        let mut buf = vec![0u8; 4096]; // Large buffer for handshake messages
        let n = socket
            .read(&mut buf)
            .await
            .map_err(|e| SdkError::IoError(e))?;

        if n == 0 {
            info!("Connection closed by peer before handshake");
            return Ok(());
        }

        // Deserialize HandshakeInit message
        let init_msg: HandshakeInit = serde_json::from_slice(&buf[..n]).map_err(|e| {
            SdkError::SerializationError(format!("Failed to deserialize HandshakeInit: {}", e))
        })?;

        info!("📨 Received HandshakeInit from peer");

        // Process init message
        handshake.process_init(&init_msg).map_err(|e| {
            SdkError::HandshakeFailed(format!("Failed to process HandshakeInit: {}", e))
        })?;

        // Set signing keypair for responder
        let keypair = identity
            .to_keypair()
            .map_err(|e| SdkError::CryptoError(format!("Failed to get keypair: {}", e)))?;
        handshake.set_signing_keypair(keypair).map_err(|e| {
            SdkError::HandshakeFailed(format!("Failed to set signing keypair: {}", e))
        })?;

        // Create and send HandshakeResponse (Message 2)
        let response = handshake.create_response().map_err(|e| {
            SdkError::HandshakeFailed(format!("Failed to create HandshakeResponse: {}", e))
        })?;

        let response_bytes = serde_json::to_vec(&response).map_err(|e| {
            SdkError::SerializationError(format!("Failed to serialize HandshakeResponse: {}", e))
        })?;

        socket
            .write_all(&response_bytes)
            .await
            .map_err(|e| SdkError::IoError(e))?;
        info!("📤 Sent HandshakeResponse to peer");

        // Read HandshakeFinish (Message 3)
        let n = socket
            .read(&mut buf)
            .await
            .map_err(|e| SdkError::IoError(e))?;

        if n == 0 {
            info!("Connection closed by peer during handshake");
            return Ok(());
        }

        // Deserialize HandshakeFinish message
        let finish_msg: HandshakeFinish = serde_json::from_slice(&buf[..n]).map_err(|e| {
            SdkError::SerializationError(format!("Failed to deserialize HandshakeFinish: {}", e))
        })?;

        info!("📨 Received HandshakeFinish from peer");

        // Process finish message
        handshake.process_finish(&finish_msg).map_err(|e| {
            SdkError::HandshakeFailed(format!("Failed to process HandshakeFinish: {}", e))
        })?;

        // Handshake complete - get shared secret for session encryption
        let shared_secret = handshake.shared_secret().ok_or_else(|| {
            SdkError::HandshakeFailed("No shared secret derived from handshake".into())
        })?;

        info!("✅ Post-quantum handshake complete, session established");
        info!("🔑 Shared secret derived: {} bytes", shared_secret.len());

        // Initialize WasifVernam cipher for encrypted traffic
        let mut cipher = zks_crypt::wasif_vernam::WasifVernam::new(shared_secret)
            .map_err(|e| SdkError::CryptoError(format!("Failed to initialize cipher: {:?}", e)))?;

        // Derive base IV for responder (we're the responder in this connection)
        cipher.derive_base_iv(&shared_secret, false);

        // Enable sequenced Vernam mode for 256-bit post-quantum computational security
        cipher.enable_sequenced_vernam(shared_secret);

        info!("🔒 Encrypted session established with WasifVernam");

        // Handle encrypted traffic
        let mut buf = vec![0u8; 4096];

        loop {
            // Read encrypted message (4-byte length prefix + encrypted data)
            let mut len_buf = [0u8; 4];
            match socket.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    info!("🔌 Connection closed by peer");
                    break;
                }
                Err(e) => return Err(SdkError::IoError(e)),
            }

            let msg_len = u32::from_be_bytes(len_buf) as usize;
            if msg_len > buf.len() {
                buf.resize(msg_len, 0);
            }

            socket
                .read_exact(&mut buf[..msg_len])
                .await
                .map_err(|e| SdkError::IoError(e))?;

            // Decrypt message
            let decrypted = cipher
                .decrypt_sequenced(&buf[..msg_len])
                .map_err(|e| SdkError::CryptoError(format!("Decryption failed: {:?}", e)))?;

            info!("📨 Received encrypted message: {} bytes", decrypted.len());

            // Echo back the decrypted message (for testing)
            let encrypted_response = cipher
                .encrypt_sequenced(&decrypted)
                .map_err(|e| SdkError::CryptoError(format!("Encryption failed: {:?}", e)))?;

            let response_len = (encrypted_response.len() as u32).to_be_bytes();
            socket
                .write_all(&response_len)
                .await
                .map_err(|e| SdkError::IoError(e))?;
            socket
                .write_all(&encrypted_response)
                .await
                .map_err(|e| SdkError::IoError(e))?;

            info!(
                "📤 Sent encrypted response: {} bytes",
                encrypted_response.len()
            );
        }

        info!("🔌 Connection closed");
        Ok(())
    }
}
