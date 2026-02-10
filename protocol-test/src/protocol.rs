//! High-Level ZKS Protocol API
//!
//! This module provides a complete, production-ready API for the ZKS Protocol
//! with all components integrated:
//! - ML-KEM-1024 post-quantum key exchange (via SDK)
//! - Wasif-Vernam encryption with sequenced mode (via SDK)
//! - Message framing and protocol state management
//!
//! Uses `zks::stream::EncryptedStream` for the authenticated handshake.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};
use zks::config::ConnectionConfig;
use zks::pqcrypto::ml_dsa::MlDsaKeypair;
use zks::proto::HandshakeRole;
use zks::stream::EncryptedStream;

/// ZKS Protocol error types
#[derive(Debug)]
pub enum ProtocolError {
    Io(std::io::Error),
    Sdk(zks::error::SdkError),
    Protocol(String),
}

impl From<std::io::Error> for ProtocolError {
    fn from(e: std::io::Error) -> Self {
        ProtocolError::Io(e)
    }
}

impl From<zks::error::SdkError> for ProtocolError {
    fn from(e: zks::error::SdkError) -> Self {
        ProtocolError::Sdk(e)
    }
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProtocolError::Io(e) => write!(f, "IO error: {}", e),
            ProtocolError::Sdk(e) => write!(f, "SDK error: {}", e),
            ProtocolError::Protocol(e) => write!(f, "Protocol error: {}", e),
        }
    }
}

impl std::error::Error for ProtocolError {}

pub type Result<T> = std::result::Result<T, ProtocolError>;

/// ZKS Protocol Server
pub struct ZksProtocolServer {
    listener: TcpListener,
    signing_key: MlDsaKeypair,
}

impl ZksProtocolServer {
    /// Create a new ZKS Protocol server
    pub async fn bind(addr: &str) -> Result<Self> {
        info!("🚀 Initializing ZKS Protocol Server");
        info!("📡 Binding to: {}", addr);

        // Generate real ML-DSA-87 keypair for server identity
        let (vk, sk) = zks::sdk_crypto::ml_dsa_keypair().await?;
        let signing_key = MlDsaKeypair::from_bytes(vk.clone(), sk)
            .map_err(|e| ProtocolError::Protocol(format!("Failed to load signing key: {}", e)))?;

        let vk_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &vk);
        info!("🔑 Server Identity (ML-DSA-87 VK): {}", vk_base64);

        let listener = TcpListener::bind(addr).await?;

        Ok(Self {
            listener,
            signing_key,
        })
    }

    /// Get server public key
    pub fn public_key(&self) -> Vec<u8> {
        self.signing_key.verifying_key.clone()
    }

    /// Accept a new client connection
    pub async fn accept(&mut self) -> Result<ZksProtocolConnection> {
        let (socket, addr) = self.listener.accept().await?;
        info!("🔌 Incoming connection from: {}", addr);

        // Server role handshake with persistent signing key
        let conn =
            ZksProtocolConnection::accept_handshake(socket, self.signing_key.clone()).await?;

        info!("✅ Client {} authenticated and encrypted (via SDK)", addr);
        Ok(conn)
    }
}

/// ZKS Protocol Client
pub struct ZksProtocolClient;

impl ZksProtocolClient {
    /// Connect to a ZKS Protocol server
    pub async fn connect(
        addr: &str,
        trusted_key: Option<Vec<u8>>,
    ) -> Result<ZksProtocolConnection> {
        info!("🔌 Connecting to ZKS Protocol server: {}", addr);

        let socket = TcpStream::connect(addr).await?;
        info!("✅ TCP connection established");

        // Client role handshake
        let conn = ZksProtocolConnection::initiate_handshake(socket, trusted_key).await?;

        info!("✅ ZKS Protocol handshake complete (via SDK)");
        Ok(conn)
    }
}

/// Active ZKS Protocol connection with encryption
pub struct ZksProtocolConnection {
    stream: EncryptedStream<TcpStream>,
    peer_addr: String,
}

impl ZksProtocolConnection {
    /// Initiate handshake as client
    async fn initiate_handshake(socket: TcpStream, trusted_key: Option<Vec<u8>>) -> Result<Self> {
        debug!("📝 Starting SDK Handshake (initiator)...");

        let peer_addr = socket
            .peer_addr()
            .map_err(|e| ProtocolError::Io(e))?
            .to_string();

        let config = ConnectionConfig::default();

        // Perform SDK handshake
        // Note: For this test, we can pin the server key if provided
        let stream = EncryptedStream::handshake(
            socket,
            &config,
            false, // is_swarm
            HandshakeRole::Initiator,
            "protocol-test-room".to_string(),
            trusted_key, // Real trusted key if provided
            None,
        )
        .await?;

        Ok(Self { stream, peer_addr })
    }

    /// Accept handshake as server
    async fn accept_handshake(socket: TcpStream, signing_key: MlDsaKeypair) -> Result<Self> {
        debug!("📝 Starting SDK Handshake (responder)...");

        let peer_addr = socket
            .peer_addr()
            .map_err(|e| ProtocolError::Io(e))?
            .to_string();

        let config = ConnectionConfig::default();

        // Perform SDK handshake with our persistent signing key
        let stream = EncryptedStream::handshake(
            socket,
            &config,
            false, // is_swarm
            HandshakeRole::Responder,
            "protocol-test-room".to_string(),
            None,              // Responder doesn't need trusted key
            Some(signing_key), // Use the server's persistent identity key
        )
        .await?;

        Ok(Self { stream, peer_addr })
    }

    /// Send data
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receive data
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 4096];
        let n = self.stream.read(&mut buf).await?;
        if n == 0 {
            return Err(ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Connection closed",
            )));
        }
        buf.truncate(n);
        Ok(buf)
    }

    /// Get peer address
    pub fn peer_addr(&self) -> &str {
        &self.peer_addr
    }

    /// Close connection gracefully
    pub async fn close(mut self) -> Result<()> {
        info!("👋 Closing connection to {}", self.peer_addr);
        self.stream.shutdown().await?;
        Ok(())
    }
}
