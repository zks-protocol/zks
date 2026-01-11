//! Direct ZK connection implementation

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, debug, warn};

use crate::{
    config::ConnectionConfig,
    error::{Result, SdkError},
    stream::EncryptedStream,
};

/// Direct ZK connection for maximum performance
pub struct ZkConnection {
    stream: EncryptedStream<TcpStream>,
    config: ConnectionConfig,
    peer_addr: String,
}

impl ZkConnection {
    /// Connect to a peer using zk:// protocol
    /// 
    /// # Security
    /// The URL **must** contain the responder's public key for authenticated connection.
    /// Use format: `zk://host:port?key=<base64_ml_dsa_pubkey>`
    /// 
    /// This ensures post-quantum authenticated key exchange with no MITM vulnerability.
    pub async fn connect(url: String, config: ConnectionConfig) -> Result<Self> {
        Self::connect_with_url(url, config).await
    }
    
    /// Connect to a peer using zk:// protocol (internal implementation)
    async fn connect_with_url(url: String, config: ConnectionConfig) -> Result<Self> {
        // Use ZkUrl for secure parsing with mandatory key validation
        let zk_url = zks_proto::ZkUrl::parse(&url)
            .map_err(|e| SdkError::InvalidUrl(format!("URL parse error: {}", e)))?;
        
        // Security check: responder_key is mandatory (validated in ZkUrl::parse)
        let responder_key = zk_url.responder_key
            .ok_or_else(|| SdkError::CryptoError(
                "Direct connection requires responder key in URL: zk://host:port?key=<base64_pubkey>".into()
            ))?;
        
        let addr = format!("{}:{}", zk_url.host, zk_url.port);
        
        info!("Connecting to ZK peer at {} (authenticated)", addr);
        
        // Connect via TCP
        let stream = TcpStream::connect(&addr).await
            .map_err(|e| SdkError::ConnectionFailed(format!("TCP connection failed: {}", e)))?;
        
        let peer_addr = stream.peer_addr()
            .map_err(|e| SdkError::ConnectionFailed(format!("Failed to get peer address: {}", e)))?
            .to_string();
        
        debug!("TCP connection established to {}", peer_addr);
        
        // Perform post-quantum handshake with verified responder key
        let encrypted_stream = EncryptedStream::handshake(
            stream,
            &config,
            false, // Not swarm mode
            zks_proto::HandshakeRole::Initiator,
            "zk-direct".to_string(),
            Some(responder_key), // Pass the verified responder key
        ).await?;
        
        info!("🔐 ZK connection established with {} (PQ-authenticated)", peer_addr);
        
        Ok(Self {
            stream: encrypted_stream,
            config,
            peer_addr,
        })
    }

    
    /// Send data to the peer
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        debug!("Sending {} bytes to {}", data.len(), self.peer_addr);
        
        tokio::time::timeout(self.config.timeout, self.stream.write_all(data))
            .await
            .map_err(|_| SdkError::Timeout)?
            .map_err(|e| SdkError::NetworkError(e.to_string()))?;
        
        debug!("Sent {} bytes successfully", data.len());
        Ok(())
    }
    
    /// Receive data from the peer
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        debug!("Receiving data from {}", self.peer_addr);
        
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
            return Err(SdkError::InvalidInput(format!(
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
    
    /// Check if the connection is still active
    pub fn is_connected(&self) -> bool {
        // Check if the encrypted stream handshake is complete
        // This is a basic check - in production you might want to add
        // additional health checks like ping/pong or timeout validation
        self.stream.is_handshake_complete()
    }
    
    /// Gracefully close the connection
    pub async fn close(mut self) -> Result<()> {
        info!("Closing ZK connection to {}", self.peer_addr);
        
        // Send close notification
        let close_msg = b"CLOSE";
        if let Err(e) = self.send(close_msg).await {
            warn!("Failed to send close notification: {}", e);
        }
        
        // Close the stream
        self.stream.shutdown().await
            .map_err(|e| SdkError::NetworkError(e.to_string()))?;
        
        info!("ZK connection to {} closed", self.peer_addr);
        Ok(())
    }
}