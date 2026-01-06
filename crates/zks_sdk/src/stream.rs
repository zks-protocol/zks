//! Encrypted stream implementation

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, AsyncWriteExt, AsyncReadExt};
use bytes::BytesMut;
use tracing::{debug, trace};
use zks_crypt::wasif_vernam::WasifVernam;
use zks_proto::{Handshake, HandshakeRole, handshake::{HandshakeInit, HandshakeResponse, HandshakeFinish}};
use zks_pqcrypto::ml_dsa::MlDsaKeypair;
use zks_wire::{WireMessage, MessageType};
use bincode;

use crate::{
    config::ConnectionConfig,
    error::{Result, SdkError},
};

/// Encrypted stream that wraps an inner stream with post-quantum encryption
pub struct EncryptedStream<S> {
    inner: S,
    read_buf: BytesMut,
    write_buf: BytesMut,
    is_handshake_complete: bool,
    cipher: Option<WasifVernam>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> EncryptedStream<S> {
    /// Create a new encrypted stream with proper post-quantum handshake
    /// 
    /// This implements the full 3-message ZK Protocol handshake:
    /// 1. Initiator -> Responder: HandshakeInit (ephemeral key + nonce)
    /// 2. Responder -> Initiator: HandshakeResponse (ephemeral key + ciphertext + signature)
    /// 3. Initiator -> Responder: HandshakeFinish (confirmation)
    pub async fn handshake(
        mut inner: S,
        config: &ConnectionConfig,
        is_swarm: bool,
        role: HandshakeRole,
        room_id: String,
        trusted_responder_key: Option<Vec<u8>>, // Required for initiator, None for responder
    ) -> Result<Self> {
        debug!("Starting encrypted stream handshake (role: {:?}, swarm: {})", role, is_swarm);
        
        // Create handshake based on role
        let mut handshake = match role {
            HandshakeRole::Initiator => {
                if trusted_responder_key.is_none() {
                    return Err(SdkError::CryptoError("Initiator requires trusted responder key".into()));
                }
                Handshake::new_initiator(room_id, trusted_responder_key.unwrap())?
            }
            HandshakeRole::Responder => {
                Handshake::new_responder(room_id)
            }
        };
        
        // Perform the 3-message handshake
        let shared_secret = match role {
            HandshakeRole::Initiator => {
                // Message 1: Send HandshakeInit
                let init = handshake.create_init()?;
                let init_payload = bincode::serialize(&init)
                    .map_err(|e| SdkError::CryptoError(format!("Failed to serialize init: {}", e).into()))?;
                let init_msg = WireMessage::new(MessageType::HandshakeInit, 1, init_payload.into());
                inner.write_all(&init_msg.to_bytes()?).await
                    .map_err(|e| SdkError::NetworkError(format!("Failed to send init: {}", e)))?;
                inner.flush().await
                    .map_err(|e| SdkError::NetworkError(format!("Failed to flush init: {}", e)))?;
                
                // Message 2: Receive HandshakeResponse
                let response_bytes = Self::read_wire_message(&mut inner).await?;
                let response_msg = WireMessage::from_bytes(response_bytes.into())?;
                let response: HandshakeResponse = bincode::deserialize(&response_msg.payload)
                    .map_err(|e| SdkError::CryptoError(format!("Failed to deserialize response: {}", e).into()))?;
                handshake.process_response(&response)?;
                
                // Message 3: Send HandshakeFinish
                let finish = handshake.create_finish()?;
                let finish_payload = bincode::serialize(&finish)
                    .map_err(|e| SdkError::CryptoError(format!("Failed to serialize finish: {}", e).into()))?;
                let finish_msg = WireMessage::new(MessageType::HandshakeFinish, 2, finish_payload.into());
                inner.write_all(&finish_msg.to_bytes()?).await
                    .map_err(|e| SdkError::NetworkError(format!("Failed to send finish: {}", e)))?;
                inner.flush().await
                    .map_err(|e| SdkError::NetworkError(format!("Failed to flush finish: {}", e)))?;
                
                handshake.shared_secret().ok_or_else(|| SdkError::CryptoError("No shared secret".into()))?
            }
            HandshakeRole::Responder => {
                // Message 1: Receive HandshakeInit
                let init_bytes = Self::read_wire_message(&mut inner).await?;
                let init_msg = WireMessage::from_bytes(init_bytes.into())?;
                let init: HandshakeInit = bincode::deserialize(&init_msg.payload)
                    .map_err(|e| SdkError::CryptoError(format!("Failed to deserialize init: {}", e).into()))?;
                handshake.process_init(&init)?;
                
                // Set signing keypair for responder
                let signing_keypair = crate::crypto::ml_dsa_keypair().await?;
                let ml_dsa_keypair = MlDsaKeypair::from_bytes(signing_keypair.0, signing_keypair.1)
                    .map_err(|e| SdkError::CryptoError(format!("Failed to create ML-DSA keypair: {}", e).into()))?;
                handshake.set_signing_keypair(ml_dsa_keypair)?;
                
                // Message 2: Send HandshakeResponse
                let response = handshake.create_response()?;
                let response_payload = bincode::serialize(&response)
                    .map_err(|e| SdkError::CryptoError(format!("Failed to serialize response: {}", e).into()))?;
                let response_msg = WireMessage::new(MessageType::HandshakeResponse, 1, response_payload.into());
                inner.write_all(&response_msg.to_bytes()?).await
                    .map_err(|e| SdkError::NetworkError(format!("Failed to send response: {}", e)))?;
                inner.flush().await
                    .map_err(|e| SdkError::NetworkError(format!("Failed to flush response: {}", e)))?;
                
                // Message 3: Receive HandshakeFinish
                let finish_bytes = Self::read_wire_message(&mut inner).await?;
                let finish_msg = WireMessage::from_bytes(finish_bytes.into())?;
                let finish: HandshakeFinish = bincode::deserialize(&finish_msg.payload)
                    .map_err(|e| SdkError::CryptoError(format!("Failed to deserialize finish: {}", e).into()))?;
                handshake.process_finish(&finish)?;
                
                handshake.shared_secret().ok_or_else(|| SdkError::CryptoError("No shared secret".into()))?
            }
        };
        
        debug!("Handshake complete, creating cipher");
        
        // Create WasifVernam cipher with the shared secret
        let mut cipher = WasifVernam::new(shared_secret)
            .map_err(|e| SdkError::CryptoError(format!("Failed to create cipher: {}", e).into()))?;
        
        // Enable features based on configuration
        if is_swarm {
            cipher.enable_scrambling(256); // Enable traffic analysis resistance
        }
        
        if config.security == crate::config::SecurityLevel::TrueVernam {
            cipher.enable_true_vernam(1024); // Enable TRUE Vernam mode
        }
        
        debug!("Encrypted stream handshake complete (security: {:?})", config.security);
        
        Ok(Self {
            inner,
            read_buf: BytesMut::with_capacity(config.buffer_size),
            write_buf: BytesMut::with_capacity(config.buffer_size),
            is_handshake_complete: true,
            cipher: Some(cipher),
        })
    }
    
    /// Read a wire message from the stream
    async fn read_wire_message(inner: &mut S) -> Result<Vec<u8>> {
        // Read message length (4 bytes)
        let mut len_bytes = [0u8; 4];
        inner.read_exact(&mut len_bytes).await
            .map_err(|e| SdkError::NetworkError(format!("Failed to read message length: {}", e)))?;
        
        let msg_len = u32::from_be_bytes(len_bytes) as usize;
        
        // Validate message size (prevent DoS)
        if msg_len > 1024 * 1024 { // 1MB max
            return Err(SdkError::NetworkError("Message too large".into()));
        }
        
        // Read message data
        let mut msg_bytes = vec![0u8; msg_len];
        inner.read_exact(&mut msg_bytes).await
            .map_err(|e| SdkError::NetworkError(format!("Failed to read message data: {}", e)))?;
        
        Ok(msg_bytes)
    }
    
    /// Create a new encrypted stream (for existing connections, skips handshake)
    pub fn new(
        inner: S,
        session_key: [u8; 32],
        config: &ConnectionConfig,
        is_swarm: bool,
    ) -> Result<Self> {
        debug!("Creating encrypted stream with existing session key");
        
        // Create WasifVernam cipher with the session key
        let mut cipher = WasifVernam::new(session_key)
            .map_err(|e| SdkError::CryptoError(format!("Failed to create cipher: {}", e).into()))?;
        
        // Enable features based on configuration
        if is_swarm {
            cipher.enable_scrambling(256); // Enable traffic analysis resistance
        }
        
        if config.security == crate::config::SecurityLevel::TrueVernam {
            cipher.enable_true_vernam(1024); // Enable TRUE Vernam mode
        }
        
        Ok(Self {
            inner,
            read_buf: BytesMut::with_capacity(config.buffer_size),
            write_buf: BytesMut::with_capacity(config.buffer_size),
            is_handshake_complete: true,
            cipher: Some(cipher),
        })
    }
    
    /// Get a reference to the inner stream
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
    
    /// Check if the handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        self.is_handshake_complete
    }
    
    /// Get a mutable reference to the inner stream
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
    
    /// Consume the encrypted stream and return the inner stream
    pub fn into_inner(self) -> S {
        self.inner
    }
    
    /// Shutdown the stream
    pub async fn shutdown(&mut self) -> Result<()> {
        debug!("Shutting down encrypted stream");
        
        // Flush any pending encrypted data
        self.flush_encrypted().await?;
        
        // Shutdown the inner stream
        self.inner.shutdown().await
            .map_err(|e| SdkError::NetworkError(e.to_string()))?;
        
        debug!("Encrypted stream shutdown complete");
        Ok(())
    }
    
    /// Flush encrypted data to the inner stream
    async fn flush_encrypted(&mut self) -> Result<()> {
        if self.write_buf.is_empty() {
            return Ok(());
        }
        
        trace!("Flushing {} bytes of encrypted data", self.write_buf.len());
        
        // Encrypt the data using WasifVernam cipher
        let encrypted_data = match &mut self.cipher {
            Some(cipher) => cipher.encrypt(&self.write_buf)
                .map_err(|e| SdkError::CryptoError(format!("Encryption failed: {}", e).into()))?,
            None => return Err(SdkError::CryptoError("Cipher not initialized - handshake incomplete".into())),
        };
        
        self.inner.write_all(&encrypted_data).await
            .map_err(|e| SdkError::NetworkError(e.to_string()))?;
        
        self.inner.flush().await
            .map_err(|e| SdkError::NetworkError(e.to_string()))?;
        
        self.write_buf.clear();
        
        trace!("Flushed encrypted data successfully");
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for EncryptedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we have buffered data, return it first
        if !self.read_buf.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), self.read_buf.len());
            buf.put_slice(&self.read_buf.split_to(to_read));
            return Poll::Ready(Ok(()));
        }
        
        // Try to read and decrypt more data
        let mut temp_buf = vec![0u8; 4096];
        match Pin::new(&mut self.inner).poll_read(cx, &mut ReadBuf::new(&mut temp_buf)) {
            Poll::Ready(Ok(())) => {
                // Get the actual number of bytes read
                let n = temp_buf.len() - ReadBuf::new(&mut temp_buf).remaining();
                
                if n > 0 {
                    // Decrypt the data using WasifVernam cipher
                    match &mut self.cipher {
                        Some(cipher) => {
                            match cipher.decrypt(&temp_buf[..n]) {
                                Ok(decrypted_data) => {
                                    let to_copy = std::cmp::min(buf.remaining(), decrypted_data.len());
                                    buf.put_slice(&decrypted_data[..to_copy]);
                                    
                                    // Buffer any remaining decrypted data
                                    if decrypted_data.len() > to_copy {
                                        self.read_buf.extend_from_slice(&decrypted_data[to_copy..]);
                                    }
                                }
                                Err(e) => {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        format!("Decryption failed: {}", e)
                                    )));
                                }
                            }
                        }
                        None => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Cipher not initialized - handshake incomplete"
                            )));
                        }
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for EncryptedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Buffer the data for encryption
        self.write_buf.extend_from_slice(buf);
        
        // If buffer is getting full, flush it
        if self.write_buf.len() >= 4096 {
            match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        
        Poll::Ready(Ok(buf.len()))
    }
    
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.write_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }
        
        // Encrypt the data using WasifVernam cipher
        let write_buf_data = self.write_buf.split().freeze();
        let encrypted_data = match &mut self.cipher {
            Some(cipher) => {
                match cipher.encrypt(write_buf_data.as_ref()) {
                    Ok(data) => data,
                    Err(e) => return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Encryption failed: {}", e)
                    ))),
                }
            }
            None => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Cipher not initialized - handshake incomplete"
                )));
            }
        };
        
        let _n = match Pin::new(&mut self.inner).poll_write(cx, &encrypted_data) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        
        // Clear the write buffer since we've processed all data
        self.write_buf.clear();
        
        if self.write_buf.is_empty() {
            Pin::new(&mut self.inner).poll_flush(cx)
        } else {
            Poll::Pending
        }
    }
    
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}