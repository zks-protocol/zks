//! Encrypted stream implementation

use bincode;
use bytes::{Buf, BytesMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, trace};
use zks_crypt::wasif_vernam::WasifVernam;
use zks_pqcrypto::ml_dsa::MlDsaKeypair;
use zks_proto::{
    handshake::{HandshakeFinish, HandshakeInit, HandshakeResponse},
    Handshake, HandshakeRole,
};
use zks_wire::{MessageType, WireMessage};

use crate::{
    config::ConnectionConfig,
    error::{Result, SdkError},
};

/// Encrypted stream that wraps an inner stream with post-quantum encryption
pub struct EncryptedStream<S> {
    inner: S,
    read_buf: BytesMut,
    write_buf: BytesMut,
    encrypted_write_buf: BytesMut,
    is_handshake_complete: bool,
    reader_cipher: Option<WasifVernam>,
    writer_cipher: Option<WasifVernam>,
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
        trusted_responder_key: Option<Vec<u8>>, // Required for initiator
        responder_signing_key: Option<MlDsaKeypair>, // Optional for responder (persistent identity)
    ) -> Result<Self> {
        debug!(
            "Starting encrypted stream handshake (role: {:?}, swarm: {})",
            role, is_swarm
        );

        // Create handshake based on role
        let mut handshake = match role {
            HandshakeRole::Initiator => {
                if trusted_responder_key.is_none() {
                    return Err(SdkError::CryptoError(
                        "Initiator requires trusted responder key".into(),
                    ));
                }
                Handshake::new_initiator(room_id, trusted_responder_key.unwrap())?
            }
            HandshakeRole::Responder => Handshake::new_responder(room_id),
        };

        // Perform the 3-message handshake
        let shared_secret = match role {
            HandshakeRole::Initiator => {
                // Message 1: Send HandshakeInit
                let init = handshake.create_init()?;
                let init_payload = bincode::serialize(&init).map_err(|e| {
                    SdkError::CryptoError(format!("Failed to serialize init: {}", e).into())
                })?;
                let init_msg = WireMessage::new(MessageType::HandshakeInit, 1, init_payload.into());
                inner
                    .write_all(&init_msg.to_bytes()?)
                    .await
                    .map_err(|e| SdkError::NetworkError(format!("Failed to send init: {}", e)))?;
                inner
                    .flush()
                    .await
                    .map_err(|e| SdkError::NetworkError(format!("Failed to flush init: {}", e)))?;

                // Message 2: Receive HandshakeResponse
                let response_bytes = Self::read_wire_message(&mut inner).await?;
                let response_msg = WireMessage::from_bytes(response_bytes.into())?;
                let response: HandshakeResponse = bincode::deserialize(&response_msg.payload)
                    .map_err(|e| {
                        SdkError::CryptoError(
                            format!("Failed to deserialize response: {}", e).into(),
                        )
                    })?;
                handshake.process_response(&response)?;

                // Message 3: Send HandshakeFinish
                let finish = handshake.create_finish()?;
                let finish_payload = bincode::serialize(&finish).map_err(|e| {
                    SdkError::CryptoError(format!("Failed to serialize finish: {}", e).into())
                })?;
                let finish_msg =
                    WireMessage::new(MessageType::HandshakeFinish, 2, finish_payload.into());
                inner
                    .write_all(&finish_msg.to_bytes()?)
                    .await
                    .map_err(|e| SdkError::NetworkError(format!("Failed to send finish: {}", e)))?;
                inner.flush().await.map_err(|e| {
                    SdkError::NetworkError(format!("Failed to flush finish: {}", e))
                })?;

                handshake
                    .shared_secret()
                    .ok_or_else(|| SdkError::CryptoError("No shared secret".into()))?
            }
            HandshakeRole::Responder => {
                // Message 1: Receive HandshakeInit
                let init_bytes = Self::read_wire_message(&mut inner).await?;
                let init_msg = WireMessage::from_bytes(init_bytes.into())?;
                let init: HandshakeInit = bincode::deserialize(&init_msg.payload).map_err(|e| {
                    SdkError::CryptoError(format!("Failed to deserialize init: {}", e).into())
                })?;
                handshake.process_init(&init)?;

                // Set signing keypair for responder
                let ml_dsa_keypair = if let Some(key) = responder_signing_key {
                    key
                } else {
                    let signing_keypair = crate::sdk_crypto::ml_dsa_keypair().await?;
                    MlDsaKeypair::from_bytes(signing_keypair.0, signing_keypair.1).map_err(|e| {
                        SdkError::CryptoError(
                            format!("Failed to create ML-DSA keypair: {}", e).into(),
                        )
                    })?
                };
                handshake.set_signing_keypair(ml_dsa_keypair)?;

                // Message 2: Send HandshakeResponse
                let response = handshake.create_response()?;
                let response_payload = bincode::serialize(&response).map_err(|e| {
                    SdkError::CryptoError(format!("Failed to serialize response: {}", e).into())
                })?;
                let response_msg =
                    WireMessage::new(MessageType::HandshakeResponse, 1, response_payload.into());
                inner
                    .write_all(&response_msg.to_bytes()?)
                    .await
                    .map_err(|e| {
                        SdkError::NetworkError(format!("Failed to send response: {}", e))
                    })?;
                inner.flush().await.map_err(|e| {
                    SdkError::NetworkError(format!("Failed to flush response: {}", e))
                })?;

                // Message 3: Receive HandshakeFinish
                let finish_bytes = Self::read_wire_message(&mut inner).await?;
                let finish_msg = WireMessage::from_bytes(finish_bytes.into())?;
                let finish: HandshakeFinish =
                    bincode::deserialize(&finish_msg.payload).map_err(|e| {
                        SdkError::CryptoError(format!("Failed to deserialize finish: {}", e).into())
                    })?;
                handshake.process_finish(&finish)?;

                handshake
                    .shared_secret()
                    .ok_or_else(|| SdkError::CryptoError("No shared secret".into()))?
            }
        };

        debug!("Handshake complete, creating ciphers");

        // Create WasifVernam ciphers with the shared secret
        // We need separate ciphers for reading and writing to ensure nonce separation
        // and correct keystream generation (since keystream depends on role)

        // Writer cipher: Uses MY role
        let mut writer_cipher = WasifVernam::new(shared_secret).map_err(|e| {
            SdkError::CryptoError(format!("Failed to create writer cipher: {}", e).into())
        })?;
        writer_cipher.derive_base_iv(&shared_secret, role == HandshakeRole::Initiator);

        // Reader cipher: Uses PEER'S role (opposite of mine)
        let mut reader_cipher = WasifVernam::new(shared_secret).map_err(|e| {
            SdkError::CryptoError(format!("Failed to create reader cipher: {}", e).into())
        })?;
        reader_cipher.derive_base_iv(&shared_secret, role != HandshakeRole::Initiator);

        // Enable features based on configuration
        if is_swarm {
            let _ = writer_cipher.enable_scrambling(256);
            let _ = reader_cipher.enable_scrambling(256);
        }

        if config.security == crate::config::SecurityLevel::TrueVernam {
            writer_cipher.enable_true_vernam(1024);
            reader_cipher.enable_true_vernam(1024);
        }

        debug!(
            "Encrypted stream handshake complete (security: {:?})",
            config.security
        );

        Ok(Self {
            inner,
            read_buf: BytesMut::with_capacity(config.buffer_size),
            write_buf: BytesMut::with_capacity(config.buffer_size),
            encrypted_write_buf: BytesMut::with_capacity(config.buffer_size),
            is_handshake_complete: true,
            reader_cipher: Some(reader_cipher),
            writer_cipher: Some(writer_cipher),
        })
    }

    /// Read a wire message from the stream
    async fn read_wire_message(inner: &mut S) -> Result<Vec<u8>> {
        // Read header (16 bytes)
        let mut header_bytes = [0u8; 16];
        inner
            .read_exact(&mut header_bytes)
            .await
            .map_err(|e| SdkError::NetworkError(format!("Failed to read message header: {}", e)))?;

        // Parse header manually to get length
        // Structure: [Version: 1] [Type: 1] [Sequence: 4] [Length: 4] [Padding: 6]
        let version = header_bytes[0];
        let _msg_type = header_bytes[1];
        let _sequence = u32::from_be_bytes(header_bytes[2..6].try_into().unwrap());
        let payload_len = u32::from_be_bytes(header_bytes[6..10].try_into().unwrap()) as usize;

        // Validate version
        if version != 1 {
            return Err(SdkError::NetworkError(format!(
                "Invalid protocol version: {}",
                version
            )));
        }

        // Validate message size (prevent DoS)
        if payload_len > 16 * 1024 * 1024 {
            // 16MB max (matching config default)
            return Err(SdkError::NetworkError(
                format!("Message too large: {} bytes", payload_len).into(),
            ));
        }

        // Read message data
        let mut msg_bytes = vec![0u8; payload_len];
        inner
            .read_exact(&mut msg_bytes)
            .await
            .map_err(|e| SdkError::NetworkError(format!("Failed to read message data: {}", e)))?;

        // Reconstruct the full message bytes (header + payload) because WireMessage::from_bytes expects the full frame
        // including the header we already read.
        let mut full_frame = Vec::with_capacity(16 + payload_len);
        full_frame.extend_from_slice(&header_bytes);
        full_frame.extend_from_slice(&msg_bytes);

        Ok(full_frame)
    }

    /// Create a new encrypted stream (for existing connections, skips handshake)
    pub fn new(
        inner: S,
        session_key: [u8; 32],
        config: &ConnectionConfig,
        is_swarm: bool,
        is_initiator: bool,
    ) -> Result<Self> {
        debug!(
            "Creating encrypted stream with existing session key (role: {})",
            if is_initiator {
                "Initiator"
            } else {
                "Responder"
            }
        );

        // Create writer cipher (my role)
        let mut writer_cipher = WasifVernam::new(session_key).map_err(|e| {
            SdkError::CryptoError(format!("Failed to create writer cipher: {}", e).into())
        })?;
        writer_cipher.derive_base_iv(&session_key, is_initiator);

        // Create reader cipher (peer's role)
        let mut reader_cipher = WasifVernam::new(session_key).map_err(|e| {
            SdkError::CryptoError(format!("Failed to create reader cipher: {}", e).into())
        })?;
        reader_cipher.derive_base_iv(&session_key, !is_initiator);

        // Enable features based on configuration
        if is_swarm {
            let _ = writer_cipher.enable_scrambling(256);
            let _ = reader_cipher.enable_scrambling(256);
        }

        if config.security == crate::config::SecurityLevel::TrueVernam {
            writer_cipher.enable_true_vernam(1024);
            reader_cipher.enable_true_vernam(1024);
        }

        Ok(Self {
            inner,
            read_buf: BytesMut::with_capacity(config.buffer_size),
            write_buf: BytesMut::with_capacity(config.buffer_size),
            encrypted_write_buf: BytesMut::with_capacity(config.buffer_size),
            is_handshake_complete: true,
            reader_cipher: Some(reader_cipher),
            writer_cipher: Some(writer_cipher),
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
        self.inner
            .shutdown()
            .await
            .map_err(|e| SdkError::NetworkError(e.to_string()))?;

        debug!("Encrypted stream shutdown complete");
        Ok(())
    }

    /// Flush encrypted data to the inner stream
    async fn flush_encrypted(&mut self) -> Result<()> {
        // First flush any plain data into encrypted buffer
        if !self.write_buf.is_empty() {
            trace!("Encrypting {} bytes of pending data", self.write_buf.len());
            // Encrypt the data using WasifVernam writer cipher
            let encrypted_data = match &mut self.writer_cipher {
                Some(cipher) => cipher.encrypt(&self.write_buf).map_err(|e| {
                    SdkError::CryptoError(format!("Encryption failed: {}", e).into())
                })?,
                None => {
                    return Err(SdkError::CryptoError(
                        "Cipher not initialized - handshake incomplete".into(),
                    ))
                }
            };

            self.encrypted_write_buf.extend_from_slice(&encrypted_data);
            self.write_buf.clear();
        }

        if self.encrypted_write_buf.is_empty() {
            return Ok(());
        }

        trace!(
            "Flushing {} bytes of encrypted data",
            self.encrypted_write_buf.len()
        );

        self.inner
            .write_all(&self.encrypted_write_buf)
            .await
            .map_err(|e| SdkError::NetworkError(e.to_string()))?;

        self.inner
            .flush()
            .await
            .map_err(|e| SdkError::NetworkError(e.to_string()))?;

        self.encrypted_write_buf.clear();

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
            trace!("EncryptedStream: Read {} buffered bytes", to_read);
            return Poll::Ready(Ok(()));
        }

        // Try to read and decrypt more data
        let mut temp_buf = vec![0u8; 4096];
        let mut read_buf = ReadBuf::new(&mut temp_buf);
        match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                // Get the actual number of bytes read
                let n = read_buf.filled().len();

                if n > 0 {
                    trace!("EncryptedStream: Read {} encrypted bytes from inner", n);
                    // Decrypt the data using WasifVernam reader cipher
                    match &mut self.reader_cipher {
                        Some(cipher) => {
                            match cipher.decrypt(&temp_buf[..n]) {
                                Ok(decrypted_data) => {
                                    trace!(
                                        "EncryptedStream: Decrypted {} bytes",
                                        decrypted_data.len()
                                    );
                                    let to_copy =
                                        std::cmp::min(buf.remaining(), decrypted_data.len());
                                    buf.put_slice(&decrypted_data[..to_copy]);

                                    // Buffer any remaining decrypted data
                                    if decrypted_data.len() > to_copy {
                                        self.read_buf.extend_from_slice(&decrypted_data[to_copy..]);
                                    }
                                }
                                Err(e) => {
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        format!("Decryption failed: {}", e),
                                    )));
                                }
                            }
                        }
                        None => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Cipher not initialized - handshake incomplete",
                            )));
                        }
                    }
                } else {
                    trace!("EncryptedStream: Read 0 bytes from inner (EOF)");
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
        trace!("EncryptedStream: Buffered {} bytes for writing", buf.len());

        // If buffer is getting full, flush it
        if self.write_buf.len() >= 4096 {
            trace!("EncryptedStream: Write buffer full, flushing...");
            match self.as_mut().poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // First, check if we have any pending encrypted data to write
        while !this.encrypted_write_buf.is_empty() {
            let to_write = this.encrypted_write_buf.len();
            trace!(
                "EncryptedStream: Attempting to write {} encrypted bytes to inner",
                to_write
            );
            let n = match Pin::new(&mut this.inner).poll_write(cx, &this.encrypted_write_buf) {
                Poll::Ready(Ok(n)) => {
                    trace!("EncryptedStream: Wrote {} encrypted bytes to inner", n);
                    n
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    trace!("EncryptedStream: inner poll_write pending");
                    return Poll::Pending;
                }
            };

            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "Zero bytes written to inner stream",
                )));
            }

            this.encrypted_write_buf.advance(n);
        }

        // If we have plain data to encrypt
        if !this.write_buf.is_empty() {
            let len = this.write_buf.len();
            trace!("EncryptedStream: Encrypting {} bytes of pending data", len);
            // Encrypt the data using WasifVernam writer cipher
            let write_buf_data = this.write_buf.split_to(len).freeze();
            let encrypted_data = match &mut this.writer_cipher {
                Some(cipher) => match cipher.encrypt(write_buf_data.as_ref()) {
                    Ok(data) => data,
                    Err(e) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Encryption failed: {}", e),
                        )))
                    }
                },
                None => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Cipher not initialized - handshake incomplete",
                    )));
                }
            };

            this.encrypted_write_buf.extend_from_slice(&encrypted_data);
            trace!(
                "EncryptedStream: Encrypted data appended to buffer, total encrypted buffered: {}",
                this.encrypted_write_buf.len()
            );

            // Now try to write the newly encrypted data
            while !this.encrypted_write_buf.is_empty() {
                let to_write = this.encrypted_write_buf.len();
                trace!("EncryptedStream: Attempting to write {} encrypted bytes to inner (second loop)", to_write);
                let n = match Pin::new(&mut this.inner).poll_write(cx, &this.encrypted_write_buf) {
                    Poll::Ready(Ok(n)) => {
                        trace!(
                            "EncryptedStream: Wrote {} encrypted bytes to inner (second loop)",
                            n
                        );
                        n
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        trace!("EncryptedStream: inner poll_write pending (second loop)");
                        return Poll::Pending;
                    }
                };

                if n == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "Zero bytes written to inner stream",
                    )));
                }

                this.encrypted_write_buf.advance(n);
            }
        }

        // If we got here, all buffers are empty or flushed to inner.
        // Now flush the inner stream.
        trace!("EncryptedStream: Flushing inner stream");
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}
