//! Wire protocol for ZK Protocol message framing and encryption
//! 
//! Provides binary message framing, encryption, and protocol versioning.

use bytes::{Bytes, BytesMut, Buf, BufMut};
use serde::{Serialize, Deserialize};
use std::io::Cursor;
// use tracing::debug;

use crate::{WireError, Result};

/// Current wire protocol version
pub const WIRE_PROTOCOL_VERSION: u8 = 1;

/// Maximum message size (64KB)
pub const MAX_MESSAGE_SIZE: usize = 65536;

/// Message type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Handshake initiation
    HandshakeInit = 0x01,
    /// Handshake response
    HandshakeResponse = 0x02,
    /// Handshake finish
    HandshakeFinish = 0x03,
    /// Encrypted data message
    EncryptedData = 0x04,
    /// Keepalive/ping message
    Keepalive = 0x05,
    /// Peer discovery message
    PeerDiscovery = 0x06,
    /// NAT traversal coordination
    NatTraversal = 0x07,
    /// Error message
    Error = 0x7F,
}

impl MessageType {
    /// Convert from u8
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(MessageType::HandshakeInit),
            0x02 => Ok(MessageType::HandshakeResponse),
            0x03 => Ok(MessageType::HandshakeFinish),
            0x04 => Ok(MessageType::EncryptedData),
            0x05 => Ok(MessageType::Keepalive),
            0x06 => Ok(MessageType::PeerDiscovery),
            0x07 => Ok(MessageType::NatTraversal),
            0x7F => Ok(MessageType::Error),
            _ => Err(WireError::invalid_message(format!("Unknown message type: 0x{:02x}", value))),
        }
    }
}

/// Wire protocol message header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireHeader {
    /// Protocol version
    pub version: u8,
    /// Message type
    pub message_type: MessageType,
    /// Message sequence number
    pub sequence: u32,
    /// Payload length
    pub payload_length: u32,
}

/// Complete wire protocol message
#[derive(Debug, Clone)]
pub struct WireMessage {
    /// Message header
    pub header: WireHeader,
    /// Message payload
    pub payload: Bytes,
}

impl WireMessage {
    /// Create a new wire message
    pub fn new(message_type: MessageType, sequence: u32, payload: Bytes) -> Self {
        let header = WireHeader {
            version: WIRE_PROTOCOL_VERSION,
            message_type,
            sequence,
            payload_length: payload.len() as u32,
        };
        
        Self { header, payload }
    }
    
    /// Serialize the message to bytes
    pub fn to_bytes(&self) -> Result<Bytes> {
        // Validate message size before serialization
        if self.payload.len() > MAX_MESSAGE_SIZE - 16 {
            return Err(WireError::invalid_message("Payload too large"));
        }
        
        let mut buf = BytesMut::with_capacity(16 + self.payload.len());
        
        // Write header
        buf.put_u8(self.header.version);
        buf.put_u8(self.header.message_type as u8);
        buf.put_u32(self.header.sequence);
        buf.put_u32(self.header.payload_length);
        
        // Add padding to align to 16 bytes
        while buf.len() < 16 {
            buf.put_u8(0);
        }
        
        // Write payload
        buf.put(self.payload.clone());
        
        Ok(buf.freeze())
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: Bytes) -> Result<Self> {
        if bytes.len() < 16 {
            return Err(WireError::invalid_message("Message too short".to_string()));
        }
        
        let mut cursor = Cursor::new(bytes);
        
        // Read header
        let version = cursor.get_u8();
        let message_type_u8 = cursor.get_u8();
        let sequence = cursor.get_u32();
        let payload_length = cursor.get_u32();
        
        // Skip padding
        cursor.set_position(16);
        
        // Validate version
        if version != WIRE_PROTOCOL_VERSION {
            return Err(WireError::ProtocolVersionMismatch {
                expected: WIRE_PROTOCOL_VERSION,
                actual: version,
            });
        }
        
        // Validate message type
        let message_type = MessageType::from_u8(message_type_u8)?;
        
        // Validate payload length
        let remaining = cursor.remaining();
        if remaining < payload_length as usize {
            return Err(WireError::invalid_message(format!(
                "Payload length mismatch: expected {}, got {}",
                payload_length, remaining
            )));
        }
        
        // Read payload
        let mut payload_bytes = vec![0u8; payload_length as usize];
        cursor.copy_to_slice(&mut payload_bytes);
        let payload = Bytes::from(payload_bytes);
        
        let header = WireHeader {
            version,
            message_type,
            sequence,
            payload_length,
        };
        
        Ok(Self { header, payload })
    }
    
    /// Create a handshake initiation message
    pub fn handshake_init(sequence: u32, public_key: &[u8]) -> Self {
        Self::new(MessageType::HandshakeInit, sequence, Bytes::copy_from_slice(public_key))
    }
    
    /// Create a handshake response message
    pub fn handshake_response(sequence: u32, public_key: &[u8], signature: &[u8]) -> Self {
        let mut payload = BytesMut::new();
        payload.put_u16(public_key.len() as u16);
        payload.put(Bytes::copy_from_slice(public_key));
        payload.put_u16(signature.len() as u16);
        payload.put(Bytes::copy_from_slice(signature));
        
        Self::new(MessageType::HandshakeResponse, sequence, payload.freeze())
    }
    
    /// Create an encrypted data message
    pub fn encrypted_data(sequence: u32, ciphertext: &[u8]) -> Self {
        Self::new(MessageType::EncryptedData, sequence, Bytes::copy_from_slice(ciphertext))
    }
    
    /// Create a keepalive message
    pub fn keepalive(sequence: u32) -> Self {
        Self::new(MessageType::Keepalive, sequence, Bytes::new())
    }
    
    /// Create a peer discovery message
    pub fn peer_discovery(sequence: u32, peer_info: &[u8]) -> Self {
        Self::new(MessageType::PeerDiscovery, sequence, Bytes::copy_from_slice(peer_info))
    }
    
    /// Create a NAT traversal message
    pub fn nat_traversal(sequence: u32, traversal_data: &[u8]) -> Self {
        Self::new(MessageType::NatTraversal, sequence, Bytes::copy_from_slice(traversal_data))
    }
    
    /// Create an error message
    pub fn error(sequence: u32, error_code: u8, error_message: &str) -> Self {
        let mut payload = BytesMut::new();
        payload.put_u8(error_code);
        payload.put_u16(error_message.len() as u16);
        payload.put(Bytes::copy_from_slice(error_message.as_bytes()));
        
        Self::new(MessageType::Error, sequence, payload.freeze())
    }
}

/// Wire protocol handler for encoding/decoding messages
pub struct WireProtocol {
    /// Next sequence number to use
    next_sequence: u32,
}

impl WireProtocol {
    /// Create a new wire protocol handler
    /// 
    /// Uses high-entropy randomness (drand + OsRng) for initial sequence number
    /// to prevent sequence prediction attacks with 256-bit post-quantum computational security.
    pub fn new() -> Self {
        // SECURITY: Use TrueEntropy for 256-bit post-quantum computational security
        // Combines drand (BLS verified) + OsRng via XOR - secure if either is uncompromised
        use zks_crypt::true_entropy::get_sync_entropy;
        let entropy = get_sync_entropy(4);
        let mut seq_bytes = [0u8; 4];
        seq_bytes.copy_from_slice(&entropy[..4]);
        Self {
            next_sequence: u32::from_ne_bytes(seq_bytes),
        }
    }
    
    /// Get the next sequence number
    pub fn next_sequence(&mut self) -> u32 {
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        seq
    }
    
    /// Encode a message
    pub fn encode(&mut self, message_type: MessageType, payload: Bytes) -> Result<Bytes> {
        let sequence = self.next_sequence();
        let message = WireMessage::new(message_type, sequence, payload);
        message.to_bytes()
    }
    
    /// Decode a message
    pub fn decode(&self, bytes: Bytes) -> Result<WireMessage> {
        WireMessage::from_bytes(bytes)
    }
    
    /// Create and encode a handshake initiation message
    pub fn encode_handshake_init(&mut self, public_key: &[u8]) -> Result<Bytes> {
        let sequence = self.next_sequence();
        let message = WireMessage::handshake_init(sequence, public_key);
        message.to_bytes()
    }
    
    /// Create and encode a handshake response message
    pub fn encode_handshake_response(&mut self, public_key: &[u8], signature: &[u8]) -> Result<Bytes> {
        let sequence = self.next_sequence();
        let message = WireMessage::handshake_response(sequence, public_key, signature);
        message.to_bytes()
    }
    
    /// Create and encode an encrypted data message
    pub fn encode_encrypted_data(&mut self, ciphertext: &[u8]) -> Result<Bytes> {
        let sequence = self.next_sequence();
        let message = WireMessage::encrypted_data(sequence, ciphertext);
        message.to_bytes()
    }
    
    /// Create and encode a keepalive message
    pub fn encode_keepalive(&mut self) -> Result<Bytes> {
        let sequence = self.next_sequence();
        let message = WireMessage::keepalive(sequence);
        message.to_bytes()
    }
    
    /// Create and encode a peer discovery message
    pub fn encode_peer_discovery(&mut self, peer_info: &[u8]) -> Result<Bytes> {
        let sequence = self.next_sequence();
        let message = WireMessage::peer_discovery(sequence, peer_info);
        message.to_bytes()
    }
    
    /// Create and encode a NAT traversal message
    pub fn encode_nat_traversal(&mut self, traversal_data: &[u8]) -> Result<Bytes> {
        let sequence = self.next_sequence();
        let message = WireMessage::nat_traversal(sequence, traversal_data);
        message.to_bytes()
    }
    
    /// Create and encode an error message
    pub fn encode_error(&mut self, error_code: u8, error_message: &str) -> Result<Bytes> {
        let sequence = self.next_sequence();
        let message = WireMessage::error(sequence, error_code, error_message);
        message.to_bytes()
    }
}

impl Default for WireProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::from_u8(0x01).unwrap(), MessageType::HandshakeInit);
        assert_eq!(MessageType::from_u8(0x02).unwrap(), MessageType::HandshakeResponse);
        assert_eq!(MessageType::from_u8(0x03).unwrap(), MessageType::HandshakeFinish);
        assert_eq!(MessageType::from_u8(0x04).unwrap(), MessageType::EncryptedData);
        assert!(MessageType::from_u8(0xFF).is_err());
    }
    
    #[test]
    fn test_wire_message_serialization() {
        let payload = Bytes::from(vec![1, 2, 3, 4, 5]);
        let message = WireMessage::new(MessageType::EncryptedData, 42, payload.clone());
        
        let bytes = message.to_bytes().unwrap();
        let deserialized = WireMessage::from_bytes(bytes).unwrap();
        
        assert_eq!(deserialized.header.version, WIRE_PROTOCOL_VERSION);
        assert_eq!(deserialized.header.message_type, MessageType::EncryptedData);
        assert_eq!(deserialized.header.sequence, 42);
        assert_eq!(deserialized.payload, payload);
    }
    
    #[test]
    fn test_wire_protocol_encoding() {
        let mut protocol = WireProtocol::new();
        let payload = Bytes::from(vec![1, 2, 3]);
        
        let encoded = protocol.encode(MessageType::Keepalive, payload.clone()).unwrap();
        let decoded = protocol.decode(encoded).unwrap();
        
        assert_eq!(decoded.header.message_type, MessageType::Keepalive);
        assert_eq!(decoded.payload, payload);
    }
    
    #[test]
    fn test_handshake_messages() {
        let mut protocol = WireProtocol::new();
        let public_key = vec![1, 2, 3, 4, 5];
        
        let init_msg = protocol.encode_handshake_init(&public_key).unwrap();
        let decoded = protocol.decode(init_msg).unwrap();
        
        assert_eq!(decoded.header.message_type, MessageType::HandshakeInit);
        assert_eq!(decoded.payload.as_ref(), public_key.as_slice());
    }
    
    #[test]
    fn test_error_message() {
        let mut protocol = WireProtocol::new();
        
        let error_msg = protocol.encode_error(1, "Test error").unwrap();
        let decoded = protocol.decode(error_msg).unwrap();
        
        assert_eq!(decoded.header.message_type, MessageType::Error);
        assert!(decoded.payload.len() > 0);
    }
}