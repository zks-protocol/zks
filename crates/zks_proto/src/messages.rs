//! Protocol messages for ZK Protocol
//! 
//! Defines structured message types used in the ZK Protocol for
//! communication between peers.

use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{ProtoError, Result};

/// Maximum allowed message size (1MB) to prevent DoS attacks
const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Maximum allowed payload size (512KB) to prevent DoS attacks
const MAX_PAYLOAD_SIZE: usize = 512 * 1024;

/// Message types in ZK Protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Handshake messages
    Handshake,
    /// Encrypted data messages
    Data,
    /// Keep-alive messages
    KeepAlive,
    /// Disconnection messages
    Disconnect,
    /// Error messages
    Error,
    /// Discovery messages (for swarm mode)
    Discovery,
    /// Peer announcement messages
    Announcement,
}

/// Priority levels for messages
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MessagePriority {
    /// Critical messages (handshake, errors)
    Critical = 0,
    /// High priority messages
    High = 1,
    /// Normal priority messages
    Normal = 2,
    /// Low priority messages (keep-alive)
    Low = 3,
}

/// Base protocol message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Message type
    pub message_type: MessageType,
    /// Message priority
    pub priority: MessagePriority,
    /// Protocol version
    pub version: u8,
    /// Message timestamp
    pub timestamp: u64,
    /// Message sequence number
    pub sequence: u64,
    /// Source peer ID (optional)
    pub source_id: Option<Vec<u8>>,
    /// Destination peer ID (optional)
    pub destination_id: Option<Vec<u8>>,
    /// Message payload
    pub payload: Vec<u8>,
    /// Message signature (optional)
    pub signature: Option<Vec<u8>>,
}

impl ProtocolMessage {
    /// Create a new protocol message
    pub fn new(
        message_type: MessageType,
        payload: impl Into<Vec<u8>>,
        sequence: u64,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let payload = payload.into();
        
        // Validate payload size to prevent DoS attacks
        let payload = if payload.len() > MAX_PAYLOAD_SIZE {
            // Truncate payload to maximum allowed size
            let mut truncated_payload = payload;
            truncated_payload.truncate(MAX_PAYLOAD_SIZE);
            truncated_payload
        } else {
            payload
        };
            
        Self {
            message_type,
            priority: Self::default_priority(message_type),
            version: 1,
            timestamp,
            sequence,
            source_id: None,
            destination_id: None,
            payload,
            signature: None,
        }
    }
    
    /// Create a handshake message
    pub fn handshake(payload: impl Into<Vec<u8>>, sequence: u64) -> Self {
        Self::new(MessageType::Handshake, payload, sequence)
    }
    
    /// Create a data message
    pub fn data(payload: impl Into<Vec<u8>>, sequence: u64) -> Self {
        Self::new(MessageType::Data, payload, sequence)
    }
    
    /// Create a keep-alive message
    pub fn keep_alive(sequence: u64) -> Self {
        Self::new(MessageType::KeepAlive, Vec::new(), sequence)
    }
    
    /// Create a disconnect message
    pub fn disconnect(sequence: u64) -> Self {
        Self::new(MessageType::Disconnect, Vec::new(), sequence)
    }
    
    /// Create an error message
    pub fn error(error_code: u32, error_message: &str, sequence: u64) -> Self {
        let payload = format!("{}:{}", error_code, error_message);
        Self::new(MessageType::Error, payload.as_bytes(), sequence)
    }
    
    /// Create a discovery message
    pub fn discovery(payload: impl Into<Vec<u8>>, sequence: u64) -> Self {
        Self::new(MessageType::Discovery, payload, sequence)
    }
    
    /// Create an announcement message
    pub fn announcement(payload: impl Into<Vec<u8>>, sequence: u64) -> Self {
        Self::new(MessageType::Announcement, payload, sequence)
    }
    
    /// Get the default priority for a message type
    fn default_priority(message_type: MessageType) -> MessagePriority {
        match message_type {
            MessageType::Handshake => MessagePriority::Critical,
            MessageType::Data => MessagePriority::Normal,
            MessageType::KeepAlive => MessagePriority::Low,
            MessageType::Disconnect => MessagePriority::High,
            MessageType::Error => MessagePriority::Critical,
            MessageType::Discovery => MessagePriority::Normal,
            MessageType::Announcement => MessagePriority::Normal,
        }
    }
    
    /// Set message priority
    pub fn with_priority(mut self, priority: MessagePriority) -> Self {
        self.priority = priority;
        self
    }
    
    /// Set source peer ID
    pub fn with_source_id(mut self, source_id: Vec<u8>) -> Self {
        self.source_id = Some(source_id);
        self
    }
    
    /// Set destination peer ID
    pub fn with_destination_id(mut self, destination_id: Vec<u8>) -> Self {
        self.destination_id = Some(destination_id);
        self
    }
    
    /// Set message signature
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }
    
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let serialized = serde_json::to_vec(self)
            .map_err(|e| ProtoError::message(format!("Serialization error: {}", e)))?;
        Ok(serialized)
    }
    
    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Validate message size to prevent DoS attacks
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(ProtoError::message(format!(
                "Message size {} exceeds maximum allowed size {}",
                bytes.len(),
                MAX_MESSAGE_SIZE
            )));
        }
        
        let message: Self = serde_json::from_slice(bytes)
            .map_err(|e| ProtoError::message(format!("Deserialization error: {}", e)))?;
        
        // Validate payload size to prevent DoS attacks
        if message.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtoError::message(format!(
                "Payload size {} exceeds maximum allowed size {}",
                message.payload.len(),
                MAX_PAYLOAD_SIZE
            )));
        }
        
        Ok(message)
    }
    
    /// Convert to bytes (alias for to_bytes)
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.to_bytes()
    }
    
    /// Get message size (more accurate calculation including Option overhead)
    pub fn size(&self) -> usize {
        // Base struct size
        let base_size = std::mem::size_of::<MessageType>() +
            std::mem::size_of::<MessagePriority>() +
            std::mem::size_of::<u8>() + // version
            std::mem::size_of::<u64>() + // timestamp
            std::mem::size_of::<u64>() + // sequence
            std::mem::size_of::<Vec<u8>>() + // payload (always present)
            std::mem::size_of::<Option<Vec<u8>>>() + // source_id
            std::mem::size_of::<Option<Vec<u8>>>() + // destination_id
            std::mem::size_of::<Option<Vec<u8>>>(); // signature
        
        // Variable-length data
        let variable_size = self.payload.len() +
            self.source_id.as_ref().map_or(0, |id| id.len()) +
            self.destination_id.as_ref().map_or(0, |id| id.len()) +
            self.signature.as_ref().map_or(0, |sig| sig.len());
        
        base_size + variable_size
    }
    
    /// Check if message is expired (older than max_age seconds)
    pub fn is_expired(&self, max_age: u64) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        current_time.saturating_sub(self.timestamp) > max_age
    }
    
    /// Validate message signature using ML-DSA
    pub fn validate_signature(&self, public_key: &[u8]) -> Result<bool> {
        // Check if signature exists
        let signature = match &self.signature {
            Some(sig) => sig,
            None => return Ok(false), // No signature to validate
        };
        
        // Create the message that was signed
        // This should match exactly what was signed during message creation
        let mut message = Vec::new();
        message.push(self.message_type as u8);
        message.push(self.priority as u8);
        message.push(self.version);
        message.extend_from_slice(&self.timestamp.to_le_bytes());
        message.extend_from_slice(&self.sequence.to_le_bytes());
        
        if let Some(source_id) = &self.source_id {
            message.extend_from_slice(source_id);
        }
        
        if let Some(destination_id) = &self.destination_id {
            message.extend_from_slice(destination_id);
        }
        
        message.extend_from_slice(&self.payload);
        
        // Verify the signature using ML-DSA
        match zks_pqcrypto::ml_dsa::MlDsa::verify(&message, signature, public_key) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Message builder for constructing protocol messages
pub struct MessageBuilder {
    message_type: MessageType,
    priority: Option<MessagePriority>,
    source_id: Option<Vec<u8>>,
    destination_id: Option<Vec<u8>>,
    payload: Option<Vec<u8>>,
}

impl MessageBuilder {
    /// Create a new message builder
    pub fn new(message_type: MessageType) -> Self {
        Self {
            message_type,
            priority: None,
            source_id: None,
            destination_id: None,
            payload: None,
        }
    }
    
    /// Set message priority
    pub fn priority(mut self, priority: MessagePriority) -> Self {
        self.priority = Some(priority);
        self
    }
    
    /// Set source peer ID
    pub fn source_id(mut self, source_id: Vec<u8>) -> Self {
        self.source_id = Some(source_id);
        self
    }
    
    /// Set destination peer ID
    pub fn destination_id(mut self, destination_id: Vec<u8>) -> Self {
        self.destination_id = Some(destination_id);
        self
    }
    
    /// Set payload
    pub fn payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = Some(payload.into());
        self
    }
    
    /// Build the final message with sequence number
    pub fn build(self, sequence: u64) -> ProtocolMessage {
        let mut message = ProtocolMessage::new(
            self.message_type,
            self.payload.unwrap_or_default(),
            sequence,
        );
        
        if let Some(priority) = self.priority {
            message = message.with_priority(priority);
        }
        
        if let Some(source_id) = self.source_id {
            message = message.with_source_id(source_id);
        }
        
        if let Some(destination_id) = self.destination_id {
            message = message.with_destination_id(destination_id);
        }
        
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_creation() {
        let message = ProtocolMessage::data(b"test payload", 1);
        assert_eq!(message.message_type, MessageType::Data);
        assert_eq!(message.sequence, 1);
        assert_eq!(message.payload.as_slice(), b"test payload");
    }
    
    #[test]
    fn test_message_serialization() {
        let message = ProtocolMessage::data(b"test payload", 1);
        let bytes = message.to_bytes().unwrap();
        let deserialized = ProtocolMessage::from_bytes(&bytes).unwrap();
        
        assert_eq!(deserialized.message_type, message.message_type);
        assert_eq!(deserialized.sequence, message.sequence);
        assert_eq!(deserialized.payload, message.payload);
    }
    
    #[test]
    fn test_message_builder() {
        let message = MessageBuilder::new(MessageType::Data)
            .priority(MessagePriority::High)
            .source_id(vec![1, 2, 3])
            .destination_id(vec![4, 5, 6])
            .payload(b"test payload")
            .build(42);
            
        assert_eq!(message.message_type, MessageType::Data);
        assert_eq!(message.priority, MessagePriority::High);
        assert_eq!(message.sequence, 42);
        assert_eq!(message.source_id, Some(vec![1, 2, 3]));
        assert_eq!(message.destination_id, Some(vec![4, 5, 6]));
        assert_eq!(message.payload.as_slice(), b"test payload");
    }
    
    #[test]
    fn test_message_expiration() {
        let mut message = ProtocolMessage::data(b"test", 1);
        message.timestamp = 0; // Very old timestamp
        
        assert!(message.is_expired(3600)); // Expired if older than 1 hour
        
        message.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        assert!(!message.is_expired(3600)); // Not expired if recent
    }
}