//! Error types for ZKS SDK

use thiserror::Error;
use zks_wire::WireError;

/// Result type alias for ZKS SDK operations
pub type Result<T> = std::result::Result<T, SdkError>;

/// Main error type for ZKS SDK operations
#[derive(Error, Debug)]
pub enum SdkError {
    /// Invalid URL format
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    
    /// Connection failed
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
    
    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),
    
    /// Protocol error
    #[error("Protocol error: {0}")]
    ProtocolError(#[from] zks_proto::ProtoError),
    
    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    /// Post-quantum crypto error
    #[error("Post-quantum crypto error: {0}")]
    PqcError(#[from] zks_pqcrypto::PqcError),
    
    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    /// Wire protocol error
    #[error("Wire protocol error: {0}")]
    WireError(#[from] WireError),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    /// Timeout error
    #[error("Operation timed out")]
    Timeout,
    
    /// Not connected
    #[error("Not connected to peer")]
    NotConnected,
    
    /// Invalid state
    #[error("Invalid connection state")]
    InvalidState,
    
    /// Not implemented
    #[error("Not implemented")]
    NotImplemented,
    
    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}