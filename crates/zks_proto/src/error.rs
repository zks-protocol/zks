//! Error types for zks_proto crate

use thiserror::Error;

/// Result type alias for zks_proto operations
pub type Result<T> = std::result::Result<T, ProtoError>;

/// Main error type for protocol operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ProtoError {
    /// Invalid URL format
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    
    /// Unsupported URL scheme
    #[error("Unsupported URL scheme: {0}")]
    UnsupportedScheme(String),
    
    /// Handshake protocol error
    #[error("Handshake error: {0}")]
    HandshakeError(String),
    
    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    /// Message serialization/deserialization error
    #[error("Message error: {0}")]
    MessageError(String),
    
    /// Network operation failed
    #[error("Network error: {0}")]
    NetworkError(String),
    
    /// Invalid protocol state
    #[error("Invalid protocol state: {0}")]
    InvalidState(String),
    
    /// Timeout occurred
    #[error("Operation timed out")]
    Timeout,
    
    /// Other error
    #[error("Protocol error: {0}")]
    Other(String),
}

impl ProtoError {
    /// Create a new invalid URL error
    pub fn invalid_url(msg: impl Into<String>) -> Self {
        Self::InvalidUrl(msg.into())
    }
    
    /// Create a new unsupported scheme error
    pub fn unsupported_scheme(scheme: impl Into<String>) -> Self {
        Self::UnsupportedScheme(scheme.into())
    }
    
    /// Create a new handshake error
    pub fn handshake(msg: impl Into<String>) -> Self {
        Self::HandshakeError(msg.into())
    }
    
    /// Create a new crypto error
    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::CryptoError(msg.into())
    }
    
    /// Create a new message error
    pub fn message(msg: impl Into<String>) -> Self {
        Self::MessageError(msg.into())
    }
    
    /// Create a new network error
    pub fn network(msg: impl Into<String>) -> Self {
        Self::NetworkError(msg.into())
    }
    
    /// Create a new invalid state error
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Self::InvalidState(msg.into())
    }
    
    /// Create a new other error
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_creation() {
        let error = ProtoError::invalid_url("test error");
        assert!(matches!(error, ProtoError::InvalidUrl(_)));
        
        let error = ProtoError::unsupported_scheme("zk");
        assert!(matches!(error, ProtoError::UnsupportedScheme(_)));
        
        let error = ProtoError::handshake("test error");
        assert!(matches!(error, ProtoError::HandshakeError(_)));
    }
}