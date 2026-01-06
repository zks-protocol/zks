//! Error types for ZKS Protocol
//! 
//! This module provides comprehensive error handling for the ZKS Protocol ecosystem,
//! including categorized error types and convenience result types.

use std::fmt;
use std::error::Error as StdError;

/// Main error type for ZKS Protocol operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZksError {
    /// The category of error that occurred
    pub kind: ErrorKind,
    /// Human-readable description of the error
    pub message: String,
}

impl ZksError {
    /// Create a new ZksError with the specified kind and message
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
    
    /// Create a cryptographic error
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Crypto, message)
    }
    
    /// Create a network error
    pub fn network(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Network, message)
    }
    
    /// Create a protocol error
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Protocol, message)
    }
}

impl fmt::Display for ZksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl StdError for ZksError {}

/// Error categories for ZKS Protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Cryptographic operation failed
    Crypto,
    /// Network operation failed
    Network,
    /// Protocol violation or error
    Protocol,
    /// Invalid parameter provided
    InvalidParameter,
    /// Authentication failed
    Authentication,
    /// Resource not found
    NotFound,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Crypto => write!(f, "CryptoError"),
            ErrorKind::Network => write!(f, "NetworkError"),
            ErrorKind::Protocol => write!(f, "ProtocolError"),
            ErrorKind::InvalidParameter => write!(f, "InvalidParameter"),
            ErrorKind::Authentication => write!(f, "AuthenticationError"),
            ErrorKind::NotFound => write!(f, "NotFound"),
        }
    }
}

/// Convenience type alias for results with ZksError
pub type Result<T> = std::result::Result<T, ZksError>;