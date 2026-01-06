//! Error types for zks_wire crate

use thiserror::Error;

/// Result type alias for zks_wire operations
pub type Result<T> = std::result::Result<T, WireError>;

/// Main error type for wire networking operations
#[derive(Error, Debug)]
pub enum WireError {
    /// Network I/O error
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    
    /// STUN protocol error
    #[error("STUN error: {0}")]
    Stun(String),
    
    /// NAT traversal error
    #[error("NAT traversal error: {0}")]
    NatTraversal(String),
    
    /// Peer not found in swarm
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    
    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),
    
    /// Connection timeout
    #[error("Connection timeout")]
    Timeout,
    
    /// Address resolution error
    #[error("Address resolution error: {0}")]
    AddressResolution(String),
    
    /// Protocol version mismatch
    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    ProtocolVersionMismatch {
        /// Expected protocol version
        expected: u8,
        /// Actual protocol version received
        actual: u8,
    },
    
    /// Encryption/Decryption error
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    /// URL parsing error
    #[error("URL parsing error: {0}")]
    UrlParse(#[from] url::ParseError),
    
    /// Generic error with message
    #[error("{0}")]
    Other(String),
    
    /// Bind error (cannot bind to address)
    #[error("Bind error: {0}")]
    BindError(String),
    
    /// Connection error
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
    /// Authentication error
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    
    /// Resource exhausted
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),
    
    /// Not found
    #[error("Not found: {0}")]
    NotFound(String),
    
    /// Not connected
    #[error("Not connected: {0}")]
    NotConnected(String),
    
    /// Channel error
    #[error("Channel error: {0}")]
    ChannelError(String),
}

impl WireError {
    /// Create a new STUN error
    pub fn stun<S: Into<String>>(msg: S) -> Self {
        WireError::Stun(msg.into())
    }
    
    /// Create a new NAT traversal error
    pub fn nat<S: Into<String>>(msg: S) -> Self {
        WireError::NatTraversal(msg.into())
    }
    
    /// Create a new peer not found error
    pub fn peer_not_found<S: Into<String>>(peer_id: S) -> Self {
        WireError::PeerNotFound(peer_id.into())
    }
    
    /// Create a new invalid message error
    pub fn invalid_message<S: Into<String>>(msg: S) -> Self {
        WireError::InvalidMessage(msg.into())
    }
    
    /// Create a new address resolution error
    pub fn address_resolution<S: Into<String>>(msg: S) -> Self {
        WireError::AddressResolution(msg.into())
    }
    
    /// Create a new crypto error
    pub fn crypto<S: Into<String>>(msg: S) -> Self {
        WireError::Crypto(msg.into())
    }
    
    /// Create a generic error
    pub fn other<S: Into<String>>(msg: S) -> Self {
        WireError::Other(msg.into())
    }
}