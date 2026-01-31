use thiserror::Error;

/// Errors that can occur in SURB operations
#[derive(Error, Debug)]
pub enum SurbError {
    /// Invalid SURB configuration
    #[error("Invalid SURB configuration: {0}")]
    InvalidConfig(String),
    
    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    /// SURB has already been used
    #[error("SURB has already been used")]
    SurbAlreadyUsed,
    
    /// SURB has expired
    #[error("SURB has expired")]
    SurbExpired,
    
    /// Invalid SURB format or data
    #[error("Invalid SURB: {0}")]
    InvalidSurb(String),
    
    /// Route construction failed
    #[error("Route construction failed: {0}")]
    RouteError(String),
    
    /// Encryption/decryption failed
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    
    /// SURB storage error
    #[error("Storage error: {0}")]
    StorageError(String),
    
    /// SURB serialization/deserialization failed
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for SURB operations
pub type Result<T> = std::result::Result<T, SurbError>;