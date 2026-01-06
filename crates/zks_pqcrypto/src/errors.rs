//! Error types for zks_pqcrypto crate

use thiserror::Error;

/// Main error type for post-quantum cryptographic operations
#[derive(Error, Debug)]
pub enum PqcError {
    /// ML-KEM (Kyber) related errors
    #[error("ML-KEM error: {0}")]
    MlKem(String),

    /// ML-DSA (Dilithium) related errors
    #[error("ML-DSA error: {0}")]
    MlDsa(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Invalid key format or size
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid ciphertext or signature
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Random number generation failed
    #[error("RNG error: {0}")]
    RngError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Operation not supported
    #[error("Operation not supported: {0}")]
    NotSupported(String),
}

/// Result type alias for post-quantum cryptographic operations
pub type Result<T> = std::result::Result<T, PqcError>;