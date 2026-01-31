use thiserror::Error;

/// Cover traffic error types
/// 
/// This enum represents all possible errors that can occur during cover traffic
/// generation, scheduling, and cryptographic operations.
#[derive(Error, Debug)]
pub enum CoverError {
    /// Invalid configuration parameter
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    /// Network operation failed
    #[error("Network error: {0}")]
    NetworkError(String),
    
    /// Scheduling error
    #[error("Scheduling error: {0}")]
    SchedulingError(String),
    
    /// Generator is already running
    #[error("Generator is already running")]
    AlreadyRunning,
    
    /// Generator is not running
    #[error("Generator is not running")]
    NotRunning,
    
    /// Invalid timing parameter
    #[error("Invalid timing parameter: {0}")]
    InvalidTiming(String),
    
    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionError(String),
    
    /// ML-KEM operation failed
    #[error("ML-KEM error: {0}")]
    MlKemError(String),
    
    /// Wasif-Vernam cipher error
    #[error("Wasif-Vernam error: {0}")]
    VernamError(String),
    
    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),
    
    /// Transport/network layer error
    #[error("Transport error: {0}")]
    TransportError(String),
}

/// Result type alias for cover traffic operations
/// 
/// This is a convenience type alias that should be used for all fallible operations
/// in the cover traffic crate. It automatically uses the CoverError type.
pub type Result<T> = std::result::Result<T, CoverError>;

impl From<zks_pqcrypto::errors::PqcError> for CoverError {
    fn from(err: zks_pqcrypto::errors::PqcError) -> Self {
        CoverError::MlKemError(err.to_string())
    }
}

impl From<zks_crypt::true_vernam::EntropyError> for CoverError {
    fn from(err: zks_crypt::true_vernam::EntropyError) -> Self {
        CoverError::VernamError(format!("{:?}", err))
    }
}

impl From<statrs::StatsError> for CoverError {
    fn from(err: statrs::StatsError) -> Self {
        CoverError::InvalidTiming(format!("Poisson distribution error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_display() {
        let err = CoverError::InvalidConfig("test config".to_string());
        assert_eq!(err.to_string(), "Invalid configuration: test config");
    }
}