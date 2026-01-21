//! Error types for the ZKS OTP crate

use std::io;
use thiserror::Error;

/// Main error type for the ZKS OTP crate
#[derive(Error, Debug)]
pub enum OtpError {
    /// I/O error occurred
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Invalid key file format
    #[error("Invalid key file format: {0}")]
    InvalidKeyFile(String),

    /// Key file is corrupted or tampered with
    #[error("Key file corruption detected: {0}")]
    KeyFileCorrupted(String),

    /// Insufficient key material remaining
    #[error("Insufficient key material: {requested} bytes requested, {remaining} bytes remaining")]
    InsufficientKeyMaterial {
        /// Number of bytes requested
        requested: u64,
        /// Number of bytes remaining in key file
        remaining: u64,
    },

    /// Key reuse detected (attempted to reuse already consumed key material)
    #[error("Key reuse detected at offset {offset}")]
    KeyReuse { 
        /// Byte offset where key reuse was detected
        offset: u64 
    },

    /// Hardware RNG error
    #[error("Hardware RNG error: {0}")]
    HardwareRng(String),

    /// Unsupported feature or operation
    #[error("Unsupported: {0}")]
    Unsupported(String),

    /// Encryption/Decryption error
    #[error("Cipher error: {0}")]
    Cipher(String),

    /// Secure deletion failed
    #[error("Secure deletion failed: {0}")]
    ShredFailed(String),

    /// Invalid input parameters
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// File path error
    #[error("File path error: {0}")]
    FilePath(String),
}

/// Convenience type alias for Results using OtpError
pub type Result<T> = std::result::Result<T, OtpError>;

impl OtpError {
    /// Create a new cipher error
    pub fn cipher<S: Into<String>>(msg: S) -> Self {
        OtpError::Cipher(msg.into())
    }

    /// Create a new invalid parameter error
    pub fn invalid<S: Into<String>>(msg: S) -> Self {
        OtpError::InvalidParameter(msg.into())
    }

    /// Create a new unsupported error
    pub fn unsupported<S: Into<String>>(msg: S) -> Self {
        OtpError::Unsupported(msg.into())
    }

    /// Create a new I/O error
    pub fn io_error<S: Into<String>>(msg: S) -> Self {
        OtpError::Io(io::Error::new(io::ErrorKind::Other, msg.into()))
    }

    /// Create a new corrupted key file error
    pub fn corrupted<S: Into<String>>(msg: S) -> Self {
        OtpError::KeyFileCorrupted(msg.into())
    }

    /// Create a new key exhausted error
    pub fn key_exhausted<S: Into<String>>(_msg: S) -> Self {
        OtpError::InsufficientKeyMaterial {
            requested: 0,
            remaining: 0,
        }
    }

    /// Create a new RNG error
    pub fn rng_error<S: Into<String>>(msg: S) -> Self {
        OtpError::HardwareRng(msg.into())
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            OtpError::Io(_) | OtpError::InvalidParameter(_) | OtpError::FilePath(_)
        )
    }

    /// Check if this error indicates a security issue
    pub fn is_security_issue(&self) -> bool {
        matches!(
            self,
            OtpError::KeyFileCorrupted(_) | OtpError::KeyReuse { .. } | OtpError::Cipher(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = OtpError::cipher("test error");
        assert!(matches!(err, OtpError::Cipher(_)));
        
        let err = OtpError::invalid("bad param");
        assert!(matches!(err, OtpError::InvalidParameter(_)));
    }

    #[test]
    fn test_error_recoverable() {
        let io_err = OtpError::Io(io::Error::new(io::ErrorKind::NotFound, "file not found"));
        assert!(io_err.is_recoverable());
        
        let cipher_err = OtpError::cipher("encryption failed");
        assert!(!cipher_err.is_recoverable());
    }

    #[test]
    fn test_security_issues() {
        let key_reuse = OtpError::KeyReuse { offset: 100 };
        assert!(key_reuse.is_security_issue());
        
        let corrupted = OtpError::KeyFileCorrupted("checksum mismatch".to_string());
        assert!(corrupted.is_security_issue());
    }
}