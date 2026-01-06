//! Cryptographic types and parameters for ZKS Protocol
//! 
//! This module provides core cryptographic types including:
//! - Security buffers for encrypted data
//! - Cryptographic parameter configurations
//! - Algorithm selection enums
//! - Security level definitions

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Security buffer for encrypted data
/// 
/// # Examples
/// 
/// ```
/// use zks_types::crypto::SecBuffer;
/// 
/// let buffer = SecBuffer::new(vec![1, 2, 3, 4]);
/// let empty = SecBuffer::empty();
/// ```
#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct SecBuffer {
    /// The encrypted data stored in this security buffer
    data: Vec<u8>,
}

impl SecBuffer {
    /// Create a new security buffer with the given data
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    /// Create an empty security buffer
    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }
    
    /// Get the length of the data in this buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    /// Check if this buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    
    /// Get a reference to the data in this buffer
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    /// Get a mutable reference to the data in this buffer
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

/// Secure debug implementation that doesn't expose sensitive data
impl std::fmt::Debug for SecBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecBuffer([REDACTED; {} bytes])", self.data.len())
    }
}

/// Manual Drop implementation for secure cleanup
impl Drop for SecBuffer {
    fn drop(&mut self) {
        // Zeroize the data when the buffer is dropped
        self.data.zeroize();
    }
}

/// Cryptographic parameters for ZKS protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoParameters {
    /// Key encapsulation mechanism algorithm
    pub kem_algorithm: KemAlgorithm,
    /// Symmetric encryption algorithm
    pub encryption_algorithm: EncryptionAlgorithm,
    /// Security level for the cryptographic operations
    pub security_level: SecurityLevel,
}

impl Default for CryptoParameters {
    fn default() -> Self {
        Self {
            kem_algorithm: KemAlgorithm::MlKem,
            encryption_algorithm: EncryptionAlgorithm::ChaCha20,
            security_level: SecurityLevel::High,
        }
    }
}

/// Key Encapsulation Mechanism algorithms
/// 
/// Note: ML-KEM is the NIST standardized version of Kyber, providing
/// post-quantum key encapsulation with equivalent security properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    /// ML-KEM (NIST standardized Kyber) - post-quantum key encapsulation
    MlKem,
}

impl Default for KemAlgorithm {
    fn default() -> Self {
        Self::MlKem
    }
}

impl fmt::Display for KemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KemAlgorithm::MlKem => write!(f, "ML-KEM"),
        }
    }
}

/// Symmetric encryption algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// ChaCha20 stream cipher
    ChaCha20,
    /// AES-256-GCM
    Aes256Gcm,
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::ChaCha20
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionAlgorithm::ChaCha20 => write!(f, "ChaCha20"),
            EncryptionAlgorithm::Aes256Gcm => write!(f, "AES-256-GCM"),
        }
    }
}

/// Security levels for different use cases
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Standard security (128-bit equivalent)
    Standard,
    /// High security (192-bit equivalent)
    High,
    /// Extreme security (256-bit equivalent)
    Extreme,
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityLevel::Standard => write!(f, "Standard"),
            SecurityLevel::High => write!(f, "High"),
            SecurityLevel::Extreme => write!(f, "Extreme"),
        }
    }
}