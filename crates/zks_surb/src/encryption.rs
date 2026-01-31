use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
// Note: rand::Rng removed - using OsRng directly for security
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{SurbError, Result};

/// Encryption for SURB replies using ChaCha20-Poly1305
#[derive(Debug)]
pub struct SurbEncryption {
    key: [u8; 32],
}

impl SurbEncryption {
    /// Create a new SURB encryption instance
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
    
    /// Encrypt reply content
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedReply> {
        // Create cipher
        let key = Key::from_slice(&self.key);
        let cipher = ChaCha20Poly1305::new(key);
        
        // Generate random nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        // Encrypt the plaintext
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| SurbError::EncryptionError(format!("Encryption failed: {}", e)))?;
        
        Ok(EncryptedReply {
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }
    
    /// Decrypt reply content
    pub fn decrypt(&self, encrypted: &EncryptedReply) -> Result<Vec<u8>> {
        // Create cipher
        let key = Key::from_slice(&self.key);
        let cipher = ChaCha20Poly1305::new(key);
        
        // Create nonce
        let nonce = Nonce::from_slice(&encrypted.nonce);
        
        // Decrypt the ciphertext
        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| SurbError::EncryptionError(format!("Decryption failed: {}", e)))?;
        
        Ok(plaintext)
    }
}

/// Encrypted reply data
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedReply {
    /// ChaCha20-Poly1305 nonce (12 bytes)
    pub nonce: Vec<u8>,
    
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
}

impl EncryptedReply {
    /// Create a new encrypted reply
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }
    
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| SurbError::SerializationError(format!("Failed to serialize encrypted reply: {}", e)))
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| SurbError::SerializationError(format!("Failed to deserialize encrypted reply: {}", e)))
    }
    
    /// Get the size of the encrypted data
    pub fn size(&self) -> usize {
        self.nonce.len() + self.ciphertext.len()
    }
}

/// Helper functions for SURB encryption
pub mod encryption_utils {
    use super::*;
    
    /// Generate a random encryption key for SURB using cryptographically secure RNG
    /// 
    /// # Security
    /// Uses `OsRng` (OS-provided CSPRNG) because predictable keys enable
    /// complete plaintext recovery.
    pub fn generate_encryption_key() -> [u8; 32] {
        // SECURITY: Use OsRng for cryptographically secure key generation
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }
    
    /// Derive encryption key from ML-KEM shared secret
    pub fn derive_key_from_shared_secret(shared_secret: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        
        let mut hasher = Sha256::new();
        hasher.update(b"zks-surb-encryption-key");
        hasher.update(shared_secret);
        let result = hasher.finalize();
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }
    
    /// Validate encrypted reply format
    pub fn validate_encrypted_reply(encrypted: &EncryptedReply) -> bool {
        // Check nonce length (ChaCha20-Poly1305 requires 12 bytes)
        if encrypted.nonce.len() != 12 {
            return false;
        }
        
        // Check ciphertext is not empty
        if encrypted.ciphertext.is_empty() {
            return false;
        }
        
        // Check total size is reasonable (max 64KB)
        if encrypted.size() > 65536 {
            return false;
        }
        
        true
    }
}