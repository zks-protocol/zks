use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zks_pqcrypto::{MlDsa, MlDsaKeypair};
use crate::error::{Result, SdkError};

/// Represents a persistent ZKS identity (Long-term ML-DSA-87 Signing Key)
#[derive(Debug, Serialize, Deserialize)]
pub struct ZksIdentity {
    /// The underlying ML-DSA keypair (encoded as bytes for serialization)
    key_bytes: Vec<u8>,
}

impl ZksIdentity {
    /// Generate a new random identity
    pub fn generate() -> Result<Self> {
        let keypair = MlDsa::generate_keypair()
            .map_err(|e| SdkError::CryptoError(format!("Failed to generate identity: {}", e)))?;
            
        // Concatenate VK and SK for storage
        let mut key_bytes = keypair.verifying_key().to_vec();
        key_bytes.extend_from_slice(keypair.signing_key());
        
        Ok(Self {
            key_bytes,
        })
    }

    /// Load identity from a file (JSON format)
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| SdkError::IoError(e))?;
            
        serde_json::from_str(&content)
            .map_err(|e| SdkError::ConfigError(format!("Failed to parse identity file: {}", e)))
    }

    /// Save identity to a file (JSON format)
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| SdkError::ConfigError(format!("Failed to serialize identity: {}", e)))?;
            
        fs::write(path, content)
            .map_err(|e| SdkError::IoError(e))
    }

    /// Get the ML-DSA public key fingerprint (SHA256 hex)
    pub fn fingerprint(&self) -> Result<String> {
        use sha2::{Sha256, Digest};
        // We can extract VK directly from bytes without full parsing
        // VK is first part. But assume sizes might vary if we support multiple algos later.
        // For now, parsing is safer validation.
        let keypair = self.to_keypair()?;
        let pk_bytes = keypair.verifying_key();
        let hash = Sha256::digest(pk_bytes);
        Ok(hex::encode(hash))
    }

    /// Sign a message with this identity
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let keypair = self.to_keypair()?;
        MlDsa::sign(message, keypair.signing_key())
            .map_err(|e| SdkError::CryptoError(format!("Signing failed: {}", e)))
    }
    
    /// Verify a signature against this identity
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let keypair = self.to_keypair()?;
        match MlDsa::verify(message, signature, keypair.verifying_key()) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get the underlying ML-DSA keypair
    pub fn to_keypair(&self) -> Result<MlDsaKeypair> {
        use zks_pqcrypto::ml_dsa::{PUBLIC_KEY_SIZE, SECRET_KEY_SIZE};
        
        let expected_len = PUBLIC_KEY_SIZE + SECRET_KEY_SIZE;
        if self.key_bytes.len() != expected_len {
             return Err(SdkError::CryptoError(format!(
                "Invalid key data length: expected {}, got {}", 
                expected_len, 
                self.key_bytes.len()
            )));
        }

        let (vk, sk) = self.key_bytes.split_at(PUBLIC_KEY_SIZE);
        
        MlDsaKeypair::from_bytes(vk.to_vec(), sk.to_vec())
            .map_err(|e| SdkError::CryptoError(format!("Invalid key data: {}", e)))
    }
    
    /// Get the underlying public key bytes
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        let keypair = self.to_keypair()?;
        Ok(keypair.verifying_key().to_vec())
    }
}
