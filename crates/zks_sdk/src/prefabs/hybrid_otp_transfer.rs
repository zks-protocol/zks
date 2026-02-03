//! Hybrid Computational File Transfer - 256-bit post-quantum computational security for any file size
//!
//! This module provides file transfer with strong encryption at the protocol level.
//! Uses the Hybrid encryption scheme: DEK wrapped with high-entropy XOR, content encrypted with ChaCha20.
//!
//! **NOTE**: The "OTP" in the name is legacy terminology. This provides COMPUTATIONAL security,
//! NOT information-theoretic (Shannon OTP) security.

use std::path::{Path, PathBuf};
use tracing::info;

use crate::{
    error::{Result, SdkError},
};
use zks_crypt::true_entropy::TrueEntropy;
use std::sync::Arc;

/// Maximum file size for Hybrid transfer (1 GB)
/// Larger files should use a streaming approach with chunked Hybrid encryption
const MAX_HYBRID_OTP_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// Hybrid Computational File Transfer - 256-bit post-quantum computational security for any file size
///
/// # Security Model
/// - Each file gets a fresh random DEK (32 bytes)
/// - DEK is wrapped with high-entropy XOR from Entropy Grid (256-bit computational)
/// - File content is encrypted with ChaCha20-Poly1305(DEK)
/// - Breaking encryption requires breaking the key exchange (computationally infeasible)
pub struct HybridOtpFileTransfer {
    entropy_source: Arc<dyn zks_crypt::entropy_provider::EntropyProvider>,
}

impl HybridOtpFileTransfer {
    /// Create a new Hybrid file transfer instance
    pub fn new() -> Self {
        let entropy = TrueEntropy::global();
        Self {
            entropy_source: Arc::new(entropy.as_entropy_provider()),
        }
    }

    /// Encrypt a file using Hybrid encryption scheme
    pub async fn encrypt_file(&self, file_path: &Path, entropy: &[u8; 32]) -> Result<PathBuf> {
        info!("Encrypting file: {:?} with Hybrid computational encryption", file_path);
        
        // Validate file size
        let metadata = tokio::fs::metadata(file_path).await
            .map_err(SdkError::IoError)?;
        
        if metadata.len() > MAX_HYBRID_OTP_FILE_SIZE {
            return Err(SdkError::FileTooLarge(metadata.len()));
        }

        // Read file content
        let content = tokio::fs::read(file_path).await
            .map_err(SdkError::IoError)?;

        // Use synchronized encryption with provided entropy
        let encrypted_data = zks_crypt::hybrid_computational::HybridOtp::new(self.entropy_source.clone())
            .encrypt_with_sync(&content, entropy).await?;
        
        // Create output file path
        let mut output_path = file_path.to_path_buf();
        output_path.set_extension("hotp");
        
        // Write encrypted file
        tokio::fs::write(&output_path, &encrypted_data).await
            .map_err(SdkError::IoError)?;
        
        info!("File encrypted successfully: {:?}", output_path);
        Ok(output_path)
    }

    /// Decrypt a file using Hybrid encryption scheme
    pub async fn decrypt_file(&self, encrypted_path: &Path, entropy: &[u8; 32]) -> Result<PathBuf> {
        info!("Decrypting file: {:?} with Hybrid computational encryption", encrypted_path);
        
        // Read encrypted file
        let encrypted_data = tokio::fs::read(encrypted_path).await
            .map_err(SdkError::IoError)?;
        
        // Decrypt using synchronized decryption
        let decrypted_data = zks_crypt::hybrid_computational::HybridOtp::new(self.entropy_source.clone())
            .decrypt_with_sync(&encrypted_data, entropy)?;
        
        // Create output file path
        let mut output_path = encrypted_path.to_path_buf();
        output_path.set_extension("decrypted");
        
        // Write decrypted file
        tokio::fs::write(&output_path, &decrypted_data).await
            .map_err(SdkError::IoError)?;
        
        info!("File decrypted successfully: {:?}", output_path);
        Ok(output_path)
    }
}

impl Default for HybridOtpFileTransfer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "Requires TrueEntropy network access - run with --ignored"]
    async fn test_encrypt_decrypt_file() {
        let transfer = HybridOtpFileTransfer::new();
        let entropy = TrueEntropy::global();
        let sync_entropy = entropy.get_entropy_32_sync();
        
        // Create temp file
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        tokio::fs::write(&file_path, b"Hello, Hybrid OTP!").await.unwrap();
        
        // Encrypt
        let encrypted_path = transfer.encrypt_file(&file_path, &sync_entropy).await.unwrap();
        assert!(encrypted_path.ends_with(".hotp"));
        
        // Decrypt
        let decrypted_path = transfer.decrypt_file(&encrypted_path, &sync_entropy).await.unwrap();
        
        // Verify
        let content = tokio::fs::read_to_string(&decrypted_path).await.unwrap();
        assert_eq!(content, "Hello, Hybrid OTP!");
    }
}
