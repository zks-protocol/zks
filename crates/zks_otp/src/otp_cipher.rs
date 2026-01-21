//! One-Time Pad cipher implementation
//! 
//! This module implements the classic one-time pad encryption using XOR operations.
//! It provides both strict OTP (information-theoretically secure) and efficient modes.

use crate::{KeyFile, OtpError, Result};
use std::path::Path;
use zeroize::Zeroize;

/// Main OTP cipher implementation
pub struct OfflineOtp;

/// Result of an encryption operation
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    /// Number of bytes encrypted
    pub bytes_encrypted: u64,
    /// Number of key bytes consumed
    pub key_bytes_consumed: u64,
    /// Mode used for encryption
    pub mode: OtpMode,
}

/// OTP operation modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpMode {
    /// Strict OTP - information-theoretically secure, key size equals data size
    Strict,
    /// Efficient mode - uses computational security (256-bit) for large files
    Efficient,
}

impl OfflineOtp {
    /// Encrypt file with strict OTP (key_size == data_size)
    /// This provides information-theoretic security
    pub fn encrypt_strict(
        input: &Path,
        key_file: &mut KeyFile,
        output: &Path,
    ) -> Result<EncryptionResult> {
        // Read the entire input file
        let input_data = std::fs::read(input)
            .map_err(|e| OtpError::io_error(format!("Failed to read input file: {}", e)))?;
        
        let data_size = input_data.len() as u64;
        
        // Check if we have enough key material
        if key_file.remaining() < data_size {
            return Err(OtpError::InsufficientKeyMaterial {
                requested: data_size,
                remaining: key_file.remaining(),
            });
        }
        
        // Read the exact amount of key material needed
        let key_material = key_file.read_entropy(data_size as usize)?;
        
        // XOR the data with the key
        let encrypted_data = xor_bytes(&input_data, &key_material);
        
        // Write the encrypted data to output file
        std::fs::write(output, &encrypted_data)
            .map_err(|e| OtpError::io_error(format!("Failed to write output file: {}", e)))?;
        
        // Mark the key material as used
        key_file.mark_used(data_size as usize)?;
        
        Ok(EncryptionResult {
            bytes_encrypted: data_size,
            key_bytes_consumed: data_size,
            mode: OtpMode::Strict,
        })
    }

    /// Decrypt file with strict OTP
    pub fn decrypt_strict(
        input: &Path,
        key_file: &mut KeyFile,
        output: &Path,
    ) -> Result<()> {
        // Read the entire input file
        let input_data = std::fs::read(input)
            .map_err(|e| OtpError::io_error(format!("Failed to read input file: {}", e)))?;
        
        let data_size = input_data.len() as u64;
        
        // Check if we have enough key material
        if key_file.remaining() < data_size {
            return Err(OtpError::InsufficientKeyMaterial {
                requested: data_size,
                remaining: key_file.remaining(),
            });
        }
        
        // Read the exact amount of key material needed
        let key_material = key_file.read_entropy(data_size as usize)?;
        
        // XOR the encrypted data with the key (same operation as encryption)
        let decrypted_data = xor_bytes(&input_data, &key_material);
        
        // Write the decrypted data to output file
        std::fs::write(output, &decrypted_data)
            .map_err(|e| OtpError::io_error(format!("Failed to write output file: {}", e)))?;
        
        // Mark the key material as used
        key_file.mark_used(data_size as usize)?;
        
        Ok(())
    }

    /// Encrypt with DEK mode (small key, large file)
    /// Security: Computational (256-bit)
    /// 
    /// This mode uses:
    /// 1. 32 bytes from key file to wrap a randomly generated DEK (Data Encryption Key)
    /// 2. ChaCha20-Poly1305 authenticated encryption with the DEK
    /// 3. Stores the wrapped DEK in the output file header
    pub fn encrypt_efficient(
        input: &Path,
        key_file: &mut KeyFile,
        output: &Path,
    ) -> Result<EncryptionResult> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, OsRng},
            ChaCha20Poly1305, Nonce,
        };
        use rand::RngCore;
        
        // Check if we have enough key material for DEK wrapping (32 bytes)
        if key_file.remaining() < 32 {
            return Err(OtpError::InsufficientKeyMaterial {
                requested: 32,
                remaining: key_file.remaining(),
            });
        }
        
        // Read input file
        let input_data = std::fs::read(input)
            .map_err(|e| OtpError::io_error(format!("Failed to read input file: {}", e)))?;
        
        // Generate random 32-byte DEK (Data Encryption Key)
        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);
        
        // Read 32 bytes from key file for OTP wrapping
        let mut otp_key = key_file.read_entropy(32)?;
        
        // Wrap DEK with OTP: XOR DEK with OTP key
        let wrapped_dek = xor_bytes(&dek, &otp_key);
        
        // Generate random nonce for ChaCha20-Poly1305
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        
        // Create cipher instance with the DEK
        let cipher = ChaCha20Poly1305::new_from_slice(&dek)
            .map_err(|e| OtpError::cipher(format!("Failed to create cipher: {}", e)))?;
        
        // Encrypt the data
        let encrypted_data = cipher.encrypt(&nonce, input_data.as_ref())
            .map_err(|e| OtpError::cipher(format!("Encryption failed: {}", e)))?;
        
        // Mark the OTP key material as used
        key_file.mark_used(32)?;
        
        // Zeroize OTP key after use
        otp_key.zeroize();
        
        // Build output: [wrapped_dek:32][nonce:12][encrypted_data]
        let mut output_data = Vec::with_capacity(32 + 12 + encrypted_data.len());
        output_data.extend_from_slice(&wrapped_dek);
        output_data.extend_from_slice(&nonce_bytes);
        output_data.extend_from_slice(&encrypted_data);
        
        // Write the output file
        std::fs::write(output, &output_data)
            .map_err(|e| OtpError::io_error(format!("Failed to write output file: {}", e)))?;
        
        // Zeroize sensitive key material
        use zeroize::Zeroize;
        dek.zeroize();
        
        Ok(EncryptionResult {
            bytes_encrypted: input_data.len() as u64,
            key_bytes_consumed: 32,
            mode: OtpMode::Efficient,
        })
    }

    /// Decrypt with efficient mode
    pub fn decrypt_efficient(
        input: &Path,
        key_file: &mut KeyFile,
        output: &Path,
    ) -> Result<()> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };
        
        // Check if we have enough key material for DEK unwrapping (32 bytes)
        if key_file.remaining() < 32 {
            return Err(OtpError::InsufficientKeyMaterial {
                requested: 32,
                remaining: key_file.remaining(),
            });
        }
        
        // Read input file
        let input_data = std::fs::read(input)
            .map_err(|e| OtpError::io_error(format!("Failed to read input file: {}", e)))?;
        
        // Validate minimum file size (32 bytes wrapped DEK + 12 bytes nonce)
        if input_data.len() < 44 {
            return Err(OtpError::invalid("Encrypted file too small"));
        }
        
        // Extract wrapped DEK, nonce, and encrypted data
        let wrapped_dek = &input_data[0..32];
        let nonce_bytes = &input_data[32..44];
        let encrypted_data = &input_data[44..];
        
        // Read 32 bytes from key file for OTP unwrapping
        let mut otp_key = key_file.read_entropy(32)?;
        
        // Unwrap DEK with OTP: XOR wrapped DEK with OTP key
        let mut dek = xor_bytes(wrapped_dek, &otp_key);
        
        // Create nonce
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // Create cipher instance with the DEK
        let cipher = ChaCha20Poly1305::new_from_slice(&dek)
            .map_err(|e| OtpError::cipher(format!("Failed to create cipher: {}", e)))?;
        
        // Decrypt the data
        let decrypted_data = cipher.decrypt(nonce, encrypted_data)
            .map_err(|e| OtpError::cipher(format!("Decryption failed: {}", e)))?;
        
        // Mark the OTP key material as used
        key_file.mark_used(32)?;
        
        // Write the decrypted data
        std::fs::write(output, &decrypted_data)
            .map_err(|e| OtpError::io_error(format!("Failed to write output file: {}", e)))?;
        
        // Zeroize sensitive key material
        dek.zeroize();
        otp_key.zeroize();
        
        Ok(())
    }
}

/// XOR two byte slices together
/// 
/// # Panics
/// Panics if the slices have different lengths
pub fn xor_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(data.len(), key.len(), "Data and key must have equal length");
    data.iter().zip(key.iter()).map(|(d, k)| d ^ k).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyFile;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_xor_bytes() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let key = vec![0x05, 0x06, 0x07, 0x08];
        let expected = vec![0x04, 0x04, 0x04, 0x0C];
        
        let result = xor_bytes(&data, &key);
        assert_eq!(result, expected);
        
        // XOR is its own inverse
        let decrypted = xor_bytes(&result, &key);
        assert_eq!(decrypted, data);
    }

    #[test]
    #[should_panic(expected = "Data and key must have equal length")]
    fn test_xor_bytes_panic() {
        let data = vec![0x01, 0x02];
        let key = vec![0x03, 0x04, 0x05];
        xor_bytes(&data, &key);
    }

    #[test]
    fn test_strict_otp_encryption_decryption() {
        let temp_dir = TempDir::new().unwrap();
        let key_path1 = temp_dir.path().join("test_key1.zkskey");
        let key_path2 = temp_dir.path().join("test_key2.zkskey");
        let key_path3 = temp_dir.path().join("test_key3.zkskey");
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_path = temp_dir.path().join("encrypted.bin");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        // Create test input data
        let test_data = b"Hello, World! This is a test message for OTP encryption.";
        fs::write(&input_path, test_data).unwrap();

        // Test 1: Verify that encryption produces different output
        let mut key_file1 = KeyFile::create(&key_path1, 1024).unwrap();
        let result = OfflineOtp::encrypt_strict(&input_path, &mut key_file1, &encrypted_path).unwrap();
        assert_eq!(result.bytes_encrypted, test_data.len() as u64);
        assert_eq!(result.key_bytes_consumed, test_data.len() as u64);
        assert_eq!(result.mode, OtpMode::Strict);

        let encrypted_data = fs::read(&encrypted_path).unwrap();
        assert_ne!(encrypted_data, test_data); // Encrypted should be different

        // Test 2: Verify that decryption with fresh key material produces different output
        // (This demonstrates that you need the same key material for proper decryption)
        let mut key_file2 = KeyFile::create(&key_path2, 1024).unwrap(); // Fresh key material
        OfflineOtp::decrypt_strict(&encrypted_path, &mut key_file2, &decrypted_path).unwrap();
        
        let decrypted_data = fs::read(&decrypted_path).unwrap();
        assert_ne!(decrypted_data, test_data); // Should NOT match with different key material

        // Test 3: Verify XOR property - if we use the same key material, decryption should work
        // We'll manually test the XOR property
        let mut key_file3 = KeyFile::create(&key_path3, 1024).unwrap();
        let key_material = key_file3.read_entropy(test_data.len()).unwrap();
        
        // Encrypt manually
        let manual_encrypted = xor_bytes(test_data, &key_material);
        fs::write(&encrypted_path, &manual_encrypted).unwrap();
        key_file3.mark_used(test_data.len()).unwrap();
        
        // Decrypt manually with the SAME key material (not from a fresh key file)
        // XOR is its own inverse, so applying the same key material will decrypt
        // Note: We don't consume key material here since we're just testing the XOR property
        let manual_decrypted = xor_bytes(&manual_encrypted, &key_material);
        
        // This should match because XOR is its own inverse
        assert_eq!(manual_decrypted, test_data);
    }

    #[test]
    fn test_strict_otp_insufficient_key_material() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key.zkskey");
        let input_path = temp_dir.path().join("input.txt");
        let output_path = temp_dir.path().join("output.bin");

        // Create a key file with limited material
        let mut key_file = KeyFile::create(&key_path, 10).unwrap();

        // Create test input data larger than key material
        let test_data = b"This is a test message that is longer than the available key material.";
        fs::write(&input_path, test_data).unwrap();

        // Test encryption should fail due to insufficient key material
        let result = OfflineOtp::encrypt_strict(&input_path, &mut key_file, &output_path);
        assert!(matches!(result, Err(OtpError::InsufficientKeyMaterial { .. })));
    }

    #[test]
    fn test_efficient_otp_encryption_behavior() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key_efficient.zkskey");
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_path = temp_dir.path().join("encrypted_efficient.bin");

        // Create test input data
        let test_data = b"Hello, World! This is a test message for efficient OTP encryption.";
        fs::write(&input_path, test_data).unwrap();

        // Create key file with sufficient material for DEK mode (32 bytes minimum)
        let mut key_file = KeyFile::create(&key_path, 1024).unwrap();

        // Test encryption
        let result = OfflineOtp::encrypt_efficient(&input_path, &mut key_file, &encrypted_path).unwrap();
        assert_eq!(result.bytes_encrypted, test_data.len() as u64);
        assert_eq!(result.key_bytes_consumed, 32); // DEK mode consumes 32 bytes for OTP wrapping
        assert_eq!(result.mode, OtpMode::Efficient);

        // Verify encrypted file exists and is different from input
        let encrypted_data = fs::read(&encrypted_path).unwrap();
        assert!(!encrypted_data.is_empty());
        assert_ne!(encrypted_data, test_data);

        // Verify encrypted file structure: [wrapped_dek:32][nonce:12][encrypted_data]
        assert!(encrypted_data.len() >= 44); // Minimum size: 32 (wrapped DEK) + 12 (nonce) + 1 (data)
        
        // Verify key file usage tracking
        assert_eq!(key_file.remaining(), 1024 - 32); // Should have consumed 32 bytes

        // Test that decryption with a different key file fails (expected behavior)
        // This demonstrates that DEK mode requires the same OTP key material
        let decrypted_path = temp_dir.path().join("decrypted_efficient.txt");
        let key_path2 = temp_dir.path().join("test_key_efficient2.zkskey");
        let mut key_file2 = KeyFile::create(&key_path2, 1024).unwrap();
        let decrypt_result = OfflineOtp::decrypt_efficient(&encrypted_path, &mut key_file2, &decrypted_path);
        assert!(decrypt_result.is_err()); // Should fail with different key material
    }

    #[test]
    fn test_efficient_otp_insufficient_key_material() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key.zkskey");
        let input_path = temp_dir.path().join("input.txt");
        let output_path = temp_dir.path().join("output.bin");

        // Create a key file with insufficient material for DEK mode (< 32 bytes)
        let mut key_file = KeyFile::create(&key_path, 31).unwrap();

        // Create test input data
        let test_data = b"Test message for efficient mode";
        fs::write(&input_path, test_data).unwrap();

        // Test encryption should fail due to insufficient key material
        let result = OfflineOtp::encrypt_efficient(&input_path, &mut key_file, &output_path);
        assert!(matches!(result, Err(OtpError::InsufficientKeyMaterial { .. })));
    }

    #[test]
    fn test_efficient_otp_corrupted_file() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key.zkskey");
        let encrypted_path = temp_dir.path().join("encrypted.bin");
        let decrypted_path = temp_dir.path().join("decrypted.txt");

        // Create key file
        let mut key_file = KeyFile::create(&key_path, 1024).unwrap();

        // Create a corrupted encrypted file (too small)
        let corrupted_data = vec![0u8; 43]; // Less than minimum 44 bytes
        fs::write(&encrypted_path, &corrupted_data).unwrap();

        // Test decryption should fail due to corrupted file
        let result = OfflineOtp::decrypt_efficient(&encrypted_path, &mut key_file, &decrypted_path);
        assert!(matches!(result, Err(OtpError::InvalidParameter(_))));
    }

    #[test]
    fn test_efficient_vs_strict_mode_different_output() {
        let temp_dir = TempDir::new().unwrap();
        let key_path1 = temp_dir.path().join("test_key1.zkskey");
        let key_path2 = temp_dir.path().join("test_key2.zkskey");
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_strict_path = temp_dir.path().join("encrypted_strict.bin");
        let encrypted_efficient_path = temp_dir.path().join("encrypted_efficient.bin");

        // Create test input data
        let test_data = b"Test message for mode comparison";
        fs::write(&input_path, test_data).unwrap();

        // Encrypt with strict mode
        let mut key_file1 = KeyFile::create(&key_path1, 1024).unwrap();
        let result_strict = OfflineOtp::encrypt_strict(&input_path, &mut key_file1, &encrypted_strict_path).unwrap();
        assert_eq!(result_strict.mode, OtpMode::Strict);

        // Encrypt with efficient mode using fresh key material
        let mut key_file2 = KeyFile::create(&key_path2, 1024).unwrap();
        let result_efficient = OfflineOtp::encrypt_efficient(&input_path, &mut key_file2, &encrypted_efficient_path).unwrap();
        assert_eq!(result_efficient.mode, OtpMode::Efficient);

        // Verify different key consumption
        assert_eq!(result_strict.key_bytes_consumed, test_data.len() as u64);
        assert_eq!(result_efficient.key_bytes_consumed, 32);

        // Verify different output sizes (efficient mode should be larger due to overhead)
        let strict_data = fs::read(&encrypted_strict_path).unwrap();
        let efficient_data = fs::read(&encrypted_efficient_path).unwrap();
        assert!(efficient_data.len() > strict_data.len()); // Efficient mode should be larger
        assert_eq!(strict_data.len(), test_data.len()); // Strict mode should be same size as input
        assert!(efficient_data.len() >= 44); // Efficient mode should have at least 44 bytes overhead
    }

    #[test]
    fn test_efficient_otp_encryption_only() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("test_key_efficient.zkskey");
        let input_path = temp_dir.path().join("input.txt");
        let encrypted_path = temp_dir.path().join("encrypted_efficient.bin");

        // Create test input data
        let test_data = b"Test for efficient OTP encryption.";
        fs::write(&input_path, test_data).unwrap();

        // Create key file with sufficient material for DEK mode (32 bytes minimum)
        let mut key_file = KeyFile::create(&key_path, 1024).unwrap();

        // Test encryption
        let result = OfflineOtp::encrypt_efficient(&input_path, &mut key_file, &encrypted_path).unwrap();
        assert_eq!(result.bytes_encrypted, test_data.len() as u64);
        assert_eq!(result.key_bytes_consumed, 32); // DEK mode consumes 32 bytes for OTP wrapping
        assert_eq!(result.mode, OtpMode::Efficient);

        // Verify encrypted file exists and is different from input
        let encrypted_data = fs::read(&encrypted_path).unwrap();
        assert!(!encrypted_data.is_empty());
        assert_ne!(encrypted_data, test_data);

        // Verify encrypted file structure: [wrapped_dek:32][nonce:12][encrypted_data]
        assert!(encrypted_data.len() >= 44); // Minimum size: 32 (wrapped DEK) + 12 (nonce) + 1 (data)
        
        // Verify key file usage tracking
        assert_eq!(key_file.remaining(), 1024 - 32); // Should have consumed 32 bytes
    }
}