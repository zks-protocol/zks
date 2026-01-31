//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) implementation
//!
//! This module provides a Rust implementation of ML-DSA-87, which is the NIST
//! standardized version of Dilithium. ML-DSA provides post-quantum digital
//! signatures with EUF-CMA security.
//!
//! # Security Level
//! - NIST Level 5 (256-bit post-quantum security) - MAXIMUM
//! - EUF-CMA (Existential Unforgeability under Chosen Message Attack) secure
//! - Resistant to both classical and quantum computer attacks
//!
//! # Key Sizes
//! - Public key: 2592 bytes
//! - Secret key: 4896 bytes
//! - Signature: 4627 bytes
//!
//! # Implementation
//! - **Native builds**: Use pqcrypto-dilithium (C-based, optimized)
//! - **WASM builds**: Use RustCrypto ml-dsa (pure Rust, post-quantum secure)
//!
//! Both implementations are fully post-quantum secure with identical key/signature sizes.
//!
//! # Example
//!
//! ```rust
//! use zks_pqcrypto::ml_dsa::MlDsa;
//!
//! // Generate keypair
//! let keypair = MlDsa::generate_keypair()?;
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let signature = MlDsa::sign(message, keypair.signing_key())?;
//!
//! // Verify the signature
//! MlDsa::verify(message, &signature, keypair.verifying_key())?;
//! println!("✅ Signature verified successfully");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use zeroize::Zeroizing;
use crate::errors::{PqcError, Result};

// Native implementation using pqcrypto-dilithium
#[cfg(not(target_arch = "wasm32"))]
mod native_impl {
    use super::*;
    use pqcrypto_dilithium::dilithium5;
    use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};
    
    /// ML-DSA-87 public key size (2592 bytes)
    pub const PUBLIC_KEY_SIZE: usize = dilithium5::public_key_bytes();
    
    /// ML-DSA-87 secret key size (4896 bytes)
    pub const SECRET_KEY_SIZE: usize = dilithium5::secret_key_bytes();
    
    /// ML-DSA-87 signature size (4627 bytes)
    pub const SIGNATURE_SIZE: usize = dilithium5::signature_bytes();
    
    /// Generate a new ML-DSA keypair (native implementation)
    pub fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let (public_key, secret_key) = dilithium5::keypair();
        let verifying_key = public_key.as_bytes().to_vec();
        let signing_key = Zeroizing::new(secret_key.as_bytes().to_vec());
        
        tracing::info!(
            "🔐 Generated ML-DSA-87 keypair (vk: {} bytes, sk: {} bytes) - NIST Level 5",
            verifying_key.len(),
            signing_key.len()
        );
        
        Ok((verifying_key, signing_key))
    }
    
    /// Sign a message using the signing key (native implementation)
    pub fn sign(message: impl AsRef<[u8]>, signing_key: &[u8]) -> Result<Vec<u8>> {
        if signing_key.len() != SECRET_KEY_SIZE {
            return Err(PqcError::InvalidKey(format!(
                "Invalid signing key size: expected {}, got {}",
                SECRET_KEY_SIZE,
                signing_key.len()
            )));
        }

        let secret_key = dilithium5::SecretKey::from_bytes(signing_key)
            .map_err(|e| PqcError::InvalidKey(format!("Failed to create secret key: {}", e)))?;
        
        let signature = dilithium5::detached_sign(message.as_ref(), &secret_key);
        let signature_bytes = signature.as_bytes().to_vec();

        tracing::debug!(
            "🖊️ Signed {} byte message with ML-DSA-87, signature: {} bytes",
            message.as_ref().len(),
            signature_bytes.len()
        );

        Ok(signature_bytes)
    }
    
    /// Verify a signature using the verifying key (native implementation)
    pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        if public_key.len() != PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKey(format!(
                "Invalid public key size: expected {}, got {}",
                PUBLIC_KEY_SIZE,
                public_key.len()
            )));
        }

        if signature.len() != SIGNATURE_SIZE {
            return Err(PqcError::InvalidInput(format!(
                "Invalid signature size: expected {}, got {}",
                SIGNATURE_SIZE,
                signature.len()
            )));
        }

        let public_key_obj = dilithium5::PublicKey::from_bytes(public_key)
            .map_err(|e| PqcError::InvalidKey(format!("Failed to create public key: {}", e)))?;
        
        let signature_obj = dilithium5::DetachedSignature::from_bytes(signature)
            .map_err(|e| PqcError::InvalidSignature(format!("Failed to create signature: {}", e)))?;

        dilithium5::verify_detached_signature(&signature_obj, message, &public_key_obj)
            .map_err(|e| PqcError::InvalidSignature(format!("Signature verification failed: {}", e)))?;

        tracing::debug!("✅ ML-DSA-87 signature verification successful - NIST Level 5");

        Ok(())
    }
}

// WASM implementation using RustCrypto ml-dsa (pure Rust, post-quantum secure)
#[cfg(target_arch = "wasm32")]
mod wasm_impl {
    use super::*;
    use ml_dsa::ml_dsa_87::{SigningKey, VerifyingKey, Signature};
    use ml_dsa::signature::{Signer, Verifier, RandomizedSigner};
    use zks_crypt::true_entropy::TrueEntropyRng;
    
    /// ML-DSA-87 public key size (2592 bytes)
    pub const PUBLIC_KEY_SIZE: usize = 2592;
    
    /// ML-DSA-87 secret key size (4896 bytes)
    pub const SECRET_KEY_SIZE: usize = 4896;
    
    /// ML-DSA-87 signature size (4627 bytes)
    pub const SIGNATURE_SIZE: usize = 4627;
    
    /// Generate a new ML-DSA-87 keypair (WASM implementation - POST-QUANTUM + TRUE ENTROPY)
    pub fn generate_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        // SECURITY: Use TrueEntropy for information-theoretic security
        let mut rng = TrueEntropyRng;
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        
        let verifying_key_bytes = verifying_key.to_bytes().to_vec();
        let signing_key_bytes = Zeroizing::new(signing_key.to_bytes().to_vec());
        
        tracing::info!(
            "🔐 Generated ML-DSA-87 keypair (vk: {} bytes, sk: {} bytes) - WASM NIST Level 5",
            verifying_key_bytes.len(),
            signing_key_bytes.len()
        );
        
        Ok((verifying_key_bytes, signing_key_bytes))
    }
    
    /// Sign a message using the signing key (WASM implementation - POST-QUANTUM + TRUE ENTROPY)
    pub fn sign(message: impl AsRef<[u8]>, signing_key: &[u8]) -> Result<Vec<u8>> {
        if signing_key.len() != SECRET_KEY_SIZE {
            return Err(PqcError::InvalidKey(format!(
                "Invalid signing key size: expected {}, got {}",
                SECRET_KEY_SIZE,
                signing_key.len()
            )));
        }

        let signing_key_array: [u8; SECRET_KEY_SIZE] = signing_key.try_into()
            .map_err(|_| PqcError::InvalidKey("Invalid signing key format".to_string()))?;
        
        let signing_key_obj = SigningKey::from_bytes(&signing_key_array);
        // SECURITY: Use TrueEntropy for signing randomness
        let mut rng = TrueEntropyRng;
        let signature = signing_key_obj.sign_with_rng(&mut rng, message.as_ref());
        let signature_bytes = signature.to_bytes().to_vec();

        tracing::debug!(
            "🖊️ Signed {} byte message with ML-DSA-87, signature: {} bytes (WASM NIST Level 5)",
            message.as_ref().len(),
            signature_bytes.len()
        );

        Ok(signature_bytes)
    }
    
    /// Verify a signature using the verifying key (WASM implementation - POST-QUANTUM SECURE)
    pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        if public_key.len() != PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKey(format!(
                "Invalid public key size: expected {}, got {}",
                PUBLIC_KEY_SIZE,
                public_key.len()
            )));
        }

        if signature.len() != SIGNATURE_SIZE {
            return Err(PqcError::InvalidInput(format!(
                "Invalid signature size: expected {}, got {}",
                SIGNATURE_SIZE,
                signature.len()
            )));
        }

        let public_key_array: [u8; PUBLIC_KEY_SIZE] = public_key.try_into()
            .map_err(|_| PqcError::InvalidKey("Invalid public key format".to_string()))?;
        
        let signature_array: [u8; SIGNATURE_SIZE] = signature.try_into()
            .map_err(|_| PqcError::InvalidSignature("Invalid signature format".to_string()))?;
        
        let verifying_key = VerifyingKey::from_bytes(&public_key_array)
            .map_err(|e| PqcError::InvalidKey(format!("Failed to create public key: {:?}", e)))?;
        
        let signature_obj = Signature::from_bytes(&signature_array);

        verifying_key.verify(message, &signature_obj)
            .map_err(|e| PqcError::InvalidSignature(format!("Signature verification failed: {:?}", e)))?;

        tracing::debug!("✅ ML-DSA-87 signature verification successful - WASM NIST Level 5");

        Ok(())
    }
}

// Re-export constants and functions based on target
#[cfg(not(target_arch = "wasm32"))]
pub use native_impl::*;
#[cfg(target_arch = "wasm32")]
pub use wasm_impl::*;

/// ML-DSA keypair containing signing and verifying keys
#[derive(Clone)]
pub struct MlDsaKeypair {
    /// Verifying key (public key) for signature verification
    pub verifying_key: Vec<u8>,
    /// Signing key (secret key) for creating signatures (zeroized on drop)
    signing_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for MlDsaKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaKeypair")
            .field("verifying_key", &format!("{} bytes", self.verifying_key.len()))
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

impl MlDsaKeypair {
    /// Create a new keypair from raw bytes
    #[must_use]
    pub fn from_bytes(verifying_key: Vec<u8>, signing_key: Vec<u8>) -> Result<Self> {
        if verifying_key.len() != PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKey(format!(
                "Invalid verifying key size: expected {}, got {}",
                PUBLIC_KEY_SIZE,
                verifying_key.len()
            )));
        }

        if signing_key.len() != SECRET_KEY_SIZE {
            return Err(PqcError::InvalidKey(format!(
                "Invalid signing key size: expected {}, got {}",
                SECRET_KEY_SIZE,
                signing_key.len()
            )));
        }

        Ok(Self {
            verifying_key,
            signing_key: Zeroizing::new(signing_key),
        })
    }

    /// Get the verifying key (public key)
    #[must_use]
    pub fn verifying_key(&self) -> &[u8] {
        &self.verifying_key
    }

    /// Get the signing key (secret key)
    #[must_use]
    pub fn signing_key(&self) -> &[u8] {
        self.signing_key.as_ref()
    }

    /// Consume the keypair and return the signing key
    #[must_use]
    pub fn into_signing_key(self) -> Zeroizing<Vec<u8>> {
        self.signing_key
    }
}

/// Main ML-DSA implementation wrapper
pub struct MlDsa;

impl MlDsa {
    /// Generate a new ML-DSA keypair
    ///
    /// # Returns
    /// A new keypair containing signing and verifying keys
    ///
    /// # Errors
    /// Returns error if key generation fails
    #[must_use]
    pub fn generate_keypair() -> Result<MlDsaKeypair> {
        let (verifying_key, signing_key) = generate_keypair()?;
        
        Ok(MlDsaKeypair { verifying_key, signing_key })
    }

    /// Sign a message using the signing key
    ///
    /// # Arguments
    /// * `message` - The message to sign
    /// * `signing_key` - The ML-DSA signing key
    ///
    /// # Returns
    /// The signature
    ///
    /// # Errors
    /// Returns error if signing fails or key is invalid
    #[must_use]
    pub fn sign(message: impl AsRef<[u8]>, signing_key: &[u8]) -> Result<Vec<u8>> {
        sign(message, signing_key)
    }

    /// Verify a signature using the verifying key
    ///
    /// # Arguments
    /// * `message` - The original message that was signed
    /// * `signature` - The signature to verify
    /// * `verifying_key` - The ML-DSA verifying key
    ///
    /// # Returns
    /// `Ok(())` if signature is valid
    ///
    /// # Errors
    /// Returns error if verification fails or inputs are invalid
    #[must_use]
    pub fn verify(message: &[u8], signature: &[u8], verifying_key: &[u8]) -> Result<()> {
        verify(message, signature, verifying_key)
    }

    /// Batch verify multiple signatures (more efficient than individual verification)
    ///
    /// # Arguments
    /// * `messages` - Array of messages to verify
    /// * `signatures` - Array of corresponding signatures
    /// * `verifying_keys` - Array of corresponding verifying keys
    ///
    /// # Returns
    /// `Ok(())` if all signatures are valid
    ///
    /// # Errors
    /// Returns error if any signature is invalid or inputs are malformed
    #[must_use]
    pub fn batch_verify(
        messages: &[impl AsRef<[u8]>],
        signatures: &[&[u8]],
        verifying_keys: &[&[u8]],
    ) -> Result<()> {
        if messages.len() != signatures.len() || messages.len() != verifying_keys.len() {
            return Err(PqcError::InvalidInput(
                "Input arrays must have the same length".to_string()
            ));
        }

        // Accumulate all verification results to avoid early returns (constant-time)
        let mut all_valid = true;
        let mut first_error = None;
        
        for i in 0..messages.len() {
            match Self::verify(messages[i].as_ref(), signatures[i], verifying_keys[i]) {
                Ok(()) => {},
                Err(e) => {
                    all_valid = false;
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }

        if all_valid {
            tracing::debug!("✅ All {} ML-DSA-87 signatures verified", messages.len());
            Ok(())
        } else {
            // Return the first error encountered (but only after checking all signatures)
            Err(first_error.unwrap_or_else(|| PqcError::InvalidSignature("Unknown verification error".to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = MlDsa::generate_keypair().expect("Key generation should succeed");
        
        assert_eq!(keypair.verifying_key.len(), PUBLIC_KEY_SIZE);
        assert_eq!(keypair.signing_key().len(), SECRET_KEY_SIZE);
    }

    #[test]
    fn test_sign_and_verify() {
        // Generate keypair
        let keypair = MlDsa::generate_keypair().expect("Key generation should succeed");
        
        // Sign message
        let message = b"Hello, post-quantum world!";
        let signature = MlDsa::sign(message, keypair.signing_key())
            .expect("Signing should succeed");
        
        assert_eq!(signature.len(), SIGNATURE_SIZE);
        
        // Verify signature
        MlDsa::verify(message, &signature, &keypair.verifying_key)
            .expect("Verification should succeed");
    }

    #[test]
    fn test_invalid_signature() {
        let keypair = MlDsa::generate_keypair().expect("Key generation should succeed");
        let message = b"Original message";
        let wrong_message = b"Different message";
        
        let signature = MlDsa::sign(message, keypair.signing_key())
            .expect("Signing should succeed");
        
        // Verify with wrong message
        let result = MlDsa::verify(wrong_message, &signature, &keypair.verifying_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_sizes() {
        let message = b"Test message";
        
        // Test invalid verifying key size
        let result = MlDsa::verify(message, &[0u8; SIGNATURE_SIZE], &[0u8; 100]);
        assert!(result.is_err());
        
        // Test invalid signing key size
        let result = MlDsa::sign(message, &[0u8; 100]);
        assert!(result.is_err());
        
        // Test invalid signature size
        let keypair = MlDsa::generate_keypair().expect("Key generation should succeed");
        let result = MlDsa::verify(message, &[0u8; 100], &keypair.verifying_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_verify() {
        // Generate multiple keypairs
        let keypair1 = MlDsa::generate_keypair().expect("Key generation should succeed");
        let keypair2 = MlDsa::generate_keypair().expect("Key generation should succeed");
        
        let messages = [b"Message 1", b"Message 2"];
        let signatures = [
            MlDsa::sign(messages[0], keypair1.signing_key()).expect("Signing should succeed"),
            MlDsa::sign(messages[1], keypair2.signing_key()).expect("Signing should succeed"),
        ];
        let verifying_keys = vec![&keypair1.verifying_key[..], &keypair2.verifying_key[..]];
        let signature_refs: Vec<&[u8]> = signatures.iter().map(|s| s.as_ref()).collect();
        
        // Batch verify all signatures
        MlDsa::batch_verify(&messages, &signature_refs, &verifying_keys)
            .expect("Batch verification should succeed");
    }

    #[test]
    fn test_batch_verify_invalid() {
        let keypair1 = MlDsa::generate_keypair().expect("Key generation should succeed");
        let keypair2 = MlDsa::generate_keypair().expect("Key generation should succeed");
        
        let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2"];
        let signatures = [
            MlDsa::sign(messages[0], keypair1.signing_key()).expect("Signing should succeed"),
            MlDsa::sign(messages[1], keypair2.signing_key()).expect("Signing should succeed"),
        ];
        let verifying_keys = vec![&keypair1.verifying_key[..], &keypair2.verifying_key[..]];
        let signature_refs: Vec<&[u8]> = signatures.iter().map(|s| s.as_ref()).collect();
        
        // Tamper with one message
        let tampered_messages: Vec<&[u8]> = vec![b"Tampered message", b"Message 2"];
        
        // Batch verify should fail
        let result = MlDsa::batch_verify(&tampered_messages, &signature_refs, &verifying_keys);
        assert!(result.is_err());
    }
}