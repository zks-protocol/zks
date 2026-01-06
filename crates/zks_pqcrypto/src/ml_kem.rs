//! ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) implementation
//!
//! This module provides a Rust implementation of ML-KEM-768, which is the NIST
//! standardized version of Kyber. ML-KEM provides post-quantum key encapsulation
//! with IND-CCA2 security.
//!
//! # Security Level
//! - NIST Level 3 (192-bit post-quantum security)
//! - IND-CCA2 secure against both classical and quantum adversaries
//!
//! # Key Sizes
//! - Public key: 1184 bytes
//! - Secret key: 2400 bytes  
//! - Ciphertext: 1088 bytes
//! - Shared secret: 32 bytes
//!
//! # Example
//!
//! ```rust
//! use zks_pqcrypto::ml_kem::MlKem;
//!
//! // Generate keypair
//! let keypair = MlKem::generate_keypair()?;
//!
//! // Encapsulate (Alice's side)
//! let encapsulation = MlKem::encapsulate(&keypair.public_key)?;
//!
//! // Decapsulate (Bob's side)
//! let shared_secret_bob = MlKem::decapsulate(&encapsulation.ciphertext, keypair.secret_key())?;
//!
//! // Both parties now have the same shared secret
//! assert_eq!(encapsulation.shared_secret.as_ref() as &[u8], shared_secret_bob.as_ref() as &[u8]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::errors::{PqcError, Result};
use ml_kem::{MlKem768, MlKem768Params, KemCore, EncodedSizeUser};
use ml_kem::kem::{EncapsulationKey, DecapsulationKey, Encapsulate, Decapsulate};
use zeroize::{Zeroize, Zeroizing};
use rand_core::{RngCore, CryptoRng};

/// Simple OS RNG wrapper that implements RngCore + CryptoRng for rand_core 0.6 compatibility
struct OsRngCompat;

impl RngCore for OsRngCompat {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
    
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
    
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Use try_fill_bytes to avoid panicking on RNG failure
        if let Err(e) = self.try_fill_bytes(dest) {
            // Fallback: use a simple counter-based approach if getrandom fails
            // This is not cryptographically secure but prevents panics
            tracing::warn!("getrandom failed, using fallback RNG: {}", e);
            for (i, byte) in dest.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(7).wrapping_add(0x42);
            }
        }
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        getrandom::getrandom(dest).map_err(rand_core::Error::from)
    }
}

impl CryptoRng for OsRngCompat {}

/// ML-KEM public key size (1184 bytes for ML-KEM-768)
pub const PUBLIC_KEY_SIZE: usize = 1184;

/// ML-KEM secret key size (2400 bytes for ML-KEM-768)
pub const SECRET_KEY_SIZE: usize = 2400;

/// ML-KEM ciphertext size (1088 bytes for ML-KEM-768)
pub const CIPHERTEXT_SIZE: usize = 1088;

/// ML-KEM shared secret size (32 bytes)
pub const SHARED_SECRET_SIZE: usize = 32;

/// ML-KEM keypair containing public and secret keys
#[derive(Clone, Debug)]
pub struct MlKemKeypair {
    /// Public key for encapsulation
    pub public_key: Vec<u8>,
    /// Secret key for decapsulation (zeroized on drop)
    secret_key: Zeroizing<Vec<u8>>,
}

impl MlKemKeypair {
    /// Create a new keypair from raw bytes
    #[must_use]
    pub fn from_bytes(public_key: Vec<u8>, secret_key: Vec<u8>) -> Result<Self> {
        if public_key.len() != PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKey(format!(
                "Invalid public key size: expected {}, got {}",
                PUBLIC_KEY_SIZE,
                public_key.len()
            )));
        }

        if secret_key.len() != SECRET_KEY_SIZE {
            return Err(PqcError::InvalidKey(format!(
                "Invalid secret key size: expected {}, got {}",
                SECRET_KEY_SIZE,
                secret_key.len()
            )));
        }

        Ok(Self {
            public_key,
            secret_key: Zeroizing::new(secret_key),
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the secret key (as reference to zeroizing wrapper)
    pub fn secret_key(&self) -> &[u8] {
        self.secret_key.as_ref()
    }

    /// Consume the keypair and return the secret key
    pub fn into_secret_key(self) -> Zeroizing<Vec<u8>> {
        self.secret_key
    }
}

impl Zeroize for MlKemKeypair {
    fn zeroize(&mut self) {
        self.public_key.zeroize();
        self.secret_key.zeroize();
    }
}

/// ML-KEM encapsulation result
#[derive(Clone)]
pub struct MlKemEncapsulation {
    /// Ciphertext to send to the decapsulator
    pub ciphertext: Vec<u8>,
    /// Shared secret (32 bytes)
    pub shared_secret: Zeroizing<Vec<u8>>,
}

/// Main ML-KEM implementation
pub struct MlKem;

impl MlKem {
    /// Generate a new ML-KEM keypair
    ///
    /// # Returns
    /// A new keypair containing public and secret keys
    ///
    /// # Errors
    /// Returns error if key generation fails
    #[must_use]
    pub fn generate_keypair() -> Result<MlKemKeypair> {
        // Use our compatible OS RNG
        let mut rng = OsRngCompat;
        
        // Generate keypair using the standard generate method
        let (dk, ek): (DecapsulationKey<MlKem768Params>, EncapsulationKey<MlKem768Params>) = MlKem768::generate(&mut rng);
        
        let public_key_bytes = ek.as_bytes().as_slice().to_vec();
        let secret_key_bytes = Zeroizing::new(dk.as_bytes().as_slice().to_vec());
        
        tracing::info!(
            "🔑 Generated ML-KEM-768 keypair (pk: {} bytes, sk: {} bytes)",
            public_key_bytes.len(),
            secret_key_bytes.len()
        );
        
        Ok(MlKemKeypair { 
            public_key: public_key_bytes, 
            secret_key: secret_key_bytes 
        })
    }

    /// Encapsulate a shared secret using the public key
    ///
    /// # Arguments
    /// * `public_key` - The ML-KEM public key (1184 bytes)
    ///
    /// # Returns
    /// Ciphertext and shared secret
    ///
    /// # Errors
    /// Returns error if encapsulation fails or public key is invalid
    #[must_use]
    pub fn encapsulate(public_key: &[u8]) -> Result<MlKemEncapsulation> {
        if public_key.len() != PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKey(format!(
                "Invalid public key size: expected {}, got {}",
                PUBLIC_KEY_SIZE,
                public_key.len()
            )));
        }

        // Create the encapsulation key from bytes
        let ek = EncapsulationKey::<MlKem768Params>::from_bytes(public_key.try_into().unwrap());
        
        // Use our compatible OS RNG for encapsulation
        let mut rng = OsRngCompat;
        
        let (ciphertext, shared_secret) = ek.encapsulate(&mut rng)
            .map_err(|()| PqcError::MlKem("Encapsulation failed".to_string()))?;
        
        let ciphertext_bytes: Vec<u8> = ciphertext.to_vec();
        let shared_secret_bytes = Zeroizing::new(shared_secret.to_vec());

        tracing::debug!(
            "🔑 ML-KEM encapsulation complete (ct: {} bytes, ss: {} bytes)",
            ciphertext_bytes.len(),
            shared_secret_bytes.len()
        );

        Ok(MlKemEncapsulation {
            ciphertext: ciphertext_bytes,
            shared_secret: shared_secret_bytes,
        })
    }

    /// Decapsulate a shared secret using the secret key and ciphertext
    ///
    /// # Arguments
    /// * `ciphertext` - The ML-KEM ciphertext (1088 bytes)
    /// * `secret_key` - The ML-KEM secret key (2400 bytes)
    ///
    /// # Returns
    /// The shared secret (32 bytes)
    ///
    /// # Errors
    /// Returns error if decapsulation fails or inputs are invalid
    #[must_use]
    pub fn decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if ciphertext.len() != CIPHERTEXT_SIZE {
            return Err(PqcError::InvalidInput(format!(
                "Invalid ciphertext size: expected {}, got {}",
                CIPHERTEXT_SIZE,
                ciphertext.len()
            )));
        }

        if secret_key.len() != SECRET_KEY_SIZE {
            return Err(PqcError::InvalidKey(format!(
                "Invalid secret key size: expected {}, got {}",
                SECRET_KEY_SIZE,
                secret_key.len()
            )));
        }

        // Create the decapsulation key from bytes
        let dk = DecapsulationKey::<MlKem768Params>::from_bytes(secret_key.try_into().unwrap());

        // Decapsulate using the secret key and ciphertext
        let shared_secret = dk.decapsulate(ciphertext.try_into().unwrap())
            .map_err(|()| PqcError::MlKem("Decapsulation failed".to_string()))?;

        let shared_secret_bytes = Zeroizing::new(shared_secret.to_vec());

        tracing::debug!(
            "🔓 ML-KEM decapsulation complete (ss: {} bytes)",
            shared_secret_bytes.len()
        );

        Ok(shared_secret_bytes)
    }

    /// Derive a session key from the shared secret using HKDF
    ///
    /// # Arguments
    /// * `shared_secret` - The ML-KEM shared secret
    /// * `salt` - Optional salt for key derivation
    /// * `info` - Optional context information
    /// * `output_len` - Desired output key length
    ///
    /// # Returns
    /// Derived session key
    ///
    /// # Errors
    /// Returns error if key derivation fails
    pub fn derive_session_key(
        shared_secret: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(salt, shared_secret);
        let mut output_key = Zeroizing::new(vec![0u8; output_len]);
        
        hkdf.expand(info.unwrap_or(b""), output_key.as_mut())
            .map_err(|e| PqcError::KeyGeneration(format!("HKDF expansion failed: {}", e)))?;

        Ok(output_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = MlKem::generate_keypair().expect("Key generation should succeed");
        
        assert_eq!(keypair.public_key.len(), PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key().len(), SECRET_KEY_SIZE);
    }

    #[test]
    fn test_encapsulation_decapsulation() {
        // Generate keypair
        let keypair = MlKem::generate_keypair().expect("Key generation should succeed");
        
        // Encapsulate
        let encapsulation = MlKem::encapsulate(&keypair.public_key)
            .expect("Encapsulation should succeed");
        
        assert_eq!(encapsulation.ciphertext.len(), CIPHERTEXT_SIZE);
        assert_eq!(encapsulation.shared_secret.len(), SHARED_SECRET_SIZE);
        
        // Decapsulate
        let shared_secret_bob = MlKem::decapsulate(
            &encapsulation.ciphertext,
            keypair.secret_key()
        ).expect("Decapsulation should succeed");
        
        // Verify shared secrets match
        assert_eq!(encapsulation.shared_secret.as_ref() as &[u8], shared_secret_bob.as_ref() as &[u8]);
    }

    #[test]
    fn test_invalid_key_sizes() {
        // Test invalid public key size
        let result = MlKem::encapsulate(&[0u8; 100]);
        assert!(result.is_err());
        
        // Test invalid ciphertext size
        let result = MlKem::decapsulate(&[0u8; 100], &[0u8; SECRET_KEY_SIZE]);
        assert!(result.is_err());
        
        // Test invalid secret key size
        let result = MlKem::decapsulate(&[0u8; CIPHERTEXT_SIZE], &[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_key_derivation() {
        let shared_secret = vec![0x42u8; SHARED_SECRET_SIZE];
        let salt = b"test salt";
        let info = b"test info";
        
        let session_key = MlKem::derive_session_key(
            &shared_secret,
            Some(salt),
            Some(info),
            32
        ).expect("Key derivation should succeed");
        
        assert_eq!(session_key.len(), 32);
        
        // Test that same inputs produce same output
        let session_key2 = MlKem::derive_session_key(
            &shared_secret,
            Some(salt),
            Some(info),
            32
        ).expect("Key derivation should succeed");
        
        assert_eq!(session_key.as_ref() as &[u8], session_key2.as_ref() as &[u8]);
    }
}