//! ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) implementation
//!
//! This module provides a Rust implementation of ML-KEM-1024, which is the NIST
//! standardized version of Kyber. ML-KEM provides post-quantum key encapsulation
//! with IND-CCA2 security.
//!
//! # Security Level
//! - NIST Level 5 (256-bit post-quantum security) - MAXIMUM SECURITY
//! - IND-CCA2 secure against both classical and quantum adversaries
//!
//! # Key Sizes
//! - Public key: 1568 bytes
//! - Secret key: 3168 bytes  
//! - Ciphertext: 1568 bytes
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
use ml_kem::{MlKem1024, MlKem1024Params, KemCore, EncodedSizeUser};
use ml_kem::kem::{EncapsulationKey, DecapsulationKey, Encapsulate, Decapsulate};
use zeroize::{Zeroize, Zeroizing};
use rand_core::{RngCore, CryptoRng};

/// TRUE Entropy RNG wrapper using dual CSPRNG sources for enhanced security
/// 
/// # Security
/// Uses getrandom + ring::rand as dual entropy sources:
/// - getrandom: OS-provided CSPRNG
/// - ring::SystemRandom: Another independent CSPRNG
/// XORs both together - unbreakable if EITHER source is truly random.
/// 
/// Note: Cannot use drand here due to circular dependency (zks_crypt depends on zks_pqcrypto).
/// TrueEntropy with drand is available in zks_crypt for other use cases.
struct TrueEntropyRngCompat;

impl RngCore for TrueEntropyRngCompat {
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
        // SECURITY: Use dual CSPRNG sources XORed together
        // This provides defense-in-depth: if one source is compromised,
        // the other still provides cryptographic security
        
        // Source 1: OS-provided CSPRNG via getrandom
        getrandom::getrandom(dest)
            .expect("CRITICAL: OS RNG failed - cannot generate secure keys");
        
        // Source 2: ring's SystemRandom (independent CSPRNG implementation)
        let mut secondary = vec![0u8; dest.len()];
        use ring::rand::SecureRandom;
        let ring_rng = ring::rand::SystemRandom::new();
        if ring_rng.fill(&mut secondary).is_ok() {
            // XOR combine both sources for defense-in-depth
            for i in 0..dest.len() {
                dest[i] ^= secondary[i];
            }
        }
        // If ring fails, we still have getrandom entropy which is sufficient
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TrueEntropyRngCompat {}

/// ML-KEM public key size (1568 bytes for ML-KEM-1024)
pub const PUBLIC_KEY_SIZE: usize = 1568;

/// ML-KEM secret key size (3168 bytes for ML-KEM-1024)
pub const SECRET_KEY_SIZE: usize = 3168;

/// ML-KEM ciphertext size (1568 bytes for ML-KEM-1024)
pub const CIPHERTEXT_SIZE: usize = 1568;

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

/// TRUE Entropy RNG with external entropy injection support
/// 
/// This allows injecting distributed randomness (e.g., drand) that couldn't
/// be included due to circular dependency. Caller fetches drand in the higher-level
/// crate and passes it here.
/// 
/// # Security
/// Uses three entropy sources XORed together:
/// - getrandom: OS-provided CSPRNG
/// - ring::SystemRandom: Another independent CSPRNG
/// - external_entropy: Caller-provided entropy (e.g., drand)
/// 
/// Unbreakable if ANY source is truly random.
struct TrueEntropyRngWithExternal {
    external_entropy: [u8; 32],
    position: std::sync::atomic::AtomicUsize,
}

impl TrueEntropyRngWithExternal {
    fn new(external_entropy: [u8; 32]) -> Self {
        Self {
            external_entropy,
            position: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl RngCore for TrueEntropyRngWithExternal {
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
        // Source 1: OS-provided CSPRNG via getrandom
        getrandom::getrandom(dest)
            .expect("CRITICAL: OS RNG failed - cannot generate secure keys");
        
        // Source 2: ring's SystemRandom (independent CSPRNG implementation)
        let mut secondary = vec![0u8; dest.len()];
        use ring::rand::SecureRandom;
        let ring_rng = ring::rand::SystemRandom::new();
        if ring_rng.fill(&mut secondary).is_ok() {
            for i in 0..dest.len() {
                dest[i] ^= secondary[i];
            }
        }
        
        // Source 3: External entropy (e.g., drand from caller)
        // Use position counter to get different bytes for each call
        let pos = self.position.fetch_add(dest.len(), std::sync::atomic::Ordering::SeqCst);
        for i in 0..dest.len() {
            let ext_idx = (pos + i) % 32;
            dest[i] ^= self.external_entropy[ext_idx];
        }
        
        tracing::debug!("🔐 ML-KEM RNG: Used 3-source entropy (getrandom ⊕ ring ⊕ external)");
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TrueEntropyRngWithExternal {}

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
        let mut rng = TrueEntropyRngCompat;
        
        // Generate keypair using the standard generate method
        let (dk, ek): (DecapsulationKey<MlKem1024Params>, EncapsulationKey<MlKem1024Params>) = MlKem1024::generate(&mut rng);
        
        let public_key_bytes = ek.as_bytes().as_slice().to_vec();
        let secret_key_bytes = Zeroizing::new(dk.as_bytes().as_slice().to_vec());
        
        tracing::info!(
            "🔑 Generated ML-KEM-1024 keypair (pk: {} bytes, sk: {} bytes) - NIST Level 5 (256-bit)",
            public_key_bytes.len(),
            secret_key_bytes.len()
        );
        
        Ok(MlKemKeypair { 
            public_key: public_key_bytes, 
            secret_key: secret_key_bytes 
        })
    }
    
    /// Generate a new ML-KEM keypair with external entropy injection
    /// 
    /// This allows incorporating distributed randomness (e.g., drand) that
    /// can't be fetched directly due to circular dependency constraints.
    /// 
    /// # Arguments
    /// * `external_entropy` - 32 bytes of external entropy (e.g., drand)
    /// 
    /// # Security
    /// The external entropy is XORed with local CSPRNG sources. The result is
    /// information-theoretically secure if ANY of the three sources is truly random:
    /// - getrandom (OS CSPRNG)
    /// - ring::SystemRandom (independent CSPRNG)
    /// - external_entropy (caller-provided, e.g., drand)
    /// 
    /// # Example
    /// ```ignore
    /// // In zks_crypt or higher-level crate:
    /// let drand = drand_client.get_latest().await?;
    /// let external = drand.randomness;
    /// let keypair = MlKem::generate_keypair_with_entropy(external)?;
    /// ```
    #[must_use]
    pub fn generate_keypair_with_entropy(external_entropy: [u8; 32]) -> Result<MlKemKeypair> {
        // Use RNG with external entropy injection
        let mut rng = TrueEntropyRngWithExternal::new(external_entropy);
        
        // Generate keypair using the standard generate method
        let (dk, ek): (DecapsulationKey<MlKem1024Params>, EncapsulationKey<MlKem1024Params>) = MlKem1024::generate(&mut rng);
        
        let public_key_bytes = ek.as_bytes().as_slice().to_vec();
        let secret_key_bytes = Zeroizing::new(dk.as_bytes().as_slice().to_vec());
        
        tracing::info!(
            "🔑 Generated ML-KEM-1024 keypair with external entropy (pk: {} bytes, sk: {} bytes) - NIST Level 5 (256-bit) + distributed randomness",
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
    /// * `public_key` - The ML-KEM-1024 public key (1568 bytes)
    ///
    /// # Returns
    /// Ciphertext (1568 bytes) and shared secret (32 bytes)
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
        let ek = EncapsulationKey::<MlKem1024Params>::from_bytes(public_key.try_into().unwrap());
        
        // Use our compatible OS RNG for encapsulation
        let mut rng = TrueEntropyRngCompat;
        
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
    
    /// Encapsulate a shared secret with external entropy injection
    ///
    /// Same as `encapsulate()` but incorporates external entropy for enhanced security.
    ///
    /// # Arguments
    /// * `public_key` - The ML-KEM-1024 public key (1568 bytes)
    /// * `external_entropy` - 32 bytes of external entropy (e.g., drand)
    ///
    /// # Returns
    /// Ciphertext (1568 bytes) and shared secret (32 bytes)
    #[must_use]
    pub fn encapsulate_with_entropy(public_key: &[u8], external_entropy: [u8; 32]) -> Result<MlKemEncapsulation> {
        if public_key.len() != PUBLIC_KEY_SIZE {
            return Err(PqcError::InvalidKey(format!(
                "Invalid public key size: expected {}, got {}",
                PUBLIC_KEY_SIZE,
                public_key.len()
            )));
        }

        // Create the encapsulation key from bytes
        let ek = EncapsulationKey::<MlKem1024Params>::from_bytes(public_key.try_into().unwrap());
        
        // Use RNG with external entropy injection
        let mut rng = TrueEntropyRngWithExternal::new(external_entropy);
        
        let (ciphertext, shared_secret) = ek.encapsulate(&mut rng)
            .map_err(|()| PqcError::MlKem("Encapsulation failed".to_string()))?;
        
        let ciphertext_bytes: Vec<u8> = ciphertext.to_vec();
        let shared_secret_bytes = Zeroizing::new(shared_secret.to_vec());

        tracing::debug!(
            "🔑 ML-KEM encapsulation with external entropy complete (ct: {} bytes, ss: {} bytes)",
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
    /// * `ciphertext` - The ML-KEM-1024 ciphertext (1568 bytes)
    /// * `secret_key` - The ML-KEM-1024 secret key (3168 bytes)
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
        let dk = DecapsulationKey::<MlKem1024Params>::from_bytes(secret_key.try_into().unwrap());

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