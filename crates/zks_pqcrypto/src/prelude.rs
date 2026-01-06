//! Prelude for zks_pqcrypto - convenient imports
//!
//! This module provides the most commonly used types and functions from the
//! zks_pqcrypto crate for easy importing.

// Core post-quantum cryptographic modules
pub use crate::ml_kem::{MlKem, MlKemKeypair, MlKemEncapsulation};
pub use crate::ml_dsa::{MlDsa, MlDsaKeypair};

// Error handling
pub use crate::errors::{PqcError, Result};

// Constants
pub use crate::ml_kem::{
    PUBLIC_KEY_SIZE as ML_KEM_PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE as ML_KEM_SECRET_KEY_SIZE,
    CIPHERTEXT_SIZE as ML_KEM_CIPHERTEXT_SIZE,
    SHARED_SECRET_SIZE as ML_KEM_SHARED_SECRET_SIZE,
};

pub use crate::ml_dsa::{
    PUBLIC_KEY_SIZE as ML_DSA_PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE as ML_DSA_SECRET_KEY_SIZE,
    SIGNATURE_SIZE as ML_DSA_SIGNATURE_SIZE,
};

// Type aliases for convenience
/// Alias for ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)
pub type Kyber = MlKem;
/// Alias for ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
pub type Dilithium = MlDsa;
/// Alias for ML-KEM keypair
pub type PQKeypair = MlKemKeypair;
/// Alias for ML-DSA keypair
pub type PQSigKeypair = MlDsaKeypair;