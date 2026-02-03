//! zks_pqcrypto - Post-Quantum Cryptography for ZKS Protocol
//!
//! This crate provides post-quantum cryptographic implementations for the ZKS Protocol,
//! focusing on NIST-standardized algorithms:
//!
//! - **ML-KEM** (Module-Lattice-Based Key Encapsulation Mechanism) - formerly Kyber
//! - **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm) - formerly Dilithium
//!
//! # Security Levels
//!
//! | Algorithm | NIST Level | Classical Security | Post-Quantum Security |
//! |-----------|------------|-------------------|----------------------|
//! | ML-KEM-768 | 3 | 192-bit | 192-bit |
//! | ML-DSA-65 | 3 | 192-bit | 192-bit |
//!
//! # Features
//!
//! - **Memory Safety**: All secret keys are automatically zeroized on drop
//! - **Constant Time**: Uses verified constant-time implementations
//! - **No Unsafe Code**: `#![forbid(unsafe_code)]` for maximum safety
//! - **Ergonomic API**: Simple, easy-to-use interfaces
//!
//! # Example
//!
//! ```rust
//! use zks_pqcrypto::{MlKem, MlDsa};
//!
//! // Key encapsulation
//! let keypair = MlKem::generate_keypair()?;
//! let encapsulation = MlKem::encapsulate(&keypair.public_key)?;
//! let shared_secret_bob = MlKem::decapsulate(&encapsulation.ciphertext, keypair.secret_key())?;
//!
//! // Digital signatures
//! let keypair = MlDsa::generate_keypair()?;
//! let message = b"Hello, post-quantum world!";
//! let signature = MlDsa::sign(message, keypair.signing_key())?;
//! MlDsa::verify(message, &signature, keypair.verifying_key())?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::all)]

pub mod ml_kem;
pub mod ml_dsa;
pub mod errors;
/// Incremental ML-KEM-1024 for bandwidth-efficient ratcheting
pub mod incremental_mlkem;
/// Katana RKEM - Bandwidth-optimized ratcheting KEM using incremental ML-KEM-1024
pub mod katana_rkem;
pub mod prelude;

// Re-export commonly used types
pub use ml_kem::{MlKem, MlKemKeypair, MlKemEncapsulation};
pub use ml_dsa::{MlDsa, MlDsaKeypair};
pub use errors::{PqcError, Result};
pub use katana_rkem::{KatanaRkem, KatanaOutput, KatanaCiphertext, BandwidthStats};

// Type aliases for convenience
/// Alias for ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)
pub type Kyber = MlKem;
/// Alias for ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
pub type Dilithium = MlDsa;