//! zks_crypt Prelude
//! 
//! This module provides convenient access to the most commonly used types and functions
//! from the zks_crypt crate.

// Core cryptographic modules
pub use crate::anti_replay::AntiReplayContainer;
pub use crate::constant_time::{ct_eq, ct_eq_fixed, ct_compare, ct_copy, ct_swap, ct_is_zero, ct_assign, ct_select_bytes, ct_xor};
pub use crate::drand::{DrandEntropy, DrandConfig, DrandError, get_drand_entropy, get_unique_entropy};
pub use crate::recursive_chain::RecursiveChain;
pub use crate::scramble::CiphertextScrambler;
pub use crate::true_vernam::{TrueVernamBuffer, TrueVernamFetcher};
pub use crate::wasif_vernam::{WasifVernam, ContinuousEntropyRefresher};

// Re-export common dependencies for convenience
pub use chacha20poly1305;
pub use sha2;
pub use hkdf;
pub use zeroize;

// Type aliases for common use cases
/// Main Vernam cipher implementation combining multiple encryption layers
pub type VernamCipher = WasifVernam;
/// Anti-replay attack protection container
pub type AntiReplay = AntiReplayContainer;
/// Ciphertext scrambler for traffic analysis resistance
pub type Scrambler = CiphertextScrambler;
/// Recursive key chain for forward secrecy
pub type KeyChain = RecursiveChain;
/// True Vernam buffer for information-theoretic security
pub type VernamBuffer = TrueVernamBuffer;
/// Entropy fetcher for random data generation
pub type EntropyFetcher = TrueVernamFetcher;
/// Continuous entropy refresher for background security updates
pub type EntropyRefresher = ContinuousEntropyRefresher;