//! Distributed Entropy API: Post-Quantum Security for ZKS Protocol
//!
//! This module provides a unified API for accessing cryptographically secure entropy
//! combining drand beacon (32 bytes, 18+ operators) + local CSPRNG.
//!
//! ## Security Model
//!
//! **256-bit Post-Quantum Computational Security** (NOT information-theoretic)
//!
//! ## XOR Entropy Composition Security Justification (F3 Fix)
//!
//! The protocol XORs drand entropy with local CSPRNG entropy. This is secure because:
//!
//! **Theorem (XOR Composition)**: If X is a random variable uniform on {0,1}^n and Y is
//! any independent random variable on {0,1}^n, then X ⊕ Y is uniform on {0,1}^n.
//!
//! **Proof Sketch**: For any fixed y, the map x ↦ x ⊕ y is a bijection. If X is uniform,
//! then for any z, P(X ⊕ Y = z) = P(X = z ⊕ Y) = 2^(-n) (by uniformity of X).
//!
//! **Application to ZKS**: If EITHER drand OR local CSPRNG produces uniform random bytes,
//! the XOR combination is uniform. An adversary must compromise BOTH sources to predict output.
//!
//! **Trust Assumptions**:
//! - drand: Threshold BLS with 18+ independent operators (t-of-n security)
//! - CSPRNG: OS-provided (getrandom) or ring::SystemRandom
//!
//! **LIMITATION**: This assumes independence between sources. If drand and CSPRNG share
//! common entropy (e.g., both seeded from system clock at same instant), security may degrade.
//! In practice, drand uses distributed entropy from 18+ independent operators, providing
//! strong independence from any local system state.
//! 
//! When using `get_entropy()`, the resulting bytes are:
//! - **Cryptographically secure** (256-bit post-quantum)
//! - **XOR combination** of distributed drand + local CSPRNG
//! - **Verified via BLS12-381** signatures (drand)
//! - **No single-provider trust** (drand has 18+ operators across jurisdictions)
//! 
//! ## Why Not Information-Theoretic?
//! 
//! True information-theoretic security requires:
//! 1. Hardware quantum RNG under your control
//! 2. Physical key exchange (not network)
//! 3. Key length = message length (One-Time Pad)
//! 
//! This module provides practical, post-quantum computational security which is
//! sufficient for all real-world use cases and resistant to quantum computers.
//! 
//! ## Entropy Sources
//! 
//! | Source | Type | Operators | Trust Model |
//! |--------|------|-----------|-------------|
//! | **drand** | Cryptographic | 18+ worldwide | Distributed (threshold BLS) |
//! | **CSPRNG** | Computational | Local device | Your device |
//! 
//! ## Usage
//! 
//! ```rust,no_run
//! use zks_crypt::true_entropy::{TrueEntropy, get_sync_entropy};
//! 
//! // Synchronous (blocking) - for use in non-async contexts
//! let entropy = get_sync_entropy(32);
//! 
//! // Async - recommended for best performance
//! // let entropy = TrueEntropy::global().get_entropy(32).await;
//! ```

use std::sync::{Arc, OnceLock};

use zeroize::Zeroizing;
use tracing::{debug, warn};

use crate::drand::DrandEntropy;
use crate::entropy_provider::EntropyProvider;

/// Global TrueEntropy instance for efficient reuse
static GLOBAL_TRUE_ENTROPY: OnceLock<Arc<TrueEntropy>> = OnceLock::new();

/// Distributed Entropy Provider: Combines entropy sources + local CSPRNG
/// 
/// ## Security Properties
/// - XOR combination of entropy sources
/// - 256-bit post-quantum computational security
/// - Support for hierarchical entropy fetching via EntropyGrid
/// - Local CSPRNG: fallback entropy source
/// - Automatic fallback if beacon unavailable
/// 
/// ## Entropy Sources (via EntropyProvider)
/// 1. EntropyGrid: Cache → Swarm → IPFS → drand API
/// 2. DirectDrandProvider: Direct drand API (default)
/// 
/// ## Trust Model
/// No single-provider trust. drand requires threshold of 18+ independent
/// operators across multiple jurisdictions to be compromised.
pub struct TrueEntropy {
    /// drand client for 32-byte distributed randomness (legacy direct access)
    drand: Arc<DrandEntropy>,
    /// Pluggable entropy provider (supports EntropyGrid hierarchical fetching)
    entropy_provider: Option<Arc<dyn EntropyProvider>>,
}

impl TrueEntropy {
    /// Create a new TrueEntropy instance with default direct drand provider
    pub fn new() -> Self {
        Self {
            drand: Arc::new(DrandEntropy::new()),
            entropy_provider: None,
        }
    }

    /// Create TrueEntropy with a custom entropy provider (e.g., EntropyGrid)
    /// 
    /// This enables hierarchical entropy fetching:
    /// 1. Local cache (fastest)
    /// 2. Swarm peers (P2P via GossipSub)
    /// 3. IPFS (decentralized storage)
    /// 4. drand API (final fallback)
    pub fn with_provider(provider: Arc<dyn EntropyProvider>) -> Self {
        Self {
            drand: Arc::new(DrandEntropy::new()),
            entropy_provider: Some(provider),
        }
    }

    /// Set the entropy provider dynamically
    pub fn set_provider(&mut self, provider: Arc<dyn EntropyProvider>) {
        self.entropy_provider = Some(provider);
    }

    /// Get the global TrueEntropy instance (singleton pattern)
    /// 
    /// This ensures efficient resource sharing across the application.
    pub fn global() -> Arc<TrueEntropy> {
        GLOBAL_TRUE_ENTROPY.get_or_init(|| {
            debug!("🔐 Initializing global TrueEntropy instance (drand + CSPRNG)");
            Arc::new(TrueEntropy::new())
        }).clone()
    }

    /// Get entropy asynchronously by combining entropy sources + local CSPRNG
    /// 
    /// ## Security
    /// Returns 256-bit post-quantum computational security:
    /// - EntropyGrid: Cache → Swarm → IPFS → drand API (if configured)
    /// - Direct drand: BLS-verified 32 bytes (fallback)
    /// - Local CSPRNG (always XORed)
    /// 
    /// All sources are XORed together for defense-in-depth.
    pub async fn get_entropy(&self, length: usize) -> Zeroizing<Vec<u8>> {
        let mut result = Zeroizing::new(vec![0u8; length]);
        
        // 1. Get local CSPRNG entropy (always available)
        let mut local_entropy = vec![0u8; length];
        if getrandom::getrandom(&mut local_entropy).is_err() {
            warn!("⚠️ Local CSPRNG failed - falling back to ring");
            use ring::rand::SecureRandom;
            let rng = ring::rand::SystemRandom::new();
            let _ = rng.fill(&mut local_entropy);
        }
        
        // 2. Get drand entropy via EntropyProvider (or direct fallback)
        let drand_entropy: Vec<u8> = if let Some(provider) = &self.entropy_provider {
            // Use hierarchical fetching: Cache → Swarm → IPFS → drand API
            let current_round = self.drand.current_round();
            match provider.fetch_round(current_round).await {
                Ok(round) => {
                    debug!("✅ Got entropy via EntropyGrid (round {})", round.round);
                    round.randomness.to_vec()
                },
                Err(e) => {
                    warn!("⚠️ EntropyProvider failed: {}. Falling back to direct drand.", e);
                    self.fetch_direct_drand().await
                }
            }
        } else {
            // Direct drand fallback (no EntropyGrid configured)
            self.fetch_direct_drand().await
        };
        
        // 3. Expand drand entropy if needed (beyond 32 bytes)
        let expanded_drand = if length > 32 {
            self.expand_entropy_csprng(&drand_entropy, length)
        } else {
            drand_entropy.clone()
        };
        
        // 4. XOR combination - drand ⊕ local CSPRNG
        for i in 0..length {
            result[i] = local_entropy[i] ^ expanded_drand[i];
        }
        
        debug!("🔐 Generated {} bytes of entropy (drand ⊕ CSPRNG)", length);
        result
    }

    /// Get 32 bytes of entropy (most common case)
    pub async fn get_entropy_32(&self) -> Zeroizing<[u8; 32]> {
        let entropy = self.get_entropy(32).await;
        let mut result = Zeroizing::new([0u8; 32]);
        result.copy_from_slice(&entropy[..32]);
        result
    }

    /// Get 64 bytes of entropy
    pub async fn get_entropy_64(&self) -> Zeroizing<[u8; 64]> {
        let entropy = self.get_entropy(64).await;
        let mut result = Zeroizing::new([0u8; 64]);
        result.copy_from_slice(&entropy[..64]);
        result
    }

    /// Get entropy synchronously (blocking)
    /// 
    /// ## Warning
    /// This blocks the current thread. Use `get_entropy()` for async contexts.
    pub fn get_entropy_sync(&self, length: usize) -> Zeroizing<Vec<u8>> {
        let mut result = Zeroizing::new(vec![0u8; length]);
        
        // 1. Get local CSPRNG entropy
        let mut local_entropy = vec![0u8; length];
        if getrandom::getrandom(&mut local_entropy).is_err() {
            warn!("⚠️ Local CSPRNG failed - using ring");
            use ring::rand::SecureRandom;
            let rng = ring::rand::SystemRandom::new();
            let _ = rng.fill(&mut local_entropy);
        }
        
        // 2. Try to get drand entropy synchronously (32 bytes)
        let drand_entropy: Vec<u8> = match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                match tokio::task::block_in_place(|| {
                    handle.block_on(self.drand.get_entropy_with_fallback())
                }) {
                    Ok(entropy) => entropy.to_vec(),
                    Err(_) => {
                        let mut fallback = vec![0u8; 32];
                        let _ = getrandom::getrandom(&mut fallback);
                        fallback
                    }
                }
            },
            Err(_) => {
                let mut fallback = vec![0u8; 32];
                let _ = getrandom::getrandom(&mut fallback);
                fallback
            }
        };
        
        // 3. Expand drand entropy if needed (beyond 32 bytes)
        let expanded_drand = if length > 32 {
            self.expand_entropy_csprng(&drand_entropy, length)
        } else {
            drand_entropy.clone()
        };
        
        // 4. XOR combination - drand ⊕ local CSPRNG
        for i in 0..length {
            result[i] = local_entropy[i] ^ expanded_drand[i];
        }
        
        debug!("🔐 Generated {} bytes of entropy sync (drand ⊕ CSPRNG)", length);
        result
    }

    /// Get 32 bytes of entropy synchronously
    pub fn get_entropy_32_sync(&self) -> Zeroizing<[u8; 32]> {
        let entropy = self.get_entropy_sync(32);
        let mut result = Zeroizing::new([0u8; 32]);
        result.copy_from_slice(&entropy[..32]);
        result
    }

    /// Fetch drand entropy directly (bypassing EntropyGrid)
    async fn fetch_direct_drand(&self) -> Vec<u8> {
        match self.drand.get_entropy_with_fallback().await {
            Ok(entropy) => {
                debug!("✅ Got BLS-verified drand entropy (32 bytes, 18+ operators)");
                entropy.to_vec()
            },
            Err(e) => {
                warn!("⚠️ drand unavailable: {}. Using local entropy only.", e);
                let mut fallback = vec![0u8; 32];
                let _ = getrandom::getrandom(&mut fallback);
                fallback
            }
        }
    }
}

impl Default for TrueEntropy {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// ENTROPY PROVIDER ADAPTER
// =============================================================================

use crate::entropy_block::DrandRound;
use crate::drand::DrandError;
use async_trait::async_trait;

/// TrueEntropy adapter implementing EntropyProvider trait
/// 
/// This allows TrueEntropy to be used wherever an EntropyProvider is needed.
pub struct TrueEntropyProvider {
    drand: std::sync::Arc<crate::drand::DrandEntropy>,
}

impl TrueEntropyProvider {
    /// Create a new TrueEntropyProvider
    pub fn new(drand: std::sync::Arc<crate::drand::DrandEntropy>) -> Self {
        Self { drand }
    }
}

#[async_trait]
impl EntropyProvider for TrueEntropyProvider {
    async fn fetch_round(&self, round_number: u64) -> Result<DrandRound, DrandError> {
        let randomness = self.drand.fetch_round(round_number).await?;
        Ok(DrandRound {
            round: round_number,
            randomness,
            signature: vec![0u8; 96],
            previous_signature: vec![0u8; 96],
        })
    }
    
    async fn fetch_range(&self, start_round: u64, count: u32) -> Result<Vec<DrandRound>, DrandError> {
        let mut rounds = Vec::new();
        for i in 0..count {
            let round_number = start_round + i as u64;
            rounds.push(self.fetch_round(round_number).await?);
        }
        Ok(rounds)
    }
}

impl TrueEntropy {
    /// Get an EntropyProvider adapter for this TrueEntropy instance
    /// 
    /// This allows TrueEntropy to be used with APIs that require EntropyProvider.
    pub fn as_entropy_provider(&self) -> TrueEntropyProvider {
        TrueEntropyProvider::new(self.drand.clone())
    }
}

// =============================================================================
// ENTROPY EXPANSION METHODS
// =============================================================================

impl TrueEntropy {
    /// Expand entropy using CSPRNG (cryptographically secure)
    /// 
    /// This prevents entropy reuse by deterministically expanding a seed
    /// using ChaCha20 CSPRNG. The expansion is cryptographically secure
    /// and produces different output for different seeds.
    fn expand_entropy_csprng(&self, seed: &[u8], target_length: usize) -> Vec<u8> {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        use chacha20::ChaCha20;
        
        let mut expanded = vec![0u8; target_length];
        
        // Use the seed as key, with a fixed nonce for deterministic expansion
        let key = &seed[..32.min(seed.len())];
        let padded_key = if key.len() < 32 {
            let mut padded = [0u8; 32];
            padded[..key.len()].copy_from_slice(key);
            padded
        } else {
            let mut hash = [0u8; 32];
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(key);
            hash.copy_from_slice(&hasher.finalize());
            hash
        };
        
        let nonce = [0u8; 12]; // Fixed nonce for deterministic expansion
        let mut cipher = ChaCha20::new(&padded_key.into(), &nonce.into());
        cipher.apply_keystream(&mut expanded);
        
        expanded
    }
}

// =============================================================================
// Convenience Functions
// =============================================================================

/// Get entropy synchronously (convenience function)
/// 
/// ## Security
/// Returns 256-bit post-quantum computational security combining drand + local CSPRNG.
/// 
/// ## Example
/// ```rust,no_run
/// use zks_crypt::true_entropy::get_sync_entropy;
/// 
/// let key_bytes = get_sync_entropy(32);
/// ```
pub fn get_sync_entropy(length: usize) -> Zeroizing<Vec<u8>> {
    TrueEntropy::global().get_entropy_sync(length)
}

/// Get 32 bytes of entropy synchronously (convenience function)
pub fn get_sync_entropy_32() -> Zeroizing<[u8; 32]> {
    TrueEntropy::global().get_entropy_32_sync()
}

/// Get entropy asynchronously (convenience function)
/// 
/// ## Example
/// ```rust,no_run
/// # use zks_crypt::true_entropy::get_async_entropy;
/// # async fn example() {
/// let entropy = get_async_entropy(32).await;
/// # }
/// ```
pub async fn get_async_entropy(length: usize) -> Zeroizing<Vec<u8>> {
    TrueEntropy::global().get_entropy(length).await
}

/// Get 32 bytes of entropy asynchronously (convenience function)
pub async fn get_async_entropy_32() -> Zeroizing<[u8; 32]> {
    TrueEntropy::global().get_entropy_32().await
}

// =============================================================================
// TrueEntropyRng - RNG adapter for cryptographic APIs
// =============================================================================

use rand::{RngCore, CryptoRng};

/// RNG adapter that uses TrueEntropy for cryptographic operations
/// 
/// This implements `RngCore` and `CryptoRng` traits for use with
/// cryptographic APIs that require a random number generator.
/// 
/// ## Security
/// Uses drand + local CSPRNG for 256-bit post-quantum security.
pub struct TrueEntropyRng;

impl RngCore for TrueEntropyRng {
    fn next_u32(&mut self) -> u32 {
        let bytes = get_sync_entropy(4);
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn next_u64(&mut self) -> u64 {
        let bytes = get_sync_entropy(8);
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let entropy = get_sync_entropy(dest.len());
        dest.copy_from_slice(&entropy);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TrueEntropyRng {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_entropy_generation() {
        let entropy = TrueEntropy::new();
        let bytes = entropy.get_entropy(32).await;
        
        assert_eq!(bytes.len(), 32);
        // Should not be all zeros
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[tokio::test]
    async fn test_entropy_uniqueness() {
        let entropy = TrueEntropy::new();
        let bytes1 = entropy.get_entropy(32).await;
        let bytes2 = entropy.get_entropy(32).await;
        
        // Two calls should produce different results
        assert_ne!(*bytes1, *bytes2);
    }

    #[test]
    fn test_sync_entropy() {
        let bytes = get_sync_entropy(32);
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_rng_adapter() {
        let mut rng = TrueEntropyRng;
        let val1 = rng.next_u64();
        let val2 = rng.next_u64();
        
        // Should produce different values
        assert_ne!(val1, val2);
    }
}
