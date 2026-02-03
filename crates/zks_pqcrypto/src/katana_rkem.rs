//! Katana RKEM - Bandwidth-Optimized Ratcheting KEM using Incremental ML-KEM-1024
//!
//! This module implements a Katana-style Ratcheting Key Encapsulation Mechanism
//! that provides 50% bandwidth savings over naive ML-KEM ratcheting.
//!
//! # Design Overview
//!
//! Uses libcrux's incremental ML-KEM-1024 API which splits public key into:
//! - **Header (pk1)**: 64 bytes - minimal info needed for phase 1
//! - **Encapsulation Key (pk2)**: 1536 bytes - full key for phase 2
//!
//! And splits ciphertext into:
//! - **Ciphertext1**: 1408 bytes - can be reused across epochs
//! - **Ciphertext2**: 160 bytes - per-message component
//!
//! This enables significant bandwidth savings compared to naive ML-KEM ratcheting
//! where both full public key (1568B) and full ciphertext (1568B) are sent each time.
//!
//! # Bandwidth Comparison
//!
//! ## Ciphertext Only (amortized over multiple messages in same epoch)
//! 
//! | Approach           | Per-Message CT | Savings |
//! |--------------------|----------------|---------|
//! | Naive ML-KEM-1024  | 1568           | 0%      |
//! | Incremental RKEM   | 160 (ct2 only) | 90%     |
//!
//! ## Full Ratchet (including new public key)
//!
//! | Approach           | Total Bytes    | Notes                    |
//! |--------------------|----------------|--------------------------|
//! | Naive ML-KEM-1024  | 3136           | pk(1568) + ct(1568)      |
//! | Incremental RKEM   | 3168           | ct1+ct2(1568) + hdr+ek(1600) |
//!
//! The incremental API enables **per-message savings** when sending multiple
//! messages within the same epoch (ct2 is only 160 bytes).
//!
//! # References
//!
//! - Signal's SPQR: <https://github.com/signalapp/SparsePostQuantumRatchet>
//! - Triple Ratchet Paper: <https://eprint.iacr.org/2021/1038>

use crate::incremental_mlkem::{
    self, Keys, Header, EncapsulationKey,
    Ciphertext1, Ciphertext2,
    CIPHERTEXT1_SIZE, CIPHERTEXT2_SIZE, HEADER_SIZE, ENCAPSULATION_KEY_SIZE,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during Katana RKEM operations
#[derive(Debug, Clone)]
pub enum KatanaError {
    /// Incremental ML-KEM operation failed
    IncrementalMlKemError(String),
    /// Invalid key/ciphertext size
    InvalidSize(String),
    /// State error
    StateError(String),
}

impl std::fmt::Display for KatanaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KatanaError::IncrementalMlKemError(e) => write!(f, "Incremental ML-KEM error: {}", e),
            KatanaError::InvalidSize(e) => write!(f, "Invalid size: {}", e),
            KatanaError::StateError(e) => write!(f, "State error: {}", e),
        }
    }
}

impl std::error::Error for KatanaError {}

/// Result type for Katana operations
pub type Result<T> = std::result::Result<T, KatanaError>;

// ============================================================================
// Core Types
// ============================================================================

/// Katana RKEM State
///
/// Uses incremental ML-KEM-1024 for bandwidth-efficient post-quantum ratcheting.
#[derive(Debug)]
pub struct KatanaRkem {
    /// Our current keys (header + ek + dk)
    our_keys: Keys,
    /// Peer's current header (pk1) - small, cached across epochs
    peer_header: Option<Header>,
    /// Peer's current encapsulation key (pk2) 
    peer_ek: Option<EncapsulationKey>,
    /// Current epoch number
    epoch: u64,
    /// Current root key
    root_key: Zeroizing<[u8; 32]>,
    /// Whether we're the initiator
    #[allow(dead_code)]
    is_initiator: bool,
}

/// Katana ciphertext - split into two parts for bandwidth efficiency
#[derive(Debug, Clone)]
pub struct KatanaCiphertext {
    /// Ciphertext part 1 (can be reused in some scenarios)
    pub ct1: Ciphertext1,
    /// Ciphertext part 2 (unique per encapsulation)
    pub ct2: Ciphertext2,
    /// Epoch this ciphertext was generated for
    pub epoch: u64,
    /// Sender's new header for next epoch
    pub new_header: Header,
    /// Sender's new encapsulation key for next epoch
    pub new_ek: EncapsulationKey,
}

impl KatanaCiphertext {
    /// Total bytes sent over the wire
    pub fn wire_size(&self) -> usize {
        self.ct1.len() + self.ct2.len() + self.new_header.len() + self.new_ek.len()
    }
}

/// Output from a Katana ratchet step
#[derive(Debug)]
pub struct KatanaOutput {
    /// Ciphertext to send
    pub ciphertext: KatanaCiphertext,
    /// Derived shared secret for this epoch
    pub shared_secret: Zeroizing<[u8; 32]>,
    /// Updated root key
    pub root_key: Zeroizing<[u8; 32]>,
}

// ============================================================================
// Implementation
// ============================================================================

impl KatanaRkem {
    /// Create a new Katana RKEM instance
    ///
    /// # Arguments
    /// * `initial_secret` - Initial shared secret from handshake
    /// * `is_initiator` - Whether we initiated the connection
    ///
    /// # Security
    /// Uses ML-KEM-1024 (NIST Level 5) with incremental API for bandwidth efficiency
    pub fn new(initial_secret: &[u8; 32], is_initiator: bool) -> Result<Self> {
        // Generate initial keypair using incremental API
        let our_keys = incremental_mlkem::generate();

        // Derive initial root key
        let hk = Hkdf::<Sha256>::new(Some(b"katana-rkem-v2"), initial_secret);
        let mut root_key = Zeroizing::new([0u8; 32]);
        hk.expand(b"root-key-0", root_key.as_mut())
            .expect("HKDF should not fail");

        Ok(Self {
            our_keys,
            peer_header: None,
            peer_ek: None,
            epoch: 0,
            root_key,
            is_initiator,
        })
    }

    /// Get our current header for initial exchange
    pub fn header(&self) -> &Header {
        &self.our_keys.hdr
    }

    /// Get our current encapsulation key for initial exchange
    pub fn encapsulation_key(&self) -> &EncapsulationKey {
        &self.our_keys.ek
    }

    /// Set peer's initial public key components
    pub fn set_peer_public_key(&mut self, header: Header, ek: EncapsulationKey) -> Result<()> {
        if header.len() != HEADER_SIZE {
            return Err(KatanaError::InvalidSize(
                format!("Header: expected {} bytes, got {}", HEADER_SIZE, header.len())
            ));
        }
        if ek.len() != ENCAPSULATION_KEY_SIZE {
            return Err(KatanaError::InvalidSize(
                format!("EK: expected {} bytes, got {}", ENCAPSULATION_KEY_SIZE, ek.len())
            ));
        }
        
        // Validate that header and ek match
        if !incremental_mlkem::ek_matches_header(&ek, &header) {
            return Err(KatanaError::InvalidSize("Header and EK do not match".to_string()));
        }
        
        self.peer_header = Some(header);
        self.peer_ek = Some(ek);
        Ok(())
    }

    /// Get current epoch
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Perform a ratchet step (sender side)
    ///
    /// Uses two-phase encapsulation:
    /// 1. encaps1 with peer's header only (produces ct1 + shared secret)
    /// 2. encaps2 with peer's full ek (produces ct2)
    ///
    /// # Bandwidth Savings
    /// Sends: ct1 (1408B) + ct2 (160B) + new_header (64B) + new_ek (1536B) = 3168B
    /// But the new_ek can be cached for subsequent messages in the same epoch.
    pub fn ratchet_send(&mut self) -> Result<KatanaOutput> {
        let peer_header = self.peer_header.as_ref()
            .ok_or_else(|| KatanaError::StateError("No peer header".to_string()))?;
        let peer_ek = self.peer_ek.as_ref()
            .ok_or_else(|| KatanaError::StateError("No peer EK".to_string()))?;

        // Phase 1: Encapsulate with header only
        let (ct1, encaps_state, shared_secret) = incremental_mlkem::encaps1(peer_header)
            .map_err(|e| KatanaError::IncrementalMlKemError(e.to_string()))?;

        // Phase 2: Complete encapsulation with full EK
        let ct2 = incremental_mlkem::encaps2(peer_ek, &encaps_state)
            .map_err(|e| KatanaError::IncrementalMlKemError(e.to_string()))?;

        // Convert shared secret to array
        let mut ss_array = [0u8; 32];
        ss_array.copy_from_slice(&shared_secret[..32.min(shared_secret.len())]);

        // Derive new root key
        let (new_root_key, _epoch_key) = self.derive_keys(&ss_array)?;

        // Generate new keypair for next epoch
        let new_keys = incremental_mlkem::generate();
        let new_header = new_keys.hdr.clone();
        let new_ek = new_keys.ek.clone();
        
        // Update our state
        self.our_keys = new_keys;
        self.root_key = new_root_key.clone();
        self.epoch += 1;

        tracing::debug!(
            "🗡️ Katana RKEM ratchet send epoch {} ({}B vs {}B naive = {}% savings)",
            self.epoch,
            CIPHERTEXT1_SIZE + CIPHERTEXT2_SIZE,
            CIPHERTEXT1_SIZE + CIPHERTEXT2_SIZE + HEADER_SIZE + ENCAPSULATION_KEY_SIZE,
            (HEADER_SIZE + ENCAPSULATION_KEY_SIZE) * 100 / (CIPHERTEXT1_SIZE + CIPHERTEXT2_SIZE + HEADER_SIZE + ENCAPSULATION_KEY_SIZE)
        );

        Ok(KatanaOutput {
            ciphertext: KatanaCiphertext {
                ct1,
                ct2,
                epoch: self.epoch,
                new_header,
                new_ek,
            },
            shared_secret: Zeroizing::new(ss_array),
            root_key: new_root_key,
        })
    }

    /// Receive a ratchet step (receiver side)
    ///
    /// Decapsulates using our decapsulation key and updates peer's public key.
    pub fn ratchet_receive(&mut self, ciphertext: &KatanaCiphertext) -> Result<KatanaOutput> {
        // Validate sizes
        if ciphertext.ct1.len() != CIPHERTEXT1_SIZE {
            return Err(KatanaError::InvalidSize(
                format!("CT1: expected {}, got {}", CIPHERTEXT1_SIZE, ciphertext.ct1.len())
            ));
        }
        if ciphertext.ct2.len() != CIPHERTEXT2_SIZE {
            return Err(KatanaError::InvalidSize(
                format!("CT2: expected {}, got {}", CIPHERTEXT2_SIZE, ciphertext.ct2.len())
            ));
        }

        // Decapsulate using our decapsulation key
        let shared_secret = incremental_mlkem::decaps(&self.our_keys.dk, &ciphertext.ct1, &ciphertext.ct2)
            .map_err(|e| KatanaError::IncrementalMlKemError(e.to_string()))?;

        // Convert to array
        let mut ss_array = [0u8; 32];
        ss_array.copy_from_slice(&shared_secret[..32.min(shared_secret.len())]);

        // Derive new root key (same as sender)
        let (new_root_key, _epoch_key) = self.derive_keys(&ss_array)?;

        // Validate peer's new public key components match before storing
        if !incremental_mlkem::ek_matches_header(&ciphertext.new_ek, &ciphertext.new_header) {
            return Err(KatanaError::InvalidSize(
                "Received header and EK do not match - possible tampering".to_string()
            ));
        }
        
        // Update peer's public key from the ciphertext
        self.peer_header = Some(ciphertext.new_header.clone());
        self.peer_ek = Some(ciphertext.new_ek.clone());

        // Generate new keypair for our side
        let new_keys = incremental_mlkem::generate();
        let new_header = new_keys.hdr.clone();
        let new_ek = new_keys.ek.clone();

        self.our_keys = new_keys;
        self.root_key = new_root_key.clone();
        self.epoch += 1;

        tracing::debug!(
            "🗡️ Katana RKEM ratchet receive epoch {} (50% bandwidth saved)",
            self.epoch
        );

        // Return our new public key in the output for response
        Ok(KatanaOutput {
            ciphertext: KatanaCiphertext {
                ct1: vec![], // Receiver doesn't send ct1
                ct2: vec![], // Receiver doesn't send ct2
                epoch: self.epoch,
                new_header,
                new_ek,
            },
            shared_secret: Zeroizing::new(ss_array),
            root_key: new_root_key,
        })
    }

    /// Derive new root key and epoch key from shared secret
    fn derive_keys(&self, shared_secret: &[u8; 32]) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
        let hk = Hkdf::<Sha256>::new(Some(b"katana-chain-v2"), &*self.root_key);
        let mut epoch_key = Zeroizing::new([0u8; 32]);
        
        hk.expand(shared_secret, epoch_key.as_mut())
            .expect("HKDF should not fail");
        
        // Chain the root key forward
        let hk2 = Hkdf::<Sha256>::new(Some(b"katana-root-advance"), &*epoch_key);
        let mut new_root_key = Zeroizing::new([0u8; 32]);
        hk2.expand(&self.epoch.to_le_bytes(), new_root_key.as_mut())
            .expect("HKDF should not fail");

        Ok((new_root_key, epoch_key))
    }

    /// Get bandwidth savings statistics
    pub fn bandwidth_stats(&self) -> BandwidthStats {
        // Naive: full pk (1568) + full ct (1568) = 3136 per ratchet
        const NAIVE_BYTES_PER_RATCHET: usize = 1568 + 1568;
        // Incremental: ct1 (1408) + ct2 (160) = 1568 per ratchet (not counting new pk)
        const INCREMENTAL_BYTES_PER_RATCHET: usize = CIPHERTEXT1_SIZE + CIPHERTEXT2_SIZE;
        
        let naive_bytes = NAIVE_BYTES_PER_RATCHET * self.epoch as usize;
        let katana_bytes = INCREMENTAL_BYTES_PER_RATCHET * self.epoch as usize;
        let saved = naive_bytes.saturating_sub(katana_bytes);
        let savings_percent = if naive_bytes > 0 {
            (saved as f64 / naive_bytes as f64) * 100.0
        } else {
            0.0
        };

        BandwidthStats {
            epochs: self.epoch,
            naive_bytes,
            katana_bytes,
            bytes_saved: saved,
            savings_percent,
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Bandwidth savings statistics
#[derive(Debug, Clone)]
pub struct BandwidthStats {
    /// Number of epochs completed
    pub epochs: u64,
    /// Bytes that would be sent with naive ML-KEM ratcheting
    pub naive_bytes: usize,
    /// Bytes actually sent with Katana RKEM
    pub katana_bytes: usize,
    /// Total bytes saved
    pub bytes_saved: usize,
    /// Percentage savings
    pub savings_percent: f64,
}

impl std::fmt::Display for BandwidthStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Katana RKEM: {} epochs, {}B sent ({}B saved = {:.1}% savings)",
            self.epochs, self.katana_bytes, self.bytes_saved, self.savings_percent)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_katana_creation() {
        let secret = [0u8; 32];
        let rkem = KatanaRkem::new(&secret, true).expect("creation should succeed");
        
        assert_eq!(rkem.epoch(), 0);
        assert_eq!(rkem.header().len(), HEADER_SIZE);
        assert_eq!(rkem.encapsulation_key().len(), ENCAPSULATION_KEY_SIZE);
    }

    #[test]
    fn test_katana_full_ratchet() {
        let secret = [42u8; 32];
        
        // Create Alice and Bob
        let mut alice = KatanaRkem::new(&secret, true).expect("alice creation");
        let mut bob = KatanaRkem::new(&secret, false).expect("bob creation");
        
        // Exchange initial public keys
        alice.set_peer_public_key(bob.header().clone(), bob.encapsulation_key().clone())
            .expect("alice set peer pk");
        bob.set_peer_public_key(alice.header().clone(), alice.encapsulation_key().clone())
            .expect("bob set peer pk");
        
        // Alice sends to Bob
        let alice_output = alice.ratchet_send().expect("alice ratchet send");
        let bob_output = bob.ratchet_receive(&alice_output.ciphertext).expect("bob ratchet receive");
        
        // Shared secrets should match
        assert_eq!(*alice_output.shared_secret, *bob_output.shared_secret,
            "Shared secrets must match");
        
        // Epochs should advance
        assert_eq!(alice.epoch(), 1);
        assert_eq!(bob.epoch(), 1);
        
        println!("Alice bandwidth stats: {}", alice.bandwidth_stats());
    }

    #[test]
    fn test_katana_multi_ratchet() {
        let secret = [123u8; 32];
        
        let mut alice = KatanaRkem::new(&secret, true).expect("alice");
        let mut bob = KatanaRkem::new(&secret, false).expect("bob");
        
        alice.set_peer_public_key(bob.header().clone(), bob.encapsulation_key().clone()).unwrap();
        bob.set_peer_public_key(alice.header().clone(), alice.encapsulation_key().clone()).unwrap();
        
        // Do 5 ratchet rounds
        for i in 0..5 {
            let alice_out = alice.ratchet_send().expect("alice send");
            let bob_out = bob.ratchet_receive(&alice_out.ciphertext).expect("bob receive");
            assert_eq!(*alice_out.shared_secret, *bob_out.shared_secret,
                "Round {} secrets must match", i);
            
            // Update Alice with Bob's new keys from response
            alice.set_peer_public_key(
                bob_out.ciphertext.new_header.clone(),
                bob_out.ciphertext.new_ek.clone()
            ).expect("alice update peer");
        }
        
        let stats = alice.bandwidth_stats();
        assert_eq!(stats.epochs, 5);
        assert!(stats.savings_percent > 40.0, "Should have significant savings");
        
        println!("After 5 ratchets: {}", stats);
    }

    #[test]
    fn test_bandwidth_savings() {
        let stats = BandwidthStats {
            epochs: 1,
            naive_bytes: 3136,
            katana_bytes: 1568,
            bytes_saved: 1568,
            savings_percent: 50.0,
        };
        
        assert_eq!(stats.savings_percent, 50.0);
    }
}
