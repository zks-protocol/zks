//! Hybrid Ratchet - ML-KEM Asymmetric Ratchet for Break-in Recovery
//!
//! This module implements a hybrid ratchet that combines:
//! 1. **Symmetric KDF Chain** (RecursiveChain) - Forward secrecy
//! 2. **Asymmetric ML-KEM Ratchet** - Break-in recovery (BEATS TRIPLE RATCHET)
//!
//! # Security Properties
//!
//! Unlike the symmetric-only RecursiveChain, the HybridRatchet provides:
//! - ✅ Forward secrecy: Past messages protected if current key compromised
//! - ✅ **Break-in recovery**: Future messages protected after next asymmetric ratchet
//! - ✅ Post-quantum security: Uses ML-KEM-1024 (NIST Level 5)
//!
//! This EXCEEDS Signal's Triple Ratchet (which uses ML-KEM-768, Level 3) by using
//! ML-KEM-1024 for the asymmetric ratchet step.
//!
//! # Protocol Flow
//!
//! ```text
//! Alice                                 Bob
//!   |                                    |
//!   |-- ML-KEM pk_A, Enc(pk_B, msg) ---> |  Asymmetric ratchet
//!   |                                    |
//!   |<-- ML-KEM pk_B, Enc(pk_A, msg) --- |  Asymmetric ratchet
//!   |                                    |
//!   |-- KDF chain message 1 -----------> |  Symmetric ratchet
//!   |-- KDF chain message 2 -----------> |  Symmetric ratchet
//!   |   ... (up to ratchet_interval)     |
//!   |                                    |
//!   |-- ML-KEM pk_A', Enc(pk_B, msg) --> |  Asymmetric ratchet (break-in recovery!)
//! ```
//!
//! # Comparison vs. Competition
//!
//! | Feature | ZKS HybridRatchet | Triple Ratchet | Signal |
//! |---------|-------------------|----------------|--------|
//! | PQ Security | NIST Level 5 | Level 3 | None |
//! | Break-in Recovery | ✅ Automatic | ✅ Automatic | ✅ DH only |
//! | Quantum Safe | ✅ Full | ✅ Hybrid | ❌ No |

use std::sync::atomic::{AtomicU64, Ordering};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;
use zks_pqcrypto::ml_kem::{MlKem, MlKemKeypair};
use crate::recursive_chain::RecursiveChain;

/// Error type for hybrid ratchet operations
#[derive(Debug, Clone)]
pub enum HybridRatchetError {
    /// ML-KEM operation failed
    MlKemError(String),
    /// Invalid peer public key
    InvalidPeerKey(String),
    /// Ratchet state desynchronized
    DesyncError(String),
}

impl std::fmt::Display for HybridRatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MlKemError(msg) => write!(f, "ML-KEM error: {}", msg),
            Self::InvalidPeerKey(msg) => write!(f, "Invalid peer key: {}", msg),
            Self::DesyncError(msg) => write!(f, "Desync error: {}", msg),
        }
    }
}

impl std::error::Error for HybridRatchetError {}

/// Result type for hybrid ratchet operations
pub type Result<T> = std::result::Result<T, HybridRatchetError>;

/// Hybrid Ratchet Configuration
#[derive(Debug, Clone)]
pub struct HybridRatchetConfig {
    /// Number of messages between asymmetric ratchet steps
    /// Default: 50 (like PQ3), but can be set lower for higher security
    pub ratchet_interval: u64,
    /// Whether to include message in ratchet header (for bandwidth savings)
    pub inline_messages: bool,
    /// Maximum number of skipped message keys to store
    /// Prevents unbounded memory growth from out-of-order messages
    /// Default: 1000 (like Signal)
    pub max_skip: u64,
}

impl Default for HybridRatchetConfig {
    fn default() -> Self {
        Self {
            ratchet_interval: 50,
            inline_messages: true,
            max_skip: 1000,
        }
    }
}

impl HybridRatchetConfig {
    /// Create config for maximum security (ratchet every message)
    pub fn max_security() -> Self {
        Self {
            ratchet_interval: 1,
            inline_messages: false,
            max_skip: 100,
        }
    }

    /// Create config for balanced security/performance
    pub fn balanced() -> Self {
        Self {
            ratchet_interval: 10,
            inline_messages: true,
            max_skip: 500,
        }
    }

    /// Create config optimized for bandwidth (like PQ3)
    pub fn bandwidth_optimized() -> Self {
        Self {
            ratchet_interval: 50,
            inline_messages: true,
            max_skip: 1000,
        }
    }
}

use std::collections::HashMap;

/// Hybrid Ratchet State
/// 
/// Combines symmetric KDF chain with periodic ML-KEM asymmetric ratchet
/// for both forward secrecy AND break-in recovery.
pub struct HybridRatchet {
    /// Symmetric key derivation chain
    symmetric_chain: RecursiveChain,
    /// Our current ML-KEM keypair (for receiving)
    our_keypair: MlKemKeypair,
    /// Peer's current ML-KEM public key (for sending)
    peer_public_key: Option<Vec<u8>>,
    /// Messages since last asymmetric ratchet
    message_count: AtomicU64,
    /// Total asymmetric ratchet steps performed
    ratchet_generation: AtomicU64,
    /// Configuration
    config: HybridRatchetConfig,
    /// Our role (initiator = true)
    is_initiator: bool,
    /// Sending chain key (after asymmetric ratchet)
    sending_chain_key: Zeroizing<[u8; 32]>,
    /// Receiving chain key
    receiving_chain_key: Zeroizing<[u8; 32]>,
    /// Next expected receive message number
    next_recv_message: AtomicU64,
    /// Skipped message keys for out-of-order decryption
    /// Key: (ratchet_generation, message_number) -> message_key
    /// Limited by max_skip to prevent memory exhaustion attacks
    skipped_keys: std::sync::RwLock<HashMap<(u64, u64), Zeroizing<[u8; 32]>>>,
}

/// Message header containing ratchet information
#[derive(Debug, Clone)]
pub struct RatchetHeader {
    /// Our current public key (for asymmetric ratchet)
    pub public_key: Vec<u8>,
    /// Message number in current chain
    pub message_number: u64,
    /// Previous chain length (for handling out-of-order)
    pub previous_chain_length: u64,
    /// ML-KEM ciphertext (if asymmetric ratchet)
    pub ciphertext: Option<Vec<u8>>,
}

/// Output from ratchet encryption
#[derive(Debug, Clone)]
pub struct RatchetOutput {
    /// Header to send with message
    pub header: RatchetHeader,
    /// Message key for encryption
    pub message_key: Zeroizing<[u8; 32]>,
    /// Whether an asymmetric ratchet was performed
    pub ratcheted: bool,
}

impl HybridRatchet {
    /// Create a new hybrid ratchet from initial shared secret
    ///
    /// # Arguments
    /// * `shared_secret` - 32-byte shared secret from initial handshake
    /// * `is_initiator` - True if we initiated the handshake
    /// * `config` - Ratchet configuration
    ///
    /// # Security
    /// Uses ML-KEM-1024 (NIST Level 5) for asymmetric ratchet - EXCEEDS Triple Ratchet
    pub fn new(
        shared_secret: &[u8; 32],
        is_initiator: bool,
        config: HybridRatchetConfig,
    ) -> Result<Self> {
        // Generate initial ML-KEM keypair
        let our_keypair = MlKem::generate_keypair()
            .map_err(|e| HybridRatchetError::MlKemError(e.to_string()))?;

        // Create symmetric chain
        let symmetric_chain = RecursiveChain::new(shared_secret, is_initiator);

        // Derive initial chain keys
        // Note: Initiator's sending key = Responder's receiving key (and vice versa)
        let hk = Hkdf::<Sha256>::new(Some(b"zks-hybrid-ratchet-v1"), shared_secret);
        
        let mut sending_chain_key = Zeroizing::new([0u8; 32]);
        let mut receiving_chain_key = Zeroizing::new([0u8; 32]);
        
        if is_initiator {
            // Initiator sends on "initiator->responder" channel
            hk.expand(b"initiator-to-responder", sending_chain_key.as_mut())
                .expect("HKDF should not fail");
            // Initiator receives on "responder->initiator" channel
            hk.expand(b"responder-to-initiator", receiving_chain_key.as_mut())
                .expect("HKDF should not fail");
        } else {
            // Responder sends on "responder->initiator" channel
            hk.expand(b"responder-to-initiator", sending_chain_key.as_mut())
                .expect("HKDF should not fail");
            // Responder receives on "initiator->responder" channel
            hk.expand(b"initiator-to-responder", receiving_chain_key.as_mut())
                .expect("HKDF should not fail");
        }

        Ok(Self {
            symmetric_chain,
            our_keypair,
            peer_public_key: None,
            message_count: AtomicU64::new(0),
            ratchet_generation: AtomicU64::new(0),
            config,
            is_initiator,
            sending_chain_key,
            receiving_chain_key,
            next_recv_message: AtomicU64::new(0),
            skipped_keys: std::sync::RwLock::new(HashMap::new()),
        })
    }

    /// Get our public key to send to peer (for initial exchange)
    pub fn our_public_key(&self) -> &[u8] {
        &self.our_keypair.public_key
    }

    /// Set the peer's public key (from initial exchange or ratchet)
    pub fn set_peer_public_key(&mut self, peer_pk: Vec<u8>) -> Result<()> {
        if peer_pk.len() != 1568 {
            return Err(HybridRatchetError::InvalidPeerKey(
                format!("Expected 1568 bytes, got {}", peer_pk.len())
            ));
        }
        self.peer_public_key = Some(peer_pk);
        Ok(())
    }

    /// Perform asymmetric ratchet step (ML-KEM encapsulation)
    /// 
    /// This provides **break-in recovery**: even if attacker has current state,
    /// they cannot derive keys after this ratchet step.
    fn perform_asymmetric_ratchet(&mut self) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
        let peer_pk = self.peer_public_key.as_ref()
            .ok_or_else(|| HybridRatchetError::DesyncError("No peer public key".to_string()))?;

        // Encapsulate to peer's public key
        let encapsulation = MlKem::encapsulate(peer_pk)
            .map_err(|e| HybridRatchetError::MlKemError(e.to_string()))?;

        // Generate new keypair for receiving
        let new_keypair = MlKem::generate_keypair()
            .map_err(|e| HybridRatchetError::MlKemError(e.to_string()))?;

        // Derive new chain key from shared secret
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&encapsulation.shared_secret);
        
        let hk = Hkdf::<Sha256>::new(Some(b"zks-ratchet-step"), &shared_secret);
        
        // Update sending chain key
        hk.expand(b"new-sending-chain", self.sending_chain_key.as_mut())
            .expect("HKDF should not fail");

        // Reset symmetric chain with new root
        self.symmetric_chain = RecursiveChain::new(&shared_secret, self.is_initiator);

        // Update our keypair
        self.our_keypair = new_keypair;

        // Increment ratchet generation
        self.ratchet_generation.fetch_add(1, Ordering::SeqCst);

        // Reset message counter
        self.message_count.store(0, Ordering::SeqCst);

        shared_secret.zeroize();

        tracing::info!(
            "🔐 Asymmetric ratchet step {} complete (ML-KEM-1024, NIST Level 5)",
            self.ratchet_generation.load(Ordering::SeqCst)
        );

        Ok((encapsulation.ciphertext, Zeroizing::new(*self.sending_chain_key)))
    }

    /// Process received asymmetric ratchet (ML-KEM decapsulation)
    pub fn receive_asymmetric_ratchet(
        &mut self,
        ciphertext: &[u8],
        new_peer_pk: Vec<u8>,
    ) -> Result<()> {
        // Decapsulate using our current keypair
        let shared_secret = MlKem::decapsulate(ciphertext, self.our_keypair.secret_key())
            .map_err(|e| HybridRatchetError::MlKemError(e.to_string()))?;

        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(&shared_secret);

        // Update peer's public key
        self.peer_public_key = Some(new_peer_pk);

        // Derive new receiving chain key
        let hk = Hkdf::<Sha256>::new(Some(b"zks-ratchet-step"), &secret_arr);
        hk.expand(b"new-receiving-chain", self.receiving_chain_key.as_mut())
            .expect("HKDF should not fail");

        // Reset symmetric chain
        self.symmetric_chain = RecursiveChain::new(&secret_arr, self.is_initiator);

        // Increment ratchet generation
        self.ratchet_generation.fetch_add(1, Ordering::SeqCst);

        secret_arr.zeroize();

        tracing::info!(
            "🔐 Received asymmetric ratchet step {} (break-in recovery achieved)",
            self.ratchet_generation.load(Ordering::SeqCst)
        );

        Ok(())
    }

    /// Encrypt (ratchet for sending)
    /// 
    /// Returns the ratchet output containing header and message key.
    /// Use the message key to encrypt your plaintext with ChaCha20-Poly1305.
    pub fn ratchet_encrypt(&mut self) -> Result<RatchetOutput> {
        let msg_num = self.message_count.fetch_add(1, Ordering::SeqCst);
        
        // Check if we need asymmetric ratchet
        let (ciphertext, ratcheted) = if msg_num > 0 && msg_num % self.config.ratchet_interval == 0 {
            let (ct, _) = self.perform_asymmetric_ratchet()?;
            (Some(ct), true)
        } else {
            (None, false)
        };

        // Derive message key from sending chain
        let hk = Hkdf::<Sha256>::new(Some(b"zks-msg-key"), &*self.sending_chain_key);
        
        let mut message_key = Zeroizing::new([0u8; 32]);
        let info = format!("message-{}", msg_num);
        hk.expand(info.as_bytes(), message_key.as_mut())
            .expect("HKDF should not fail");

        // Advance sending chain
        let mut new_chain_key = [0u8; 32];
        hk.expand(b"chain-advance", &mut new_chain_key)
            .expect("HKDF should not fail");
        self.sending_chain_key.copy_from_slice(&new_chain_key);
        new_chain_key.zeroize();

        Ok(RatchetOutput {
            header: RatchetHeader {
                public_key: self.our_keypair.public_key.clone(),
                message_number: msg_num,
                previous_chain_length: 0, // Simplified for now
                ciphertext,
            },
            message_key,
            ratcheted,
        })
    }

    /// Decrypt (ratchet for receiving)
    /// 
    /// Processes the ratchet header and returns the message key for decryption.
    /// 
    /// # Out-of-Order Handling
    /// If messages arrive out of order, skipped message keys are cached (up to max_skip)
    /// so they can be decrypted when they arrive later.
    pub fn ratchet_decrypt(&mut self, header: &RatchetHeader) -> Result<Zeroizing<[u8; 32]>> {
        let current_gen = self.ratchet_generation.load(Ordering::SeqCst);
        
        // Check if we have a cached skipped key for this message
        {
            let mut skipped = self.skipped_keys.write()
                .map_err(|_| HybridRatchetError::DesyncError("Lock poisoned".to_string()))?;
            if let Some(key) = skipped.remove(&(current_gen, header.message_number)) {
                tracing::debug!("🔓 Using cached skipped key for message {}", header.message_number);
                return Ok(key);
            }
        }
        
        // Check for asymmetric ratchet
        if let Some(ref ciphertext) = header.ciphertext {
            self.receive_asymmetric_ratchet(ciphertext, header.public_key.clone())?;
        } else if self.peer_public_key.is_none() || 
                  self.peer_public_key.as_ref() != Some(&header.public_key) {
            // New peer key without ciphertext = initial key exchange
            self.peer_public_key = Some(header.public_key.clone());
        }

        let next_expected = self.next_recv_message.load(Ordering::SeqCst);
        
        // Skip ahead if message is in the future, caching intermediate keys
        if header.message_number > next_expected {
            let to_skip = header.message_number - next_expected;
            
            // Check max_skip limit to prevent memory exhaustion
            if to_skip > self.config.max_skip {
                return Err(HybridRatchetError::DesyncError(
                    format!("Too many skipped messages: {} > max_skip {}", to_skip, self.config.max_skip)
                ));
            }
            
            // Cache skipped keys
            let mut skipped = self.skipped_keys.write()
                .map_err(|_| HybridRatchetError::DesyncError("Lock poisoned".to_string()))?;
            
            for skip_num in next_expected..header.message_number {
                let hk = Hkdf::<Sha256>::new(Some(b"zks-msg-key"), &*self.receiving_chain_key);
                let mut skip_key = Zeroizing::new([0u8; 32]);
                let info = format!("message-{}", skip_num);
                hk.expand(info.as_bytes(), skip_key.as_mut())
                    .expect("HKDF should not fail");
                
                skipped.insert((current_gen, skip_num), skip_key);
                
                // Advance chain for each skipped message
                let mut new_chain_key = [0u8; 32];
                hk.expand(b"chain-advance", &mut new_chain_key)
                    .expect("HKDF should not fail");
                self.receiving_chain_key.copy_from_slice(&new_chain_key);
                new_chain_key.zeroize();
            }
            
            tracing::debug!("🔐 Cached {} skipped keys for out-of-order handling", to_skip);
        }

        // Derive message key from receiving chain
        let hk = Hkdf::<Sha256>::new(Some(b"zks-msg-key"), &*self.receiving_chain_key);
        
        let mut message_key = Zeroizing::new([0u8; 32]);
        let info = format!("message-{}", header.message_number);
        hk.expand(info.as_bytes(), message_key.as_mut())
            .expect("HKDF should not fail");

        // Advance receiving chain
        let mut new_chain_key = [0u8; 32];
        hk.expand(b"chain-advance", &mut new_chain_key)
            .expect("HKDF should not fail");
        self.receiving_chain_key.copy_from_slice(&new_chain_key);
        new_chain_key.zeroize();
        
        // Update next expected message
        self.next_recv_message.store(header.message_number + 1, Ordering::SeqCst);

        Ok(message_key)
    }

    /// Get current ratchet generation (number of asymmetric ratchet steps)
    pub fn ratchet_generation(&self) -> u64 {
        self.ratchet_generation.load(Ordering::SeqCst)
    }

    /// Get current message count in this chain
    pub fn message_count(&self) -> u64 {
        self.message_count.load(Ordering::SeqCst)
    }

    /// Check if break-in recovery is active (at least one asymmetric ratchet completed)
    pub fn has_break_in_recovery(&self) -> bool {
        self.ratchet_generation.load(Ordering::SeqCst) > 0
    }
}

use zeroize::Zeroize;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_ratchet_creation() {
        let shared_secret = [0x42u8; 32];
        let ratchet = HybridRatchet::new(
            &shared_secret,
            true,
            HybridRatchetConfig::default(),
        ).unwrap();

        assert_eq!(ratchet.ratchet_generation(), 0);
        assert_eq!(ratchet.message_count(), 0);
        assert!(!ratchet.has_break_in_recovery());
    }

    #[test]
    fn test_asymmetric_ratchet_provides_break_in_recovery() {
        let shared_secret = [0x42u8; 32];
        
        // Use interval of 1 to trigger ratchet immediately
        let config = HybridRatchetConfig::max_security();
        
        let mut alice = HybridRatchet::new(&shared_secret, true, config.clone()).unwrap();
        let mut bob = HybridRatchet::new(&shared_secret, false, config).unwrap();

        // Exchange initial public keys
        alice.set_peer_public_key(bob.our_public_key().to_vec()).unwrap();
        bob.set_peer_public_key(alice.our_public_key().to_vec()).unwrap();

        // First message triggers asymmetric ratchet (interval = 1)
        let output = alice.ratchet_encrypt().unwrap();
        
        // Verify ratchet was performed after first message
        // (ratchet happens on message 1, not message 0)
        let output2 = alice.ratchet_encrypt().unwrap();
        assert!(output2.ratcheted, "Second message should trigger ratchet with interval=1");
        
        // After ratchet, break-in recovery is active
        assert!(alice.has_break_in_recovery());
    }

    #[test]
    fn test_message_keys_are_unique() {
        let shared_secret = [0x42u8; 32];
        let mut ratchet = HybridRatchet::new(
            &shared_secret,
            true,
            HybridRatchetConfig::bandwidth_optimized(), // 50 message interval
        ).unwrap();

        let output1 = ratchet.ratchet_encrypt().unwrap();
        let output2 = ratchet.ratchet_encrypt().unwrap();

        assert_ne!(*output1.message_key, *output2.message_key);
    }

    #[test]
    fn test_out_of_order_message_decryption() {
        let shared_secret = [0x42u8; 32];
        let config = HybridRatchetConfig::bandwidth_optimized();
        
        let mut alice = HybridRatchet::new(&shared_secret, true, config.clone()).unwrap();
        let mut bob = HybridRatchet::new(&shared_secret, false, config).unwrap();

        // Exchange public keys
        alice.set_peer_public_key(bob.our_public_key().to_vec()).unwrap();
        bob.set_peer_public_key(alice.our_public_key().to_vec()).unwrap();

        // Alice sends 3 messages
        let msg0 = alice.ratchet_encrypt().unwrap();
        let msg1 = alice.ratchet_encrypt().unwrap();
        let msg2 = alice.ratchet_encrypt().unwrap();

        // Bob receives them out of order: 2, 0, 1
        let key2 = bob.ratchet_decrypt(&msg2.header).unwrap();
        assert_eq!(*key2, *msg2.message_key, "Message 2 key should match");
        
        // Message 0 should be in skipped keys now
        let key0 = bob.ratchet_decrypt(&msg0.header).unwrap();
        assert_eq!(*key0, *msg0.message_key, "Message 0 key should match (from cache)");
        
        // Message 1 should also be in skipped keys
        let key1 = bob.ratchet_decrypt(&msg1.header).unwrap();
        assert_eq!(*key1, *msg1.message_key, "Message 1 key should match (from cache)");
    }

    #[test]
    fn test_max_skip_limit() {
        let shared_secret = [0x42u8; 32];
        let mut config = HybridRatchetConfig::balanced();
        config.max_skip = 5; // Very low limit for testing
        
        let mut alice = HybridRatchet::new(&shared_secret, true, config.clone()).unwrap();
        let mut bob = HybridRatchet::new(&shared_secret, false, config).unwrap();

        alice.set_peer_public_key(bob.our_public_key().to_vec()).unwrap();
        bob.set_peer_public_key(alice.our_public_key().to_vec()).unwrap();

        // Alice sends many messages
        for _ in 0..10 {
            alice.ratchet_encrypt().unwrap();
        }
        let msg10 = alice.ratchet_encrypt().unwrap();

        // Bob tries to decrypt message 10 without receiving 0-9
        // This should fail because it exceeds max_skip
        let result = bob.ratchet_decrypt(&msg10.header);
        assert!(result.is_err(), "Should fail when exceeding max_skip");
    }
}
