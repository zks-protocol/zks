//! Faisal Swarm - P2P Onion Routing with 256-bit Post-Quantum Security
//! 
//! # Overview
//! 
//! Faisal Swarm is a novel anonymity network topology combining:
//! - Multi-hop circuit construction (for traffic analysis resistance)
//! - Wasif-Vernam encryption at each layer (for 256-bit post-quantum computational security)
//! - P2P swarm architecture (for decentralization)
//! 
//! Unlike traditional onion routing (e.g., Tor) which uses AES encryption,
//! Faisal Swarm uses the Wasif-Vernam cipher, providing post-quantum security
//! against quantum computers.
//! 
//! # Architecture
//! 
//! ```text
//! Client → Guard Peer → Middle Peer → Exit Peer → Destination
//!          ↓ Vernam      ↓ Vernam       ↓ Vernam
//!        (256-bit post-quantum computational security at each hop)
//! ```
//! 
//! # Citation
//! 
//! If you use Faisal Swarm in academic work, please cite:
//! ```text
//! Faisal Swarm: A P2P Onion Routing Protocol with Post-Quantum Security
//! Author: Faisal
//! Year: 2026
//! ```

use libp2p::PeerId;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;
use tracing::info;

// Re-export submodules
pub mod circuit_manager;
pub mod cells;
pub mod encryption;

// =============================================================================
// Faisal Swarm Circuit Types
// =============================================================================

/// Circuit identifier (locally unique)
pub type CircuitId = u32;

/// Circuit state in Faisal Swarm topology
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    /// Building the circuit (handshakes in progress)
    Building,
    
    /// Ready for data transfer
    Ready,
    
    /// Extending with more hops
    Extending,
    
    /// Circuit failed
    Error(String),
    
    /// Being torn down
    Closing,
}

/// A single peer in the Faisal Swarm circuit
#[derive(Debug, Clone)]
pub struct SwarmHop {
    /// libp2p peer ID
    pub peer_id: PeerId,
    
    /// Peer's role in swarm circuit
    pub role: HopRole,
    
    /// Multiaddr to reach this peer
    pub multiaddr: libp2p::Multiaddr,
    
    /// Peer capabilities
    pub capabilities: SwarmCapabilities,
}

/// Role of a hop in a Faisal Swarm circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HopRole {
    /// Guard: Entry point (knows client IP)
    Guard,
    
    /// Middle: Intermediate relay (knows nothing)
    Middle,
    
    /// Exit: Destination endpoint (knows target)
    Exit,
}

/// Capabilities of a peer in the Faisal Swarm network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmCapabilities {
    /// Can relay traffic for others
    pub can_relay: bool,
    
    /// Can act as exit node
    pub can_exit: bool,
    
    /// Bandwidth tier (1-5, higher = faster)
    pub bandwidth_tier: u8,
}

/// Wasif-Vernam encryption layer for one hop
/// 
/// Each hop in a Faisal Swarm circuit has its own Wasif-Vernam cipher,
/// providing 256-bit post-quantum computational security at every layer.
pub struct SwarmLayer {
    /// Peer ID of this hop
    pub peer_id: PeerId,
    
    /// Forward cipher (client → relay) using Wasif-Vernam
    pub forward_cipher: Arc<RwLock<zks_crypt::wasif_vernam::WasifVernam>>,
    
    /// Backward cipher (relay → client) using Wasif-Vernam
    pub backward_cipher: Arc<RwLock<zks_crypt::wasif_vernam::WasifVernam>>,
    
    /// Shared secret (from ML-KEM handshake)
    pub shared_secret: [u8; 32],
    
    /// Constant-time anti-replay protection
    pub anti_replay: zks_crypt::anti_replay::BitmapAntiReplay,
    
    /// Packet counter
    pub counter: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for SwarmLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwarmLayer")
            .field("peer_id", &self.peer_id)
            .field("shared_secret", &"[REDACTED]")
            .field("counter", &self.counter.load(std::sync::atomic::Ordering::Relaxed))
            .finish()
    }
}

impl SwarmLayer {
    /// Create a new Wasif-Vernam layer for this hop
    pub fn new(peer_id: PeerId, forward_key: [u8; 32], backward_key: [u8; 32]) -> Result<Self> {
        let mut forward_cipher = zks_crypt::wasif_vernam::WasifVernam::new(forward_key)
            .map_err(|e| SwarmError::Encryption(format!("Failed to create forward cipher: {:?}", e)))?;
        
        let mut backward_cipher = zks_crypt::wasif_vernam::WasifVernam::new(backward_key)
            .map_err(|e| SwarmError::Encryption(format!("Failed to create backward cipher: {:?}", e)))?;
        
        // Required: derive base_iv for both ciphers (security fix M3)
        forward_cipher.derive_base_iv(&forward_key, true);
        backward_cipher.derive_base_iv(&backward_key, true);
        
        // Enable sequenced Vernam mode for 256-bit post-quantum computational security with desync resistance
        forward_cipher.enable_sequenced_vernam(forward_key);
        backward_cipher.enable_sequenced_vernam(backward_key);
        
        Ok(Self {
            peer_id,
            forward_cipher: Arc::new(RwLock::new(forward_cipher)),
            backward_cipher: Arc::new(RwLock::new(backward_cipher)),
            shared_secret: [0u8; 32],
            anti_replay: zks_crypt::anti_replay::BitmapAntiReplay::new(),
            counter: std::sync::atomic::AtomicU64::new(0),
        })
    }
    
    /// Encrypt data with Wasif-Vernam (client → relay)
    pub fn encrypt_forward(&self, data: &[u8]) -> Result<Vec<u8>> {
        let _pid = self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut cipher = self.forward_cipher.write()
            .map_err(|e| SwarmError::Encryption(format!("Failed to acquire forward cipher lock: {}", e)))?;
        cipher.encrypt(data)
            .map_err(|e| SwarmError::Encryption(format!("Forward encryption failed: {:?}", e)))
    }
    
    /// Decrypt data with Wasif-Vernam (relay → client)
    pub fn decrypt_backward(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 8 {
            return Err(SwarmError::Encryption("Packet too short".into()));
        }
        
        let pid = u64::from_be_bytes(data[0..8].try_into()
            .map_err(|_| SwarmError::Encryption("Invalid packet format: invalid PID".into()))?);
        
        // Constant-time anti-replay check
        self.anti_replay.validate(pid)
            .map_err(|_| SwarmError::ReplayDetected)?;
        
        let cipher = self.backward_cipher.write()
            .map_err(|e| SwarmError::Encryption(format!("Failed to acquire backward cipher lock: {}", e)))?;
        cipher.decrypt(data)
            .map_err(|e| SwarmError::Encryption(format!("Backward decryption failed: {:?}", e)))
    }
}

/// A complete Faisal Swarm circuit
#[derive(Debug)]
pub struct FaisalSwarmCircuit {
    /// Circuit ID
    pub id: CircuitId,
    
    /// Ordered list of hops (Guard → Middle → Exit)
    pub hops: Vec<SwarmHop>,
    
    /// Wasif-Vernam layers (one per hop)
    pub layers: Vec<SwarmLayer>,
    
    /// Current state
    pub state: CircuitState,
    
    /// When created
    pub created_at: Instant,
}

// No stream needed - we use request-response protocol

impl FaisalSwarmCircuit {
    /// Encrypt data with all Wasif-Vernam layers (onion encryption)
    /// 
    /// This is the core of Faisal Swarm: each layer uses Wasif-Vernam
    /// instead of AES, providing 256-bit post-quantum computational security.
    pub fn encrypt_onion(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut encrypted = plaintext.to_vec();
        
        // Encrypt in reverse (Exit → Guard)
        // Each layer wraps the previous with Wasif-Vernam
        for layer in self.layers.iter_mut().rev() {
            encrypted = layer.encrypt_forward(&encrypted)
                .map_err(|e| SwarmError::Encryption(format!("Onion encryption failed: {:?}", e)))?;
        }
        
        Ok(encrypted)
    }
    
    /// Decrypt data received from swarm circuit
    pub fn decrypt_onion(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut decrypted = ciphertext.to_vec();
        
        // Decrypt in order (Guard → Exit)
        // Each layer peels one Wasif-Vernam encryption
        for layer in &mut self.layers {
            decrypted = layer.decrypt_backward(&decrypted)
                .map_err(|e| SwarmError::Encryption(format!("Onion decryption failed: {:?}", e)))?;
        }
        
        Ok(decrypted)
    }
}

/// Faisal Swarm errors
/// Errors that can occur in Faisal Swarm operations
#[derive(Debug, thiserror::Error)]
pub enum SwarmError {
    /// Circuit with specified ID was not found
    #[error("Circuit not found: {0}")]
    NotFound(CircuitId),
    
    /// Handshake with peer failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
    
    /// Encryption/decryption operation failed
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    /// Replay attack was detected
    #[error("Replay attack detected")]
    ReplayDetected,
    
    /// Not enough swarm peers available to form circuit
    #[error("Not enough swarm peers: {0}")]
    NotEnoughPeers(String),
    
    /// libp2p networking error
    #[error("libp2p error: {0}")]
    Libp2p(String),
    
    /// Circuit is in invalid state for requested operation
    #[error("Invalid state: expected {expected:?}, got {actual:?}")]
    InvalidState { 
        /// Expected circuit state
        expected: CircuitState, 
        /// Actual circuit state
        actual: CircuitState 
    },
    
    /// Invalid argument was provided
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    
    /// Protocol violation or error
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    /// Feature or operation is not implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    
    /// Network connectivity error
    #[error("Network error: {0}")]
    Network(String),
    
    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Result type alias for Faisal Swarm operations
pub type Result<T> = std::result::Result<T, SwarmError>;

// Re-export main types
pub use circuit_manager::FaisalSwarmManager;
pub use cells::{FaisalSwarmCell, CellCommand, CellHeader};
pub use encryption::FaisalSwarmEncryption;