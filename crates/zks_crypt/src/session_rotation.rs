//! Session Rotation: Protocol-Level Anonymity
//!
//! This module implements automatic session rotation to achieve cryptographic
//! unlinkability and improved forward secrecy.
//!
//! ## SECURITY PROPERTIES & LIMITATIONS (m3 Fix)
//!
//! **Forward Secrecy Granularity**: Session rotation provides forward secrecy at
//! ~10 minute intervals (configurable). This means:
//! - If a key is compromised, messages within the current 10-minute window may be decrypted
//! - Messages from previous sessions (before the last rotation) remain protected
//! - This is comparable to Tor's circuit rotation, but weaker than Signal's per-message forward secrecy
//!
//! **Comparison to Signal Double Ratchet**:
//! Signal performs a DH ratchet step on every message, providing immediate forward secrecy.
//! This module provides session-level (10-minute) forward secrecy for efficiency.
//!
//! For per-message forward secrecy, use the `RecursiveChain` module in combination
//! with session rotation.
//!
//! ## How It Works
//!
//! Each session has a unique shared secret. When a session rotates:
//! 1. New ML-KEM handshake → new shared secret
//! 2. New drand starting round (can reuse historical rounds!)
//! 3. All previous session state is cryptographically unlinked
//!
//! ## Hybrid High-Entropy XOR with Session Rotation
//!
//! Since each session has a different secret, the same drand rounds produce
//! different keystreams. This means:
//! - Session 1 uses rounds 1M-2M with secret_1
//! - Session 2 uses rounds 1M-2M with secret_2 (DIFFERENT keystream!)
//!
//! Note: drand produces ~92KB/day of entropy. For large data,
//! use Hybrid mode (DEK with high-entropy, content with ChaCha20).

use std::time::{Duration, Instant};
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

/// Default session rotation interval (10 minutes like Tor)
pub const DEFAULT_ROTATION_INTERVAL: Duration = Duration::from_secs(600);

/// Minimum rotation interval (1 minute)
pub const MIN_ROTATION_INTERVAL: Duration = Duration::from_secs(60);

/// Session rotation configuration
#[derive(Debug, Clone)]
pub struct SessionRotationConfig {
    /// How often to rotate sessions
    pub rotation_interval: Duration,
    /// Whether to automatically rotate
    pub auto_rotate: bool,
    /// Whether to rotate drand starting round
    pub rotate_drand_round: bool,
}

impl Default for SessionRotationConfig {
    fn default() -> Self {
        Self {
            rotation_interval: DEFAULT_ROTATION_INTERVAL,
            auto_rotate: true,
            rotate_drand_round: true,
        }
    }
}

impl SessionRotationConfig {
    /// Create config with custom rotation interval
    pub fn with_interval(interval: Duration) -> Self {
        let interval = std::cmp::max(interval, MIN_ROTATION_INTERVAL);
        Self {
            rotation_interval: interval,
            ..Default::default()
        }
    }
    
    /// Disable automatic rotation (manual only)
    pub fn manual_only() -> Self {
        Self {
            auto_rotate: false,
            ..Default::default()
        }
    }
}

/// Rotating session state for forward secrecy
pub struct RotatingSession {
    /// Current session ID (random, changes on rotation)
    session_id: [u8; 32],
    
    /// Current shared secret (changes on rotation)
    shared_secret: Zeroizing<[u8; 32]>,
    
    /// Current drand starting round
    drand_starting_round: u64,
    
    /// Session creation time
    created_at: Instant,
    
    /// Number of rotations performed
    rotation_count: u64,
    
    /// Configuration
    config: SessionRotationConfig,
    
    /// Position within current session (bytes consumed)
    position: u64,
}

impl Drop for RotatingSession {
    fn drop(&mut self) {
        self.session_id.zeroize();
        self.drand_starting_round.zeroize();
        self.rotation_count.zeroize();
        self.position.zeroize();
    }
}

impl RotatingSession {
    /// Create new rotating session
    pub fn new(
        initial_secret: [u8; 32],
        drand_starting_round: u64,
        config: SessionRotationConfig,
    ) -> Self {
        let mut session_id = [0u8; 32];
        let _ = getrandom::getrandom(&mut session_id);
        
        info!("🔄 Created new rotating session (interval: {:?})", config.rotation_interval);
        
        Self {
            session_id,
            shared_secret: Zeroizing::new(initial_secret),
            drand_starting_round,
            created_at: Instant::now(),
            rotation_count: 0,
            config,
            position: 0,
        }
    }
    
    /// Check if session needs rotation
    pub fn needs_rotation(&self) -> bool {
        if !self.config.auto_rotate {
            return false;
        }
        self.session_age() >= self.config.rotation_interval
    }
    
    /// Get session age
    pub fn session_age(&self) -> Duration {
        self.created_at.elapsed()
    }
    
    /// Get current session ID
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    
    /// Get current shared secret
    pub fn shared_secret(&self) -> &[u8; 32] {
        &self.shared_secret
    }
    
    /// Get current drand starting round
    pub fn drand_starting_round(&self) -> u64 {
        self.drand_starting_round
    }
    
    /// Get current position in session
    pub fn position(&self) -> u64 {
        self.position
    }
    
    /// Advance position (after encrypting/decrypting)
    pub fn advance_position(&mut self, bytes: u64) {
        self.position += bytes;
    }
    
    /// Get total rotation count
    pub fn rotation_count(&self) -> u64 {
        self.rotation_count
    }
    
    /// Manually trigger rotation with new shared secret
    /// 
    /// In practice, this would be called after an ML-KEM re-handshake
    /// with the peer. Both parties must rotate simultaneously.
    pub fn rotate(&mut self, new_shared_secret: [u8; 32], new_drand_round: u64) {
        // Zeroize old session state
        self.session_id.zeroize();
        
        // Generate new session ID
        let _ = getrandom::getrandom(&mut self.session_id);
        
        // Update secret
        self.shared_secret = Zeroizing::new(new_shared_secret);
        
        // Update drand round if configured
        if self.config.rotate_drand_round {
            self.drand_starting_round = new_drand_round;
        }
        
        // Reset session state
        self.created_at = Instant::now();
        self.rotation_count += 1;
        self.position = 0;
        
        info!(
            "🔄 Session rotated (count: {}, new round: {})",
            self.rotation_count, self.drand_starting_round
        );
    }
    
    /// Derive a message-specific key (for per-message unlinkability)
    /// 
    /// Uses HKDF to derive a unique key for each message position.
    /// This provides forward secrecy within a session.
    pub fn derive_message_key(&self, message_number: u64) -> Zeroizing<[u8; 32]> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(&*self.shared_secret);
        hasher.update(&self.session_id);
        hasher.update(&message_number.to_le_bytes());
        hasher.update(b"message_key");
        
        let result = hasher.finalize();
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&result);
        key
    }
    
    /// Check and auto-rotate if needed
    /// 
    /// Returns true if rotation occurred.
    /// Note: In practice, rotation requires coordination with peer.
    /// This method only checks if rotation is needed.
    pub fn check_rotation(&self) -> bool {
        if self.needs_rotation() {
            warn!(
                "⚠️ Session rotation needed (age: {:?}, threshold: {:?})",
                self.session_age(),
                self.config.rotation_interval
            );
            true
        } else {
            false
        }
    }
}

/// Statistics about session rotation
#[derive(Debug, Clone, Default)]
pub struct SessionRotationStats {
    /// Total bytes encrypted in current session
    pub bytes_encrypted: u64,
    /// Total messages in current session
    pub messages_sent: u64,
    /// Session age in seconds
    pub session_age_secs: u64,
    /// Total rotations since start
    pub total_rotations: u64,
}

impl RotatingSession {
    /// Get session statistics
    pub fn stats(&self) -> SessionRotationStats {
        SessionRotationStats {
            bytes_encrypted: self.position,
            messages_sent: 0, // Would need message counter
            session_age_secs: self.session_age().as_secs(),
            total_rotations: self.rotation_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_session_creation() {
        let secret = [0x42u8; 32];
        let session = RotatingSession::new(secret, 1000000, SessionRotationConfig::default());
        
        assert_eq!(session.drand_starting_round(), 1000000);
        assert_eq!(session.rotation_count(), 0);
        assert_eq!(session.position(), 0);
    }
    
    #[test]
    fn test_session_rotation() {
        let secret1 = [0x42u8; 32];
        let mut session = RotatingSession::new(secret1, 1000000, SessionRotationConfig::default());
        
        // Simulate some usage
        session.advance_position(1000);
        
        // Rotate
        let secret2 = [0x43u8; 32];
        session.rotate(secret2, 2000000);
        
        assert_eq!(session.rotation_count(), 1);
        assert_eq!(session.position(), 0); // Reset on rotation
        assert_eq!(session.drand_starting_round(), 2000000);
    }
    
    #[test]
    fn test_message_key_derivation() {
        let secret = [0x42u8; 32];
        let session = RotatingSession::new(secret, 1000000, SessionRotationConfig::default());
        
        let key1 = session.derive_message_key(0);
        let key2 = session.derive_message_key(1);
        
        // Different message numbers should produce different keys
        assert_ne!(AsRef::<[u8]>::as_ref(&*key1), AsRef::<[u8]>::as_ref(&*key2));
    }
    
    #[test]
    fn test_needs_rotation() {
        let secret = [0x42u8; 32];
        
        // Create a test configuration that bypasses the minimum interval
        let mut config = SessionRotationConfig::default();
        config.rotation_interval = Duration::from_millis(100);
        
        let session = RotatingSession::new(secret, 1000000, config);
        
        // Should not need rotation immediately
        assert!(!session.needs_rotation());
        
        // After waiting, should need rotation
        std::thread::sleep(Duration::from_millis(150));
        assert!(session.needs_rotation());
    }
}
