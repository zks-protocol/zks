//! Configuration types for ZKS SDK

use serde::{Deserialize, Serialize};

/// Security levels for connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Classical encryption (ChaCha20-Poly1305 only)
    Classical,
    
    /// Post-quantum encryption (ML-KEM + ChaCha20-Poly1305)
    PostQuantum,
    
    /// Maximum security (ML-KEM + drand + swarm entropy, 256-bit post-quantum computational)
    TrueVernam,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::PostQuantum
    }
}

/// Connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Security level
    pub security: SecurityLevel,
    
    /// Connection timeout
    pub timeout: std::time::Duration,
    
    /// Buffer size for data transfer
    pub buffer_size: usize,
    
    /// Enable traffic scrambling for traffic analysis resistance
    pub enable_scrambling: bool,
    
    /// Enable anti-replay protection
    pub enable_anti_replay: bool,
    
    /// Enable compression
    pub enable_compression: bool,
    
    /// Maximum message size
    pub max_message_size: usize,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            security: SecurityLevel::default(),
            timeout: std::time::Duration::from_secs(30),
            buffer_size: 64 * 1024, // 64KB
            enable_scrambling: true,
            enable_anti_replay: true,
            enable_compression: false,
            max_message_size: 16 * 1024 * 1024, // 16MB
        }
    }
}

impl ConnectionConfig {
    /// Create a new configuration with post-quantum security
    pub fn post_quantum() -> Self {
        Self {
            security: SecurityLevel::PostQuantum,
            ..Default::default()
        }
    }
    
    /// Create a new configuration with classical security
    pub fn classical() -> Self {
        Self {
            security: SecurityLevel::Classical,
            ..Default::default()
        }
    }
    
    /// Create a new configuration with true vernam security
    pub fn true_vernam() -> Self {
        Self {
            security: SecurityLevel::TrueVernam,
            ..Default::default()
        }
    }
    
    /// Set the buffer size
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }
    
    /// Set the timeout
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }
    
    /// Enable or disable scrambling
    pub fn with_scrambling(mut self, enable: bool) -> Self {
        self.enable_scrambling = enable;
        self
    }
    
    /// Enable or disable anti-replay protection
    pub fn with_anti_replay(mut self, enable: bool) -> Self {
        self.enable_anti_replay = enable;
        self
    }
    
    /// Enable or disable compression
    pub fn with_compression(mut self, enable: bool) -> Self {
        self.enable_compression = enable;
        self
    }
    
    /// Set the maximum message size
    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }
}