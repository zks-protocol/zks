use serde::{Deserialize, Serialize};
use std::time::Duration;
use crate::defaults;
use crate::error::{SurbError, Result};

/// Configuration for SURB operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurbConfig {
    /// SURB lifetime before expiration
    pub lifetime: Duration,
    
    /// Maximum size of reply that can be sent via SURB
    pub max_reply_size: usize,
    
    /// Number of hops in SURB route
    pub route_length: usize,
    
    /// SURB ID length in bytes
    pub surb_id_length: usize,
    
    /// Whether to enable SURB functionality
    pub enabled: bool,
    
    /// Whether to use post-quantum cryptography (ML-KEM)
    pub post_quantum: bool,
}

impl Default for SurbConfig {
    fn default() -> Self {
        Self {
            lifetime: defaults::DEFAULT_SURB_LIFETIME,
            max_reply_size: defaults::DEFAULT_MAX_REPLY_SIZE,
            route_length: defaults::DEFAULT_ROUTE_LENGTH,
            surb_id_length: defaults::DEFAULT_SURB_ID_LENGTH,
            enabled: true,
            post_quantum: true,
        }
    }
}

/// Builder for SurbConfig
#[derive(Debug, Default)]
pub struct SurbConfigBuilder {
    config: SurbConfig,
}

impl SurbConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set SURB lifetime
    pub fn lifetime(mut self, lifetime: Duration) -> Self {
        if !lifetime.is_zero() {
            self.config.lifetime = lifetime;
        }
        self
    }
    
    /// Set maximum reply size
    pub fn max_reply_size(mut self, size: usize) -> Self {
        if size > 0 && size <= 65536 { // 64KB max
            self.config.max_reply_size = size;
        }
        self
    }
    
    /// Set route length
    pub fn route_length(mut self, length: usize) -> Self {
        if length >= 2 && length <= 10 {
            self.config.route_length = length;
        }
        self
    }
    
    /// Set SURB ID length
    pub fn surb_id_length(mut self, length: usize) -> Self {
        if length >= 8 && length <= 32 {
            self.config.surb_id_length = length;
        }
        self
    }
    
    /// Enable or disable SURB functionality
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }
    
    /// Enable or disable post-quantum cryptography
    pub fn post_quantum(mut self, post_quantum: bool) -> Self {
        self.config.post_quantum = post_quantum;
        self
    }
    
    /// Build the configuration
    pub fn build(self) -> Result<SurbConfig> {
        // Validate configuration
        if self.config.lifetime.is_zero() {
            return Err(SurbError::InvalidConfig("Lifetime cannot be zero".to_string()));
        }
        
        if self.config.max_reply_size == 0 || self.config.max_reply_size > 65536 {
            return Err(SurbError::InvalidConfig("Max reply size must be between 1 and 65536 bytes".to_string()));
        }
        
        if self.config.route_length < 2 || self.config.route_length > 10 {
            return Err(SurbError::InvalidConfig("Route length must be between 2 and 10 hops".to_string()));
        }
        
        if self.config.surb_id_length < 8 || self.config.surb_id_length > 32 {
            return Err(SurbError::InvalidConfig("SURB ID length must be between 8 and 32 bytes".to_string()));
        }
        
        Ok(self.config)
    }
}

impl SurbConfig {
    /// Create a builder
    pub fn builder() -> SurbConfigBuilder {
        SurbConfigBuilder::new()
    }
    
    /// Create configuration with no SURB functionality
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
    
    /// Create configuration for maximum anonymity
    pub fn maximum_anonymity() -> Self {
        Self {
            lifetime: Duration::from_secs(1800), // 30 minutes
            max_reply_size: 2048,
            route_length: 5,
            surb_id_length: 32,
            ..Default::default()
        }
    }
    
    /// Create configuration for minimal overhead
    pub fn minimal_overhead() -> Self {
        Self {
            lifetime: Duration::from_secs(300), // 5 minutes
            max_reply_size: 512,
            route_length: 2,
            surb_id_length: 8,
            ..Default::default()
        }
    }
}