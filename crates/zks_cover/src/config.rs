use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for cover traffic generation
/// 
/// This struct contains all parameters needed to configure cover traffic generation,
/// including Poisson timing rates, payload sizes, and cryptographic settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverConfig {
    /// Poisson rate (messages per second)
    poisson_rate: f64,
    
    /// Maximum delay between cover messages
    max_delay: Duration,
    
    /// Minimum delay between cover messages
    min_delay: Duration,
    
    /// Payload size for cover messages (bytes)
    payload_size: usize,
    
    /// Whether to use ML-KEM for key exchange
    use_post_quantum: bool,
    
    /// Circuit ID for Faisal Swarm integration
    circuit_id: Option<String>,
    
    /// Enable debug logging
    debug_logging: bool,
}

impl Default for CoverConfig {
    fn default() -> Self {
        Self {
            poisson_rate: 0.5, // 0.5 messages per second
            max_delay: Duration::from_secs(10),
            min_delay: Duration::from_millis(100),
            payload_size: 512, // Match ZKS fixed cell size
            use_post_quantum: true,
            circuit_id: None,
            debug_logging: false,
        }
    }
}

impl CoverConfig {
    /// Create a new builder for cover configuration
    /// 
    /// # Example
    /// ```
    /// use zks_cover::CoverConfig;
    /// 
    /// let config = CoverConfig::builder()
    ///     .poisson_rate(1.0)
    ///     .payload_size(512)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder() -> CoverConfigBuilder {
        CoverConfigBuilder::default()
    }
    
    /// Get the Poisson rate
    pub fn poisson_rate(&self) -> f64 {
        self.poisson_rate
    }
    
    /// Get the maximum delay
    pub fn max_delay(&self) -> Duration {
        self.max_delay
    }
    
    /// Get the minimum delay
    pub fn min_delay(&self) -> Duration {
        self.min_delay
    }
    
    /// Get the payload size
    pub fn payload_size(&self) -> usize {
        self.payload_size
    }
    
    /// Check if post-quantum cryptography is enabled
    pub fn use_post_quantum(&self) -> bool {
        self.use_post_quantum
    }
    
    /// Get the circuit ID
    pub fn circuit_id(&self) -> Option<&str> {
        self.circuit_id.as_deref()
    }
    
    /// Check if debug logging is enabled
    pub fn debug_logging(&self) -> bool {
        self.debug_logging
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> crate::error::Result<()> {
        if self.poisson_rate <= 0.0 {
            return Err(crate::error::CoverError::InvalidConfig(
                "Poisson rate must be positive".to_string()
            ));
        }
        
        if self.max_delay <= self.min_delay {
            return Err(crate::error::CoverError::InvalidConfig(
                "Max delay must be greater than min delay".to_string()
            ));
        }
        
        if self.payload_size == 0 {
            return Err(crate::error::CoverError::InvalidConfig(
                "Payload size must be positive".to_string()
            ));
        }
        
        Ok(())
    }
}

/// Builder for cover configuration
/// 
/// Provides a fluent API for constructing CoverConfig instances with
/// validation and sensible defaults.
#[derive(Debug, Default)]
pub struct CoverConfigBuilder {
    config: CoverConfig,
}

impl CoverConfigBuilder {
    /// Set the Poisson rate (messages per second)
    pub fn poisson_rate(mut self, rate: f64) -> Self {
        self.config.poisson_rate = rate;
        self
    }
    
    /// Set the maximum delay between messages
    pub fn max_delay(mut self, delay: Duration) -> Self {
        self.config.max_delay = delay;
        self
    }
    
    /// Set the minimum delay between messages
    pub fn min_delay(mut self, delay: Duration) -> Self {
        self.config.min_delay = delay;
        self
    }
    
    /// Set the payload size for cover messages
    pub fn payload_size(mut self, size: usize) -> Self {
        self.config.payload_size = size;
        self
    }
    
    /// Enable or disable post-quantum cryptography
    pub fn use_post_quantum(mut self, enabled: bool) -> Self {
        self.config.use_post_quantum = enabled;
        self
    }
    
    /// Set the circuit ID for Faisal Swarm
    pub fn circuit_id(mut self, id: String) -> Self {
        self.config.circuit_id = Some(id);
        self
    }
    
    /// Enable or disable debug logging
    pub fn debug_logging(mut self, enabled: bool) -> Self {
        self.config.debug_logging = enabled;
        self
    }
    
    /// Build the configuration
    pub fn build(self) -> crate::error::Result<CoverConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = CoverConfig::default();
        assert_eq!(config.poisson_rate(), 0.5);
        assert_eq!(config.payload_size(), 512);
        assert!(config.use_post_quantum());
    }
    
    #[test]
    fn test_builder() {
        let config = CoverConfig::builder()
            .poisson_rate(2.0)
            .payload_size(256)
            .debug_logging(true)
            .build()
            .unwrap();
        
        assert_eq!(config.poisson_rate(), 2.0);
        assert_eq!(config.payload_size(), 256);
        assert!(config.debug_logging());
    }
    
    #[test]
    fn test_invalid_config() {
        let result = CoverConfig::builder()
            .poisson_rate(-1.0)
            .build();
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_validate_delays() {
        let result = CoverConfig::builder()
            .min_delay(Duration::from_secs(10))
            .max_delay(Duration::from_secs(5))
            .build();
        
        assert!(result.is_err());
    }
}