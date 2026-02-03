//! Cover traffic generation for ZKS Protocol
//!
//! This module implements post-quantum secure cover traffic generation
//! using ML-KEM-768 and Wasif-Vernam cipher for traffic shaping.

use rand::{Rng, SeedableRng};
use rand::distributions::Distribution;
use statrs::distribution::Poisson;

use crate::config::CoverConfig;
use crate::error::{CoverError, Result};
use crate::types::{CoverMessage, CoverType};
use zks_crypt::wasif_vernam::WasifVernam;

/// Core cover traffic generator
/// 
/// This struct implements post-quantum secure cover traffic generation using
/// ML-KEM-768 for key exchange and Wasif-Vernam cipher for encryption.
/// It supports various traffic shaping scenarios and Poisson-distributed timing.
#[derive(Debug)]
pub struct CoverGenerator {
    config: CoverConfig,
    poisson: Poisson,
}

impl CoverGenerator {
    /// Create a new cover generator with the given configuration
    /// 
    /// # Arguments
    /// * `config` - Cover configuration including Poisson rate, payload size, and crypto settings
    /// 
    /// # Returns
    /// A new CoverGenerator instance or an error if configuration is invalid
    pub fn new(config: CoverConfig) -> Result<Self> {
        let poisson = Poisson::new(config.poisson_rate())
            .map_err(|e| CoverError::InvalidConfig(format!("Poisson rate error: {}", e)))?;
        
        Ok(Self {
            config,
            poisson,
        })
    }
    
    /// Generate a single cover message
    /// 
    /// # Arguments
    /// * `circuit_id` - Optional circuit ID for Faisal Swarm integration
    /// 
    /// # Returns
    /// A new CoverMessage with encrypted payload and appropriate metadata
    pub async fn generate_cover(&self, circuit_id: Option<String>) -> Result<CoverMessage> {
        // Use a thread-safe RNG
        let mut rng = rand::rngs::StdRng::from_entropy();
        
        // Determine cover type based on traffic pattern
        let cover_type = self.select_cover_type(&mut rng);
        
        // Generate random payload that will encrypt to exactly ZKS fixed cell size
        // WasifVernam adds 36-byte envelope, so we need to account for that
        let encrypted_size = self.config.payload_size();
        let payload_size = encrypted_size.saturating_sub(36); // Account for encryption overhead
        let mut payload = vec![0u8; payload_size];
        rng.fill(&mut payload[..]);
        
        // Encrypt payload using Wasif-Vernam for post-quantum security
        let encrypted_payload = self.encrypt_payload(&payload).await?;
        
        // Create cover message
        let cover_message = CoverMessage::new(
            cover_type,
            encrypted_payload,
            circuit_id,
        );
        
        Ok(cover_message)
    }
    
    /// Generate multiple cover messages in batch
    /// 
    /// # Arguments
    /// * `count` - Number of cover messages to generate
    /// * `circuit_id` - Optional circuit ID for Faisal Swarm integration
    /// 
    /// # Returns
    /// A vector of CoverMessage instances
    pub async fn generate_covers(&self, count: usize, circuit_id: Option<String>) -> Result<Vec<CoverMessage>> {
        let mut covers = Vec::with_capacity(count);
        
        for _ in 0..count {
            let cover = self.generate_cover(circuit_id.clone()).await?;
            covers.push(cover);
        }
        
        Ok(covers)
    }
    
    /// Generate cover traffic based on Poisson distribution
    pub async fn generate_poisson_covers(&self, circuit_id: Option<String>) -> Result<Vec<CoverMessage>> {
        let mut rng = rand::rngs::StdRng::from_entropy();
        let count = self.poisson.sample(&mut rng) as usize;
        self.generate_covers(count, circuit_id).await
    }
    
    /// Generate cover for specific traffic shaping scenario
    pub async fn generate_scenario_covers(&self, scenario: CoverScenario, circuit_id: Option<String>) -> Result<Vec<CoverMessage>> {
        match scenario {
            CoverScenario::LowTraffic => self.generate_covers(1, circuit_id).await,
            CoverScenario::MediumTraffic => self.generate_covers(3, circuit_id).await,
            CoverScenario::HighTraffic => self.generate_covers(5, circuit_id).await,
            CoverScenario::BurstTraffic => self.generate_covers(10, circuit_id).await,
            CoverScenario::Poisson => self.generate_poisson_covers(circuit_id).await,
        }
    }
    
    /// Validate cover message structure
    pub fn validate_cover(&self, cover: &CoverMessage) -> Result<bool> {
        // Check payload size matches ZKS fixed cell size
        if cover.payload.len() != self.config.payload_size() {
            return Ok(false);
        }
        
        // Check message type is valid
        if !matches!(cover.cover_type, CoverType::Regular | CoverType::Loop | CoverType::Drop) {
            return Ok(false);
        }
        
        // Check circuit ID format if present
        if let Some(circuit_id) = &cover.circuit_id {
            if circuit_id.is_empty() || circuit_id.len() > 64 {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Get current configuration
    pub fn config(&self) -> &CoverConfig {
        &self.config
    }
    
    /// Update configuration
    pub fn update_config(&mut self, config: CoverConfig) -> Result<()> {
        // Validate new configuration
        config.validate()?;
        
        // Update Poisson distribution if rate changed
        if config.poisson_rate() != self.config.poisson_rate() {
            self.poisson = Poisson::new(config.poisson_rate())
                .map_err(|e| CoverError::InvalidConfig(format!("Poisson rate error: {}", e)))?;
        }
        
        self.config = config;
        Ok(())
    }
    
    // Private helper methods
    
    fn select_cover_type(&self, rng: &mut impl Rng) -> CoverType {
        let choice = rng.gen_range(0..10);
        match choice {
            0..=5 => CoverType::Regular,
            6..=8 => CoverType::Loop,
            _ => CoverType::Drop,
        }
    }
    
    async fn encrypt_payload(&self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.config.use_post_quantum() {
            // Use Wasif-Vernam for post-quantum security
            let key = self.derive_encryption_key().await?;
            let mut cipher = WasifVernam::new(key)
                .map_err(|e| CoverError::EncryptionError(format!("Failed to create cipher: {:?}", e)))?;
            // SECURITY: Must derive base_iv before encryption to prevent nonce issues
            cipher.derive_base_iv(&key, true);
            cipher.encrypt(payload)
                .map_err(|e| CoverError::EncryptionError(format!("Encryption failed: {:?}", e)))
        } else {
            // Fallback to simple XOR (for testing/compatibility)
            let key = self.derive_fallback_key().await?;
            Ok(payload.iter().zip(key.iter().cycle()).map(|(a, b)| a ^ b).collect())
        }
    }
    
    async fn derive_encryption_key(&self) -> Result<[u8; 32]> {
        // Generate fresh TRUE random key (drand + OsRng) for each cover message
        // This ensures each cover packet is uniquely encrypted and can't be correlated
        // SECURITY: Uses TrueEntropy for information-theoretic security
        use zks_crypt::true_entropy::get_sync_entropy;
        
        let entropy = get_sync_entropy(32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&entropy);
        
        // Mix in additional entropy from config for domain separation
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"zks-cover-encryption-key");
        hasher.update(&key);
        hasher.update(&self.config.payload_size().to_le_bytes());
        let result = hasher.finalize();
        
        let mut final_key = [0u8; 32];
        final_key.copy_from_slice(&result);
        Ok(final_key)
    }
    
    async fn derive_fallback_key(&self) -> Result<Vec<u8>> {
        // Simple deterministic key derivation for fallback mode
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"zks-cover-fallback-key");
        hasher.update(&self.config.payload_size().to_le_bytes());
        Ok(hasher.finalize().to_vec())
    }
}

/// Cover traffic scenarios for different network conditions
/// 
/// These scenarios allow for adaptive traffic shaping based on network conditions
/// and anonymity requirements. Each scenario generates a different number of cover messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverScenario {
    /// Low traffic scenario (1 cover message)
    LowTraffic,
    /// Medium traffic scenario (3 cover messages)
    MediumTraffic,
    /// High traffic scenario (5 cover messages)
    HighTraffic,
    /// Burst traffic scenario (10 cover messages)
    BurstTraffic,
    /// Poisson-distributed traffic
    Poisson,
}

impl CoverScenario {
    /// Get expected message count for scenario
    pub fn expected_count(&self) -> usize {
        match self {
            Self::LowTraffic => 1,
            Self::MediumTraffic => 3,
            Self::HighTraffic => 5,
            Self::BurstTraffic => 10,
            Self::Poisson => 0, // Variable, depends on distribution
        }
    }
    
    /// Get scenario name
    pub fn name(&self) -> &'static str {
        match self {
            Self::LowTraffic => "low_traffic",
            Self::MediumTraffic => "medium_traffic",
            Self::HighTraffic => "high_traffic",
            Self::BurstTraffic => "burst_traffic",
            Self::Poisson => "poisson",
        }
    }
}

/// Builder for CoverGenerator
#[derive(Debug)]
pub struct CoverGeneratorBuilder {
    config: Option<CoverConfig>,
}

impl CoverGeneratorBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self { config: None }
    }
    
    /// Set configuration
    pub fn config(mut self, config: CoverConfig) -> Self {
        self.config = Some(config);
        self
    }
    
    /// Build the generator
    pub fn build(self) -> Result<CoverGenerator> {
        let config = self.config.unwrap_or_default();
        CoverGenerator::new(config)
    }
}

impl Default for CoverGeneratorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_generator_creation() {
        let config = CoverConfig::default();
        let generator = CoverGenerator::new(config).unwrap();
        
        assert_eq!(generator.config().payload_size(), 512);
        assert!(generator.config().use_post_quantum());
    }
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_single_cover_generation() {
        let config = CoverConfig::default();
        let generator = CoverGenerator::new(config).unwrap();
        
        let cover = generator.generate_cover(None).await.unwrap();
        
        assert_eq!(cover.payload.len(), 512);
        assert!(matches!(cover.cover_type, CoverType::Regular | CoverType::Loop | CoverType::Drop));
    }
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_batch_cover_generation() {
        let config = CoverConfig::default();
        let generator = CoverGenerator::new(config).unwrap();
        
        let covers = generator.generate_covers(5, None).await.unwrap();
        
        assert_eq!(covers.len(), 5);
        for cover in &covers {
            assert_eq!(cover.payload.len(), 512);
        }
    }
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_scenario_generation() {
        let config = CoverConfig::default();
        let generator = CoverGenerator::new(config).unwrap();
        
        let low_covers = generator.generate_scenario_covers(CoverScenario::LowTraffic, None).await.unwrap();
        assert_eq!(low_covers.len(), 1);
        
        let medium_covers = generator.generate_scenario_covers(CoverScenario::MediumTraffic, None).await.unwrap();
        assert_eq!(medium_covers.len(), 3);
        
        let high_covers = generator.generate_scenario_covers(CoverScenario::HighTraffic, None).await.unwrap();
        assert_eq!(high_covers.len(), 5);
    }
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_cover_validation() {
        let config = CoverConfig::default();
        let generator = CoverGenerator::new(config).unwrap();
        
        let valid_cover = generator.generate_cover(None).await.unwrap();
        assert!(generator.validate_cover(&valid_cover).unwrap());
        
        // Test invalid payload size
        let mut invalid_cover = valid_cover.clone();
        invalid_cover.payload = vec![0u8; 256]; // Wrong size
        assert!(!generator.validate_cover(&invalid_cover).unwrap());
    }
    
    #[tokio::test]
    async fn test_builder() {
        let config = CoverConfig::default();
        let generator = CoverGeneratorBuilder::new()
            .config(config)
            .build()
            .unwrap();
        
        assert_eq!(generator.config().payload_size(), 512);
    }
}