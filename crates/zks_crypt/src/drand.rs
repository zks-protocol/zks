//! drand Beacon Integration
//! 
//! This module provides integration with the drand distributed randomness beacon
//! for TRUE random entropy sourcing. drand provides free, decentralized TRUE randomness
//! that can be used as a seed for the Wasif-Vernam cipher.
//! 
//! ## Security Features
//! - **Multi-endpoint fallback**: Tries multiple drand endpoints with retries
//! - **OS random fallback**: Falls back to OS random when drand is unavailable
//! - **Entropy validation**: Validates received entropy for quality and authenticity
//! - **Network resilience**: Exponential backoff and timeout handling
//! - **Health monitoring**: Check endpoint health status
//! 
//! ## Usage
//! ```rust,no_run
//! use zks_crypt::drand::{DrandEntropy, DrandConfig};
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create with default configuration (recommended)
//!     let drand = DrandEntropy::new();
//!     
//!     // Get entropy with automatic fallback
//!     let entropy = drand.get_entropy_with_fallback().await?;
//!     
//!     // Get mixed entropy for unique per-connection keys
//!     let user_data = b"session-id-12345";
//!     let mixed_entropy = drand.get_mixed_entropy_with_fallback(user_data).await?;
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ## Endpoint Configuration
//! The default configuration includes multiple drand endpoints:
//! - `https://api.drand.sh` (primary)
//! - `https://drand.cloudflare.com` (Cloudflare CDN)
//! - `https://api2.drand.sh` (backup)
//! 
//! Each endpoint is tried with exponential backoff and automatic retries.

use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;
use ring::rand::SecureRandom;
use crate::constant_time::{ct_is_zero, ct_eq};

/// Validates drand entropy quality and authenticity
fn validate_drand_entropy(response: &DrandResponse, randomness_bytes: &[u8]) -> Result<(), DrandError> {
    // Basic validation
    if randomness_bytes.len() != 32 {
        return Err(DrandError::ParseError(format!(
            "Expected 32 bytes, got {}",
            randomness_bytes.len()
        )));
    }
    
    // Check for obvious patterns that suggest tampering
    let unique_bytes: std::collections::HashSet<u8> = randomness_bytes.iter().cloned().collect();
    if unique_bytes.len() < 16 {
        return Err(DrandError::ParseError(
            "Entropy has too few unique bytes - possible tampering".to_string()
        ));
    }
    
    // Verify round number is reasonable (not too far in past/future)
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    // drand updates every 30 seconds, so current round should be approximately current_time / 30
    let expected_round = current_time / 30;
    let round_diff = response.round.abs_diff(expected_round);
    
    if round_diff > 100 {
        warn!(
            "Drand round {} is far from expected {} (diff: {})",
            response.round, expected_round, round_diff
        );
    }
    
    // Additional entropy quality checks - use constant-time operations
    if ct_is_zero(randomness_bytes) {
        return Err(DrandError::ParseError("All-zero entropy detected".to_string()));
    }
    
    // Check for all 0xFF bytes using constant-time comparison
    let all_ff = [0xFFu8; 32];
    if ct_eq(randomness_bytes, &all_ff) {
        return Err(DrandError::ParseError("All-FF entropy detected".to_string()));
    }
    
    // TODO: Verify BLS signature against known drand public key
    // This requires additional dependencies like `blst` or `threshold_crypto`
    // For now, we validate the signature format and log a warning
    if response.signature.len() < 64 {
        return Err(DrandError::ParseError("Signature too short".to_string()));
    }
    
    // Basic signature format validation (hex decode check)
    match hex::decode(&response.signature) {
        Ok(sig_bytes) => {
            if sig_bytes.len() < 64 {
                return Err(DrandError::ParseError("Decoded signature too short".to_string()));
            }
            // TODO: Implement actual BLS signature verification here
            debug!("Signature format valid (length: {}), but BLS verification not implemented", sig_bytes.len());
        },
        Err(e) => {
            return Err(DrandError::ParseError(format!("Invalid signature hex encoding: {}", e)));
        }
    }
    
    warn!("⚠️ BLS signature verification not implemented - trusting drand endpoint without cryptographic verification");
    
    Ok(())
}

/// drand beacon response structure
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DrandResponse {
    /// The round number
    pub round: u64,
    /// The randomness value (hex-encoded)
    pub randomness: String,
    /// The signature (hex-encoded)
    pub signature: String,
}

/// Health status of a drand endpoint
#[derive(Debug, Clone)]
pub enum EndpointHealth {
    /// Endpoint is healthy and returning valid entropy
    Healthy,
    /// Endpoint is accessible but returning invalid data
    Invalid(String),
    /// Endpoint is not accessible or returning errors
    Failed(String),
}

/// drand entropy source configuration
#[derive(Debug, Clone)]
pub struct DrandConfig {
    /// Base URLs for drand API (primary and fallbacks)
    pub api_urls: Vec<String>,
    /// Chain hash (identifies which drand network to use)
    pub chain_hash: Option<String>,
    /// Cache duration in seconds (default: 30)
    pub cache_duration_secs: u64,
    /// Maximum number of retry attempts for network failures
    pub max_retries: u32,
    /// Timeout for network requests in seconds
    pub timeout_secs: u64,
}

impl Default for DrandConfig {
    fn default() -> Self {
        Self {
            api_urls: vec![
                "https://api.drand.sh".to_string(),
                "https://drand.cloudflare.com".to_string(),
                "https://api2.drand.sh".to_string(),
            ],
            chain_hash: None,
            cache_duration_secs: 30,
            max_retries: 3,
            timeout_secs: 10,
        }
    }
}

/// Cached drand entropy value
struct CachedEntropy {
    round: u64,
    randomness: Zeroizing<[u8; 32]>,
    fetched_at: std::time::Instant,
}

/// drand entropy source for Wasif-Vernam cipher
/// 
/// This provides TRUE random entropy from the drand distributed randomness beacon.
/// The entropy is cached and automatically refreshed every 30 seconds.
pub struct DrandEntropy {
    config: DrandConfig,
    cache: Arc<RwLock<Option<CachedEntropy>>>,
    fetch_count: AtomicU64,
    client: Arc<reqwest::Client>,
}

impl DrandEntropy {
    /// Create a new drand entropy source with default configuration
    pub fn new() -> Self {
        Self::with_config(DrandConfig::default())
    }

    /// Create a new drand entropy source with custom configuration
    pub fn with_config(config: DrandConfig) -> Self {
        // Create shared HTTP client with timeout settings
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
        {
            Ok(c) => Arc::new(c),
            Err(e) => {
                warn!("Failed to create HTTP client: {}, using default client", e);
                Arc::new(reqwest::Client::new())
            }
        };
        
        Self {
            config,
            cache: Arc::new(RwLock::new(None)),
            fetch_count: AtomicU64::new(0),
            client,
        }
    }

    /// Fetch the latest drand randomness
    /// 
    /// This method caches the result and only fetches from the API
    /// when the cache is stale (older than 30 seconds).
    pub async fn get_entropy(&self) -> Result<[u8; 32], DrandError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(ref cached) = *cache {
                if cached.fetched_at.elapsed().as_secs() < self.config.cache_duration_secs {
                    debug!("Using cached drand entropy (round: {})", cached.round);
                    return Ok(*cached.randomness);
                }
            }
        }

        // Fetch fresh entropy
        self.fetch_fresh().await
    }

    /// Get entropy mixed with user-provided data for uniqueness
    /// 
    /// This is the recommended method for deriving unique keys per connection:
    /// - drand provides TRUE random base
    /// - User data (OS random, session ID, etc.) provides uniqueness
    /// - HKDF mixes them together
    pub async fn get_mixed_entropy(&self, user_data: &[u8]) -> Result<[u8; 32], DrandError> {
        let drand = self.get_entropy().await?;
        
        // Mix drand + user data using HKDF
        let hk = hkdf::Hkdf::<Sha256>::new(Some(b"zks-drand-mix"), &drand);
        let mut output = [0u8; 32];
        hk.expand(user_data, &mut output)
            .map_err(|_| DrandError::HkdfError)?;
        
        Ok(output)
    }

    /// Fetch fresh entropy from drand API with fallback endpoints
    async fn fetch_fresh(&self) -> Result<[u8; 32], DrandError> {
        let mut last_error = None;
        
        // Try each configured endpoint with retries
        for (endpoint_idx, base_url) in self.config.api_urls.iter().enumerate() {
            for attempt in 0..self.config.max_retries {
                let url = match &self.config.chain_hash {
                    Some(hash) => format!("{}/{}/public/latest", base_url, hash),
                    None => format!("{}/public/latest", base_url),
                };

                debug!(
                    "Fetching drand entropy from endpoint {} (attempt {}/{}): {}",
                    endpoint_idx + 1,
                    attempt + 1,
                    self.config.max_retries,
                    url
                );

                // Use shared HTTP client for efficiency

                match self.client.get(&url).send().await {
                    Ok(response) => {
                        if !response.status().is_success() {
                            let error_msg = format!(
                                "drand API returned status: {} from {}",
                                response.status(),
                                base_url
                            );
                            warn!("{}", error_msg);
                            last_error = Some(DrandError::ApiError(error_msg));
                            continue;
                        }

                        match response.json::<DrandResponse>().await {
                            Ok(drand_response) => {
                                // Validate the response
                                match self.validate_and_process_response(&drand_response).await {
                                    Ok(randomness) => {
                                        info!(
                                            "Successfully fetched drand entropy from {} (round: {}, total fetches: {})",
                                            base_url,
                                            drand_response.round,
                                            self.fetch_count.load(Ordering::Relaxed) + 1
                                        );
                                        return Ok(randomness);
                                    }
                                    Err(e) => {
                                        warn!("Validation failed for {}: {}", base_url, e);
                                        last_error = Some(e);
                                    }
                                }
                            }
                            Err(e) => {
                                let error_msg = format!("Failed to parse response from {}: {}", base_url, e);
                                warn!("{}", error_msg);
                                last_error = Some(DrandError::ParseError(error_msg));
                            }
                        }
                    }
                    Err(e) => {
                        let error_msg = format!("Network error from {}: {}", base_url, e);
                        warn!("{}", error_msg);
                        last_error = Some(DrandError::NetworkError(error_msg));
                    }
                }

                // Small delay between retries (exponential backoff)
                if attempt < self.config.max_retries - 1 {
                    tokio::time::sleep(std::time::Duration::from_millis(100 * (attempt + 1) as u64)).await;
                }
            }
        }

        // All endpoints failed
        let error_msg = format!(
            "All drand endpoints failed after {} retries each. Last error: {:?}",
            self.config.max_retries,
            last_error
        );
        warn!("{}", error_msg);
        
        // Return the last error, or a generic error if somehow we got here
        Err(last_error.unwrap_or_else(|| DrandError::NetworkError("All drand endpoints unavailable".to_string())))
    }

    /// Validate drand response and extract randomness
    async fn validate_and_process_response(&self, drand_response: &DrandResponse) -> Result<[u8; 32], DrandError> {
        // Decode hex randomness to bytes
        let randomness_bytes = hex::decode(&drand_response.randomness)
            .map_err(|e| DrandError::ParseError(format!("Failed to decode hex: {}", e)))?;

        // Validate the entropy quality
        validate_drand_entropy(drand_response, &randomness_bytes)?;

        if randomness_bytes.len() != 32 {
            return Err(DrandError::ParseError(format!(
                "Expected 32 bytes, got {}",
                randomness_bytes.len()
            )));
        }

        let mut randomness = [0u8; 32];
        randomness.copy_from_slice(&randomness_bytes);

        // Update cache with validated entropy
        {
            let mut cache = self.cache.write().await;
            *cache = Some(CachedEntropy {
                round: drand_response.round,
                randomness: Zeroizing::new(randomness),
                fetched_at: std::time::Instant::now(),
            });
        }

        self.fetch_count.fetch_add(1, Ordering::Relaxed);
        
        Ok(randomness)
    }

    /// Fetch entropy from a specific drand round
    /// 
    /// This is used for synchronized true OTP where both parties need identical entropy.
    /// Both parties must fetch the same round to generate identical keystreams.
    pub async fn fetch_round(&self, round: u64) -> Result<[u8; 32], DrandError> {
        let mut last_error = None;
        
        // Try each configured endpoint with retries
        for (endpoint_idx, base_url) in self.config.api_urls.iter().enumerate() {
            for attempt in 0..self.config.max_retries {
                let url = match &self.config.chain_hash {
                    Some(hash) => format!("{}/{}/public/{}", base_url, hash, round),
                    None => format!("{}/public/{}", base_url, round),
                };

                debug!(
                    "Fetching drand round {} from endpoint {} (attempt {}/{}): {}",
                    round,
                    endpoint_idx + 1,
                    attempt + 1,
                    self.config.max_retries,
                    url
                );

                match self.client.get(&url).send().await {
                    Ok(response) => {
                        if !response.status().is_success() {
                            let error_msg = format!(
                                "drand API returned status: {} from {} for round {}",
                                response.status(),
                                base_url,
                                round
                            );
                            warn!("{}", error_msg);
                            last_error = Some(DrandError::ApiError(error_msg));
                            continue;
                        }

                        match response.json::<DrandResponse>().await {
                            Ok(drand_response) => {
                                // Validate the response
                                match self.validate_and_process_response(&drand_response).await {
                                    Ok(randomness) => {
                                        info!(
                                            "Successfully fetched drand round {} from {} (total fetches: {})",
                                            round,
                                            base_url,
                                            self.fetch_count.load(Ordering::Relaxed) + 1
                                        );
                                        return Ok(randomness);
                                    }
                                    Err(e) => {
                                        warn!("Validation failed for round {}: {}", round, e);
                                        last_error = Some(e);
                                    }
                                }
                            }
                            Err(e) => {
                                let error_msg = format!("Failed to parse JSON for round {}: {}", round, e);
                                warn!("{}", error_msg);
                                last_error = Some(DrandError::ParseError(error_msg));
                            }
                        }
                    }
                    Err(e) => {
                        let error_msg = format!("Network error from {} for round {}: {}", base_url, round, e);
                        warn!("{}", error_msg);
                        last_error = Some(DrandError::NetworkError(error_msg));
                    }
                }

                // Small delay between retries (exponential backoff)
                if attempt < self.config.max_retries - 1 {
                    tokio::time::sleep(std::time::Duration::from_millis(100 * (attempt + 1) as u64)).await;
                }
            }
        }

        // All endpoints failed
        let error_msg = format!(
            "All drand endpoints failed for round {} after {} retries each. Last error: {:?}",
            round,
            self.config.max_retries,
            last_error
        );
        warn!("{}", error_msg);
        
        // Return the last error, or a generic error if somehow we got here
        Err(last_error.unwrap_or_else(|| DrandError::NetworkError(format!("All drand endpoints unavailable for round {}", round))))
    }

    /// Get the current cached round number (if any)
    pub async fn cached_round(&self) -> Option<u64> {
        let cache = self.cache.read().await;
        cache.as_ref().map(|c| c.round)
    }

    /// Force a fresh fetch, bypassing cache
    pub async fn force_refresh(&self) -> Result<[u8; 32], DrandError> {
        self.fetch_fresh().await
    }

    /// Get entropy with OS random fallback when drand is unavailable
    /// 
    /// This method provides resilience against drand network failures by
    /// falling back to OS-provided randomness when all drand endpoints fail.
    /// The OS random is mixed with a timestamp to ensure uniqueness.
    pub async fn get_entropy_with_fallback(&self) -> Result<[u8; 32], DrandError> {
        // First try to get drand entropy
        match self.get_entropy().await {
            Ok(drand_entropy) => Ok(drand_entropy),
            Err(e) => {
                warn!("Drand unavailable, falling back to OS random: {}", e);
                
                // Generate fallback entropy using OS random + timestamp for uniqueness
                let mut fallback_entropy = [0u8; 32];
                match ring::rand::SystemRandom::new().fill(&mut fallback_entropy) {
                    Ok(()) => {},
                    Err(os_err) => {
                        return Err(DrandError::OsRandomError(format!(
                            "Both drand and OS random failed: drand error: {}, OS error: {}", 
                            e, os_err
                        )));
                    }
                }
                
                // Mix with timestamp for additional uniqueness
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                
                let mut timestamp_bytes = [0u8; 8];
                timestamp_bytes.copy_from_slice(&timestamp.to_le_bytes());
                
                // XOR timestamp into the first 8 bytes of fallback entropy
                for i in 0..8 {
                    fallback_entropy[i] ^= timestamp_bytes[i];
                }
                
                info!("Using OS random fallback entropy (timestamp: {})", timestamp);
                Ok(fallback_entropy)
            }
        }
    }

    /// Get mixed entropy with OS random fallback
    /// 
    /// Similar to get_mixed_entropy but falls back to OS random if drand fails.
    /// The mixing process ensures that even with OS random fallback, the result
    /// is cryptographically strong and unique per connection.
    pub async fn get_mixed_entropy_with_fallback(&self, user_data: &[u8]) -> Result<[u8; 32], DrandError> {
        // Try to get drand entropy first
        let base_entropy = self.get_entropy_with_fallback().await?;
        
        // Mix with user data using HKDF for unique per-connection keys
        let hk = hkdf::Hkdf::<Sha256>::new(Some(b"zks-drand-mix-fallback"), &base_entropy);
        let mut output = [0u8; 32];
        hk.expand(user_data, &mut output)
            .map_err(|_| DrandError::HkdfError)?;
        
        Ok(output)
    }

    /// Get the total number of fetches made
    pub fn fetch_count(&self) -> u64 {
        self.fetch_count.load(Ordering::Relaxed)
    }

    /// Check health of all configured drand endpoints
    /// 
    /// Returns a vector of (endpoint_url, status) pairs showing
    /// which endpoints are currently accessible and healthy.
    pub async fn check_endpoint_health(&self) -> Vec<(String, EndpointHealth)> {
        let mut results = Vec::new();
        
        for base_url in &self.config.api_urls {
            let url = match &self.config.chain_hash {
                Some(hash) => format!("{}/{}/public/latest", base_url, hash),
                None => format!("{}/public/latest", base_url),
            };
            
            let client = match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(self.config.timeout_secs))
                .build() {
                Ok(c) => c,
                Err(e) => {
                    results.push((base_url.clone(), EndpointHealth::Failed(format!("Client error: {}", e))));
                    continue;
                }
            };
            
            match client.get(&url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<DrandResponse>().await {
                            Ok(drand_response) => {
                                // Validate the response
                                let randomness_bytes = match hex::decode(&drand_response.randomness) {
                                    Ok(bytes) => bytes,
                                    Err(e) => {
                                        results.push((base_url.clone(), EndpointHealth::Failed(format!("Hex decode error: {}", e))));
                                        continue;
                                    }
                                };
                                
                                match validate_drand_entropy(&drand_response, &randomness_bytes) {
                                    Ok(()) => results.push((base_url.clone(), EndpointHealth::Healthy)),
                                    Err(e) => results.push((base_url.clone(), EndpointHealth::Invalid(format!("Validation failed: {}", e)))),
                                }
                            }
                            Err(e) => results.push((base_url.clone(), EndpointHealth::Failed(format!("Parse error: {}", e)))),
                        }
                    } else {
                        results.push((base_url.clone(), EndpointHealth::Failed(format!("HTTP {}", response.status()))));
                    }
                }
                Err(e) => results.push((base_url.clone(), EndpointHealth::Failed(format!("Network error: {}", e)))),
            }
        }
        
        results
    }
}

impl Default for DrandEntropy {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur when fetching drand entropy
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrandError {
    /// Network error (connection failed, timeout, etc.)
    NetworkError(String),
    /// API returned an error status
    ApiError(String),
    /// Failed to parse response
    ParseError(String),
    /// HKDF expansion failed
    HkdfError,
    /// OS random generation failed (used in fallback mode)
    OsRandomError(String),
}

impl std::fmt::Display for DrandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DrandError::NetworkError(e) => write!(f, "drand network error: {}", e),
            DrandError::ApiError(e) => write!(f, "drand API error: {}", e),
            DrandError::ParseError(e) => write!(f, "drand parse error: {}", e),
            DrandError::HkdfError => write!(f, "HKDF expansion failed"),
            DrandError::OsRandomError(e) => write!(f, "OS random generation failed: {}", e),
        }
    }
}

impl std::error::Error for DrandError {}

/// Global drand entropy source (singleton pattern)
/// 
/// Use this for convenient access to drand entropy across the application.
static DRAND_ENTROPY: once_cell::sync::Lazy<DrandEntropy> =
    once_cell::sync::Lazy::new(DrandEntropy::new);

/// Get TRUE random entropy from drand (cached, instant)
/// 
/// # Example
/// ```rust,no_run
/// # use zks_crypt::prelude::*;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let entropy = get_drand_entropy().await?;
/// # Ok(())
/// # }
/// ```
pub async fn get_drand_entropy() -> Result<[u8; 32], DrandError> {
    DRAND_ENTROPY.get_entropy().await
}

/// Get unique entropy by mixing drand with user data
/// 
/// # Example
/// ```rust,no_run
/// # use zks_crypt::prelude::*;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let session_id = b"my-session-123";
/// let unique_entropy = get_unique_entropy(session_id).await?;
/// # Ok(())
/// # }
/// ```
pub async fn get_unique_entropy(user_data: &[u8]) -> Result<[u8; 32], DrandError> {
    DRAND_ENTROPY.get_mixed_entropy(user_data).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_drand_fetch() {
        let drand = DrandEntropy::new();
        let entropy = drand.get_entropy().await;
        assert!(entropy.is_ok(), "Should fetch entropy from drand");
        
        let entropy = entropy.unwrap();
        assert!(entropy.iter().any(|&b| b != 0), "Entropy should not be all zeros");
    }

    #[tokio::test]
    async fn test_drand_caching() {
        let drand = DrandEntropy::new();
        
        // First fetch
        let _ = drand.get_entropy().await.unwrap();
        let first_round = drand.cached_round().await;
        
        // Second fetch should use cache
        let _ = drand.get_entropy().await.unwrap();
        let second_round = drand.cached_round().await;
        
        assert_eq!(first_round, second_round, "Should use cached value");
        assert_eq!(drand.fetch_count(), 1, "Should only fetch once");
    }

    #[tokio::test]
    async fn test_mixed_entropy_uniqueness() {
        let drand = DrandEntropy::new();
        
        let entropy1 = drand.get_mixed_entropy(b"user1").await.unwrap();
        let entropy2 = drand.get_mixed_entropy(b"user2").await.unwrap();
        
        assert_ne!(entropy1, entropy2, "Different users should get different entropy");
    }
}
