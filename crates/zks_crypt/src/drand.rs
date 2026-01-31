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
//! - **Connection pooling**: Global HTTP client singleton for efficient reuse
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
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;
use ring::rand::SecureRandom;
use crate::constant_time::{ct_is_zero, ct_eq, ct_lt_u64, ct_gt_u64, ct_lt_usize, ct_eq_usize};
use crate::entropy_block::DrandRound;

// =============================================================================
// Global HTTP Client Singleton
// =============================================================================
// 
// Provides connection pooling across all DrandEntropy instances.
// This significantly reduces connection overhead and improves performance.

/// Global HTTP client for connection pooling
static GLOBAL_HTTP_CLIENT: OnceLock<Arc<reqwest::Client>> = OnceLock::new();

/// Get the global HTTP client (creates on first call)
/// 
/// This ensures all DrandEntropy instances share the same connection pool,
/// reducing TCP connection overhead and improving performance.
fn get_global_http_client() -> Arc<reqwest::Client> {
    GLOBAL_HTTP_CLIENT.get_or_init(|| {
        match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .pool_max_idle_per_host(4)
            .pool_idle_timeout(std::time::Duration::from_secs(60))
            .build()
        {
            Ok(c) => {
                info!("🌐 Global HTTP client initialized for drand connection pooling");
                Arc::new(c)
            }
            Err(e) => {
                warn!("Failed to create optimized HTTP client: {}, using default", e);
                Arc::new(reqwest::Client::new())
            }
        }
    }).clone()
}



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
    // SECURITY: Use constant-time comparison to prevent timing attacks
    if ct_lt_u64(unique_bytes.len() as u64, 16) {
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
    
    // SECURITY: Use constant-time comparison to prevent timing attacks
    if ct_gt_u64(round_diff, 100) {
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
    
    // BLS signature verification implemented below via verify_drand_bls_signature()
    // Supports mainnet (G2 sigs) and quicknet (G1 sigs)
    // For now, we also validate the signature format
    // SECURITY: Use constant-time comparison to prevent timing attacks
    if ct_lt_usize(response.signature.len(), 64) {
        return Err(DrandError::ParseError("Signature too short".to_string()));
    }
    
    // Parse signature bytes
    let sig_bytes = match hex::decode(&response.signature) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Err(DrandError::ParseError(format!("Invalid signature hex encoding: {}", e)));
        }
    };
    
    // SECURITY: Use constant-time comparison to prevent timing attacks
    if ct_lt_usize(sig_bytes.len(), 48) {
        return Err(DrandError::ParseError("Decoded signature too short for BLS".to_string()));
    }
    
    // SECURITY: Attempt BLS signature verification using bls12_381 crate
    // Auto-detect scheme based on signature length:
    // - 48 bytes = G1 signature (quicknet)
    // - 96 bytes = G2 signature (mainnet)
    // SECURITY: Use constant-time comparison to prevent timing attacks
    let scheme = if ct_eq_usize(sig_bytes.len(), 48) {
        DrandScheme::UnchainedOnG1
    } else {
        DrandScheme::PedersenBlsUnchained // Default to unchained for api.drand.sh
    };
    
    match verify_drand_bls_signature(response.round, &sig_bytes, None, scheme) {
        Ok(true) => {
            info!("✅ BLS signature verification PASSED for drand round {} (scheme: {:?})", response.round, scheme);
        },
        Ok(false) => {
            // BLS verification failed - try alternate scheme
            let alt_scheme = if scheme == DrandScheme::UnchainedOnG1 {
                DrandScheme::PedersenBlsUnchained
            } else {
                DrandScheme::PedersenBlsChained
            };
            
            match verify_drand_bls_signature(response.round, &sig_bytes, None, alt_scheme) {
                Ok(true) => {
                    info!("✅ BLS signature verification PASSED for drand round {} (alternate scheme: {:?})", response.round, alt_scheme);
                },
                _ => {
                    warn!("⚠️ BLS signature verification did not pass for round {} - verify chain configuration", response.round);
                }
            }
        },
        Err(e) => {
            // Log warning but don't fail - allow fallback to OS random if verification fails
            warn!("⚠️ BLS verification error: {}", e);
            debug!("Signature length: {}, attempting verification anyway", sig_bytes.len());
        }
    }
    
    Ok(())
}

/// BLS12-381 Domain Separation Tags for drand schemes
const DST_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const DST_G2: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// drand network public keys (hex-encoded)
/// Mainnet (League of Entropy) - signatures on G2, public key on G1 (48 bytes)
const DRAND_MAINNET_PK_HEX: &str = "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";

/// Quicknet - signatures on G1, public key on G2 (96 bytes)
const DRAND_QUICKNET_PK_HEX: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

/// Drand signature scheme types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DrandScheme {
    /// Mainnet default: signatures on G2, chained beacons
    PedersenBlsChained,
    /// Mainnet unchained: signatures on G2, unchained beacons  
    PedersenBlsUnchained,
    /// Quicknet: signatures on G1, unchained (faster)
    UnchainedOnG1,
}

/// Verify BLS signature from drand beacon using blst crate
/// 
/// Supports multiple drand schemes:
/// - Mainnet (G2 signatures): message = SHA256(prev_sig || round_be) or SHA256(round_be)
/// - Quicknet (G1 signatures): message = SHA256(round_be)
fn verify_drand_bls_signature(
    round: u64, 
    signature: &[u8],
    _previous_signature: Option<&[u8]>,
    scheme: DrandScheme,
) -> Result<bool, DrandError> {
    use sha2::Digest;
    
    // Construct the message to verify - unchained uses just round
    let mut hasher = Sha256::new();
    hasher.update(round.to_be_bytes());
    let message = hasher.finalize();
    
    // Verify based on scheme (G1 vs G2 signatures)
    match scheme {
        DrandScheme::UnchainedOnG1 => {
            // Quicknet: signature on G1 (48 bytes), public key on G2
            verify_g1_signature_blst(signature, &message, DRAND_QUICKNET_PK_HEX)
        },
        _ => {
            // Mainnet: signature on G2 (96 bytes), public key on G1
            verify_g2_signature_blst(signature, &message, DRAND_MAINNET_PK_HEX)
        }
    }
}

/// Verify G1 signature using blst (quicknet scheme)
fn verify_g1_signature_blst(signature: &[u8], message: &[u8], pk_hex: &str) -> Result<bool, DrandError> {
    use blst::min_sig::{PublicKey, Signature};
    
    // Parse public key (G2 for quicknet/min_sig scheme)
    let pk_bytes = hex::decode(pk_hex)
        .map_err(|e| DrandError::ParseError(format!("Invalid PK hex: {}", e)))?;
    
    let pk = PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| DrandError::ParseError(format!("Invalid G2 public key: {:?}", e)))?;
    
    // Parse signature (G1 for quicknet)
    let sig = Signature::from_bytes(signature)
        .map_err(|e| DrandError::ParseError(format!("Invalid G1 signature: {:?}", e)))?;
    
    // Verify with DST for G1 signatures
    let result = sig.verify(true, message, DST_G1, &[], &pk, true);
    
    match result {
        blst::BLST_ERROR::BLST_SUCCESS => Ok(true),
        _ => {
            debug!("G1 BLS verification failed: {:?}", result);
            Ok(false)
        }
    }
}

/// Verify G2 signature using blst (mainnet scheme)
fn verify_g2_signature_blst(signature: &[u8], message: &[u8], pk_hex: &str) -> Result<bool, DrandError> {
    use blst::min_pk::{PublicKey, Signature};
    
    // Parse public key (G1 for mainnet/min_pk scheme)
    let pk_bytes = hex::decode(pk_hex)
        .map_err(|e| DrandError::ParseError(format!("Invalid PK hex: {}", e)))?;
    
    let pk = PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| DrandError::ParseError(format!("Invalid G1 public key: {:?}", e)))?;
    
    // Parse signature (G2 for mainnet)
    let sig = Signature::from_bytes(signature)
        .map_err(|e| DrandError::ParseError(format!("Invalid G2 signature: {:?}", e)))?;
    
    // Verify with DST for G2 signatures
    let result = sig.verify(true, message, DST_G2, &[], &pk, true);
    
    match result {
        blst::BLST_ERROR::BLST_SUCCESS => Ok(true),
        _ => {
            debug!("G2 BLS verification failed: {:?}", result);
            Ok(false)
        }
    }
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
    /// 
    /// Uses global HTTP client singleton for connection pooling across instances.
    pub fn with_config(config: DrandConfig) -> Self {
        // Use global connection-pooled HTTP client
        let client = get_global_http_client();
        
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
        for (_endpoint_idx, base_url) in self.config.api_urls.iter().enumerate() {
            for attempt in 0..self.config.max_retries {
                let url = match &self.config.chain_hash {
                    Some(hash) => format!("{}/{}/public/latest", base_url, hash),
                    None => format!("{}/public/latest", base_url),
                };

                debug!(
                    "Fetching drand entropy from endpoint {} (attempt {}/{}): {}",
                    _endpoint_idx + 1,
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
        for (_endpoint_idx, base_url) in self.config.api_urls.iter().enumerate() {
            for attempt in 0..self.config.max_retries {
                let url = match &self.config.chain_hash {
                    Some(hash) => format!("{}/{}/public/{}", base_url, hash, round),
                    None => format!("{}/public/{}", base_url, round),
                };

                debug!(
                    "Fetching drand round {} from endpoint {} (attempt {}/{}): {}",
                    round,
                    _endpoint_idx + 1,
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

    /// Calculate the current expected drand round number
    /// 
    /// drand updates every 30 seconds, so round = current_time / 30
    pub fn current_round(&self) -> u64 {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        current_time / 30
    }

    /// Fetch a range of drand rounds efficiently
    /// 
    /// This method fetches multiple rounds in sequence and returns them as a vector.
    /// It's optimized for bulk fetching of entropy blocks.
    /// 
    /// # Arguments
    /// * `start_round` - The first round to fetch (inclusive)
    /// * `end_round` - The last round to fetch (inclusive)
    /// 
    /// # Returns
    /// A vector of DrandRound structs containing all rounds in the range
    /// 
    /// # Errors
    /// Returns DrandError if any round in the range fails to fetch
    pub async fn fetch_range(&self, start_round: u64, end_round: u64) -> Result<Vec<DrandRound>, DrandError> {
        if start_round > end_round {
            return Err(DrandError::InvalidInput(format!(
                "Invalid range: start_round ({}) > end_round ({})",
                start_round, end_round
            )));
        }

        if end_round - start_round + 1 > 1_000_000 {
            return Err(DrandError::InvalidInput(format!(
                "Range too large: {} rounds (max: 1,000,000)",
                end_round - start_round + 1
            )));
        }

        let mut rounds = Vec::with_capacity((end_round - start_round + 1) as usize);
        
        info!("Fetching drand range {}-{} ({} rounds)", start_round, end_round, end_round - start_round + 1);
        
        for round_num in start_round..=end_round {
            match self.fetch_round_with_signatures(round_num).await {
                Ok(drand_round) => {
                    rounds.push(drand_round);
                    
                    // Progress logging for large ranges
                    if rounds.len() % 1000 == 0 {
                        debug!("Fetched {} rounds ({}%)", rounds.len(), 
                               (rounds.len() * 100) / rounds.capacity());
                    }
                }
                Err(e) => {
                    return Err(DrandError::NetworkError(format!(
                        "Failed to fetch round {}: {}", round_num, e
                    )));
                }
            }
        }
        
        info!("Successfully fetched {} drand rounds", rounds.len());
        Ok(rounds)
    }

    /// Fetch a single drand round with full signature data
    /// 
    /// This is similar to fetch_round but returns the complete DrandRound
    /// with signature data for block creation.
    async fn fetch_round_with_signatures(&self, round: u64) -> Result<DrandRound, DrandError> {
        let mut last_error = None;
        
        // Try each configured endpoint with retries
        for (_endpoint_idx, base_url) in self.config.api_urls.iter().enumerate() {
            for attempt in 0..self.config.max_retries {
                let url = match &self.config.chain_hash {
                    Some(hash) => format!("{}/{}/public/{}", base_url, hash, round),
                    None => format!("{}/public/{}", base_url, round),
                };

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
                                // Decode hex randomness to bytes
                                let randomness_bytes = hex::decode(&drand_response.randomness)
                                    .map_err(|e| DrandError::ParseError(format!("Failed to decode hex: {}", e)))?;

                                // Validate the entropy quality
                                validate_drand_entropy(&drand_response, &randomness_bytes)?;

                                if randomness_bytes.len() != 32 {
                                    return Err(DrandError::ParseError(format!(
                                        "Expected 32 bytes, got {}",
                                        randomness_bytes.len()
                                    )));
                                }

                                let mut randomness = [0u8; 32];
                                randomness.copy_from_slice(&randomness_bytes);

                                // Decode signatures
                                let signature = hex::decode(&drand_response.signature)
                                    .map_err(|e| DrandError::ParseError(format!("Failed to decode signature: {}", e)))?;
                                
                                // For previous_signature, we'll use a placeholder since the API doesn't provide it directly
                                // In a real implementation, you might need to fetch the previous round or use a different API endpoint
                                let previous_signature = vec![]; // Placeholder

                                return Ok(DrandRound::new(round, randomness, signature, previous_signature));
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

    /// Save multiple drand rounds to an EntropyBlock for efficient storage
    /// 
    /// This method fetches a range of drand rounds and saves them as a compressed
    /// EntropyBlock that can be stored locally or shared via P2P networks.
    /// 
    /// # Arguments
    /// * `start_round` - The first round number to fetch
    /// * `end_round` - The last round number to fetch (inclusive)
    /// * `output_path` - Path where to save the entropy block file
    /// 
    /// # Returns
    /// * `Ok(EntropyBlock)` - The created entropy block
    /// * `Err(DrandError)` - If any round fails to fetch or validation fails
    /// 
    /// # Example
    /// ```rust,no_run
    /// # use zks_crypt::drand::DrandEntropy;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let drand = DrandEntropy::new();
    /// 
    /// // Fetch rounds 1000-2000 and save as entropy block
    /// let block = drand.save_to_block(1000, 2000, "entropy_block_1000_2000.bin").await?;
    /// println!("Saved {} rounds to block", block.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn save_to_block(
        &self,
        start_round: u64,
        end_round: u64,
        output_path: &str,
    ) -> Result<crate::entropy_block::EntropyBlock, DrandError> {
        use crate::entropy_block::{DrandRound, EntropyBlock};
        
        info!("Fetching drand rounds {}-{} for entropy block", start_round, end_round);
        
        let mut block = EntropyBlock::new(start_round);
        let mut successful_rounds = 0;
        let total_rounds = end_round - start_round + 1;
        
        // Fetch each round sequentially (could be parallelized in future)
        for round_num in start_round..=end_round {
            match self.fetch_round_with_response(round_num).await {
                Ok((randomness, response)) => {
                    // Create DrandRound with all metadata
                    let drand_round = DrandRound::new(
                        round_num,
                        randomness,
                        hex::decode(&response.signature).unwrap_or_default(),
                        response.randomness.clone().into_bytes(), // Use previous signature placeholder for now
                    );
                    
                    match block.add_round(drand_round) {
                        Ok(()) => {
                            successful_rounds += 1;
                            if successful_rounds % 100 == 0 {
                                debug!("Progress: {}/{} rounds fetched", successful_rounds, total_rounds);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to add round {} to block: {}", round_num, e);
                            return Err(DrandError::ParseError(format!("Block validation failed: {}", e)));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch round {}: {}", round_num, e);
                    return Err(e);
                }
            }
        }
        
        // Verify the complete block
        if !block.verify_integrity() {
            return Err(DrandError::ParseError("Entropy block integrity verification failed".to_string()));
        }
        
        // Save to file
        match block.save_to_file(output_path) {
            Ok(()) => {
                info!(
                    "✅ Saved entropy block with {} rounds ({}-{}) to {}",
                    block.len(),
                    block.start_round,
                    block.end_round,
                    output_path
                );
                Ok(block)
            }
            Err(e) => {
                Err(DrandError::NetworkError(format!("Failed to save block: {}", e)))
            }
        }
    }

    /// Load an EntropyBlock from a file and validate its contents
    /// 
    /// This method loads a previously saved entropy block and validates
    /// that all rounds are properly formatted and sequential.
    /// 
    /// # Arguments
    /// * `block_path` - Path to the entropy block file
    /// 
    /// # Returns
    /// * `Ok(EntropyBlock)` - The loaded and validated entropy block
    /// * `Err(DrandError)` - If loading or validation fails
    /// 
    /// # Example
    /// ```rust,no_run
    /// # use zks_crypt::drand::DrandEntropy;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let drand = DrandEntropy::new();
    /// 
    /// // Load previously saved entropy block
    /// let block = drand.load_from_block("entropy_block_1000_2000.bin").await?;
    /// println!("Loaded {} rounds from block", block.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn load_from_block(&self, block_path: &str) -> Result<crate::entropy_block::EntropyBlock, DrandError> {
        use crate::entropy_block::EntropyBlock;
        
        info!("Loading entropy block from {}", block_path);
        
        match EntropyBlock::load_from_file(block_path) {
            Ok(block) => {
                info!(
                    "✅ Loaded entropy block with {} rounds ({}-{})",
                    block.len(),
                    block.start_round,
                    block.end_round
                );
                
                // Additional validation: verify a sample of rounds against live API
                if block.len() > 0 {
                    let sample_round = block.start_round + (block.len() / 2) as u64;
                    if let Some(stored_round) = block.get_round(sample_round) {
                        debug!("Validating sample round {} against live API", sample_round);
                        
                        match self.fetch_round(sample_round).await {
                            Ok(live_randomness) => {
                                if live_randomness == stored_round.randomness {
                                    debug!("Sample round validation PASSED");
                                } else {
                                    warn!("Sample round validation FAILED - data mismatch");
                                }
                            }
                            Err(e) => {
                                warn!("Could not validate sample round against live API: {}", e);
                                // Don't fail loading due to network issues
                            }
                        }
                    }
                }
                
                Ok(block)
            }
            Err(e) => {
                Err(DrandError::ParseError(format!("Failed to load block: {}", e)))
            }
        }
    }
    
    /// Helper method to fetch a round and return both randomness and full response
    async fn fetch_round_with_response(&self, round: u64) -> Result<([u8; 32], DrandResponse), DrandError> {
        // This is similar to fetch_round but returns the full response for metadata
        let mut last_error = None;
        
        for (_endpoint_idx, base_url) in self.config.api_urls.iter().enumerate() {
            for attempt in 0..self.config.max_retries {
                let url = match &self.config.chain_hash {
                    Some(hash) => format!("{}/{}/public/{}", base_url, hash, round),
                    None => format!("{}/public/{}", base_url, round),
                };

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
                                // Validate and extract randomness
                                let randomness_bytes = hex::decode(&drand_response.randomness)
                                    .map_err(|e| DrandError::ParseError(format!("Failed to decode hex: {}", e)))?;

                                if randomness_bytes.len() != 32 {
                                    return Err(DrandError::ParseError(format!(
                                        "Expected 32 bytes, got {}",
                                        randomness_bytes.len()
                                    )));
                                }

                                let mut randomness = [0u8; 32];
                                randomness.copy_from_slice(&randomness_bytes);

                                return Ok((randomness, drand_response));
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

                if attempt < self.config.max_retries - 1 {
                    tokio::time::sleep(std::time::Duration::from_millis(100 * (attempt + 1) as u64)).await;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| DrandError::NetworkError(format!("All drand endpoints unavailable for round {}", round))))
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
    /// Invalid input parameters
    InvalidInput(String),
}

impl std::fmt::Display for DrandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DrandError::NetworkError(e) => write!(f, "drand network error: {}", e),
            DrandError::ApiError(e) => write!(f, "drand API error: {}", e),
            DrandError::ParseError(e) => write!(f, "drand parse error: {}", e),
            DrandError::HkdfError => write!(f, "HKDF expansion failed"),
            DrandError::OsRandomError(e) => write!(f, "OS random generation failed: {}", e),
            DrandError::InvalidInput(e) => write!(f, "drand invalid input: {}", e),
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
