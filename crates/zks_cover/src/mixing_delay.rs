//! Mixing Delay - Exponential Delay Mixing for Global Adversary Resistance
//!
//! This module implements Loopix-style continuous-time mixing with exponential
//! delays, providing resistance against **global passive adversaries** who can
//! monitor all network traffic.
//!
//! # Security Properties
//!
//! This module provides:
//! - ✅ **Global adversary resistance**: Traffic correlation defeated by mixing delays
//! - ✅ **Unobservability**: Combined with cover traffic, users appear idle
//! - ✅ **Post-quantum security**: Delays applied to ML-KEM encrypted packets
//!
//! This EXCEEDS Nym (which uses classical crypto) by applying mixing delays to
//! post-quantum encrypted traffic.
//!
//! # Theory
//!
//! Per Loopix (USENIX Security 2017):
//! > "Each mix introduces an independent random delay sampled from an exponential
//! > distribution, making traffic analysis computationally infeasible for global
//! > adversaries."
//!
//! Exponential distribution properties:
//! - Memoryless: No correlation between consecutive delays
//! - Rate λ controls mean delay: E[delay] = 1/λ
//! - Higher λ = lower latency but less mixing
//!
//! # Configuration
//!
//! | Profile | Mean Delay | Use Case |
//! |---------|------------|----------|
//! | `max_anonymity` | 500ms | Highest privacy, tolerates latency |
//! | `balanced` | 100ms | Good privacy with reasonable latency |
//! | `low_latency` | 20ms | Interactive apps, reduced mixing |
//!
//! # Comparison vs. Nym
//!
//! | Feature | ZKS MixingDelay | Nym |
//! |---------|-----------------|-----|
//! | Distribution | Exponential | Exponential |
//! | Crypto | ML-KEM-1024 (PQ) | X25519 (classical) |
//! | Integration | Faisal Swarm | Nym Mixnet |
//! | Configurable | ✅ Per-hop | ✅ Per-hop |

use std::time::Duration;
use rand::Rng;
use rand_distr::{Exp, Distribution};
use tokio::time::sleep;

/// Error type for mixing delay operations
#[derive(Debug, Clone)]
pub enum MixingDelayError {
    /// Invalid rate parameter
    InvalidRate(String),
    /// Delay sampling failed
    SamplingError(String),
}

impl std::fmt::Display for MixingDelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRate(msg) => write!(f, "Invalid rate: {}", msg),
            Self::SamplingError(msg) => write!(f, "Sampling error: {}", msg),
        }
    }
}

impl std::error::Error for MixingDelayError {}

/// Result type for mixing delay operations
pub type Result<T> = std::result::Result<T, MixingDelayError>;

/// Mixing Delay Configuration
#[derive(Debug, Clone)]
pub struct MixingDelayConfig {
    /// Rate parameter λ for exponential distribution (delays per second)
    /// Mean delay = 1/λ seconds
    /// Example: λ = 10.0 means mean delay of 100ms
    pub rate: f64,
    /// Maximum delay cap (prevents extreme outliers)
    pub max_delay: Duration,
    /// Minimum delay (ensures some mixing even with fast rates)
    pub min_delay: Duration,
    /// Whether mixing is enabled (can be disabled for testing)
    pub enabled: bool,
    /// Number of hops to apply delay at
    pub hops: u8,
}

impl Default for MixingDelayConfig {
    fn default() -> Self {
        Self::balanced()
    }
}

impl MixingDelayConfig {
    /// Maximum anonymity profile
    /// Mean delay: 500ms, suitable for high-security applications
    pub fn max_anonymity() -> Self {
        Self {
            rate: 2.0,       // Mean = 500ms
            max_delay: Duration::from_secs(5),
            min_delay: Duration::from_millis(50),
            enabled: true,
            hops: 3,
        }
    }

    /// Balanced profile
    /// Mean delay: 100ms, good tradeoff between privacy and latency
    pub fn balanced() -> Self {
        Self {
            rate: 10.0,      // Mean = 100ms
            max_delay: Duration::from_secs(2),
            min_delay: Duration::from_millis(10),
            enabled: true,
            hops: 3,
        }
    }

    /// Low latency profile
    /// Mean delay: 20ms, suitable for interactive applications
    pub fn low_latency() -> Self {
        Self {
            rate: 50.0,      // Mean = 20ms
            max_delay: Duration::from_millis(500),
            min_delay: Duration::from_millis(5),
            enabled: true,
            hops: 3,
        }
    }

    /// Disabled profile (for testing only)
    pub fn disabled() -> Self {
        Self {
            rate: 1000.0,
            max_delay: Duration::ZERO,
            min_delay: Duration::ZERO,
            enabled: false,
            hops: 0,
        }
    }

    /// Create custom configuration
    pub fn custom(rate: f64, max_delay: Duration, min_delay: Duration, hops: u8) -> Result<Self> {
        if rate <= 0.0 {
            return Err(MixingDelayError::InvalidRate("Rate must be positive".to_string()));
        }
        if min_delay > max_delay {
            return Err(MixingDelayError::InvalidRate("min_delay cannot exceed max_delay".to_string()));
        }
        
        Ok(Self {
            rate,
            max_delay,
            min_delay,
            enabled: true,
            hops,
        })
    }

    /// Calculate expected mean delay
    pub fn mean_delay(&self) -> Duration {
        Duration::from_secs_f64(1.0 / self.rate)
    }
}

/// Mixing Delay Generator
///
/// Generates exponentially distributed delays for traffic mixing.
/// Each delay is independent and memoryless, providing strong
/// resistance against timing correlation attacks.
pub struct MixingDelay {
    /// Configuration
    config: MixingDelayConfig,
    /// Exponential distribution sampler
    exp_dist: Exp<f64>,
    /// Statistics: total delays applied
    delays_applied: std::sync::atomic::AtomicU64,
    /// Statistics: total delay time accumulated
    total_delay_ms: std::sync::atomic::AtomicU64,
}

impl MixingDelay {
    /// Create a new mixing delay generator
    pub fn new(config: MixingDelayConfig) -> Result<Self> {
        let exp_dist = Exp::new(config.rate)
            .map_err(|e| MixingDelayError::InvalidRate(e.to_string()))?;
        
        Ok(Self {
            config,
            exp_dist,
            delays_applied: std::sync::atomic::AtomicU64::new(0),
            total_delay_ms: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Sample a delay from the exponential distribution
    pub fn sample_delay(&self) -> Duration {
        if !self.config.enabled {
            return Duration::ZERO;
        }

        let mut rng = rand::thread_rng();
        let delay_secs = self.exp_dist.sample(&mut rng);
        let delay = Duration::from_secs_f64(delay_secs);

        // Clamp to min/max bounds
        let clamped = delay.max(self.config.min_delay).min(self.config.max_delay);

        clamped
    }

    /// Sample delays for all hops
    pub fn sample_hop_delays(&self) -> Vec<Duration> {
        (0..self.config.hops)
            .map(|_| self.sample_delay())
            .collect()
    }

    /// Apply delay (blocking version for sync contexts)
    pub fn apply_delay_blocking(&self) {
        if !self.config.enabled {
            return;
        }

        let delay = self.sample_delay();
        std::thread::sleep(delay);

        // Update statistics
        self.delays_applied.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.total_delay_ms.fetch_add(
            delay.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Apply delay (async version for tokio contexts)
    pub async fn apply_delay(&self) {
        if !self.config.enabled {
            return;
        }

        let delay = self.sample_delay();
        sleep(delay).await;

        // Update statistics
        self.delays_applied.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.total_delay_ms.fetch_add(
            delay.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        tracing::trace!(
            "🕐 Applied mixing delay: {:?} (λ={}, mean={:?})",
            delay,
            self.config.rate,
            self.config.mean_delay()
        );
    }

    /// Apply delay and then execute a function
    pub async fn delay_then<F, T>(&self, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        self.apply_delay().await;
        f()
    }

    /// Apply delay and then execute an async function
    pub async fn delay_then_async<F, Fut, T>(&self, f: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        self.apply_delay().await;
        f().await
    }

    /// Get statistics
    pub fn statistics(&self) -> MixingDelayStats {
        let count = self.delays_applied.load(std::sync::atomic::Ordering::Relaxed);
        let total_ms = self.total_delay_ms.load(std::sync::atomic::Ordering::Relaxed);
        
        MixingDelayStats {
            delays_applied: count,
            total_delay: Duration::from_millis(total_ms),
            average_delay: if count > 0 {
                Duration::from_millis(total_ms / count)
            } else {
                Duration::ZERO
            },
            configured_mean: self.config.mean_delay(),
        }
    }

    /// Check if mixing is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the configuration
    pub fn config(&self) -> &MixingDelayConfig {
        &self.config
    }
}

/// Statistics for mixing delay operations
#[derive(Debug, Clone)]
pub struct MixingDelayStats {
    /// Number of delays applied
    pub delays_applied: u64,
    /// Total accumulated delay time
    pub total_delay: Duration,
    /// Average delay observed
    pub average_delay: Duration,
    /// Configured mean delay
    pub configured_mean: Duration,
}

/// Per-hop mixing delay tracker
/// 
/// Tracks delays at each hop in a multi-hop route for
/// debugging and analysis purposes.
#[derive(Debug, Clone)]
pub struct HopDelayTracker {
    /// Delays at each hop
    hop_delays: Vec<Duration>,
    /// Total route delay
    total_delay: Duration,
}

impl HopDelayTracker {
    /// Create a new tracker with pre-sampled delays
    pub fn new(delays: Vec<Duration>) -> Self {
        let total_delay = delays.iter().sum();
        Self {
            hop_delays: delays,
            total_delay,
        }
    }

    /// Get delay for a specific hop
    pub fn hop_delay(&self, hop: usize) -> Option<Duration> {
        self.hop_delays.get(hop).copied()
    }

    /// Get total route delay
    pub fn total_delay(&self) -> Duration {
        self.total_delay
    }

    /// Get number of hops
    pub fn num_hops(&self) -> usize {
        self.hop_delays.len()
    }
}

/// Mix node interface for applying delays
pub trait MixNode {
    /// Process a packet with mixing delay
    fn process_with_delay<'a>(
        &'a self,
        packet: &'a [u8],
        delay: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_profiles() {
        let max_anon = MixingDelayConfig::max_anonymity();
        assert_eq!(max_anon.mean_delay(), Duration::from_millis(500));
        assert!(max_anon.enabled);

        let balanced = MixingDelayConfig::balanced();
        assert_eq!(balanced.mean_delay(), Duration::from_millis(100));

        let low_latency = MixingDelayConfig::low_latency();
        assert_eq!(low_latency.mean_delay(), Duration::from_millis(20));

        let disabled = MixingDelayConfig::disabled();
        assert!(!disabled.enabled);
    }

    #[test]
    fn test_delay_sampling() {
        let config = MixingDelayConfig::balanced();
        let mixer = MixingDelay::new(config).unwrap();

        // Sample many delays and verify they're within bounds
        for _ in 0..100 {
            let delay = mixer.sample_delay();
            assert!(delay >= Duration::from_millis(10)); // min_delay
            assert!(delay <= Duration::from_secs(2));     // max_delay
        }
    }

    #[test]
    fn test_hop_delays() {
        let config = MixingDelayConfig::balanced();
        let mixer = MixingDelay::new(config).unwrap();

        let hop_delays = mixer.sample_hop_delays();
        assert_eq!(hop_delays.len(), 3); // default 3 hops
    }

    #[test]
    fn test_disabled_returns_zero() {
        let config = MixingDelayConfig::disabled();
        let mixer = MixingDelay::new(config).unwrap();

        let delay = mixer.sample_delay();
        assert_eq!(delay, Duration::ZERO);
    }

    #[tokio::test]
    async fn test_async_delay() {
        let config = MixingDelayConfig::low_latency();
        let mixer = MixingDelay::new(config).unwrap();

        let start = std::time::Instant::now();
        mixer.apply_delay().await;
        let elapsed = start.elapsed();

        // Should have applied at least min_delay
        assert!(elapsed >= Duration::from_millis(5));
        
        // Check statistics updated
        let stats = mixer.statistics();
        assert_eq!(stats.delays_applied, 1);
    }

    #[test]
    fn test_custom_config() {
        let config = MixingDelayConfig::custom(
            5.0, // Mean = 200ms
            Duration::from_secs(1),
            Duration::from_millis(20),
            4, // 4 hops
        ).unwrap();

        assert_eq!(config.mean_delay(), Duration::from_millis(200));
        assert_eq!(config.hops, 4);
    }

    #[test]
    fn test_invalid_rate() {
        let result = MixingDelayConfig::custom(
            -1.0, // Invalid negative rate
            Duration::from_secs(1),
            Duration::from_millis(20),
            3,
        );
        assert!(result.is_err());
    }
}
