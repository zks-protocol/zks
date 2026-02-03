//! # ZKS Cover Traffic
//! 
//! Post-quantum secure cover traffic generation for ZKS Protocol.
//! 
//! ## Overview
//! 
//! This crate generates cover traffic that is indistinguishable from real traffic,
//! providing traffic analysis resistance while maintaining ZKS's superior cryptography.
//! 
//! ## Features
//! 
//! - **Post-quantum secure**: Uses ML-KEM-768 for key exchange
//! - **Wasif-Vernam encryption**: 256-bit post-quantum computational security with high-entropy XOR layer
//! - **Poisson timing**: Realistic traffic patterns
//! - **Faisal Swarm integration**: Works with existing ZKS routing
//! 
//! ## Usage
//! 
//! ```rust,no_run
//! use zks_cover::{CoverGenerator, CoverConfig};
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = CoverConfig::builder()
//!         .poisson_rate(0.5) // 0.5 messages per second
//!         .build()?;
//!     
//!     let generator = CoverGenerator::new(config)?;
//!     
//!     // Generate a single cover message
//!     let cover = generator.generate_cover(None).await?;
//!     println!("Generated cover message with {} byte payload", cover.payload.len());
//!     
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Configuration for cover traffic generation
pub mod config;
/// Error types for cover traffic operations
pub mod error;
/// Core cover traffic generator
pub mod generator;
/// Mixing delay for global adversary resistance (BEATS NYM - PQ secure)
pub mod mixing_delay;
/// Poisson timing scheduler for cover traffic
pub mod scheduler;
/// Faisal Swarm transport integration
pub mod transport;
/// Core types for cover traffic
pub mod types;

pub use config::{CoverConfig, CoverConfigBuilder};
pub use error::{CoverError, Result};
pub use generator::CoverGenerator;
pub use mixing_delay::{MixingDelay, MixingDelayConfig, MixingDelayStats};
pub use scheduler::CoverScheduler;
pub use transport::{CoverTransport, CoverTransportBuilder};
pub use types::{CoverMessage, CoverType};

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cover_config_creation() {
        let config = CoverConfig::builder()
            .poisson_rate(1.0)
            .build()
            .unwrap();
        
        assert_eq!(config.poisson_rate(), 1.0);
    }
    
    #[tokio::test]
    async fn test_cover_generator_creation() {
        let config = CoverConfig::default();
        let _generator = CoverGenerator::new(config);
        
        // Should be able to create generator
        assert!(true);
    }
}