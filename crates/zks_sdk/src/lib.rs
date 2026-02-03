//! # ZKS - Zero Knowledge Swarm Protocol
//!
//! Post-quantum secure networking SDK with built-in anonymity.
//!
//! ## Overview
//!
//! ZKS provides two protocol types:
//! - `zk://` - Direct encrypted connection (fast, post-quantum secure)
//! - `zks://` - Swarm-routed anonymous connection (onion routing)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use zks::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let conn = ZkConnectionBuilder::new()
//!         .url("zk://example.com:8443")
//!         .security(SecurityLevel::PostQuantum)
//!         .build()
//!         .await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Crate Structure
//!
//! This crate re-exports all ZKS sub-crates for convenience:
//!
//! - [`crypto`] - Wasif-Vernam cipher, encryption primitives
//! - [`pqcrypto`] - Post-quantum cryptography (ML-KEM, ML-DSA)
//! - [`wire`] - Network layer, NAT traversal, swarm
//! - [`proto`] - Protocol layer, handshake, messages
//! - [`types`] - Common types and errors

// Re-export sub-crates for unified access
pub use zks_crypt as crypto;
pub use zks_pqcrypto as pqcrypto;
pub use zks_wire as wire;
pub use zks_proto as proto;
pub use zks_types as types;

// SDK-specific modules
pub mod builder;
pub mod config;
pub mod connection;
pub mod error;
pub mod prefabs;
pub mod stream;
pub mod sdk_crypto;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::builder::ZkConnectionBuilder;
    pub use crate::config::SecurityLevel;
    pub use crate::error::Result;
    
    // Re-export commonly used items from sub-crates
    pub use zks_crypt::wasif_vernam::WasifVernam;
    pub use zks_pqcrypto::prelude::*;
    
    // Cover traffic and SURB exports
    pub use zks_cover::{CoverGenerator, CoverConfig};
    pub use zks_surb::{ZksSurb, ReplyRequest, SurbConfig};
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sdk_imports() {
        // Test that prelude imports work
        let _builder = prelude::ZkConnectionBuilder::new();
    }
    
    #[tokio::test]
    async fn test_zk_connection_builder() {
        use crate::config::SecurityLevel;
        use crate::prelude::{ZkConnectionBuilder, Result};
        
        let result: Result<_> = ZkConnectionBuilder::new()
            .url("zk://localhost:8080")
            .security(SecurityLevel::PostQuantum)
            .build()
            .await;
        
        // We expect this to fail since there's no server running
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_encryption_roundtrip() {
        use zks_crypt::wasif_vernam::WasifVernam;
        
        let key = [0u8; 32];
        let mut sender = WasifVernam::new(key).unwrap();
        sender.derive_base_iv(&key, true); // Required for encryption
        
        let mut receiver = WasifVernam::new(key).unwrap();
        receiver.derive_base_iv(&key, true); // Same as sender for anti-replay
        
        let plaintext = b"Hello, quantum world!";
        
        let encrypted = sender.encrypt(plaintext).unwrap();
        let decrypted = receiver.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}