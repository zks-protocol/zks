//! ZKS SDK - High-level API for ZKS Protocol
//!
//! This crate provides a user-friendly interface to the ZKS Protocol stack,
//! including post-quantum secure networking, NAT traversal, and cryptographic operations.
//!
//! # Features
//!
//! - **Post-quantum security**: ML-KEM (Kyber) + ML-DSA (Dilithium)
//! - **NAT traversal**: STUN/TURN/ICE support
//! - **Simple API**: Builder pattern for easy configuration
//! - **Async/await**: Full async support with Tokio
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use zks_sdk::builder::ZkConnectionBuilder;
//! use zks_sdk::config::SecurityLevel;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a connection
//!     let conn = ZkConnectionBuilder::new()
//!         .url("zk://peer.example.com:8080")
//!         .security(SecurityLevel::PostQuantum)
//!         .build()
//!         .await?;
//!
//!     // Note: In a real application, you would connect and use the connection
//!     // This is just a documentation example
//!     Ok(())
//! }
//! ```

pub mod builder;
pub mod config;
pub mod connection;
pub mod crypto;
pub mod error;
pub mod prefabs;
pub mod stream;

pub mod prelude {
    pub use crate::builder::ZkConnectionBuilder;
    pub use crate::config::SecurityLevel;
    pub use crate::error::Result;
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
        let mut cipher = WasifVernam::new(key).unwrap();
        let plaintext = b"Hello, quantum world!";
        
        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}