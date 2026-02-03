#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # zks_surb
//! 
//! Single-Use Reply Blocks (SURBs) for ZKS Protocol - post-quantum anonymous replies with ML-KEM and Wasif-Vernam.
//! 
//! SURBs enable anonymous replies in onion routing networks by allowing recipients to send messages
//! back to the original sender without revealing the sender's identity or location.
//! 
//! This crate provides:
//! - **Post-Quantum Security**: Uses ML-KEM-768 for key encapsulation
//! - **Anonymous Replies**: Send messages without revealing sender identity
//! - **Faisal Swarm Integration**: Seamless integration with ZKS onion routing
//! - **Single-Use Design**: Each SURB can only be used once for maximum security
//! 
//! # Example
//! 
//! ```rust,no_run
//! use zks_surb::{ZksSurb, ReplyRequest, SurbEncryption};
//! use zks_pqcrypto::ml_kem::MlKem;
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Alice creates a SURB for Bob to reply anonymously
//!     let alice_keypair = MlKem::generate_keypair()?;
//!     let (surb, private_data) = ZksSurb::create(&alice_keypair.public_key())?;
//!     
//!     // Alice sends SURB to Bob
//!     // Bob uses SURB to send anonymous reply
//!     let reply_content = b"Anonymous reply from Bob";
//!     let mut reply_request = ReplyRequest::from_surb(surb, reply_content)?;
//!     
//!     // Bob encrypts the reply
//!     reply_request.encrypt_reply()?;
//!     
//!     // Alice receives and decrypts the reply (in real scenario, via Faisal Swarm)
//!     if let Some(encrypted_reply) = reply_request.encrypted_reply() {
//!         let alice_encryption = SurbEncryption::new(private_data.encryption_key);
//!         let decrypted_reply = alice_encryption.decrypt(encrypted_reply)?;
//!         println!("Received reply: {:?}", String::from_utf8_lossy(&decrypted_reply));
//!     }
//!     
//!     Ok(())
//! }
//! ```

/// SURB configuration and builder patterns
pub mod config;
/// Core SURB implementation and route generation
pub mod surb;
/// Encryption and decryption functionality for SURB replies
pub mod encryption;
/// Error types and result handling
pub mod error;
/// Storage backends for SURB persistence
pub mod storage;
/// Utility functions for SURB generation and management
pub mod surb_utils;

pub use config::{SurbConfig, SurbConfigBuilder};
pub use surb::{ZksSurb, ReplyRequest, SurbId, PrivateSurbData};
pub use encryption::{SurbEncryption, EncryptedReply};
pub use error::{SurbError, Result};
pub use storage::{SurbStorage, MemorySurbStorage, FileSurbStorage};

/// Default SURB parameters
pub mod defaults {
    use std::time::Duration;
    
    /// Default SURB lifetime (24 hours)
    /// 
    /// SECURITY NOTE (m6 Fix): Extended from 1 hour to 24 hours for practical
    /// anonymous correspondence. Mixminion SURBs supported lifetimes up to weeks.
    /// 
    /// Considerations:
    /// - Longer lifetimes increase window for replay attacks if SURB ID tracking fails
    /// - Shorter lifetimes may cause usability issues for asynchronous communication
    /// - 24 hours balances security and usability for most use cases
    /// 
    /// Use `SurbConfigBuilder::lifetime()` to customize for your application.
    pub const DEFAULT_SURB_LIFETIME: Duration = Duration::from_secs(86400); // 24 hours
    
    /// Legacy SURB lifetime (1 hour) - for high-security applications
    pub const SURB_LIFETIME_HIGH_SECURITY: Duration = Duration::from_secs(3600);
    
    /// Default maximum reply size (1KB)
    pub const DEFAULT_MAX_REPLY_SIZE: usize = 1024;
    
    /// Default number of hops in SURB route (3: Guard → Middle → Exit)
    pub const DEFAULT_ROUTE_LENGTH: usize = 3;
    
    /// Default SURB ID length (16 bytes)
    pub const DEFAULT_SURB_ID_LENGTH: usize = 16;
}