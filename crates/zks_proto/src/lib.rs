//! # zks_proto
//! 
//! Protocol layer for ZK Protocol - handshake and URL parsing.
//! 
//! This crate provides high-level protocol functionality:
//! - **3-Message Handshake**: Post-quantum secure key exchange
//! - **URL Parsing**: Support for `zk://` (direct) and `zks://` (swarm) URLs
//! - **Protocol Messages**: Structured message types for ZK Protocol
//! 
//! # Example
//! 
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use zks_proto::{ZkUrl, Handshake, ProtocolMode};
//! 
//! // Parse a ZK Protocol URL
//! let url = ZkUrl::parse("zks://peer.example.com:8080")?;
//! assert_eq!(url.mode(), ProtocolMode::Swarm);
//! 
//! // Create a handshake initiator (with trusted responder public key)
//! let trusted_key = vec![0u8; 1952]; // Example trusted key
//! let handshake = Handshake::new_initiator("test-room".to_string(), trusted_key);
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod error;
pub mod handshake;
pub mod url;
pub mod messages;

pub use error::{ProtoError, Result};
pub use handshake::{Handshake, HandshakeState, HandshakeRole};
pub use url::{ZkUrl, ProtocolMode, UrlScheme};
pub use messages::{ProtocolMessage, MessageType};