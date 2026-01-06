//! # zks_wire
//! 
//! Network primitives for ZK Protocol - NAT traversal, STUN, and swarm networking.
//! 
//! This crate provides low-level networking primitives for the ZK Protocol:
//! - **NAT Traversal**: Hole punching and UPnP/NAT-PMP support
//! - **STUN/TURN**: ICE-like connection establishment  
//! - **Swarm Networking**: Peer discovery and mesh formation
//! - **Wire Protocol**: Binary message framing and encryption
//! 
//! # Example
//! 
//! ```rust,no_run
//! use zks_wire::{Swarm, StunClient, NatTraversal};
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a swarm for peer discovery
//!     let swarm = Swarm::new("my-network".to_string());
//!     
//!     // Perform STUN to discover public address
//!     let stun_client = StunClient::new("8.8.8.8:3478");
//!     // let public_addr = stun_client.discover().await?;
//!     
//!     // Enable NAT traversal
//!     let nat = NatTraversal::new();
//!     // nat.enable_upnp().await?;
//!     
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod error;
pub mod nat;
pub mod relay;
pub mod stun;
pub mod swarm;
pub mod circuit;
pub mod wire;

pub use error::{WireError, Result};
pub use nat::{NatTraversal, NatType};
pub use relay::{RelayServer, RelayClient, RelayId, RelayConfig, RelayCredentials};
pub use stun::{StunClient, StunServer, IceCandidate};
pub use swarm::{Swarm, Peer, PeerId, SwarmEvent};
pub use circuit::{SwarmCircuit, CircuitBuilder};
pub use wire::{WireMessage, WireProtocol, MessageType};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::{Swarm, StunClient, NatTraversal, WireProtocol, Result};
    pub use crate::{PeerId, Peer, SwarmEvent};
    pub use crate::{SwarmCircuit, CircuitBuilder};
    pub use crate::{RelayServer, RelayClient, RelayId, RelayConfig};
}