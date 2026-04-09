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

pub mod anonymity;
pub mod circuit;
pub mod cloudflare_signaling;
pub mod dht_lookup;
pub mod entropy_cache;
pub mod entropy_grid;
pub mod entropy_swarm;
pub mod error;
pub mod faisal_swarm;
pub mod nat;
pub mod p2p;
pub mod relay;
pub mod seeder;
pub mod signaling;
pub mod stun;
pub mod swarm;
pub mod swarm_controller;
pub mod wire;

use async_trait::async_trait;
// Removed redundant imports of PeerInfo and Result

/// Trait for providing peers for route generation (e.g., SURBs)
#[async_trait]
pub trait PeerProvider: Send + Sync {
    /// Get available peers in a room
    async fn get_available_peers(&self, room_id: &str) -> Result<Vec<PeerInfo>>;
}

pub use circuit::{CircuitBuilder, SwarmCircuit};
pub use cloudflare_signaling::{
    CloudflareSignalingClient, CloudflareSignalingConfig, CloudflareSignalingMessage,
    ConnectionStats,
};
pub use dht_lookup::{
    DHTLookupConfig, DHTLookupError, DHTLookupManager, DHTLookupResult, DHTLookupService,
};
pub use entropy_cache::{EntropyCache, EntropyCacheConfig, EntropyCacheStats};
pub use entropy_grid::{
    EntropyCacheInterface, EntropyGrid, EntropyGridConfig, EntropySwarmInterface, IpfsInterface,
};
pub use entropy_swarm::{
    EntropyRequest, EntropyResponse, EntropySwarm, EntropySwarmConfig, ENTROPY_TOPIC,
};
pub use error::{Result, WireError};
pub use faisal_swarm::{CircuitState, FaisalSwarmCircuit, FaisalSwarmManager, HopRole, SwarmHop};
pub use anonymity::{
    AggregateAnonymityMetrics, AnonymitySet, CircuitAnonymityMetrics, TrafficPattern,
    aggregate_anonymity_metrics, analyze_size_correlation, analyze_timing_correlation,
    calculate_byte_entropy, calculate_effective_anonymity_set, calculate_min_entropy,
    calculate_path_diversity, calculate_scaled_anonymity_set, calculate_shannon_entropy,
    calculate_size_correlation_risk, calculate_timing_resistance, compute_circuit_anonymity_metrics,
};
pub use nat::{NatTraversal, NatType};
pub use p2p::{NativeP2PError, NativeP2PTransport};
pub use relay::{RelayClient, RelayConfig, RelayCredentials, RelayId, RelayServer};
pub use seeder::{EntropySeeder, SeederConfig, SeederError};
pub use signaling::{PeerCapabilities, PeerInfo, SignalingClient, SignalingMessage};
pub use stun::{IceCandidate, StunClient, StunServer};
pub use swarm::{Peer, PeerId, Swarm, SwarmEvent};
pub use swarm_controller::{
    OnionStream, Platform, SwarmController, SwarmControllerConfig, SwarmControllerError,
    TransportCapabilities,
};
pub use wire::{MessageType, WireMessage, WireProtocol};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::{CircuitBuilder, SwarmCircuit};
    pub use crate::{CircuitState, FaisalSwarmCircuit, FaisalSwarmManager, HopRole, SwarmHop};
    pub use crate::{NatTraversal, Result, StunClient, Swarm, WireProtocol};
    pub use crate::{Peer, PeerId, SwarmEvent};
    pub use crate::{RelayClient, RelayConfig, RelayId, RelayServer};
}
