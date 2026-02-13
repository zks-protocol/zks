//! ZKS Protocol Relay Node
//!
//! This binary runs a relay node for the ZKS Protocol, providing NAT traversal
//! and data relaying services for the swarm. It connects to the signaling server
//! to advertise its presence and capabilities.

use clap::Parser;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use zks_wire::relay::{RelayConfig, RelayServer};
use zks_wire::signaling::{PeerCapabilities, SignalingClient};
use zks_wire::SwarmController;

/// ZKS Protocol Relay Node
#[derive(Parser)]
#[clap(name = "zks-node")]
#[clap(about = "ZKS Protocol Relay Node - Provides NAT traversal and relay services")]
#[clap(version)]
struct Cli {
    /// Bind address for the relay server
    #[clap(long, default_value = "0.0.0.0:3478")]
    bind_addr: String,

    /// Public address to advertise (e.g. wss://relay.example.com)
    #[clap(long)]
    advertise_addr: Option<String>,

    /// Signaling server URL
    #[clap(
        long,
        default_value = "wss://zks-protocol-signaling.md-wasif-faisal.workers.dev"
    )]
    signaling_url: String,

    /// Swarm network name/room ID
    #[clap(long, default_value = "zks-mainnet")]
    network: String,

    /// Maximum number of allocations
    #[clap(long, default_value = "1000")]
    max_allocations: usize,

    /// Enable verbose logging
    #[clap(short, long)]
    verbose: bool,

    /// Disable colored output
    #[clap(long)]
    no_color: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(!cli.no_color);

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(tracing_subscriber::EnvFilter::new(log_level))
        .init();

    info!("Starting ZKS Protocol Relay Node");

    // Parse bind address
    let bind_addr: SocketAddr = cli.bind_addr.parse()?;

    // 1. Start Relay Server
    let config = RelayConfig {
        bind_addr,
        max_allocations: cli.max_allocations,
        allocation_lifetime: 3600,
        idle_timeout: 600,
        auth_required: true,
    };

    info!("Relay Configuration:");
    info!("  Bind address: {}", config.bind_addr);
    info!("  Max allocations: {}", config.max_allocations);

    // Create and start relay server
    let mut relay_server = RelayServer::new(config);
    relay_server.start().await?;
    info!("✅ Relay server started on {}", bind_addr);

    // 2. Initialize Swarm Controller for Signaling
    info!("Initializing Swarm Controller...");
    let swarm = SwarmController::new().await?;

    // Generate a local peer ID (in a real app, this should be consistent/persisted)
    let peer_id = format!("relay-{}", uuid::Uuid::new_v4());
    info!("Local Peer ID: {}", peer_id);

    // Connect to signaling server
    info!("Connecting to signaling server: {}", cli.signaling_url);
    let signaling = SignalingClient::connect(&cli.signaling_url, peer_id.clone()).await?;

    // Set advertised addresses if provided
    if let Some(addr) = cli.advertise_addr {
        info!("Advertising address: {}", addr);
        signaling.set_advertised_addresses(vec![addr]).await;
    } else {
        // Default to bind address if no explicit advertise addr
        // Note: binding to 0.0.0.0 is not useful to advertise, so we warn
        if bind_addr.ip().is_unspecified() {
            tracing::warn!("No advertise address specified and bind address is unspecified. Peers may not be able to connect.");
        } else {
            let addr = format!("tcp://{}", bind_addr);
            info!("Advertising bind address: {}", addr);
            signaling.set_advertised_addresses(vec![addr]).await;
        }
    }

    // Connect swarm with this signaling client
    swarm.connect_with_signaling(signaling).await?;

    // Join the network room
    let capabilities = PeerCapabilities {
        supports_p2p: true,
        supports_relay: true, // We are a relay!
        supports_onion_routing: true,
        max_message_size: 1024 * 1024,
        supported_protocols: vec!["zks/1.0".to_string()],
        max_hops: 8,
    };

    swarm.join_room(&cli.network, capabilities).await?;
    info!("✅ Joined swarm network '{}' as relay", cli.network);

    info!("Relay node running. Press Ctrl+C to stop.");

    // Keep running
    tokio::signal::ctrl_c().await?;

    info!("Shutting down relay node...");

    // Disconnect swarm
    swarm.disconnect().await?;

    Ok(())
}
