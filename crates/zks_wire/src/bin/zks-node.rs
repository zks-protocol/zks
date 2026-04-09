//! ZKS Protocol Relay Node
//!
//! This binary runs a relay node for the ZKS Protocol, providing NAT traversal
//! and data relaying services for the swarm. It connects to the signaling server
//! to advertise its presence and capabilities.

use clap::Parser;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, warn};
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

    /// Libp2p listen address (e.g. /ip4/0.0.0.0/tcp/4001)
    #[clap(long)]
    libp2p_addr: Option<String>,

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
    let mut swarm_config = zks_wire::SwarmControllerConfig::new(&cli.network);
    if let Some(ref addr) = cli.libp2p_addr {
        info!("Setting fixed libp2p listen address: {}", addr);
        swarm_config = swarm_config.with_listen_addr(addr.clone());
    }
    let swarm = SwarmController::with_config(swarm_config).await?;

    // Generate a local peer ID (in a real app, this should be consistent/persisted)
    let peer_id = format!("relay-{}", uuid::Uuid::new_v4());
    info!("Local Peer ID: {}", peer_id);

    // Connect to signaling server
    info!("Connecting to signaling server: {}", cli.signaling_url);
    let signaling = SignalingClient::connect(&cli.signaling_url, peer_id.clone()).await?;

    // Set advertised addresses if provided manually
    if let Some(addr) = cli.advertise_addr.as_ref() {
        info!("Advertising manual address: {}", addr);
        signaling.set_advertised_addresses(vec![addr.clone()]).await;
    }

    // Connect swarm with this signaling client
    swarm.connect_with_signaling(signaling.clone()).await?;

    // Join the network room
    let capabilities = PeerCapabilities {
        supports_p2p: true,
        supports_relay: true, // We are a relay!
        supports_onion_routing: true,
        max_message_size: 1024 * 1024,
        supported_protocols: vec!["zks/1.0".to_string()],
        max_hops: 8,
    };

    // Wait briefly for P2P network to initialize and get listen addresses
    // This ensures we have addresses to advertise when joining the room
    tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;

    // Retrieve actual libp2p listen addresses
    let libp2p_addrs = swarm.get_listen_addresses().await;
    
    // Auto-detect public IP if not explicitly provided
    let final_advertise_addrs = if let Some(addr) = cli.advertise_addr.as_ref() {
        vec![addr.clone()]
    } else {
        let mut addrs_to_adv = libp2p_addrs.clone();
        
        info!("Trying to detect public IP...");
        
        // Try getting public IP
        match reqwest::get("https://api.ipify.org").await {
            Ok(resp) => {
                if let Ok(ip) = resp.text().await {
                    let ip = ip.trim();
                    info!("Got public IP: {}", ip);
                    
                    // Replace 0.0.0.0 or internal IPs with the public IP
                    addrs_to_adv = addrs_to_adv.into_iter().map(|a| {
                        a.replace("0.0.0.0", ip).replace("127.0.0.1", ip)
                    }).collect();
                    
                    // Further handling for VPC internal IPs (172.x.x.x, 10.x.x.x, 192.168.x.x)
                    // We'll add the public IP with the ports we are actually listening on
                    for addr in &libp2p_addrs {
                        if let Some(port) = addr.split('/').last() {
                            let public_addr = format!("/ip4/{}/tcp/{}", ip, port);
                            if !addrs_to_adv.contains(&public_addr) {
                                addrs_to_adv.push(public_addr);
                            }
                        }
                    }
                }
            }
            Err(e) => warn!("Failed to auto-detect public IP: {}", e),
        }
        addrs_to_adv
    };

    if !final_advertise_addrs.is_empty() {
        info!("Advertising addresses to signaling server: {:?}", final_advertise_addrs);
        signaling.set_advertised_addresses(final_advertise_addrs).await;
    } else {
        warn!("⚠️ Swarm has no listen addresses and auto-IP failed! Peer discovery may fail.");
    }

    swarm.join_room(&cli.network, capabilities).await?;
    info!("✅ Joined swarm network '{}' as relay", cli.network);

    // Initial peer discovery
    info!("🔍 Discovering peers in room '{}'...", cli.network);
    match swarm.discover_peers(&cli.network).await {
        Ok(peers) => {
            let actual_peers: Vec<zks_wire::signaling::PeerInfo> = peers;
            let peer_count = actual_peers.len();
            info!("✅ Discovered {} peers in room '{}'", peer_count, cli.network);
            for peer in &actual_peers {
                info!("  Peer: {} (addresses: {:?})", peer.peer_id, peer.addresses);
            }
        }
        Err(e) => {
            warn!("⚠️ Initial peer discovery failed (will retry): {:?}", e);
        }
    }

    // Spawn periodic peer discovery in background
    let discovery_swarm = swarm.clone();
    let discovery_room = cli.network.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.tick().await; // Skip first immediate tick
        loop {
            interval.tick().await;
            match discovery_swarm.discover_peers(&discovery_room).await {
                Ok(peers) => {
                    let actual_peers: Vec<zks_wire::signaling::PeerInfo> = peers;
                    let peer_count = actual_peers.len();
                    info!("🔄 Periodic discovery: {} peers in '{}'", peer_count, discovery_room);
                }
                Err(e) => {
                    warn!("⚠️ Periodic discovery failed: {:?}", e);
                }
            }
        }
    });

    info!("Relay node running. Press Ctrl+C to stop.");

    // Keep running
    tokio::signal::ctrl_c().await?;

    info!("Shutting down relay node...");

    // Disconnect swarm
    swarm.disconnect().await?;

    Ok(())
}
