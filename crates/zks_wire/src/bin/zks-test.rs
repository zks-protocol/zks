//! ZKS Protocol Test Client
//!
//! This binary provides a CLI for testing the ZKS Protocol's end-to-end functionality,
//! including circuit building, onion stream creation, and performance benchmarking.

use clap::{Parser, Subcommand};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use zks_wire::signaling::{PeerCapabilities, SignalingClient};
use zks_wire::swarm_controller::{SwarmController, SwarmControllerConfig};

/// Continuous test metrics
#[derive(Debug, Default)]
struct ContinuousTestMetrics {
    circuits_built: u32,
    circuits_failed: u32,
    messages_sent: u64,
    messages_failed: u64,
    total_bytes_sent: u64,
    min_build_time_ms: u64,
    max_build_time_ms: u64,
    avg_build_time_ms: f64,
}

/// Run continuous test mode for sustained load validation
async fn run_continuous_test(
    swarm: &SwarmController<SignalingClient>,
    room: &str,
    hops: u8,
    num_circuits: u32,
    messages_per_circuit: u32,
    message_size: usize,
    message_delay_ms: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut metrics = ContinuousTestMetrics::default();
    let test_message = vec![0x42; message_size];
    let mut circuits_tested = 0;

    info!("Starting continuous test...");

    loop {
        if num_circuits > 0 && circuits_tested >= num_circuits {
            break;
        }

        // 1. Discover peers
        let peers = swarm.discover_peers(room).await?;
        if peers.is_empty() {
            info!("No peers found, waiting 5s...");
            sleep(Duration::from_secs(5)).await;
            continue;
        }

        let target = &peers[0].peer_id;
        let build_start = Instant::now();

        // 2. Build circuit
        match swarm.build_onion_circuit(target, hops, hops).await {
            Ok(circuit_id) => {
                let build_time = build_start.elapsed().as_millis() as u64;
                metrics.circuits_built += 1;
                circuits_tested += 1;

                // Update timing metrics
                if build_time < metrics.min_build_time_ms || metrics.circuits_built == 1 {
                    metrics.min_build_time_ms = build_time;
                }
                if build_time > metrics.max_build_time_ms {
                    metrics.max_build_time_ms = build_time;
                }
                metrics.avg_build_time_ms = (
                    metrics.avg_build_time_ms * (metrics.circuits_built - 1) as f64
                        + build_time as f64
                ) / metrics.circuits_built as f64;

                info!(
                    "✅ Circuit {} built in {}ms ({} circuits total)",
                    circuit_id, build_time, metrics.circuits_built
                );

                // 3. Create stream and send messages
                match swarm.create_onion_stream(&circuit_id).await {
                    Ok(mut stream) => {
                        // Send messages through the circuit via AsyncWrite
                        for i in 0..messages_per_circuit {
                            match stream.write_all(&test_message).await {
                                Ok(_) => {
                                    metrics.messages_sent += 1;
                                    metrics.total_bytes_sent += message_size as u64;
                                }
                                Err(e) => {
                                    metrics.messages_failed += 1;
                                    info!("⚠️ Write failed at message {}: {:?}", i, e);
                                    break;
                                }
                            }

                            if i < messages_per_circuit - 1 {
                                sleep(Duration::from_millis(message_delay_ms)).await;
                            }
                        }

                        info!(
                            "✅ Sent {}/{} messages through circuit {}",
                            messages_per_circuit, messages_per_circuit, circuit_id
                        );

                        // Shutdown stream to ensure all pending writes complete before teardown
                        stream.shutdown().await;
                    }
                    Err(e) => {
                        metrics.messages_failed += messages_per_circuit as u64;
                        info!("⚠️ Failed to create stream: {:?}", e);
                    }
                }

                // 4. Teardown circuit
                if let Err(e) = swarm.teardown_circuit(&circuit_id).await {
                    info!("⚠️ Failed to teardown circuit: {:?}", e);
                    metrics.circuits_failed += 1;
                }

                // 5. Print periodic metrics
                if metrics.circuits_built % 5 == 0 {
                    print_metrics(&metrics);
                }
            }
            Err(e) => {
                metrics.circuits_failed += 1;
                circuits_tested += 1;
                info!("⚠️ Failed to build circuit: {:?}", e);
            }
        }

        // Small delay between circuits
        sleep(Duration::from_millis(1000)).await;
    }

    print_metrics(&metrics);
    info!("Continuous test complete!");
    Ok(())
}

/// Print test metrics summary
fn print_metrics(metrics: &ContinuousTestMetrics) {
    info!("\n=== Continuous Test Metrics ===");
    info!("Circuits Built: {}", metrics.circuits_built);
    info!("Circuits Failed: {}", metrics.circuits_failed);
    info!("Messages Sent: {}", metrics.messages_sent);
    info!("Messages Failed: {}", metrics.messages_failed);
    info!("Total Bytes Sent: {}", metrics.total_bytes_sent);
    info!("\nCircuit Build Times:");
    info!("  Min: {}ms", metrics.min_build_time_ms);
    info!("  Max: {}ms", metrics.max_build_time_ms);
    info!("  Avg: {:.2}ms", metrics.avg_build_time_ms);

    if metrics.circuits_built > 0 {
        let success_rate = (metrics.circuits_built as f64
            / (metrics.circuits_built + metrics.circuits_failed) as f64)
            * 100.0;
        let msg_success_rate = if metrics.messages_sent + metrics.messages_failed > 0 {
            (metrics.messages_sent as f64 / (metrics.messages_sent + metrics.messages_failed) as f64) * 100.0
        } else {
            0.0
        };
        info!("\nSuccess Rates:");
        info!("  Circuit Success: {:.2}%", success_rate);
        info!("  Message Success: {:.2}%", msg_success_rate);
    }
    info!("=============================\n");
}

/// ZKS Protocol Test Client
#[derive(Parser)]
#[clap(name = "zks-test")]
#[clap(about = "ZKS Protocol Test Client - Circuit building and benchmarking")]
#[clap(version)]
struct Cli {
    /// Signaling server URL
    #[clap(
        long,
        default_value = "wss://zks-protocol-signaling.md-wasif-faisal.workers.dev"
    )]
    signaling_url: String,

    /// Swarm network name/room ID
    #[clap(long, default_value = "zks-mainnet")]
    network: String,

    /// Enable verbose logging
    #[clap(short, long)]
    verbose: bool,

    /// Network/room ID for testing (can override network flag)
    #[clap(long)]
    room_id: Option<String>,

    /// Disable colored output
    #[clap(long)]
    no_color: bool,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all peers in the network with their capabilities and addresses
    ListPeers,

    /// Build a circuit to a destination
    Build {
        /// Destination Peer ID (optional, will pick random if not provided)
        #[clap(long)]
        dest: Option<String>,

        /// Number of hops
        #[clap(long, default_value = "3")]
        hops: u8,
    },

    /// Run a bandwidth/latency benchmark
    Bench {
        /// Destination Peer ID (hex)
        #[clap(long)]
        dest: String,

        /// Duration of test in seconds
        #[clap(long, default_value = "10")]
        duration: u64,

        /// Packet size in bytes
        #[clap(long, default_value = "1024")]
        size: usize,
    },

    /// Listen for incoming connections (server mode)
    Listen {
        /// Port to listen on (if applicable)
        #[clap(short, long, default_value = "0")]
        port: u16,
    },

    /// Run continuous test mode for sustained load validation (H5 fix)
    /// This mode continuously builds circuits, streams data, and collects metrics
    Continuous {
        /// Number of hops for each circuit
        #[clap(long, default_value = "3")]
        hops: u8,

        /// Number of circuits to build before stopping (0 = infinite)
        #[clap(long, default_value = "10")]
        num_circuits: u32,

        /// Number of messages per circuit
        #[clap(long, default_value = "10")]
        messages_per_circuit: u32,

        /// Message size in bytes
        #[clap(long, default_value = "512")]
        message_size: usize,

        /// Delay between messages in milliseconds
        #[clap(long, default_value = "100")]
        message_delay_ms: u64,
    },
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

    info!("Starting ZKS Protocol Test Client");

    // Determine room ID from CLI
    let room = cli.room_id.clone().unwrap_or_else(|| cli.network.clone());

    // Initialize Swarm Controller with the correct default room
    let config = SwarmControllerConfig::new(&room);
    let swarm = SwarmController::with_config(config).await?;

    // Generate local peer ID
    let peer_id = format!("client-{}", uuid::Uuid::new_v4());
    info!("Local Peer ID: {}", peer_id);

    // Connect to signaling
    info!("Connecting to signaling server: {}", cli.signaling_url);
    let signaling = SignalingClient::connect(&cli.signaling_url, peer_id).await?;
    swarm.connect_with_signaling(signaling).await?;

    // Join room
    let capabilities = PeerCapabilities {
        supports_p2p: true,
        supports_relay: true,
        supports_onion_routing: false,
        max_message_size: 1024 * 1024,
        supported_protocols: vec!["zks/1.0".to_string()],
        max_hops: 3,
    };
    // Wait briefly for P2P network to initialize
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

    swarm.join_room(&room, capabilities).await?;
    info!("Joined room: {}", room);

    // Initial peer discovery
    info!("🔍 Discovering peers in room '{}'...", room);
    match swarm.discover_peers(&room).await {
        Ok(peers) => {
            info!("✅ Initial discovery: {} peers in room '{}'", peers.len(), room);
            for peer in &peers {
                let relay_str = if peer.capabilities.supports_relay { "RELAY" } else { "node" };
                let onion_str = if peer.capabilities.supports_onion_routing { ", ONION" } else { "" };
                info!("  - Peer: {} [{}{}] (addresses: {:?})", 
                    peer.peer_id, relay_str, onion_str, peer.addresses);
            }
        }
        Err(e) => {
            warn!("⚠️ Initial peer discovery failed (will retry if needed): {:?}", e);
        }
    }

    match cli.command {
        Commands::ListPeers => {
            info!("🔍 Listing all peers in room '{}'...", room);
            let peers = swarm.discover_peers(&room).await?;
            
            if peers.is_empty() {
                info!("⚠️ No peers found in room '{}'", room);
            } else {
                info!("✅ Found {} peer(s) in room '{}':", peers.len(), room);
                println!("\n{:?}", "=".repeat(100));
                println!("{:<60} {:<15} {:<25}", "Peer ID", "Capabilities", "Addresses");
                println!("{:?}", "=".repeat(100));
                
                for peer in &peers {
                    let mut capabilities = Vec::new();
                    if peer.capabilities.supports_relay {
                        capabilities.push("RELAY");
                    }
                    if peer.capabilities.supports_onion_routing {
                        capabilities.push("ONION");
                    }
                    if peer.capabilities.supports_p2p {
                        capabilities.push("P2P");
                    }
                    
                    let caps_str = if capabilities.is_empty() {
                        "NONE".to_string()
                    } else {
                        capabilities.join(", ")
                    };
                    
                    let addr_str = if peer.addresses.is_empty() {
                        "❌ EMPTY (CULPRIT!)".to_string()
                    } else {
                        peer.addresses.iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    
                    println!("{:<60} {:<15} {:<25}", 
                        peer.peer_id, 
                        caps_str, 
                        addr_str
                    );
                }
                println!("{:?}", "=".repeat(100));
                println!("\nTotal: {} peer(s)", peers.len());
                
                let relay_peers: Vec<_> = peers.iter()
                    .filter(|p| p.capabilities.supports_relay && !p.addresses.is_empty())
                    .collect();
                let empty_addr_peers: Vec<_> = peers.iter()
                    .filter(|p| p.addresses.is_empty())
                    .collect();
                
                println!("\nSummary:");
                println!("  Relay-capable with addresses: {} (needed for 3-hop circuits)", relay_peers.len());
                if !empty_addr_peers.is_empty() {
                    println!("  ⚠️ Peers with empty addresses (CULPRIT!):");
                    for peer in empty_addr_peers {
                        println!("    - {} (supports_relay: {})", 
                            peer.peer_id, 
                            peer.capabilities.supports_relay);
                    }
                }
            }
        }
        Commands::Build { dest, hops } => {
            // Discover peers with retries
            let mut peers: Vec<zks_wire::signaling::PeerInfo> = Vec::new();
            let mut retry_count = 0;
            let max_retries = 6; // 30 seconds total (6 * 5s)

            info!("🔍 Discovering peers in room '{}'...", room);
            while retry_count < max_retries {
                peers = swarm.discover_peers(&room).await?;
                if !peers.is_empty() {
                    break;
                }
                
                retry_count += 1;
                if retry_count < max_retries {
                    info!("  No peers found yet, waiting 5s (attempt {}/{})...", retry_count, max_retries);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }

            let peer_count = peers.len();
            info!("✅ Discovery complete: {} peers found", peer_count);
            for peer in &peers {
                let relay_str = if peer.capabilities.supports_relay { "RELAY" } else { "node" };
                info!("  - Peer: {} [{}] (addresses: {:?})", 
                    peer.peer_id, relay_str, peer.addresses);
            }

            let target = if let Some(d) = dest {
                d
            } else {
                // Pick a random peer that isn't us
                let local_pid = swarm.local_peer_id().await.unwrap_or_default();
                let filtered_peers: Vec<_> = peers
                    .iter()
                    .filter(|p| p.peer_id != local_pid)
                    .collect();

                if filtered_peers.is_empty() {
                    return Err("No other peers found in network to build circuit".into());
                }
                let p = filtered_peers[0]; // Simple pick for now
                p.peer_id.clone()
            };

            info!("Building {}-hop circuit to {}", hops, target);

            let circuit_id = swarm.build_onion_circuit(&target, hops, hops).await?;
            info!("✅ Circuit established! ID: {}", circuit_id);

            // Try creating a stream
            let mut _stream = swarm.create_onion_stream(&circuit_id).await?;
            info!("✅ Onion Stream created successfully");

            // Clean up
            swarm.teardown_circuit(&circuit_id).await?;
            info!("Circuit torn down.");
        }
        Commands::Bench {
            dest,
            duration,
            size,
        } => {
            info!(
                "Running benchmark to {} ({}s, {} bytes)",
                dest, duration, size
            );
            // Benchmark implementation would go here
            info!("Benchmark requires active stream; use Build first.");
        }
        Commands::Continuous {
            hops,
            num_circuits,
            messages_per_circuit,
            message_size,
            message_delay_ms,
        } => {
            info!("Running continuous test mode:");
            info!("  Hops: {}", hops);
            let circuits_display = if num_circuits == 0 { "infinite".to_string() } else { num_circuits.to_string() };
            info!("  Circuits: {}", circuits_display);
            info!("  Messages per circuit: {}", messages_per_circuit);
            info!("  Message size: {} bytes", message_size);
            info!("  Message delay: {} ms", message_delay_ms);

            run_continuous_test(
                &swarm,
                &room,
                hops,
                num_circuits,
                messages_per_circuit,
                message_size,
                message_delay_ms,
            ).await?;
        }
        Commands::Listen { port: _ } => {
            info!("Client listening for incoming circuit requests...");

            // Spawn periodic peer discovery in background for Listen mode
            let discovery_swarm = swarm.clone();
            let discovery_room = room.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                interval.tick().await; // Skip first immediate tick
                loop {
                    interval.tick().await;
                    match discovery_swarm.discover_peers(&discovery_room).await {
                        Ok(peers) => {
                            let peer_count = peers.len();
                            info!("🔄 Listen mode - {} peers in '{}'", peer_count, discovery_room);
                        }
                        Err(e) => {
                            warn!("⚠️ Listen mode discovery failed: {:?}", e);
                        }
                    }
                }
            });

            // Keep running
            tokio::signal::ctrl_c().await?;
        }
    }

    // Disconnect
    swarm.disconnect().await?;
    info!("Done.");

    Ok(())
}
