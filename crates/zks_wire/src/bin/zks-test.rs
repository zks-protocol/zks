//! ZKS Protocol Test Client
//!
//! This binary provides a CLI for testing the ZKS Protocol's end-to-end functionality,
//! including circuit building, onion stream creation, and performance benchmarking.

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use zks_wire::signaling::{PeerCapabilities, SignalingClient};
use zks_wire::SwarmController;

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

    /// Disable colored output
    #[clap(long)]
    no_color: bool,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a circuit to a destination
    Build {
        /// Destination Peer ID (optional, will pick random if not provided)
        #[clap(long)]
        dest: Option<String>,

        /// Number of hops
        #[clap(short, long, default_value = "3")]
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

    // Initialize Swarm Controller
    let swarm = SwarmController::new().await?;

    // Generate local peer ID
    let peer_id = format!("client-{}", uuid::Uuid::new_v4());
    info!("Local Peer ID: {}", peer_id);

    // Connect to signaling
    info!("Connecting to signaling server: {}", cli.signaling_url);
    let signaling = SignalingClient::connect(&cli.signaling_url, peer_id).await?;
    swarm.connect_with_signaling(signaling).await?;

    // Join room
    let capabilities = PeerCapabilities::default();
    swarm.join_room(&cli.network, capabilities).await?;
    info!("Joined room: {}", cli.network);

    match cli.command {
        Commands::Build { dest, hops } => {
            // Discover peers
            let peers = swarm.discover_peers(&cli.network).await?;
            info!("Discovered {} peers", peers.len());

            let target = if let Some(d) = dest {
                d
            } else {
                // Pick a random peer that isn't us (though signaling shouldn't return us normally)
                if peers.is_empty() {
                    return Err("No peers found in network to build circuit".into());
                }
                let p = &peers[0]; // Simple pick for now
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
        Commands::Listen { port: _ } => {
            info!("Client listening for incoming circuit requests...");
            // Keep running
            tokio::signal::ctrl_c().await?;
        }
    }

    // Disconnect
    swarm.disconnect().await?;
    info!("Done.");

    Ok(())
}
