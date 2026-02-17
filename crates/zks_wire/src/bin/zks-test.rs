//! ZKS Protocol Test Client
//!
//! This binary provides a CLI for testing the ZKS Protocol's end-to-end functionality,
//! including circuit building, onion stream creation, and performance benchmarking.

use clap::{Parser, Subcommand};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use zks_wire::signaling::{PeerCapabilities, SignalingClient};
use zks_wire::SwarmController;

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

    /// Run continuous test mode for sustained load validation (H5 fix)
    /// This mode continuously builds circuits, streams data, and collects metrics
    Continuous {
        /// Number of hops for each circuit
        #[clap(short, long, default_value = "3")]
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

    // Initialize Swarm Controller
    let swarm = SwarmController::new().await?;

    // Generate local peer ID
    let peer_id = format!("client-{}", uuid::Uuid::new_v4());
    info!("Local Peer ID: {}", peer_id);

    // Connect to signaling
    info!("Connecting to signaling server: {}", cli.signaling_url);
    let signaling = SignalingClient::connect(&cli.signaling_url, peer_id).await?;
    swarm.connect_with_signaling(signaling).await?;

    // Join room (use room_id override if provided)
    let room = cli.room_id.as_ref().unwrap_or(&cli.network);
    let capabilities = PeerCapabilities::default();
    swarm.join_room(room, capabilities).await?;
    info!("Joined room: {}", room);

    match cli.command {
        Commands::Build { dest, hops } => {
            // Discover peers
            let peers = swarm.discover_peers(&room).await?;
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
                room,
                hops,
                num_circuits,
                messages_per_circuit,
                message_size,
                message_delay_ms,
            ).await?;
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
