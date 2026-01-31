//! ZKS Protocol Entropy Seeder CLI
//! 
//! This binary provides command-line interface for running and managing
//! the entropy seeder daemon that polls drand and publishes entropy blocks
//! to the P2P swarm.

use clap::{Parser, Subcommand};
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use serde_json;

use zks_wire::seeder::{EntropySeeder, SeederConfig};
use zks_crypt::drand::DrandEntropy;

/// ZKS Protocol Entropy Seeder CLI
#[derive(Parser)]
#[clap(name = "zks-seeder")]
#[clap(about = "ZKS Protocol Entropy Seeder - Poll drand and publish entropy blocks to P2P swarm")]
#[clap(version)]
struct Cli {
    /// Configuration file path
    #[clap(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

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
    /// Initialize a new seeder configuration
    Init {
        /// Network name for the swarm
        #[clap(short, long, default_value = "zks-mainnet")]
        network: String,

        /// Drand chain hash (mainnet: 8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce)
        #[clap(long, default_value = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce")]
        chain_hash: String,

        /// Drand API URL
        #[clap(long, default_value = "https://api.drand.sh")]
        drand_url: String,

        /// Block size (number of rounds per EntropyBlock)
        #[clap(long, default_value = "100")]
        block_size: u64,

        /// Poll interval in seconds
        #[clap(long, default_value = "30")]
        poll_interval: u64,

        /// Start from current round instead of a specific round
        #[clap(long)]
        start_from_current: bool,

        /// Specific start round (ignored if --start-from-current is set)
        #[clap(long)]
        start_round: Option<u64>,

        /// Enable auto-publishing to swarm
        #[clap(long, default_value = "true")]
        auto_publish: bool,

        /// Enable entropy caching
        #[clap(long, default_value = "true")]
        enable_cache: bool,

        /// Cache capacity (number of blocks)
        #[clap(long, default_value = "1000")]
        cache_capacity: usize,

        /// Cache TTL in seconds
        #[clap(long, default_value = "3600")]
        cache_ttl: u64,
    },

    /// Run the seeder daemon
    Run {
        /// Override the network name
        #[clap(short, long)]
        network: Option<String>,

        /// Override the drand URL
        #[clap(long)]
        drand_url: Option<String>,

        /// Override the block size
        #[clap(long)]
        block_size: Option<u64>,

        /// Override the poll interval
        #[clap(long)]
        poll_interval: Option<u64>,

        /// Override auto-publish setting
        #[clap(long)]
        auto_publish: Option<bool>,
    },

    /// Show seeder status and statistics
    Status,

    /// Stop the running seeder daemon
    Stop,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
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

    info!("Starting ZKS Protocol Entropy Seeder");

    match cli.command {
        Commands::Init { 
            network, 
            chain_hash, 
            drand_url, 
            block_size, 
            poll_interval,
            start_from_current,
            start_round,
            auto_publish,
            enable_cache,
            cache_capacity,
            cache_ttl,
        } => {
            init_seeder_config(
                network,
                chain_hash,
                drand_url,
                block_size,
                poll_interval,
                start_from_current,
                start_round,
                auto_publish,
                enable_cache,
                cache_capacity,
                cache_ttl,
            ).await?;
        }
        Commands::Run { 
            network, 
            drand_url, 
            block_size, 
            poll_interval,
            auto_publish,
        } => {
            run_seeder(
                cli.config,
                network,
                drand_url,
                block_size,
                poll_interval,
                auto_publish,
            ).await?;
        }
        Commands::Status => {
            show_status().await?;
        }
        Commands::Stop => {
            stop_seeder().await?;
        }
    }

    Ok(())
}

async fn init_seeder_config(
    network: String,
    chain_hash: String,
    drand_url: String,
    block_size: u64,
    poll_interval: u64,
    start_from_current: bool,
    start_round: Option<u64>,
    auto_publish: bool,
    enable_cache: bool,
    cache_capacity: usize,
    cache_ttl: u64,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Initializing seeder configuration for network: {}", network);

    // Save configuration to file
    let config_path = "seeder_config.json";
    // For now, we'll save a simple JSON representation since SeederConfig doesn't derive Serialize
    let config_data = serde_json::json!({
        "network": network,
        "chain_hash": chain_hash,
        "drand_url": drand_url,
        "block_size": block_size,
        "poll_interval": poll_interval,
        "start_from_current": start_from_current,
        "start_round": start_round,
        "auto_publish": auto_publish,
        "enable_cache": enable_cache,
        "cache_capacity": cache_capacity,
        "cache_ttl": cache_ttl,
    });
    let config_json = serde_json::to_string_pretty(&config_data)?;
    tokio::fs::write(config_path, config_json).await?;

    info!("Seeder configuration saved to: {}", config_path);
    info!("Network: {}", network);
    info!("Block size: {} rounds", block_size);
    info!("Poll interval: {} seconds", poll_interval);
    info!("Auto-publish: {}", auto_publish);
    info!("Cache enabled: {}", enable_cache);

    Ok(())
}

async fn run_seeder(
    config_path: Option<PathBuf>,
    _network: Option<String>,
    _drand_url: Option<String>,
    block_size: Option<u64>,
    poll_interval: Option<u64>,
    auto_publish: Option<bool>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Starting seeder daemon");

    // Create default config first
    let mut config = SeederConfig::default();

    // Try to load configuration from file if provided
    if let Some(path) = config_path {
        match tokio::fs::read_to_string(path).await {
            Ok(config_json) => {
                let config_data: serde_json::Value = serde_json::from_str(&config_json)?;
                // Apply loaded config values
                if let Some(block_size_val) = config_data.get("block_size").and_then(|v| v.as_u64()) {
                    config.block_size = block_size_val;
                }
                if let Some(poll_interval_val) = config_data.get("poll_interval").and_then(|v| v.as_u64()) {
                    config.poll_interval = std::time::Duration::from_secs(poll_interval_val);
                }
                if let Some(start_from_current) = config_data.get("start_from_current").and_then(|v| v.as_bool()) {
                    config.start_from_current = start_from_current;
                }
                if let Some(start_round_val) = config_data.get("start_round").and_then(|v| v.as_u64()) {
                    config.start_round = Some(start_round_val);
                }
                if let Some(auto_publish_val) = config_data.get("auto_publish").and_then(|v| v.as_bool()) {
                    config.auto_publish = auto_publish_val;
                }
                if let Some(cache_blocks_val) = config_data.get("enable_cache").and_then(|v| v.as_bool()) {
                    config.cache_blocks = cache_blocks_val;
                }
                if let Some(max_cached_blocks_val) = config_data.get("cache_capacity").and_then(|v| v.as_u64()) {
                    config.max_cached_blocks = max_cached_blocks_val as usize;
                }
                info!("Configuration loaded from file");
            }
            Err(e) => {
                warn!("Failed to load configuration file: {}", e);
                info!("Using default configuration");
            }
        }
    }

    // Apply command line overrides
    if let Some(block_size_val) = block_size {
        config.block_size = block_size_val;
    }
    if let Some(poll_interval_val) = poll_interval {
        config.poll_interval = std::time::Duration::from_secs(poll_interval_val);
    }
    if let Some(auto_publish_val) = auto_publish {
        config.auto_publish = auto_publish_val;
    }

    info!("Configuration:");
    info!("  Block size: {} rounds", config.block_size);
    info!("  Poll interval: {:?}", config.poll_interval);
    info!("  Auto-publish: {}", config.auto_publish);
    info!("  Cache blocks: {}", config.cache_blocks);
    info!("  Max cached blocks: {}", config.max_cached_blocks);

    // Create drand client
    let _drand_client = Arc::new(DrandEntropy::new());

    // Create seeder
    let mut seeder = EntropySeeder::new(config).await?;

    // Start seeder
    seeder.start().await?;

    info!("Seeder daemon started successfully");
    info!("Press Ctrl+C to stop");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    
    info!("Shutting down seeder daemon...");
    
    // Stop seeder and handle errors
    if let Err(e) = seeder.stop().await {
        error!("Error stopping seeder: {}", e);
    }

    info!("Seeder daemon stopped");

    Ok(())
}

async fn show_status() -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("=== ZKS Protocol Entropy Seeder Status ===");
    
    // Check for default configuration file
    let default_config_path = PathBuf::from("seeder_config.json");
    if default_config_path.exists() {
        info!("Configuration file found: {}", default_config_path.display());
        
        // Try to load and display basic config info
        match tokio::fs::read_to_string(&default_config_path).await {
            Ok(config_content) => {
                if let Ok(config_json) = serde_json::from_str::<serde_json::Value>(&config_content) {
                    info!("Configuration summary:");
                    if let Some(poll_interval) = config_json.get("poll_interval_secs") {
                        info!("  Poll interval: {} seconds", poll_interval);
                    }
                    if let Some(block_size) = config_json.get("block_size") {
                        info!("  Block size: {} rounds", block_size);
                    }
                    if let Some(auto_publish) = config_json.get("auto_publish") {
                        info!("  Auto-publish: {}", auto_publish);
                    }
                    if let Some(cache_blocks) = config_json.get("cache_blocks") {
                        info!("  Cache blocks: {}", cache_blocks);
                    }
                } else {
                    info!("  Configuration file exists but format is invalid");
                }
            }
            Err(e) => {
                info!("  Could not read configuration file: {}", e);
            }
        }
    } else {
        info!("No configuration file found at: {}", default_config_path.display());
        info!("Run 'zks-seeder init' to create a configuration");
    }
    
    // Check if seeder might be running (basic check - this could be enhanced)
    // In a real implementation, we might check for a PID file or use IPC
    info!("Daemon status: Unknown (status communication not implemented)");
    info!("Note: To check if seeder is running, check system processes or logs");
    
    Ok(())
}

async fn stop_seeder() -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Stopping seeder daemon...");
    info!("This feature is not yet implemented");
    Ok(())
}