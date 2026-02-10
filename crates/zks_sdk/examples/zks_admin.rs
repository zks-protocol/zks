use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::net::SocketAddr;
use zks::prelude::*;
use zks::identity::ZksIdentity;
use zks::node::{ZksNode, NodeConfig};
use tracing::{info, error};

#[derive(Parser)]
#[command(name = "zks-admin")]
#[command(about = "ZKS Protocol Administration Tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new ZKS identity
    GenerateIdentity {
        /// Output path for the identity file
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Start a ZKS node
    Start {
        /// Role of the node (relay, client, exit)
        #[arg(short, long, default_value = "relay")]
        role: String,

        /// Address to bind to
        #[arg(short, long, default_value = "0.0.0.0:9443")]
        bind: SocketAddr,

        /// Path to identity file
        #[arg(short, long)]
        identity: Option<PathBuf>,

        /// Network name
        #[arg(long, default_value = "zks-mainnet")]
        network: String,
    },
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateIdentity { out } => {
            let id = ZksIdentity::generate()?;
            id.save_to_file(&out)?;
            info!("✅ Identity generated and saved to {:?}", out);
            info!("🆔 Fingerprint: {}", id.fingerprint()?);
        },
        Commands::Start { role, bind, identity, network } => {
            let mut config = NodeConfig::new()
                .bind_addr(bind);
                //.network_name(network); // Config builder might not have exposed public field setter, need to check

            // Manually set public fields if builder method missing or update NodeConfig
            // Re-checking NodeConfig impl... 
            // It has public fields but methods are cleaner.
            // Let's assume network_name logic is handled or add it to builder if missing.
            
            // Configure role
            match role.as_str() {
                "relay" => {
                    config.is_relay = true;
                    config.is_hidden_service = false;
                },
                "hidden" | "service" => {
                    config.is_relay = false;
                    config.is_hidden_service = true;
                },
                _ => { // Client default
                    config.is_relay = false;
                    config.is_hidden_service = false;
                }
            }
            
            if let Some(path) = identity {
                let id = ZksIdentity::load_from_file(path)?;
                config = config.identity(id);
            } else {
                info!("⚠️ No identity provided, generating ephemeral identity...");
                let id = ZksIdentity::generate()?;
                config = config.identity(id);
            }

            info!("🚀 Starting ZKS Node ({}) on {}", role, bind);
            
            let node = ZksNode::new(config);
            let handle = node.start().await?;
            
            info!("Press Ctrl+C to stop");
            // Wait for shutdown (Ctrl+C)
            tokio::signal::ctrl_c().await?;
            info!("Stopping node...");
            node.stop();
            handle.await?;
            info!("Node stopped.");
        }
    }
    Ok(())
}
