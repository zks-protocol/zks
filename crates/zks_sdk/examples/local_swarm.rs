use std::time::Duration;
use tracing::info;
use zks::config::SecurityLevel;
use zks::prelude::*;
use zks::swarm::ZksSwarm;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("🚀 Starting Local ZKS Swarm Test...");

    // 1. Create a local swarm with 3 relays
    let mut swarm = ZksSwarm::local_testnet(3).await?;

    // Give nodes a moment to start
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 2. Create a client and connect to the swarm
    // (In a real implementation, the client would use the swarm's info to build a circuit)
    // For now, we just verify the swarm started

    info!("✅ Swarm is running. Press Ctrl+C to stop.");

    // Keep running for 10 seconds then exit
    tokio::time::sleep(Duration::from_secs(10)).await;

    swarm.shutdown();
    info!("🛑 Swarm stopped.");

    Ok(())
}
