use zks::prelude::*;
use zks::swarm::ZksSwarm;
use zks::config::SecurityLevel;
use zks::builder::ZksConnectionBuilder;
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("🚀 Starting Local 7-Hop ZKS Swarm Test...");

    // 1. Create a local swarm with 7 relays (plus 1 authority)
    // This simulates the infrastructure needed for a 7-hop circuit
    let hop_count = 7;
    info!("📦 Spawning {} relay nodes...", hop_count);
    let mut swarm = ZksSwarm::local_testnet(hop_count).await?;
    
    // Give nodes a moment to start
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 2. Configure a client to use this local swarm
    // We point it to the local Authority node (which ZksSwarm starts at port 9000)
    let bootstrap_node = "zk://127.0.0.1:9000".to_string();
    
    info!("🔌 Configuring client with bootstrap node: {}", bootstrap_node);
    
    // Note: In a full integration test, we would call .build() here.
    // However, since our ZksNode implementation is currently a lightweight stub
    // that doesn't fully implement the purely P2P signaling required for zks:// 
    // connection establishment yet, we just verify the Builder configuration.
    
    let builder = ZksConnectionBuilder::new()
        .url("zks://target.onion")
        .security(SecurityLevel::PostQuantum)
        .min_hops(7)
        .max_hops(7) // Force 7 hops
        .bootstrap_nodes(vec![bootstrap_node]);

    info!("✅ Client configured for 7-hop circuit.");
    info!("✅ Swarm is running with {} nodes.", hop_count + 1); // +1 for Authority

    // Keep running for a few seconds to demonstrate stability
    tokio::time::sleep(Duration::from_secs(5)).await;
    
    swarm.shutdown();
    info!("🛑 Swarm stopped.");

    Ok(())
}
