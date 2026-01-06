//! Anonymous ZKS:// swarm-routed connection example
//! 
//! This example demonstrates how to establish an anonymous connection
//! through the ZKS swarm network using onion routing.

use zks_sdk::{ZksClient, ConnectionConfig, AnonymityConfig, Result};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Configure for maximum anonymity
    let mut config = ConnectionConfig::default();
    config.anonymity = AnonymityConfig::maximum();
    
    // Initialize the ZKS client with anonymity features
    let client = ZksClient::new(config)?;
    println!("🔐 Anonymous ZKS Client initialized");
    
    // Generate a new ephemeral identity for this session
    let identity = client.generate_ephemeral_identity()?;
    println!("🎭 Ephemeral identity generated: {}", identity.fingerprint());
    
    // Set up onion routing through 3 relay nodes
    // Note: These are demonstration/example relay URLs
    // In production, use configurable relay endpoints or discovery mechanisms
    let relay_nodes = vec![
        "zks://relay1.zks-protocol.org:8443",
        "zks://relay2.zks-protocol.org:8443", 
        "zks://relay3.zks-protocol.org:8443",
    ];
    
    println!("🧅 Setting up onion routing through {} relays", relay_nodes.len());
    
    // Build the anonymous path
    let path = client.build_anonymous_path(&relay_nodes).await?;
    println!("🛤️  Anonymous path established");
    
    // Connect to the target through the anonymous path
    let target = "zks://hidden-service.zks-protocol.org:8443";
    println!("🌐 Connecting anonymously to {}", target);
    
    let connection = client.connect_anonymous(target, &path).await?;
    println!("✅ Anonymous connection established!");
    
    // Verify anonymity properties
    let anonymity_info = connection.anonymity_info()?;
    println!("🔍 Anonymity verification:");
    println!("   - Path length: {} hops", anonymity_info.path_length);
    println!("   - Entry relay: {}", anonymity_info.entry_relay);
    println!("   - Exit relay: {}", anonymity_info.exit_relay);
    println!("   - Timing obfuscation: {}", anonymity_info.timing_obfuscation);
    
    // Send an anonymous message
    let message = "Hello from the shadows!";
    println!("💬 Sending anonymous message...");
    connection.send_anonymous(message.as_bytes()).await?;
    println!("📤 Message sent anonymously!");
    
    // Wait a bit to demonstrate the connection stays alive
    tokio::time::sleep(Duration::from_secs(3)).await;
    
    // Clean up - close connection and wipe ephemeral identity
    connection.close().await?;
    client.wipe_ephemeral_identity(&identity)?;
    
    println!("🧹 Anonymous session terminated and identity wiped");
    
    Ok(())
}