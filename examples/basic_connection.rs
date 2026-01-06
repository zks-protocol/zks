//! Basic ZK:// connection example
//! 
//! This example demonstrates how to establish a basic ZK:// connection
//! using the ZKS Protocol SDK.

use zks_sdk::{ZksClient, ConnectionConfig, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the ZKS client with default configuration
    let client = ZksClient::new(ConnectionConfig::default())?;
    
    println!("🔐 ZKS Client initialized");
    
    // Generate a new identity for this connection
    let identity = client.generate_identity()?;
    println!("🆔 Identity generated: {}", identity.fingerprint());
    
    // Connect to a ZKS node
    let node_address = "zk://bootstrap.zks-protocol.org:8443";
    println!("🌐 Connecting to {}", node_address);
    
    let connection = client.connect(node_address).await?;
    println!("✅ Connected successfully!");
    
    // Perform a simple ping to verify the connection
    let latency = connection.ping().await?;
    println!("📊 Connection latency: {:?}", latency);
    
    // Get connection info
    let info = connection.info()?;
    println!("🔗 Connection established with peer: {}", info.peer_id);
    println!("🔒 Protocol version: {}", info.protocol_version);
    println!("🛡️  Encryption: {}", info.encryption_type);
    
    // Keep the connection alive for a moment
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    // Gracefully close the connection
    connection.close().await?;
    println!("👋 Connection closed gracefully");
    
    Ok(())
}