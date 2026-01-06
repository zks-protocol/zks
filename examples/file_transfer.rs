//! Encrypted file transfer example
//! 
//! This example demonstrates how to transfer files securely using
//! ZKS Protocol's post-quantum encryption and swarm networking.

use zks_sdk::{ZksClient, ConnectionConfig, FileTransferConfig, Result};
use std::path::Path;
use tokio::fs;

#[tokio::main]
async fn main() -> Result<()> {
    // Configure for secure file transfer
    let config = ConnectionConfig::default();
    let client = ZksClient::new(config)?;
    
    println!("🔐 ZKS File Transfer Client initialized");
    
    // Generate sender and receiver identities
    let sender_identity = client.generate_identity()?;
    let receiver_identity = client.generate_identity()?;
    
    println!("📤 Sender identity: {}", sender_identity.fingerprint());
    println!("📥 Receiver identity: {}", receiver_identity.fingerprint());
    
    // Create a sample file to transfer
    let test_file = "test_document.txt";
    let file_content = "This is a confidential document that needs secure transfer.\n";
    fs::write(test_file, file_content).await?;
    println!("📝 Created test file: {}", test_file);
    
    // Set up file transfer configuration
    let transfer_config = FileTransferConfig {
        chunk_size: 64 * 1024, // 64KB chunks
        compression: true,
        integrity_check: true,
        post_quantum_encryption: true,
    };
    
    // Connect to receiver through ZKS network
    let receiver_address = "zks://receiver.zks-protocol.org:8443";
    println!("🌐 Connecting to receiver at {}", receiver_address);
    
    let connection = client.connect(receiver_address).await?;
    println!("✅ Connection established with receiver");
    
    // Store config values before moving
    let chunk_size = transfer_config.chunk_size;
    let compression = transfer_config.compression;
    let integrity_check = transfer_config.integrity_check;
    let post_quantum = transfer_config.post_quantum_encryption;
    
    // Initialize secure file transfer
    let mut file_transfer = connection.initiate_file_transfer(
        &sender_identity,
        &receiver_identity,
        transfer_config,
    ).await?;
    
    println!("🔒 Secure file transfer initialized");
    println!("   - Post-quantum encryption: {}", post_quantum);
    println!("   - Chunk size: {} bytes", chunk_size);
    println!("   - Compression: {}", compression);
    println!("   - Integrity check: {}", integrity_check);
    
    // Transfer the file
    let file_path = Path::new(test_file);
    println!("📤 Starting file transfer...");
    
    let transfer_result = file_transfer.send_file(file_path).await?;
    
    println!("✅ File transfer completed!");
    println!("   - File name: {}", test_file);
    println!("   - Original size: {} bytes", transfer_result.original_size);
    println!("   - Encrypted size: {} bytes", transfer_result.encrypted_size);
    println!("   - Transfer time: {:?}", transfer_result.duration);
    println!("   - Integrity hash: {}", transfer_result.integrity_hash);
    
    // Verify the transfer was successful
    if transfer_result.verified {
        println!("🔍 Transfer integrity verified ✓");
    } else {
        println!("⚠️  Transfer integrity check failed!");
    }
    
    // Clean up test file
    fs::remove_file(test_file).await?;
    println!("🧹 Cleaned up test file");
    
    // Close connection
    connection.close().await?;
    println!("👋 Connection closed");
    
    Ok(())
}