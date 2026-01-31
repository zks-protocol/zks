//! Cover Traffic Example
//!
//! This example demonstrates how to generate and send cover traffic
//! through the Faisal Swarm network for traffic analysis resistance.
//!
//! Run with: cargo run --example cover_traffic

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use zks_cover::{
    CoverConfig, CoverGenerator, CoverScheduler, CoverTransport,
    CoverMessage, CoverType,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ZKS Cover Traffic Example ===\n");

    // 1. Configure cover traffic
    println!("1. Configuring cover traffic...");
    let config = CoverConfig::builder()
        .poisson_rate(2.0)           // 2 messages per second average
        .payload_size(512)            // Match ZKS fixed cell size
        .use_post_quantum(true)       // Use ML-KEM encryption
        .build()?;
    
    println!("   - Poisson rate: {} msg/sec", config.poisson_rate());
    println!("   - Payload size: {} bytes", config.payload_size());
    println!("   - Post-quantum: {}", config.use_post_quantum());

    // 2. Create cover generator
    println!("\n2. Creating cover generator...");
    let generator = Arc::new(CoverGenerator::new(config.clone())?);
    
    // 3. Generate single cover message
    println!("\n3. Generating single cover message...");
    let cover = generator.generate_cover(Some("circuit-001".to_string())).await?;
    
    println!("   - Type: {:?}", cover.cover_type);
    println!("   - Payload size: {} bytes", cover.payload.len());
    println!("   - Circuit ID: {:?}", cover.circuit_id);
    
    // 4. Generate burst of cover messages
    println!("\n4. Generating burst of cover messages (5 messages)...");
    let covers = generator.generate_covers(5, None).await?;
    
    for (i, c) in covers.iter().enumerate() {
        println!("   Cover {}: {:?}, {} bytes", i + 1, c.cover_type, c.payload.len());
    }
    
    // 5. Demonstrate cover message types
    println!("\n5. Cover message types:");
    let regular = CoverMessage::regular(vec![0u8; 512], None);
    let loop_msg = CoverMessage::loop_message(vec![0u8; 512], None);
    let drop_msg = CoverMessage::drop_message(vec![0u8; 512], None);
    
    println!("   - Regular: indistinguishable from real traffic");
    println!("   - Loop: routes back to sender (additional anonymity)");
    println!("   - Drop: intentionally dropped (confuses traffic analysis)");
    
    // 6. Demonstrate scheduler with channel
    println!("\n6. Setting up scheduled cover traffic...");
    let scheduler = CoverScheduler::new(config.clone(), generator.clone())?;
    
    let (tx, mut rx) = mpsc::channel::<CoverMessage>(100);
    
    // Start scheduler in background
    scheduler.start(tx, Some("scheduled-circuit".to_string())).await?;
    
    println!("   Scheduler started, waiting for 3 cover messages...");
    
    // Receive a few cover messages
    let mut received = 0;
    let timeout = tokio::time::timeout(Duration::from_secs(5), async {
        while received < 3 {
            if let Some(msg) = rx.recv().await {
                received += 1;
                println!("   Received scheduled cover {}: {:?}", received, msg.cover_type);
            }
        }
    }).await;
    
    match timeout {
        Ok(_) => println!("   ✅ Received {} scheduled cover messages", received),
        Err(_) => println!("   ⚠️ Timeout - scheduler may need higher rate for testing"),
    }
    
    // 7. Demonstrate FaisalSwarmCell conversion
    println!("\n7. Converting to Faisal Swarm cell...");
    let cover = generator.generate_cover(None).await?;
    
    match cover.to_faisal_swarm_cell(12345) {
        Ok(cell) => {
            println!("   - Circuit ID: {}", cell.header.circuit_id);
            println!("   - Command: {:?}", cell.header.command);
            println!("   - Payload length: {} bytes", cell.header.payload_len);
            println!("   ✅ Ready for Faisal Swarm transmission!");
        }
        Err(e) => println!("   ❌ Conversion failed: {}", e),
    }

    println!("\n=== Example Complete ===");
    println!("\nCover traffic provides:");
    println!("  • Traffic analysis resistance");
    println!("  • Indistinguishable from real traffic");
    println!("  • Poisson-distributed timing (realistic patterns)");
    println!("  • Post-quantum secure encryption (ML-KEM)");
    
    Ok(())
}
