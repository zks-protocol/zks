use std::time::Duration;
use tokio::time::timeout;
use zks_wire::{stun::StunClient, nat::NatTraversal};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Testing STUN/NAT Implementation ===\n");
    
    // Test 1: Basic STUN client functionality
    println!("1. Testing STUN client with Google STUN servers...");
    let stun_servers = vec![
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun2.l.google.com:19302",
        "stun3.l.google.com:19302",
        "stun4.l.google.com:19302",
    ];
    
    for server in &stun_servers {
        println!("   Testing {}...", server);
        match timeout(Duration::from_secs(5), test_stun_server(server)).await {
            Ok(Ok(addr)) => println!("   ✓ Success: Public address: {}", addr),
            Ok(Err(e)) => println!("   ✗ Failed: {}", e),
            Err(_) => println!("   ✗ Timeout after 5 seconds"),
        }
    }
    
    // Test 2: NAT type detection
    println!("\n2. Testing NAT type detection...");
    let mut nat = NatTraversal::new();
    match timeout(Duration::from_secs(15), nat.discover_nat_type()).await {
        Ok(Ok(nat_type)) => {
            println!("   ✓ Detected NAT type: {:?}", nat_type);
        },
        Ok(Err(e)) => println!("   ✗ NAT detection failed: {}", e),
        Err(_) => println!("   ✗ NAT detection timeout after 15 seconds"),
    }
    
    // Test 3: Multiple STUN server reliability
    println!("\n3. Testing multi-server reliability...");
    let test_servers = vec![
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun.services.mozilla.com:3478",
        "stun.stunprotocol.org:3478",
    ];
    
    let mut successful_queries = 0;
    for server in &test_servers {
        match timeout(Duration::from_secs(3), test_stun_server(server)).await {
            Ok(Ok(addr)) => {
                println!("   ✓ {} -> {}", server, addr);
                successful_queries += 1;
            },
            _ => println!("   ✗ {} (failed/timeout)", server),
        }
    }
    
    println!("\n=== Results Summary ===");
    println!("STUN servers tested: {}", stun_servers.len());
    println!("Multi-server reliability: {}/{}", successful_queries, test_servers.len());
    
    Ok(())
}

async fn test_stun_server(server_addr: &str) -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    let mut client = StunClient::new(server_addr).await;
    client.discover().await.map_err(|e| e.into())
}