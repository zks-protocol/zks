mod protocol;

use protocol::{ZksProtocolServer, ZksProtocolClient};
use tracing::{info, error};
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .init();
    
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage:");
        println!("  server <bind_addr>");
        println!("  client <server_addr> [--key <base64_pubkey>] [--benchmark]");
        return Ok(());
    }

    let mode = &args[1];
    
    if mode == "server" {
        let bind_addr = args.get(2).cloned().unwrap_or_else(|| "0.0.0.0:9443".to_string());
        run_server(&bind_addr).await
    } else if mode == "client" {
        let addr = args.get(2).cloned().unwrap_or_else(|| "127.0.0.1:9443".to_string());
        
        let mut trusted_key = None;
        let mut benchmark = false;
        
        let mut i = 3;
        while i < args.len() {
            if args[i] == "--key" && i + 1 < args.len() {
                let key_b64 = &args[i+1];
                let key_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key_b64)?;
                trusted_key = Some(key_bytes);
                i += 2;
            } else if args[i] == "--benchmark" {
                benchmark = true;
                i += 1;
            } else {
                i += 1;
            }
        }
        
        if benchmark {
            run_benchmark(&addr, trusted_key).await
        } else {
            run_client(&addr, trusted_key).await
        }
    } else {
        error!("Invalid mode: {}. Use 'server' or 'client'.", mode);
        Ok(())
    }
}

async fn run_server(bind_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    info!("════════════════════════════════════════════════════════");
    info!("  🚀 ZKS PROTOCOL - REAL-WORLD SERVER");
    info!("════════════════════════════════════════════════════════");
    
    let mut server = ZksProtocolServer::bind(bind_addr).await?;

    loop {
        match server.accept().await {
            Ok(mut conn) => {
                info!("✅ Connection accepted from {}", conn.peer_addr());
                tokio::spawn(async move {
                    loop {
                        match conn.recv().await {
                            Ok(data) => {
                                if let Err(e) = conn.send(&data).await {
                                    info!("❌ Echo error: {}", e);
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
            Err(e) => {
                info!("❌ Accept failed: {}", e);
            }
        }
    }
}

async fn run_client(addr: &str, trusted_key: Option<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>> {
    info!("════════════════════════════════════════════════════════");
    info!("  🔌 ZKS PROTOCOL - CLIENT TEST");
    info!("════════════════════════════════════════════════════════");
    
    let mut conn = ZksProtocolClient::connect(addr, trusted_key).await?;
    
    // Run standard tests
    let test_msgs = vec![
        b"Small message".to_vec(),
        vec![0xAA; 1024], // 1KB
        (0..255).collect::<Vec<u8>>(), // Binary
    ];

    for (i, msg) in test_msgs.iter().enumerate() {
        conn.send(msg).await?;
        let echo = conn.recv().await?;
        assert_eq!(msg, &echo);
        info!("✅ Test {} PASSED ({} bytes)", i + 1, msg.len());
    }

    conn.close().await?;
    info!("🎉 ALL TESTS PASSED!");
    Ok(())
}

async fn run_benchmark(addr: &str, trusted_key: Option<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>> {
    info!("════════════════════════════════════════════════════════");
    info!("  📊 ZKS PROTOCOL - PERFORMANCE BENCHMARK");
    info!("════════════════════════════════════════════════════════");
    info!("Target: {}", addr);
    
    // 1. Handshake Latency
    let start = Instant::now();
    let mut conn = ZksProtocolClient::connect(addr, trusted_key).await?;
    let handshake_duration = start.elapsed();
    info!("⏱️  Handshake Latency: {:?}", handshake_duration);
    
    // 2. RTT / Latency (Ping-Pong)
    let mut latencies = Vec::new();
    let ping_msg = b"ping";
    for _ in 0..10 {
        let start = Instant::now();
        conn.send(ping_msg).await?;
        let _ = conn.recv().await?;
        latencies.push(start.elapsed());
    }
    let avg_rtt = latencies.iter().sum::<std::time::Duration>() / 10;
    info!("⏱️  Average RTT (10 iterations): {:?}", avg_rtt);
    
    // 3. Throughput Test
    info!("📥 Measuring throughput (sending 5MB payload)...");
    let payload_size = 5 * 1024 * 1024;
    let payload = vec![0x42u8; payload_size];
    
    let start = Instant::now();
    conn.send(&payload).await?;
    let _ = conn.recv().await?; // Wait for echo
    let duration = start.elapsed();
    
    // Throughput calculation: (size * 2) / duration since it's a round trip
    let total_bytes = payload_size * 2;
    let mb_per_sec = (total_bytes as f64 / 1024.0 / 1024.0) / duration.as_secs_f64();
    
    info!("🚀 Throughput: {:.2} MB/s (RTT included)", mb_per_sec);
    info!("⏱️  Total time for 5MB round-trip: {:?}", duration);
    
    conn.close().await?;
    info!("✅ Benchmark complete");
    
    Ok(())
}
