mod protocol;

use protocol::{ZksProtocolClient, ZksProtocolServer};
use std::time::Instant;
use tracing::{error, info, warn};

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
        println!("  client <server_addr> [--key <base64_pubkey>] [--keyfile <path>] [--benchmark]");
        return Ok(());
    }

    let mode = &args[1];

    if mode == "server" {
        let bind_addr = args
            .get(2)
            .cloned()
            .unwrap_or_else(|| "0.0.0.0:9443".to_string());
        run_server(&bind_addr).await
    } else if mode == "client" {
        let addr = args
            .get(2)
            .cloned()
            .unwrap_or_else(|| "127.0.0.1:9443".to_string());

        let mut trusted_key = None;
        let mut benchmark = false;

        let mut i = 3;
        while i < args.len() {
            if args[i] == "--key" && i + 1 < args.len() {
                let key_b64 = &args[i + 1];
                let key_bytes =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key_b64)?;
                trusted_key = Some(key_bytes);
                i += 2;
            } else if args[i] == "--keyfile" && i + 1 < args.len() {
                let content = std::fs::read_to_string(&args[i + 1])?;
                // Robust cleanup: remove BOM, whitespace and newlines
                let content_no_bom = content.trim_start_matches('\u{feff}');
                let key_b64: String = content_no_bom.chars().filter(|c| !c.is_whitespace()).collect();
                
                info!("Key string length (raw): {}", key_b64.len());
                if key_b64.len() > 3456 {
                    warn!("Key too long, truncating to 3456 chars");
                }
                let key_b64: String = key_b64.chars().take(3456).collect();
                
                info!("Key string length (truncated): {}", key_b64.len());

                let key_bytes =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &key_b64)?;
                info!("🔑 Loaded trusted key from file: {} ({} bytes)", &args[i + 1], key_bytes.len());
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

async fn run_client(
    addr: &str,
    trusted_key: Option<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("════════════════════════════════════════════════════════");
    info!("  🔌 ZKS PROTOCOL - CLIENT TEST");
    info!("════════════════════════════════════════════════════════");

    let mut conn = ZksProtocolClient::connect(addr, trusted_key).await?;

    // Run standard tests
    let test_msgs = vec![
        b"Small message".to_vec(),
        vec![0xAA; 1024],              // 1KB
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

async fn run_benchmark(
    addr: &str,
    trusted_key: Option<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
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

    // 3. Throughput Test — send many small chunks to avoid TCP deadlock
    let chunk_size = 4096;
    let num_chunks = 256; // 256 × 4KB = 1MB total
    let total_payload = chunk_size * num_chunks;
    info!(
        "📥 Measuring throughput ({} × {}B = {}KB total)...",
        num_chunks,
        chunk_size,
        total_payload / 1024
    );
    let chunk = vec![0x42u8; chunk_size];

    let start = Instant::now();
    for _ in 0..num_chunks {
        conn.send(&chunk).await?;
        let _ = conn.recv().await?; // Wait for echo of each chunk
    }
    let duration = start.elapsed();

    // Throughput: total bytes transferred (send + recv) / time
    let total_bytes = total_payload * 2; // round-trip
    let mb_per_sec = (total_bytes as f64 / 1024.0 / 1024.0) / duration.as_secs_f64();

    info!("🚀 Throughput: {:.2} MB/s (send+recv, {} chunks)", mb_per_sec, num_chunks);
    info!("⏱️  Total time for {}KB round-trip: {:?}", total_payload / 1024, duration);

    conn.close().await?;
    info!("✅ Benchmark complete");

    Ok(())
}
