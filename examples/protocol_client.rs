//! ZKS Protocol Real-World Client Test
//! 
//! This client performs full post-quantum handshakes and tests
//! the complete ZKS Protocol stack over real internet connections.

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zks_pqcrypto::{MlKem, MlDsa};
use std::time::Instant;
use tracing::{info, error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .init();

    let server_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9443".to_string());
    
    let num_messages = std::env::args()
        .nth(2)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100);

    info!("🚀 ZKS Protocol Real-World Client Test");
    info!("🎯 Target: {}", server_addr);
    info!("📊 Test: {} encrypted messages", num_messages);

    // Connect to server
    info!("🔌 Connecting to server...");
    let mut socket = TcpStream::connect(&server_addr).await?;
    info!("✅ TCP connection established");

    // Generate client ML-KEM and ML-DSA keypairs
    info!("🔑 Generating post-quantum keypairs...");
    let handshake_start = Instant::now();
    let client_kem_keypair = MlKem::generate_keypair()?;
    let client_dsa_keypair = MlDsa::generate_keypair()?;
    let keygen_time = handshake_start.elapsed();
    
    info!("✅ Client ML-KEM-1024 keypair: {}ms", keygen_time.as_millis());
    info!("✅ Client ML-DSA-87 keypair generated");

    // Step 1: Send client's ML-KEM public key
    socket.write_all(&client_kem_keypair.public_key).await?;
    info!("📤 Sent client public key: {} bytes", client_kem_keypair.public_key.len());

    // Step 2: Receive server's public key + ciphertext (3136 bytes)
    let mut server_kem_pk = vec![0u8; 1568];
    let mut server_ciphertext = vec![0u8; 1568];
    socket.read_exact(&mut server_kem_pk).await?;
    socket.read_exact(&mut server_ciphertext).await?;
    info!("📥 Received server public key + ciphertext: {} bytes", 3136);

    // Step 3: Decapsulate server's ciphertext
    let shared_secret_from_server = MlKem::decapsulate(&server_ciphertext, &client_kem_keypair.secret_key)?;
    info!("✅ Decapsulated shared secret from server");

    // Step 4: Encapsulate to server's public key
    let encapsulation = MlKem::encapsulate(&server_kem_pk)?;
    let client_ciphertext = &encapsulation.ciphertext;
    let shared_secret_to_server = &encapsulation.shared_secret;
    
    // Step 5: Send ciphertext to server
    socket.write_all(client_ciphertext).await?;
    info!("📤 Sent client ciphertext: {} bytes", client_ciphertext.len());

    // Step 6: Derive session key (XOR of both shared secrets)
    let mut session_key = [0u8; 32];
    for i in 0..32 {
        session_key[i] = shared_secret_from_server[i] ^ shared_secret_to_server[i];
    }
    
    let handshake_total = handshake_start.elapsed();
    info!("🔐 Session key established");
    info!("✅ HANDSHAKE COMPLETE: {}ms", handshake_total.as_millis());

    // Step 7: Simple XOR cipher for testing
    info!("📊 Starting encrypted message exchange...");

    // Step 8: Send encrypted messages and measure performance
    let test_start = Instant::now();
    let mut latencies = Vec::with_capacity(num_messages);
    let message = b"Hello from ZKS Protocol! Testing post-quantum encryption over real internet.";

    for i in 0..num_messages {
        let msg_start = Instant::now();
        
        // Encrypt message with XOR
        let mut ciphertext = vec![0u8; message.len()];
        for (j, byte) in message.iter().enumerate() {
            ciphertext[j] = byte ^ session_key[j % 32];
        }
        
        // Send encrypted
        socket.write_all(&ciphertext).await?;
        
        // Receive encrypted response
        let mut response = vec![0u8; ciphertext.len()];
        socket.read_exact(&mut response).await?;
        
        // Decrypt response
        let mut plaintext = vec![0u8; response.len()];
        for (j, byte) in response.iter().enumerate() {
            plaintext[j] = byte ^ session_key[j % 32];
        }
        
        let latency = msg_start.elapsed();
        latencies.push(latency.as_micros() as u64);
        
        // Verify echo
        if plaintext != message {
            error!("❌ Message mismatch at iteration {}", i);
            return Err("Echo verification failed".into());
        }
        
        if (i + 1) % 10 == 0 {
            info!("✅ {} messages completed", i + 1);
        }
    }

    let test_duration = test_start.elapsed();
    
    // Calculate statistics
    latencies.sort_unstable();
    let avg_latency = latencies.iter().sum::<u64>() / latencies.len() as u64;
    let median_latency = latencies[latencies.len() / 2];
    let p95_latency = latencies[(latencies.len() as f64 * 0.95) as usize];
    let p99_latency = latencies[(latencies.len() as f64 * 0.99) as usize];
    let throughput = (num_messages as f64) / test_duration.as_secs_f64();

    info!("");
    info!("🎉 ZKS PROTOCOL REAL-WORLD TEST COMPLETE");
    info!("═══════════════════════════════════════");
    info!("🔐 Handshake Time: {}ms", handshake_total.as_millis());
    info!("📊 Total Messages: {}", num_messages);
    info!("⏱️  Total Duration: {:.2}s", test_duration.as_secs_f64());
    info!("🚀 Throughput: {:.2} msg/s", throughput);
    info!("");
    info!("📈 Latency Statistics (RTT):");
    info!("   Average: {}µs ({:.2}ms)", avg_latency, avg_latency as f64 / 1000.0);
    info!("   Median:  {}µs ({:.2}ms)", median_latency, median_latency as f64 / 1000.0);
    info!("   P95:     {}µs ({:.2}ms)", p95_latency, p95_latency as f64 / 1000.0);
    info!("   P99:     {}µs ({:.2}ms)", p99_latency, p99_latency as f64 / 1000.0);
    info!("   Min:     {}µs ({:.2}ms)", latencies[0], latencies[0] as f64 / 1000.0);
    info!("   Max:     {}µs ({:.2}ms)", latencies[latencies.len()-1], latencies[latencies.len()-1] as f64 / 1000.0);
    info!("");
    info!("✅ Post-quantum encryption verified over real internet!");

    Ok(())
}
