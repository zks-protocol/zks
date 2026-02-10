//! ZKS Protocol Stress Test Client
//! 
//! Tests ZKS protocol under load to reveal any flaws or performance issues

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};

struct TestStats {
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    errors: AtomicU64,
    latencies_us: Arc<tokio::sync::Mutex<Vec<u64>>>,
}

impl TestStats {
    fn new() -> Self {
        Self {
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            latencies_us: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    async fn print_report(&self) {
        let latencies = self.latencies_us.lock().await;
        let mut sorted = latencies.clone();
        sorted.sort_unstable();

        println!("\n📊 === TEST RESULTS ===");
        println!("Messages sent:     {}", self.messages_sent.load(Ordering::Relaxed));
        println!("Messages received: {}", self.messages_received.load(Ordering::Relaxed));
        println!("Bytes sent:        {}", self.bytes_sent.load(Ordering::Relaxed));
        println!("Bytes received:    {}", self.bytes_received.load(Ordering::Relaxed));
        println!("Errors:            {}", self.errors.load(Ordering::Relaxed));
        
        if !sorted.is_empty() {
            let p50 = sorted[sorted.len() / 2];
            let p95 = sorted[sorted.len() * 95 / 100];
            let p99 = sorted[sorted.len() * 99 / 100];
            let avg: u64 = sorted.iter().sum::<u64>() / sorted.len() as u64;
            
            println!("\n⏱️  Latency:");
            println!("  Average: {}µs ({:.2}ms)", avg, avg as f64 / 1000.0);
            println!("  P50:     {}µs ({:.2}ms)", p50, p50 as f64 / 1000.0);
            println!("  P95:     {}µs ({:.2}ms)", p95, p95 as f64 / 1000.0);
            println!("  P99:     {}µs ({:.2}ms)", p99, p99 as f64 / 1000.0);
        }
    }
}

async fn test_connection(
    server_addr: &str,
    msg_count: usize,
    msg_size: usize,
    stats: Arc<TestStats>,
    conn_id: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[{}] Connecting to {}...", conn_id, server_addr);
    
    let mut stream = TcpStream::connect(server_addr).await?;
    println!("[{}] ✅ Connected", conn_id);

    let message = vec![0x41u8; msg_size]; // 'A' repeated
    let mut buffer = vec![0u8; msg_size * 2];

    for i in 0..msg_count {
        let start = Instant::now();
        
        // Send message
        stream.write_all(&message).await?;
        stats.messages_sent.fetch_add(1, Ordering::Relaxed);
        stats.bytes_sent.fetch_add(msg_size as u64, Ordering::Relaxed);
        
        // Receive echo
        let n = stream.read(&mut buffer).await?;
        let latency = start.elapsed().as_micros() as u64;
        
        if n != msg_size {
            println!("[{}] ⚠️  Size mismatch: sent {}, got {}", conn_id, msg_size, n);
            stats.errors.fetch_add(1, Ordering::Relaxed);
        }
        
        stats.messages_received.fetch_add(1, Ordering::Relaxed);
        stats.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
        stats.latencies_us.lock().await.push(latency);
        
        if (i + 1) % 100 == 0 {
            println!(
                "[{}] Sent {} messages (latency: {}µs)",
                conn_id, i + 1, latency
            );
        }
    }

    println!("[{}] ✅ Test complete", conn_id);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <server_addr> [connections] [messages_per_conn] [message_size]", args[0]);
        eprintln!("Example: {} 178.128.24.90:8443 10 1000 256", args[0]);
        std::process::exit(1);
    }

    let server_addr = &args[1];
    let num_connections: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);
    let messages_per_conn: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let message_size: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(256);

    println!("🧪 ZKS Protocol Stress Test");
    println!("============================");
    println!("Server:       {}", server_addr);
    println!("Connections:  {}", num_connections);
    println!("Messages:     {} per connection", messages_per_conn);
    println!("Message size: {} bytes", message_size);
    println!("Total data:   {} MB\n", 
        (num_connections * messages_per_conn * message_size * 2) / 1024 / 1024);

    let stats = Arc::new(TestStats::new());
    let start = Instant::now();

    // Spawn concurrent connections
    let mut handles = Vec::new();
    for i in 0..num_connections {
        let addr = server_addr.to_string();
        let stats_clone = stats.clone();
        
        let handle = tokio::spawn(async move {
            if let Err(e) = test_connection(&addr, messages_per_conn, message_size, stats_clone.clone(), i).await {
                println!("[{}] ❌ Error: {}", i, e);
                stats_clone.errors.fetch_add(1, Ordering::Relaxed);
            }
        });
        
        handles.push(handle);
        tokio::time::sleep(Duration::from_millis(100)).await; // Stagger connections
    }

    // Wait for all connections to complete
    for handle in handles {
        handle.await?;
    }

    let duration = start.elapsed();
    stats.print_report().await;
    
    println!("\n⏰ Total time: {:.2}s", duration.as_secs_f64());
    println!("📈 Throughput: {:.2} msg/s", 
        stats.messages_received.load(Ordering::Relaxed) as f64 / duration.as_secs_f64());
    
    Ok(())
}
