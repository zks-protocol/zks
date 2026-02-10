//! ZKS Echo Server - Real-world production testing
//! 
//! This server accepts ZKS protocol connections and echoes back messages,
//! allowing for comprehensive real-world testing of the protocol.

use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Instant;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// Simple statistics tracker
struct ServerStats {
    connections_total: AtomicU64,
    messages_received: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    errors: AtomicU64,
}

impl ServerStats {
    fn new() -> Self {
        Self {
            connections_total: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    fn print_stats(&self) {
        println!("\n📊 Server Statistics:");
        println!("  Connections: {}", self.connections_total.load(Ordering::Relaxed));
        println!("  Messages:    {}", self.messages_received.load(Ordering::Relaxed));
        println!("  Received:    {} bytes", self.bytes_received.load(Ordering::Relaxed));
        println!("  Sent:        {} bytes", self.bytes_sent.load(Ordering::Relaxed));
        println!("  Errors:      {}", self.errors.load(Ordering::Relaxed));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:8443".to_string());

    println!("🚀 ZKS Echo Server Starting...");
    println!("📍 Binding to: {}", bind_addr);
    
    let listener = TcpListener::bind(&bind_addr).await?;
    let stats = Arc::new(ServerStats::new());
    
    println!("✅ Server ready and listening on {}", bind_addr);
    println!("🔐 Waiting for ZKS protocol connections...\n");

    // Statistics reporter
    let stats_clone = stats.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            stats_clone.print_stats();
        }
    });

    loop {
        match listener.accept().await {
            Ok((mut socket, addr)) => {
                let conn_id = stats.connections_total.fetch_add(1, Ordering::Relaxed) + 1;
                let stats = stats.clone();
                
                println!("📥 [{}] Connection from: {}", conn_id, addr);
                
                tokio::spawn(async move {
                    let start = Instant::now();
                    let mut buffer = vec![0u8; 65536];
                    let mut msg_count = 0u64;
                    
                    loop {
                        match socket.read(&mut buffer).await {
                            Ok(0) => {
                                // Connection closed
                                let duration = start.elapsed();
                                println!(
                                    "👋 [{}] Closed after {:.2}s ({} messages)",
                                    conn_id, duration.as_secs_f64(), msg_count
                                );
                                break;
                            }
                            Ok(n) => {
                                msg_count += 1;
                                stats.messages_received.fetch_add(1, Ordering::Relaxed);
                                stats.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
                                
                                // Echo back
                                if let Err(e) = socket.write_all(&buffer[..n]).await {
                                    println!("❌ [{}] Write error: {}", conn_id, e);
                                    stats.errors.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                                
                                stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                                
                                if msg_count % 100 == 0 {
                                    println!(
                                        "📨 [{}] Echoed {} messages ({} bytes total)",
                                        conn_id, msg_count, stats.bytes_received.load(Ordering::Relaxed)
                                    );
                                }
                            }
                            Err(e) => {
                                println!("❌ [{}] Read error: {}", conn_id, e);
                                stats.errors.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => {
                println!("❌ Accept error: {}", e);
                stats.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
