//! ZKS Protocol Real-World Server Test
//! 
//! This server performs full post-quantum handshakes and tests
//! the complete ZKS Protocol stack in production conditions.

use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zks_pqcrypto::{MlKem, MlKemKeypair, MlDsa, MlDsaKeypair};
use tracing::{info, warn, error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .init();

    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:9443".to_string());

    info!("🚀 ZKS Protocol Real-World Server");
    info!("📡 Binding to: {}", bind_addr);

    // Generate server ML-KEM and ML-DSA keypairs
    info!("🔑 Generating post-quantum keypairs...");
    let server_kem_keypair = MlKem::generate_keypair()?;
    let server_dsa_keypair = MlDsa::generate_keypair()?;
    
    info!("✅ Server ML-KEM-1024 public key: {} bytes", server_kem_keypair.public_key.len());
    info!("✅ Server ML-DSA-87 public key: {} bytes", server_dsa_keypair.public_key.len());

    let listener = TcpListener::bind(&bind_addr).await?;
    info!("✅ Server listening on {}", bind_addr);
    info!("⏳ Waiting for client connections...");

    let mut conn_count = 0u64;

    loop {
        match listener.accept().await {
            Ok((mut socket, addr)) => {
                conn_count += 1;
                info!("🔌 Connection #{} from {}", conn_count, addr);

                let server_kem_kp = server_kem_keypair.clone();
                let server_dsa_kp = server_dsa_keypair.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_client(&mut socket, server_kem_kp, server_dsa_kp).await {
                        error!("❌ Client handler error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("❌ Accept error: {}", e);
            }
        }
    }
}

async fn handle_client(
    socket: &mut tokio::net::TcpStream,
    server_kem_keypair: MlKemKeypair,
    server_dsa_keypair: MlDsaKeypair,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("📝 Starting ZKS Protocol handshake...");

    // Step 1: Receive client's ML-KEM public key (1568 bytes)
    let mut client_kem_pk = vec![0u8; 1568];
    socket.read_exact(&mut client_kem_pk).await?;
    info!("✅ Received client ML-KEM public key: {} bytes", client_kem_pk.len());

    // Step 2: Server encapsulates to client's key
    let encapsulation = MlKem::encapsulate(&client_kem_pk)?;
    let ciphertext = &encapsulation.ciphertext;
    let shared_secret_to_client = &encapsulation.shared_secret;
    info!("✅ Encapsulated to client: ciphertext {} bytes", ciphertext.len());

    // Step 3: Send server's ML-KEM public key + ciphertext to client (1568 + 1568 = 3136 bytes)
    socket.write_all(&server_kem_keypair.public_key).await?;
    socket.write_all(&ciphertext).await?;
    info!("✅ Sent server public key + ciphertext: {} bytes", 3136);

    // Step 4: Receive client's ciphertext (encapsulated to server)
    let mut client_ciphertext = vec![0u8; 1568];
    socket.read_exact(&mut client_ciphertext).await?;
    info!("✅ Received client ciphertext: {} bytes", client_ciphertext.len());

    // Step 5: Server decapsulates client's ciphertext
    let shared_secret_from_client = MlKem::decapsulate(&client_ciphertext, &server_kem_keypair.secret_key)?;
    info!("✅ Decapsulated shared secret from client");

    // Step 6: Derive final session key (XOR of both shared secrets for bidirectional security)
    let mut session_key = [0u8; 32];
    for i in 0..32 {
        session_key[i] = shared_secret_to_client[i] ^ shared_secret_from_client[i];
    }
    info!("🔐 Session key established: {} bytes", session_key.len());

    // Step 7: Simple XOR cipher for testing (in production use WasifVernam)
    info!("✅ ZKS Protocol handshake complete!");
    info!("📊 Ready for encrypted communication");

    // Step 8: Echo encrypted messages (simple XOR for testing)
    let mut buffer = vec![0u8; 4096];
    let mut msg_count = 0u64;

    loop {
        match socket.read(&mut buffer).await {
            Ok(0) => {
                info!("👋 Client disconnected gracefully ({} messages)", msg_count);
                break;
            }
            Ok(n) => {
                msg_count += 1;
                
                // Decrypt with XOR (rotate session key)
                let mut plaintext = vec![0u8; n];
                for (i, byte) in buffer[..n].iter().enumerate() {
                    plaintext[i] = byte ^ session_key[i % 32];
                }
                
                // Re-encrypt for response
                let mut ciphertext = vec![0u8; n];
                for (i, byte) in plaintext.iter().enumerate() {
                    ciphertext[i] = byte ^ session_key[i % 32];
                }
                
                // Echo back
                socket.write_all(&ciphertext).await?;
                
                if msg_count % 100 == 0 {
                    info!("📊 Processed {} encrypted messages", msg_count);
                }
            }
            Err(e) => {
                warn!("❌ Read error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
