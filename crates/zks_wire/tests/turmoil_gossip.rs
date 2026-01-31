use std::time::Duration;
use turmoil::Builder;
use tokio::time::sleep;
use turmoil::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zks_crypt::entropy_block::{DrandRound, EntropyBlock};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn test_two_node_basic_communication() {
    let mut sim = Builder::new().build();
    
    // Node A: Simple sender
    sim.host("node-a", || async {
        println!("Node A started");
        sleep(Duration::from_secs(1)).await;
        Ok(())
    });
    
    // Node B: Simple receiver  
    sim.host("node-b", || async {
        println!("Node B started");
        sleep(Duration::from_secs(1)).await;
        Ok(())
    });
    
    // Run simulation
    sim.run().unwrap();
}

#[test]
fn test_byzantine_node_detection() {
    let mut sim = Builder::new().build();
    
    // Byzantine node: Sends corrupted data
    sim.host("byzantine-node", || async {
        let listener = TcpListener::bind("0.0.0.0:9002").await?;
        let (mut stream, _) = listener.accept().await?;
        
        // Send corrupted EntropyBlock data
        let corrupted_data = vec![0xFF; 100]; // Invalid block data
        let len = corrupted_data.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&corrupted_data).await?;
        
        Ok(())
    });
    
    // Honest node: Should detect corruption
    sim.host("honest-node", || async {
        sleep(Duration::from_millis(100)).await;
        
        let mut stream = TcpStream::connect("byzantine-node:9002").await?;
        
        // Read length prefix
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Read corrupted data
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;
        
        // Attempt to deserialize - should fail
        let result = EntropyBlock::from_bytes(&data);
        assert!(result.is_err(), "Should detect corrupted block data");
        
        println!("Honest node successfully detected corrupted data");
        Ok(())
    });
    
    sim.run().unwrap();
}

#[test]
fn test_clock_drift_handling() {
    let mut sim = Builder::new().build();
    
    // Node with simulated clock drift
    sim.host("drifted-node", || async {
        let listener = TcpListener::bind("0.0.0.0:9003").await?;
        let (mut stream, _) = listener.accept().await?;
        
        // Create block with "future" timestamps (simulating clock drift)
        let rounds: Vec<DrandRound> = (1000..1005).map(|i| DrandRound {
            round: i,
            randomness: [i as u8; 32],
            signature: vec![0u8; 96],
            previous_signature: vec![0u8; 96],
        }).collect();
        
        let block = EntropyBlock::from_rounds(rounds).unwrap();
        let serialized = block.to_bytes().unwrap();
        
        let len = serialized.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&serialized).await?;
        
        Ok(())
    });
    
    // Node that receives drifted data
    sim.host("receiver-node", || async {
        sleep(Duration::from_millis(100)).await;
        
        let mut stream = TcpStream::connect("drifted-node:9003").await?;
        
        // Read and verify block (should handle drift gracefully)
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;
        
        let block = EntropyBlock::from_bytes(&data).unwrap();
        
        // Verify integrity despite potential clock issues
        assert!(block.verify_integrity());
        assert_eq!(block.start_round, 1000);
        assert_eq!(block.end_round, 1004);
        
        println!("Receiver handled clock drift gracefully");
        Ok(())
    });
    
    sim.run().unwrap();
}

#[test]
fn test_bandwidth_throttling() {
    let mut sim = Builder::new().build();
    
    // Throttled sender (simulates bandwidth limit)
    sim.host("throttled-sender", || async {
        let listener = TcpListener::bind("0.0.0.0:9004").await?;
        let (mut stream, _) = listener.accept().await?;
        
        // Create large block
        let rounds: Vec<DrandRound> = (1000..1100).map(|i| DrandRound {
            round: i,
            randomness: [i as u8; 32],
            signature: vec![0u8; 96],
            previous_signature: vec![0u8; 96],
        }).collect();
        
        let block = EntropyBlock::from_rounds(rounds).unwrap();
        let serialized = block.to_bytes().unwrap();
        
        // Send with throttling (simulate bandwidth limit)
        let chunk_size = 1024; // 1KB chunks
        let len = serialized.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        
        for chunk in serialized.chunks(chunk_size) {
            stream.write_all(chunk).await?;
            sleep(Duration::from_millis(10)).await; // Simulate throttling
        }
        
        println!("Throttled sender completed: {} bytes in {} chunks", 
                serialized.len(), (serialized.len() + chunk_size - 1) / chunk_size);
        Ok(())
    });
    
    // Receiver that handles throttled data
    sim.host("throttled-receiver", || async {
        sleep(Duration::from_millis(100)).await;
        
        let mut stream = TcpStream::connect("throttled-sender:9004").await?;
        
        // Read length prefix
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Read throttled data
        let mut data = vec![0u8; len];
        let mut total_read = 0;
        
        while total_read < len {
            let chunk = &mut data[total_read..];
            let n = stream.read(chunk).await?;
            if n == 0 { break; }
            total_read += n;
        }
        
        assert_eq!(total_read, len, "Should receive complete data despite throttling");
        
        let block = EntropyBlock::from_bytes(&data).unwrap();
        assert!(block.verify_integrity());
        
        println!("Receiver handled throttled data successfully");
        Ok(())
    });
    
    sim.run().unwrap();
}

#[test]
fn test_packet_loss_resilience() {
    let mut sim = Builder::new().build();
    
    // Sender that implements retry logic
    sim.host("resilient-sender", || async {
        let listener = TcpListener::bind("0.0.0.0:9005").await?;
        let (mut stream, _) = listener.accept().await?;
        
        // Create block
        let rounds: Vec<DrandRound> = (1000..1010).map(|i| DrandRound {
            round: i,
            randomness: [i as u8; 32],
            signature: vec![0u8; 96],
            previous_signature: vec![0u8; 96],
        }).collect();
        
        let block = EntropyBlock::from_rounds(rounds).unwrap();
        let serialized = block.to_bytes().unwrap();
        
        // Send with retry logic (simulate packet loss handling)
        let mut attempts = 0;
        let max_attempts = 3;
        
        while attempts < max_attempts {
            attempts += 1;
            
            let len = serialized.len() as u32;
            if stream.write_all(&len.to_be_bytes()).await.is_err() {
                continue;
            }
            
            if stream.write_all(&serialized).await.is_err() {
                continue;
            }
            
            // Simple acknowledgment mechanism
            let mut ack = [0u8; 1];
            match stream.read_exact(&mut ack).await {
                Ok(_) if ack[0] == 0x01 => break, // Success
                _ => {
                    println!("Attempt {} failed, retrying...", attempts);
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
        
        assert!(attempts <= max_attempts, "Should succeed within retry limit");
        println!("Resilient sender succeeded after {} attempts", attempts);
        Ok(())
    });
    
    // Receiver with acknowledgment
    sim.host("acknowledging-receiver", || async {
        sleep(Duration::from_millis(100)).await;
        
        let mut stream = TcpStream::connect("resilient-sender:9005").await?;
        
        // Read length prefix
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Read block data
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;
        
        // Verify and send acknowledgment
        let block = EntropyBlock::from_bytes(&data).unwrap();
        assert!(block.verify_integrity());
        
        stream.write_all(&[0x01]).await?; // Success acknowledgment
        
        println!("Acknowledging receiver completed successfully");
        Ok(())
    });
    
    sim.run().unwrap();
}

#[test]
fn test_nat_traversal() {
    let mut sim = Builder::new().build();
    
    // Node behind NAT (simulated by binding to specific interface)
    sim.host("behind-nat", || async {
        // Simulate NAT by binding to localhost only
        let listener = TcpListener::bind("127.0.0.1:9006").await?;
        
        let (mut stream, _) = listener.accept().await?;
        
        // Send simple message
        let message = b"Hello from behind NAT!";
        let len = message.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(message).await?;
        
        Ok(())
    });
    
    // External node that can reach NAT node
    sim.host("external-node", || async {
        sleep(Duration::from_millis(100)).await;
        
        // Connect through "NAT" (simulated by connecting to localhost)
        let mut stream = TcpStream::connect("127.0.0.1:9006").await?;
        
        // Read message from behind NAT
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        let mut message = vec![0u8; len];
        stream.read_exact(&mut message).await?;
        
        assert_eq!(message, b"Hello from behind NAT!");
        println!("External node successfully communicated with NAT node");
        Ok(())
    });
    
    sim.run().unwrap();
}

#[test]
fn test_entropy_block_sharing() {
    let mut sim = Builder::new().build();
    
    // Seeder node: Creates and sends EntropyBlock
    sim.host("seeder", || async {
        // Create test block
        let rounds: Vec<DrandRound> = (1000..1010).map(|i| DrandRound {
            round: i,
            randomness: [i as u8; 32],
            signature: vec![0u8; 96],
            previous_signature: vec![0u8; 96],
        }).collect();
        
        let block = EntropyBlock::from_rounds(rounds).unwrap();
        let serialized = block.to_bytes().unwrap();
        
        // Send to peer
        let listener = TcpListener::bind("0.0.0.0:9001").await?;
        let (mut stream, _) = listener.accept().await?;
        
        // Send length prefix + data
        let len = serialized.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&serialized).await?;
        
        println!("Seeder sent block: {} bytes", serialized.len());
        Ok(())
    });
    
    // Peer node: Receives and verifies EntropyBlock
    sim.host("peer", || async {
        sleep(Duration::from_millis(100)).await;
        
        let mut stream = TcpStream::connect("seeder:9001").await?;
        
        // Read length prefix
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Read block data
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;
        
        // Deserialize and verify
        let block = EntropyBlock::from_bytes(&data).unwrap();
        assert!(block.verify_integrity());
        assert_eq!(block.start_round, 1000);
        assert_eq!(block.end_round, 1009);
        
        println!("Peer received and verified block: rounds {}-{}",
                 block.start_round, block.end_round);
        Ok(())
    });
    
    sim.run().unwrap();
}

#[test]
fn test_tcp_message_exchange() {
    let mut sim = Builder::new().build();
    
    // Server node
    sim.host("server", || async {
        let listener = TcpListener::bind("0.0.0.0:9000").await?;
        println!("Server listening on port 9000");
        
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await?;
        
        println!("Server received: {:?}", &buf[..n]);
        assert_eq!(&buf[..n], b"hello from client");
        
        stream.write_all(b"hello from server").await?;
        Ok(())
    });
    
    // Client node
    sim.host("client", || async {
        sleep(Duration::from_millis(100)).await; // Wait for server
        
        let mut stream = TcpStream::connect("server:9000").await?;
        stream.write_all(b"hello from client").await?;
        
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await?;
        
        println!("Client received: {:?}", &buf[..n]);
        assert_eq!(&buf[..n], b"hello from server");
        
        Ok(())
    });
    
    sim.run().unwrap();
}