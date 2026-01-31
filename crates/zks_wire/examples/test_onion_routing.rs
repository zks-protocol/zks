//! Test program for swarm onion routing functionality
//! 
//! This example demonstrates building circuits through the swarm
//! and using onion encryption/decryption for secure multi-hop routing.

use zks_wire::{Swarm, Peer, PeerId, SwarmCircuit};
use zks_wire::swarm::PeerState;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    info!("🧅 Starting Swarm Onion Routing Test");
    
    // Create a swarm for testing
    let mut swarm = Swarm::new("test-onion-network".to_string());
    
    // Add some test peers to the swarm
    add_test_peers(&swarm).await?;
    
    info!("Added test peers to swarm");
    
    // Test 1: Build a simple 3-hop circuit
    test_simple_circuit(&swarm).await?;
    
    // Test 2: Test onion encryption/decryption
    test_onion_encryption().await?;
    
    // Test 3: Test circuit builder with different configurations
    test_circuit_builder(&swarm).await?;
    
    // Test 4: Test circuit with many hops
    test_large_circuit(&swarm).await?;
    
    info!("✅ All onion routing tests completed successfully!");
    Ok(())
}

async fn add_test_peers(swarm: &Swarm) -> Result<(), Box<dyn std::error::Error>> {
    // Create test peers with different addresses
    let test_peers = vec![
        Peer {
            id: PeerId::new(),
            addresses: vec!["127.0.0.1:8001".parse()?],
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            state: PeerState::Connected,
            protocol_version: 1,
        },
        Peer {
            id: PeerId::new(),
            addresses: vec!["127.0.0.1:8002".parse()?],
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            state: PeerState::Connected,
            protocol_version: 1,
        },
        Peer {
            id: PeerId::new(),
            addresses: vec!["127.0.0.1:8003".parse()?],
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            state: PeerState::Connected,
            protocol_version: 1,
        },
        Peer {
            id: PeerId::new(),
            addresses: vec!["127.0.0.1:8004".parse()?],
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            state: PeerState::Connected,
            protocol_version: 1,
        },
        Peer {
            id: PeerId::new(),
            addresses: vec!["127.0.0.1:8005".parse()?],
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            state: PeerState::Connected,
            protocol_version: 1,
        },
        Peer {
            id: PeerId::new(),
            addresses: vec!["127.0.0.1:8006".parse()?],
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            state: PeerState::Connected,
            protocol_version: 1,
        },
        Peer {
            id: PeerId::new(),
            addresses: vec!["127.0.0.1:8007".parse()?],
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            state: PeerState::Connected,
            protocol_version: 1,
        },
        Peer {
            id: PeerId::new(),
            addresses: vec!["127.0.0.1:8008".parse()?],
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            state: PeerState::Connected,
            protocol_version: 1,
        },
    ];
    
    for peer in test_peers {
        swarm.add_peer(peer).await?;
    }
    
    Ok(())
}

async fn test_simple_circuit(swarm: &Swarm) -> Result<(), Box<dyn std::error::Error>> {
    info!("\n--- Test 1: Simple 3-hop Circuit ---");
    
    // Build a circuit with 3 hops (entry + 1 middle + exit)
    let circuit = swarm.build_circuit(3, 3).await?;
    
    info!("Built circuit with {} hops:", circuit.hop_count());
    info!("  Entry peer: {}", circuit.entry_peer);
    info!("  Middle peers: {:?}", circuit.middle_peers);
    info!("  Exit peer: {}", circuit.exit_peer);
    info!("  Circuit ID: {:?}", circuit.circuit_id);
    
    // Test that all peers are unique
    let all_peers = circuit.all_peers();
    let unique_peers: std::collections::HashSet<_> = all_peers.iter().collect();
    assert_eq!(all_peers.len(), unique_peers.len(), "Circuit contains duplicate peers");
    
    info!("✅ Simple circuit test passed");
    Ok(())
}

async fn test_onion_encryption() -> Result<(), Box<dyn std::error::Error>> {
    info!("\n--- Test 2: Onion Encryption/Decryption ---");
    
    // Create a circuit with known keys for testing
    let mut circuit = SwarmCircuit::new()?;
    circuit.set_layer_keys(vec![
        [1u8; 32], // Entry peer key
        [2u8; 32], // Middle peer key  
        [3u8; 32], // Exit peer key
    ]);
    
    let test_data = b"Hello, onion routing world! This is a secret message.";
    info!("Original data: {} bytes", test_data.len());
    
    // Encrypt the data
    let encrypted = circuit.onion_encrypt(test_data)?;
    info!("Encrypted data: {} bytes", encrypted.len());
    
    // Verify encryption changed the data
    assert_ne!(encrypted, test_data, "Encryption did not change the data");
    
    // Decrypt the data
    let decrypted = circuit.onion_decrypt(&encrypted)?;
    info!("Decrypted data: {} bytes", decrypted.len());
    
    // Verify decryption worked correctly
    assert_eq!(decrypted, test_data, "Decryption did not restore original data");
    
    info!("✅ Onion encryption/decryption test passed");
    Ok(())
}

async fn test_circuit_builder(swarm: &Swarm) -> Result<(), Box<dyn std::error::Error>> {
    info!("\n--- Test 3: Circuit Builder Configurations ---");
    
    // Test with minimum 2 hops, maximum 4 hops
    let circuit = swarm.build_circuit(2, 4).await?;
    info!("Built circuit with {} hops (requested 2-4)", circuit.hop_count());
    assert!(circuit.hop_count() >= 2 && circuit.hop_count() <= 4);
    
    // Test with minimum 5 hops, maximum 6 hops
    let circuit = swarm.build_circuit(5, 6).await?;
    info!("Built circuit with {} hops (requested 5-6)", circuit.hop_count());
    assert!(circuit.hop_count() >= 5 && circuit.hop_count() <= 6);
    
    // Test with exact 3 hops
    let circuit = swarm.build_circuit(3, 3).await?;
    info!("Built circuit with {} hops (requested exactly 3)", circuit.hop_count());
    assert_eq!(circuit.hop_count(), 3);
    
    info!("✅ Circuit builder test passed");
    Ok(())
}

async fn test_large_circuit(swarm: &Swarm) -> Result<(), Box<dyn std::error::Error>> {
    info!("\n--- Test 4: Large Circuit (7 hops) ---");
    
    // Build a large circuit with 7 hops
    let circuit = swarm.build_circuit(7, 7).await?;
    info!("Built large circuit with {} hops:", circuit.hop_count());
    info!("  Entry peer: {}", circuit.entry_peer);
    info!("  Middle peers: {:?} ({} peers)", circuit.middle_peers, circuit.middle_peers.len());
    info!("  Exit peer: {}", circuit.exit_peer);
    
    // Test onion encryption with many layers
    let mut circuit = circuit; // Make circuit mutable
    circuit.set_layer_keys(vec![[1u8; 32]; 7]); // 7 identical keys for simplicity
    
    let test_data = b"Testing large circuit with many hops for maximum privacy!";
    let encrypted = circuit.onion_encrypt(test_data)?;
    let decrypted = circuit.onion_decrypt(&encrypted)?;
    
    assert_eq!(decrypted, test_data, "Large circuit encryption/decryption failed");
    info!("✅ Large circuit test passed");
    
    Ok(())
}