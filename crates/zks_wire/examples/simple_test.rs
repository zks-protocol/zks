use zks_wire::{Swarm, Peer, PeerId, SwarmCircuit};
use zks_wire::swarm::PeerState;
use std::fs::File;
use std::io::Write;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = File::create("test_output.txt")?;
    
    writeln!(output, "🧅 Starting Swarm Onion Routing Test")?;
    
    // Create a swarm for testing
    let swarm = Swarm::new("test-onion-network".to_string());
    
    // Add some test peers to the swarm
    add_test_peers(&swarm).await?;
    
    writeln!(output, "Added test peers to swarm")?;
    
    // Test 1: Build a simple 3-hop circuit
    test_simple_circuit(&swarm, &mut output).await?;
    
    writeln!(output, "✅ All onion routing tests completed successfully!")?;
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

async fn test_simple_circuit(swarm: &Swarm, output: &mut File) -> Result<(), Box<dyn std::error::Error>> {
    writeln!(output, "\n--- Test 1: Simple 3-hop Circuit ---")?;
    
    // Build a circuit with 3 hops (entry + 1 middle + exit)
    let circuit = swarm.build_circuit(3, 3).await?;
    
    writeln!(output, "Built circuit with {} hops:", circuit.hop_count())?;
    writeln!(output, "  Entry peer: {}", circuit.entry_peer)?;
    writeln!(output, "  Middle peers: {:?}", circuit.middle_peers)?;
    writeln!(output, "  Exit peer: {}", circuit.exit_peer)?;
    writeln!(output, "  Circuit ID: {:?}", circuit.circuit_id)?;
    
    // Test that all peers are unique
    let all_peers = circuit.all_peers();
    let unique_peers: std::collections::HashSet<_> = all_peers.iter().collect();
    assert_eq!(all_peers.len(), unique_peers.len(), "Circuit contains duplicate peers");
    
    writeln!(output, "✅ Simple circuit test passed")?;
    Ok(())
}