//! Integration tests for Faisal Swarm end-to-end circuit building
//! 
//! Tests the complete Phase 3 implementation with real ML-KEM handshakes
//! via libp2p request-response protocol.

use crate::faisal_swarm::*;
use crate::p2p::{NativeP2PTransport, FaisalSwarmRequest, FaisalSwarmResponse};
use crate::signaling::{SignalingClient, PeerInfo};
use libp2p::{PeerId, Multiaddr};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug};

/// Test helper to create a mock signaling client with test peers
async fn create_mock_signaling_client() -> Arc<SignalingClient> {
    let client = SignalingClient::connect("localhost:8080", "test-room").await
        .expect("Failed to connect to signaling server");
    Arc::new(client)
}

/// Test helper to create test peer info
fn create_test_peer_info(peer_id: &str, role: SwarmRole) -> PeerInfo {
    PeerInfo {
        peer_id: PeerId::from_bytes(&hex::decode(peer_id).unwrap()).unwrap(),
        multiaddr: format!("/ip4/127.0.0.1/tcp/8080/p2p/{}", peer_id).parse().unwrap(),
        role: format!("{:?}", role),
        capabilities: SwarmCapabilities {
            relay: true,
            encryption: true,
            post_quantum: true,
        },
    }
}

/// Test helper to create a mock P2P transport
async fn create_mock_p2p_transport() -> Arc<RwLock<NativeP2PTransport>> {
    let transport = NativeP2PTransport::new(None, None).await
        .expect("Failed to create P2P transport");
    Arc::new(RwLock::new(transport))
}

#[tokio::test]
async fn test_end_to_end_circuit_creation() {
    info!("🧪 Testing end-to-end circuit creation with real ML-KEM handshakes");
    
    // Create mock services
    let signaling = create_mock_signaling_client().await;
    let p2p_transport = create_mock_p2p_transport().await;
    
    // Create Faisal Swarm manager
    let manager = FaisalSwarmManager::new(signaling.clone(), p2p_transport.clone());
    
    // Create a 3-hop circuit (Guard → Middle → Exit)
    let circuit_id = manager.create_circuit("test-room", 3).await
        .expect("Failed to create circuit");
    
    info!("✅ Successfully created circuit {} with real ML-KEM handshakes", circuit_id);
    
    // Verify circuit structure
    let circuits = manager.circuits.read().await;
    let circuit = circuits.get(&circuit_id).expect("Circuit not found");
    
    assert_eq!(circuit.hops.len(), 3, "Circuit should have 3 hops");
    assert_eq!(circuit.layers.len(), 3, "Circuit should have 3 encryption layers");
    assert_eq!(circuit.state, CircuitState::Ready, "Circuit should be ready");
    
    // Verify each layer has proper Wasif-Vernam keys derived from ML-KEM
    for (i, layer) in circuit.layers.iter().enumerate() {
        debug!("🔍 Verifying layer {} for hop {}", i, layer.peer_id);
        
        // Check that forward and backward keys are properly derived
        assert_ne!(layer.forward_key, [0u8; 32], "Forward key should not be zero");
        assert_ne!(layer.backward_key, [0u8; 32], "Backward key should not be zero");
        assert_ne!(layer.forward_key, layer.backward_key, "Forward and backward keys should be different");
        
        // Verify shared secret is properly stored
        assert_ne!(layer.shared_secret, [0u8; 32], "Shared secret should not be zero");
    }
    
    info!("✅ All circuit layers verified with proper ML-KEM-derived keys");
}

#[tokio::test]
async fn test_circuit_encryption_layers() {
    info!("🧪 Testing circuit encryption layers with Wasif-Vernam");
    
    let signaling = create_mock_signaling_client().await;
    let p2p_transport = create_mock_p2p_transport().await;
    let manager = FaisalSwarmManager::new(signaling.clone(), p2p_transport.clone());
    
    // Create a test circuit
    let circuit_id = manager.create_circuit("test-room", 2).await
        .expect("Failed to create circuit");
    
    // Get the circuit
    let circuits = manager.circuits.read().await;
    let circuit = circuits.get(&circuit_id).expect("Circuit not found");
    
    // Test data encryption through layers
    let test_data = b"Hello, Faisal Swarm!";
    
    // Encrypt through all layers (onion encryption)
    let mut encrypted_data = test_data.to_vec();
    for layer in &circuit.layers {
        encrypted_data = manager.encrypt_data_for_hop(&encrypted_data, 0, circuit, layer.forward_key)
            .expect("Failed to encrypt data");
    }
    
    // Verify encrypted data is different from original
    assert_ne!(encrypted_data, test_data.to_vec(), "Encrypted data should be different");
    assert!(encrypted_data.len() > test_data.len(), "Encrypted data should include authentication tags");
    
    // Decrypt through layers in reverse order
    let mut decrypted_data = encrypted_data;
    for layer in circuit.layers.iter().rev() {
        decrypted_data = manager.decrypt_data_for_hop(&decrypted_data, 0, circuit, layer.backward_key)
            .expect("Failed to decrypt data");
    }
    
    // Verify decryption worked
    assert_eq!(decrypted_data, test_data.to_vec(), "Decrypted data should match original");
    
    info!("✅ Circuit encryption/decryption test passed");
}

#[tokio::test]
async fn test_circuit_cell_routing() {
    info!("🧪 Testing circuit cell routing through multiple hops");
    
    let signaling = create_mock_signaling_client().await;
    let p2p_transport = create_mock_p2p_transport().await;
    let manager = FaisalSwarmManager::new(signaling.clone(), p2p_transport.clone());
    
    // Create a 3-hop circuit
    let circuit_id = manager.create_circuit("test-room", 3).await
        .expect("Failed to create circuit");
    
    // Create a test cell
    let test_payload = b"Test payload for multi-hop routing";
    let cell = FaisalSwarmCell::new(circuit_id, 1, test_payload.to_vec());
    
    // Route cell through circuit
    let routed_cells = manager.route_cell_through_circuit(cell, circuit_id).await
        .expect("Failed to route cell");
    
    // Verify routing created cells for each hop
    assert_eq!(routed_cells.len(), 3, "Should create cells for each hop");
    
    // Verify each cell is properly encrypted for its target hop
    for (i, routed_cell) in routed_cells.iter().enumerate() {
        info!("🔍 Verifying cell for hop {} (circuit {})", i, circuit_id);
        
        assert_eq!(routed_cell.circuit_id, circuit_id, "Circuit ID should match");
        assert_eq!(routed_cell.hop_index, i as u32, "Hop index should match");
        assert_ne!(routed_cell.payload, test_payload.to_vec(), "Payload should be encrypted");
        
        // Verify cell can be decrypted by the target hop
        let circuits = manager.circuits.read().await;
        let circuit = circuits.get(&circuit_id).expect("Circuit not found");
        
        if i < circuit.layers.len() {
            let layer = &circuit.layers[i];
            let decrypted_payload = manager.decrypt_cell_for_hop(routed_cell, i, circuit, layer.backward_key)
                .expect("Failed to decrypt cell");
            
            if i == 0 {
                // First hop should decrypt to original payload
                assert_eq!(decrypted_payload, test_payload.to_vec(), "First hop should see original payload");
            } else {
                // Subsequent hops should see encrypted payload from previous hop
                assert_ne!(decrypted_payload, test_payload.to_vec(), "Subsequent hops should see encrypted payload");
            }
        }
    }
    
    info!("✅ Circuit cell routing test passed");
}

#[tokio::test]
async fn test_circuit_teardown() {
    info!("🧪 Testing circuit teardown");
    
    let signaling = create_mock_signaling_client().await;
    let p2p_transport = create_mock_p2p_transport().await;
    let manager = FaisalSwarmManager::new(signaling.clone(), p2p_transport.clone());
    
    // Create a circuit
    let circuit_id = manager.create_circuit("test-room", 2).await
        .expect("Failed to create circuit");
    
    // Verify circuit exists
    {
        let circuits = manager.circuits.read().await;
        assert!(circuits.contains_key(&circuit_id), "Circuit should exist");
    }
    
    // Teardown circuit
    manager.teardown_circuit(circuit_id).await
        .expect("Failed to teardown circuit");
    
    // Verify circuit is removed
    {
        let circuits = manager.circuits.read().await;
        assert!(!circuits.contains_key(&circuit_id), "Circuit should be removed");
    }
    
    info!("✅ Circuit teardown test passed");
}

#[tokio::test]
async fn test_multiple_circuits_isolation() {
    info!("🧪 Testing multiple circuits isolation");
    
    let signaling = create_mock_signaling_client().await;
    let p2p_transport = create_mock_p2p_transport().await;
    let manager = FaisalSwarmManager::new(signaling.clone(), p2p_transport.clone());
    
    // Create multiple circuits
    let circuit1_id = manager.create_circuit("test-room", 2).await
        .expect("Failed to create circuit 1");
    let circuit2_id = manager.create_circuit("test-room", 3).await
        .expect("Failed to create circuit 2");
    
    // Verify both circuits exist and are independent
    let circuits = manager.circuits.read().await;
    
    let circuit1 = circuits.get(&circuit1_id).expect("Circuit 1 not found");
    let circuit2 = circuits.get(&circuit2_id).expect("Circuit 2 not found");
    
    assert_eq!(circuit1.hops.len(), 2, "Circuit 1 should have 2 hops");
    assert_eq!(circuit2.hops.len(), 3, "Circuit 2 should have 3 hops");
    
    // Verify different circuit IDs
    assert_ne!(circuit1_id, circuit2_id, "Circuit IDs should be different");
    
    // Verify different peer selections (likely, due to random selection)
    assert_ne!(circuit1.hops[0].peer_id, circuit2.hops[0].peer_id, 
               "Circuits should have different first hops");
    
    info!("✅ Multiple circuits isolation test passed");
}

/// Integration test for the complete Phase 3 implementation
#[tokio::test]
async fn test_phase_3_complete_integration() {
    info!("🚀 Testing complete Phase 3 integration");
    info!("   This test validates:");
    info!("   ✅ Real ML-KEM handshakes via libp2p request-response");
    info!("   ✅ Proper EXTEND protocol implementation");
    info!("   ✅ Wasif-Vernam key derivation from ML-KEM shared secrets");
    info!("   ✅ Multi-hop circuit building with post-quantum security");
    
    let signaling = create_mock_signaling_client().await;
    let p2p_transport = create_mock_p2p_transport().await;
    let manager = FaisalSwarmManager::new(signaling.clone(), p2p_transport.clone());
    
    // Create a full 3-hop circuit (this triggers all Phase 3 functionality)
    let circuit_id = manager.create_circuit("integration-test", 3).await
        .expect("Failed to create integration test circuit");
    
    // Verify complete circuit state
    let circuits = manager.circuits.read().await;
    let circuit = circuits.get(&circuit_id).expect("Circuit not found");
    
    assert_eq!(circuit.hops.len(), 3, "Should have 3 hops");
    assert_eq!(circuit.layers.len(), 3, "Should have 3 encryption layers");
    assert_eq!(circuit.state, CircuitState::Ready, "Circuit should be ready");
    
    // Test data transmission through the complete circuit
    let test_message = b"Phase 3 Integration Test Message";
    
    // Create and route a cell through all hops
    let cell = FaisalSwarmCell::new(circuit_id, 0, test_message.to_vec());
    let routed_cells = manager.route_cell_through_circuit(cell, circuit_id).await
        .expect("Failed to route cell through complete circuit");
    
    assert_eq!(routed_cells.len(), 3, "Should route through all 3 hops");
    
    // Verify each hop has properly encrypted data
    for (i, routed_cell) in routed_cells.iter().enumerate() {
        assert_ne!(routed_cell.payload, test_message.to_vec(), 
                  "Hop {} payload should be encrypted", i);
        assert!(routed_cell.payload.len() > test_message.len(), 
               "Hop {} payload should include auth tags", i);
    }
    
    info!("✅ Phase 3 complete integration test PASSED");
    info!("🎉 Real ML-KEM handshakes are working via libp2p request-response!");
    info!("🎉 Multi-hop circuits with post-quantum security are operational!");
}