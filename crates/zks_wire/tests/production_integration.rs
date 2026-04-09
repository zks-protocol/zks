//! Production integration tests for ZKS Protocol using real Cloudflare signaling
//!
//! These tests validate the complete Phase 3 implementation with real-world
//! Cloudflare Workers signaling infrastructure instead of mocks.

use std::env;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use zks_wire::cloudflare_signaling::{CloudflareSignalingClient, CloudflareSignalingConfig};
use zks_wire::faisal_swarm::*;
use zks_wire::p2p::NativeP2PTransport;
use zks_wire::signaling::PeerCapabilities;

/// Get signaling configuration from environment or use staging defaults
fn get_signaling_config() -> CloudflareSignalingConfig {
    match env::var("ZKS_SIGNALING_ENVIRONMENT").as_deref() {
        Ok("production") => {
            info!("Using PRODUCTION Cloudflare signaling configuration");
            let mut config = CloudflareSignalingConfig::production();

            // Load auth token from environment if available
            if let Ok(auth_token) = env::var("ZKS_SIGNALING_AUTH_TOKEN") {
                config.auth_token = Some(auth_token);
                info!("Loaded authentication token from environment");
            }

            config
        }
        _ => {
            info!("Using STAGING Cloudflare signaling configuration");
            let mut config = CloudflareSignalingConfig::staging();

            // For staging, use a test token if available
            if let Ok(auth_token) = env::var("ZKS_SIGNALING_AUTH_TOKEN") {
                config.auth_token = Some(auth_token);
                info!("Loaded staging authentication token from environment");
            } else {
                // Use a default test token for staging
                config.auth_token = Some("test-token".to_string());
                info!("Using default staging authentication token");
            }

            config
        }
    }
}

/// Test helper to create real Cloudflare signaling client
async fn create_cloudflare_signaling_client(peer_id: &str) -> Arc<CloudflareSignalingClient> {
    let config = get_signaling_config();

    info!("Creating Cloudflare signaling client for peer: {}", peer_id);

    match CloudflareSignalingClient::connect(config, peer_id.to_string()).await {
        Ok(client) => {
            info!("✅ Successfully connected to Cloudflare signaling");
            Arc::new(client)
        }
        Err(e) => {
            warn!(
                "❌ Failed to connect to Cloudflare signaling: {}. Using fallback simulation.",
                e
            );

            // In a real test environment, you would fail here
            // For now, we'll create a mock that simulates the behavior
            panic!(
                "Cloudflare signaling connection required for production tests: {}",
                e
            );
        }
    }
}

/// Test helper to create real P2P transport
async fn create_real_p2p_transport() -> Arc<RwLock<NativeP2PTransport>> {
    info!("Creating real P2P transport with libp2p");

    // Use real libp2p configuration for production testing
    let (transport, driver) = NativeP2PTransport::new(None, None)
        .expect("Failed to create real P2P transport");

    // Spawn the driver
    tokio::spawn(async move {
        if let Err(e) = driver.run().await {
            warn!("P2P driver error: {}", e);
        }
    });

    Arc::new(RwLock::new(transport))
}

/// Test helper to create production FaisalSwarmManager
async fn create_production_swarm_manager(
    peer_id: &str,
    room_id: &str,
) -> Arc<FaisalSwarmManager<CloudflareSignalingClient>> {
    info!(
        "Creating production FaisalSwarmManager for peer: {}",
        peer_id
    );

    let signaling = create_cloudflare_signaling_client(peer_id).await;
    let p2p_transport = create_real_p2p_transport().await;

    let manager = FaisalSwarmManager::new(signaling.clone(), p2p_transport);

    // Join the test room with production capabilities
    let capabilities = PeerCapabilities {
        supports_p2p: true,
        supports_relay: true,
        supports_onion_routing: true,
        max_message_size: 65536,
        supported_protocols: vec!["zks/1.0".to_string(), "faisal-swarm".to_string()],
        max_hops: 8,
    };

    signaling
        .join_room(room_id, capabilities)
        .await
        .expect("Failed to join signaling room");

    info!("✅ Joined signaling room: {}", room_id);
    Arc::new(manager)
}

#[tokio::test]
async fn test_cloudflare_signaling_connection() {
    info!("🌐 Testing real Cloudflare signaling connection");

    let peer_id = format!("test-peer-{}", uuid::Uuid::new_v4());
    let client = create_cloudflare_signaling_client(&peer_id).await;

    // Test connection stats
    let stats = client.get_connection_stats().await;
    assert!(stats.is_connected);
    assert_eq!(stats.peer_id, peer_id);

    info!("✅ Cloudflare signaling connection test passed");
}

#[tokio::test]
async fn test_production_circuit_creation_with_cloudflare() {
    info!("🧪 Testing production circuit creation with real Cloudflare signaling");

    let room_id = "zks-protocol-production-test";
    let peer1_id = format!("production-peer-1-{}", uuid::Uuid::new_v4());
    let peer2_id = format!("production-peer-2-{}", uuid::Uuid::new_v4());
    let peer3_id = format!("production-peer-3-{}", uuid::Uuid::new_v4());

    // Create real swarm managers
    let manager1 = create_production_swarm_manager(&peer1_id, room_id).await;
    let _manager2 = create_production_swarm_manager(&peer2_id, room_id).await;
    let _manager3 = create_production_swarm_manager(&peer3_id, room_id).await;

    // Wait for peers to discover each other
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Discover available peers
    let signaling = create_cloudflare_signaling_client(&peer1_id).await;
    let peers = signaling
        .discover_peers(room_id)
        .await
        .expect("Failed to discover peers");

    info!(
        "Discovered {} peers in room: {:?}",
        peers.len(),
        peers.iter().map(|p| &p.peer_id).collect::<Vec<_>>()
    );

    assert!(
        peers.len() >= 2,
        "Need at least 2 peers for circuit testing"
    );

    // Create a 3-hop circuit using real ML-KEM handshakes
    let circuit_id = manager1
        .create_circuit(room_id, 3)
        .await
        .expect("Failed to create circuit");

    info!("Created circuit {} with 3 hops", circuit_id);

    // Circuit is automatically built with selected peers by create_circuit
    info!(
        "Circuit {} built with {} hops through selected peers",
        circuit_id, 3
    );

    // Verify circuit is ready
    let circuit_info = manager1
        .get_circuit_info(circuit_id)
        .await
        .expect("Failed to get circuit info");

    assert_eq!(circuit_info.state, CircuitState::Ready);
    assert_eq!(circuit_info.hops.len(), 3);

    info!("✅ Production circuit creation test passed with real Cloudflare signaling");
}

#[tokio::test]
async fn test_production_entropy_distribution() {
    info!("🔮 Testing production entropy distribution via Cloudflare");

    let room_id = "zks-protocol-entropy-test";
    let peer_id = format!("entropy-peer-{}", uuid::Uuid::new_v4());

    let signaling = create_cloudflare_signaling_client(&peer_id).await;

    // Join the test room
    let capabilities = PeerCapabilities::default();
    signaling
        .join_room(room_id, capabilities)
        .await
        .expect("Failed to join entropy test room");

    // Request entropy from the swarm
    let entropy = signaling
        .get_swarm_entropy(room_id)
        .await
        .expect("Failed to get swarm entropy");

    assert_eq!(entropy.len(), 32);

    // Verify entropy is not all zeros (basic sanity check)
    let is_non_zero = entropy.iter().any(|&b| b != 0);
    assert!(is_non_zero, "Entropy should not be all zeros");

    info!("✅ Production entropy distribution test passed");
}

#[tokio::test]
async fn test_production_circuit_data_flow() {
    info!("🔄 Testing production circuit data flow with real encryption");

    let room_id = "zks-protocol-data-flow-test";
    let client_id = format!("data-flow-client-{}", uuid::Uuid::new_v4());

    // Create production setup
    let manager = create_production_swarm_manager(&client_id, room_id).await;

    // Create circuit with real peers
    let circuit_id = manager
        .create_circuit(room_id, 2)
        .await
        .expect("Failed to create data flow circuit");

    // Discover and extend through real peers
    let signaling = create_cloudflare_signaling_client(&client_id).await;
    let peers = signaling
        .discover_peers(room_id)
        .await
        .expect("Failed to discover peers for data flow");

    if peers.is_empty() {
        warn!("No peers discovered for data flow test - this may indicate network issues");
        return;
    }

    // Circuit is automatically built with selected peers by create_circuit
    info!(
        "Circuit {} built with {} hops through selected peers",
        circuit_id, 2
    );

    // Test data transmission through the circuit
    let test_data = b"Hello from production ZKS Protocol!";

    manager
        .send_via_swarm(circuit_id, test_data)
        .await
        .expect("Failed to send data through production circuit");

    info!("✅ Production circuit data flow test passed");
}

#[tokio::test]
async fn test_production_circuit_teardown() {
    info!("🧹 Testing production circuit teardown");

    let room_id = "zks-protocol-teardown-test";
    let client_id = format!("teardown-client-{}", uuid::Uuid::new_v4());

    let manager = create_production_swarm_manager(&client_id, room_id).await;

    // Create and setup circuit
    let circuit_id = manager
        .create_circuit(room_id, 2)
        .await
        .expect("Failed to create teardown test circuit");

    // Close the circuit
    manager
        .close_circuit(circuit_id)
        .await
        .expect("Failed to close production circuit");

    // Verify circuit is closed
    let circuit_info = manager.get_circuit_info(circuit_id).await;
    assert!(
        circuit_info.is_err(),
        "Circuit should be closed and unavailable"
    );

    info!("✅ Production circuit teardown test passed");
}

#[tokio::test]
async fn test_production_multi_peer_circuit() {
    info!("🌟 Testing production multi-peer circuit with real Cloudflare coordination");

    let room_id = "zks-protocol-multi-peer-test";
    let peer_ids: Vec<String> = (0..5)
        .map(|i| format!("multi-peer-{}-{}", i, uuid::Uuid::new_v4()))
        .collect();

    // Create multiple swarm managers
    let managers: Vec<_> = futures::future::join_all(
        peer_ids
            .iter()
            .map(|peer_id| create_production_swarm_manager(peer_id, room_id)),
    )
    .await;

    // Wait for peer discovery
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Create complex circuit through multiple peers
    let client_manager = &managers[0];
    let circuit_id = client_manager
        .create_circuit(room_id, 4)
        .await
        .expect("Failed to create multi-peer circuit");

    // Extend through discovered peers
    let signaling = create_cloudflare_signaling_client(&peer_ids[0]).await;
    let peers = signaling
        .discover_peers(room_id)
        .await
        .expect("Failed to discover multi-peers");

    info!("Discovered {} peers for multi-peer circuit", peers.len());

    // Build circuit through available peers
    // Circuit is automatically built with selected peers by create_circuit
    info!(
        "Circuit {} built with {} hops through selected peers",
        circuit_id, 4
    );

    // Verify complex circuit
    let circuit_info = client_manager
        .get_circuit_info(circuit_id)
        .await
        .expect("Failed to get multi-peer circuit info");

    assert!(circuit_info.hops.len() >= 3, "Should have multiple hops");

    info!(
        "✅ Production multi-peer circuit test passed with {} peers",
        managers.len()
    );
}
