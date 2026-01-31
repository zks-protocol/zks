use insta::assert_snapshot;
use zks_crypt::drand::DrandError;
use zks_wire::dht_lookup::DHTLookupError;
use zks_wire::faisal_swarm::{CircuitId, CircuitState, SwarmError};

#[test]
fn test_drand_network_error() {
    let error = DrandError::NetworkError("Connection timeout after 30 seconds".to_string());
    assert_snapshot!("drand_network_error", format!("{:?}", error));
}

#[test]
fn test_drand_api_error() {
    let error = DrandError::ApiError("HTTP 503 Service Unavailable".to_string());
    assert_snapshot!("drand_api_error", format!("{:?}", error));
}

#[test]
fn test_drand_parse_error() {
    let error = DrandError::ParseError("Invalid JSON response".to_string());
    assert_snapshot!("drand_parse_error", format!("{:?}", error));
}

#[test]
fn test_drand_invalid_input() {
    let error = DrandError::InvalidInput("Round number must be positive".to_string());
    assert_snapshot!("drand_invalid_input", format!("{:?}", error));
}

#[test]
fn test_dht_lookup_in_progress() {
    let error = DHTLookupError::LookupInProgress;
    assert_snapshot!("dht_lookup_in_progress", format!("{:?}", error));
}

#[test]
fn test_dht_no_providers_found() {
    let error = DHTLookupError::NoProvidersFound;
    assert_snapshot!("dht_no_providers_found", format!("{:?}", error));
}

#[test]
fn test_dht_max_retries_exceeded() {
    let error = DHTLookupError::MaxRetriesExceeded;
    assert_snapshot!("dht_max_retries_exceeded", format!("{:?}", error));
}

#[test]
fn test_dht_timeout() {
    let error = DHTLookupError::Timeout;
    assert_snapshot!("dht_timeout", format!("{:?}", error));
}

#[test]
fn test_swarm_not_found() {
    let circuit_id: CircuitId = 12345;
    let error = SwarmError::NotFound(circuit_id);
    assert_snapshot!("swarm_not_found", format!("{:?}", error));
}

#[test]
fn test_swarm_encryption_error() {
    let error = SwarmError::Encryption("AES key derivation failed".to_string());
    assert_snapshot!("swarm_encryption_error", format!("{:?}", error));
}

#[test]
fn test_swarm_invalid_state() {
    let expected = CircuitState::Ready;
    let actual = CircuitState::Building;
    let error = SwarmError::InvalidState { expected, actual };
    assert_snapshot!("swarm_invalid_state", format!("{:?}", error));
}

#[test]
fn test_swarm_handshake_failed() {
    let error = SwarmError::HandshakeFailed("Invalid protocol version".to_string());
    assert_snapshot!("swarm_handshake_failed", format!("{:?}", error));
}

#[test]
fn test_swarm_protocol_error() {
    let error = SwarmError::Protocol("Invalid message format".to_string());
    assert_snapshot!("swarm_protocol_error", format!("{:?}", error));
}

#[test]
fn test_swarm_libp2p_error() {
    let error = SwarmError::Libp2p("Transport error: connection refused".to_string());
    assert_snapshot!("swarm_libp2p_error", format!("{:?}", error));
}

#[test]
fn test_swarm_not_enough_peers() {
    let error = SwarmError::NotEnoughPeers("Need at least 3 peers, found 1".to_string());
    assert_snapshot!("swarm_not_enough_peers", format!("{:?}", error));
}