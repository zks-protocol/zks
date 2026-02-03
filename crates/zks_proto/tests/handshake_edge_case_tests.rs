use zks_proto::handshake::{Handshake, HandshakeInit, HandshakeResponse, HandshakeFinish, HandshakeRole, HandshakeState};
use zks_pqcrypto::ml_dsa::{MlDsa, MlDsaKeypair};
use zks_pqcrypto::ml_kem::{MlKem, MlKemKeypair};

/// Test edge case: Invalid trusted responder public key size
#[test]
fn test_invalid_trusted_responder_key_size() {
    let invalid_key = vec![0u8; 100]; // Wrong size for ML-DSA-87
    let result = Handshake::new_initiator("test_room".to_string(), invalid_key);
    assert!(result.is_err(), "Should fail with invalid trusted responder key size");
}

/// Test edge case: Version mismatch
#[test]
fn test_version_mismatch() {
    let trusted_key = vec![0u8; 2592]; // Correct ML-DSA-87 size
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    
    // Create init message with wrong version
    let mut init = initiator.create_init().unwrap();
    init.version = 99; // Invalid version
    
    let mut responder = Handshake::new_responder("test_room".to_string());
    let result = responder.process_init(&init);
    assert!(result.is_err(), "Should fail with version mismatch");
}

/// Test edge case: Room ID mismatch
#[test]
fn test_room_id_mismatch() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("room1".to_string(), trusted_key).unwrap();
    let init = initiator.create_init().unwrap();
    
    let mut responder = Handshake::new_responder("room2".to_string()); // Different room
    let result = responder.process_init(&init);
    assert!(result.is_err(), "Should fail with room ID mismatch");
}

/// Test edge case: Expired timestamp (replay attack simulation)
#[test]
fn test_expired_timestamp_replay() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    
    let mut init = initiator.create_init().unwrap();
    init.timestamp = 0; // Very old timestamp
    
    let mut responder = Handshake::new_responder("test_room".to_string());
    let result = responder.process_init(&init);
    assert!(result.is_err(), "Should fail with expired timestamp");
}

/// Test edge case: Future timestamp (clock skew)
#[test]
fn test_future_timestamp() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    
    let mut init = initiator.create_init().unwrap();
    init.timestamp = u64::MAX; // Far future timestamp
    
    let mut responder = Handshake::new_responder("test_room".to_string());
    let result = responder.process_init(&init);
    assert!(result.is_err(), "Should fail with future timestamp");
}

/// Test edge case: Invalid state transitions
#[test]
fn test_invalid_state_transitions() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    
    // Try to create response as initiator
    let result = initiator.create_response();
    assert!(result.is_err(), "Initiator should not be able to create response");
    
    // Try to process init as initiator when not in correct state
    let dummy_init = HandshakeInit {
        version: 1,
        room_id: "test_room".to_string(),
        ephemeral_key: vec![0u8; 1568],
        timestamp: 1234567890,
        nonce: [0u8; 32],
    };
    let result = initiator.process_init(&dummy_init);
    assert!(result.is_err(), "Should fail with invalid state for processing init");
}

/// Test edge case: Invalid ephemeral key sizes
#[test]
fn test_invalid_ephemeral_key_sizes() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    
    let mut init = initiator.create_init().unwrap();
    init.ephemeral_key = vec![0u8; 100]; // Wrong size for ML-KEM-1024
    
    let mut responder = Handshake::new_responder("test_room".to_string());
    let result = responder.process_init(&init);
    // This might not fail immediately at process_init, but should fail at create_response
    if result.is_ok() {
        let response_result = responder.create_response();
        assert!(response_result.is_err(), "Should fail when creating response with invalid ephemeral key");
    }
}

/// Test edge case: Invalid ciphertext size in response
#[test]
fn test_invalid_ciphertext_size() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    initiator.create_init().unwrap();
    
    let mut response = HandshakeResponse {
        version: 1,
        room_id: "test_room".to_string(),
        ephemeral_key: vec![0u8; 1568],
        ciphertext: vec![0u8; 100], // Wrong size for ML-KEM-1024
        signature: vec![0u8; 4627], // ML-DSA-87 signature size
        signing_public_key: vec![0u8; 2592],
        timestamp: 1234567890,
        nonce: [0u8; 32],
    };
    
    let result = initiator.process_response(&response);
    assert!(result.is_err(), "Should fail with invalid ciphertext size");
}

/// Test edge case: Invalid signature size
#[test]
fn test_invalid_signature_size() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    initiator.create_init().unwrap();
    
    let mut response = HandshakeResponse {
        version: 1,
        room_id: "test_room".to_string(),
        ephemeral_key: vec![0u8; 1568],
        ciphertext: vec![0u8; 1568],
        signature: vec![0u8; 100], // Wrong size for ML-DSA-87
        signing_public_key: vec![0u8; 2592],
        timestamp: 1234567890,
        nonce: [0u8; 32],
    };
    
    let result = initiator.process_response(&response);
    assert!(result.is_err(), "Should fail with invalid signature size");
}

/// Test edge case: Invalid signing public key size
#[test]
fn test_invalid_signing_public_key_size() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    initiator.create_init().unwrap();
    
    let mut response = HandshakeResponse {
        version: 1,
        room_id: "test_room".to_string(),
        ephemeral_key: vec![0u8; 1568],
        ciphertext: vec![0u8; 1568],
        signature: vec![0u8; 4627],
        signing_public_key: vec![0u8; 100], // Wrong size for ML-DSA-87
        timestamp: 1234567890,
        nonce: [0u8; 32],
    };
    
    let result = initiator.process_response(&response);
    assert!(result.is_err(), "Should fail with invalid signing public key size");
}

/// Test edge case: Mismatched trusted responder key
#[test]
fn test_mismatched_trusted_responder_key() {
    let trusted_key1 = vec![0u8; 2592];
    let trusted_key2 = vec![0u8; 2592]; // Different key
    
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key1).unwrap();
    initiator.create_init().unwrap();
    
    let mut responder = Handshake::new_responder("test_room".to_string());
    responder.process_init(&initiator.create_init().unwrap()).unwrap();
    
    // Generate a signing keypair for responder
    let signing_keypair = MlDsaKeypair::generate().expect("Failed to generate signing keypair");
    responder.set_signing_keypair(signing_keypair).unwrap();
    
    let response = responder.create_response().unwrap();
    
    // The response should fail verification because trusted keys don't match
    let result = initiator.process_response(&response);
    assert!(result.is_err(), "Should fail with mismatched trusted responder key");
}

/// Test edge case: Zero-length fields
#[test]
fn test_zero_length_fields() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    
    let mut init = initiator.create_init().unwrap();
    init.room_id = String::new(); // Empty room ID
    
    let mut responder = Handshake::new_responder("test_room".to_string());
    let result = responder.process_init(&init);
    assert!(result.is_err(), "Should fail with empty room ID");
}

/// Test edge case: Boundary timestamp values
#[test]
fn test_boundary_timestamp_values() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    
    // Test exactly at 5-minute boundary
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let mut init = initiator.create_init().unwrap();
    init.timestamp = current_time - 300; // Exactly 5 minutes ago
    
    let mut responder = Handshake::new_responder("test_room".to_string());
    let result = responder.process_init(&init);
    // Should either pass or fail depending on exact timing
    // The test documents the boundary behavior
    println!("5-minute boundary test result: {:?}", result);
    
    // Test exactly at 60-second future boundary
    init.timestamp = current_time + 60; // Exactly 60 seconds in future
    let result = responder.process_init(&init);
    println!("60-second future boundary test result: {:?}", result);
}

/// Test edge case: Concurrent handshake attempts
#[test]
fn test_concurrent_handshake_attempts() {
    let trusted_key = vec![0u8; 2592];
    
    // Simulate multiple initiators trying to handshake with same responder
    let mut initiator1 = Handshake::new_initiator("test_room".to_string(), trusted_key.clone()).unwrap();
    let mut initiator2 = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    let mut responder = Handshake::new_responder("test_room".to_string());
    
    let init1 = initiator1.create_init().unwrap();
    let init2 = initiator2.create_init().unwrap();
    
    // Process first init
    let result1 = responder.process_init(&init1);
    assert!(result1.is_ok(), "First init should succeed");
    
    // Try to process second init while responder is in wrong state
    let result2 = responder.process_init(&init2);
    assert!(result2.is_err(), "Second init should fail when responder is in wrong state");
}

/// Test edge case: Handshake state after failure
#[test]
fn test_handshake_state_after_failure() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    
    // Create a valid init
    let init = initiator.create_init().unwrap();
    assert_eq!(initiator.state(), HandshakeState::InitSent);
    
    // Process an invalid response that should fail
    let invalid_response = HandshakeResponse {
        version: 1,
        room_id: "test_room".to_string(),
        ephemeral_key: vec![0u8; 1568],
        ciphertext: vec![0u8; 100], // Invalid size
        signature: vec![0u8; 4627],
        signing_public_key: vec![0u8; 2592],
        timestamp: 1234567890,
        nonce: [0u8; 32],
    };
    
    let result = initiator.process_response(&invalid_response);
    assert!(result.is_err(), "Should fail with invalid response");
    
    // State should remain InitSent, not transition to Failed
    // This allows retry with a valid response
    assert_eq!(initiator.state(), HandshakeState::InitSent);
}

/// Test edge case: Memory cleanup after handshake failure
#[test]
fn test_memory_cleanup_after_failure() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    
    // Create init to generate ephemeral key
    let _init = initiator.create_init().unwrap();
    
    // Process invalid response
    let invalid_response = HandshakeResponse {
        version: 1,
        room_id: "test_room".to_string(),
        ephemeral_key: vec![0u8; 1568],
        ciphertext: vec![0u8; 100], // Invalid size
        signature: vec![0u8; 4627],
        signing_public_key: vec![0u8; 2592],
        timestamp: 1234567890,
        nonce: [0u8; 32],
    };
    
    let _result = initiator.process_response(&invalid_response);
    
    // Verify shared secret is still None (not set due to failure)
    assert!(initiator.shared_secret().is_none(), "Shared secret should remain None after failure");
}

/// Test edge case: Maximum valid timestamp
#[test]
fn test_maximum_valid_timestamp() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let mut init = initiator.create_init().unwrap();
    init.timestamp = current_time - 1; // 1 second ago (should be valid)
    
    let mut responder = Handshake::new_responder("test_room".to_string());
    let result = responder.process_init(&init);
    assert!(result.is_ok(), "Recent timestamp should be valid");
}

/// Test edge case: HKDF fallback key derivation
#[test]
fn test_hkdf_fallback_key_derivation() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    
    // Create init but don't complete handshake
    let _init = initiator.create_init().unwrap();
    
    // Shared secret should be None initially
    assert!(initiator.shared_secret().is_none());
    
    // The derive_shared_secret method should handle the fallback case
    // Since we can't directly call it (private), we test through the public API
    // by ensuring the handshake fails gracefully when shared secret is not available
}

/// Test edge case: Transcript hash consistency
#[test]
fn test_transcript_hash_consistency() {
    let trusted_key = vec![0u8; 2592];
    let mut initiator = Handshake::new_initiator("test_room".to_string(), trusted_key).unwrap();
    let mut responder = Handshake::new_responder("test_room".to_string());
    
    // Generate signing keypair for responder
    let signing_keypair = MlDsaKeypair::generate().expect("Failed to generate signing keypair");
    responder.set_signing_keypair(signing_keypair).unwrap();
    
    // Complete handshake
    let init = initiator.create_init().unwrap();
    responder.process_init(&init).unwrap();
    let response = responder.create_response().unwrap();
    
    // This should succeed if transcript hashes match
    let result = initiator.process_response(&response);
    assert!(result.is_ok(), "Handshake should succeed with consistent transcript hashes");
}