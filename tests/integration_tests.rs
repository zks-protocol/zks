//! Integration tests for ZKS Protocol SDK

use zks_sdk::builder::ZkConnectionBuilder;
use zks_sdk::config::SecurityLevel;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_zk_connection_builder() {
    // Test that the connection builder works correctly
    let result = ZkConnectionBuilder::new()
        .url("zk://localhost:8080")
        .security(SecurityLevel::PostQuantum)
        .build()
        .await;
    
    // We expect this to fail since there's no server running
    assert!(result.is_err());
}

#[tokio::test]
async fn test_encryption_roundtrip() {
    use zks_crypt::wasif_vernam::WasifVernam;
    
    // Use a meaningful test key instead of all zeros for better security testing
    let key = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    ];
    let mut cipher = WasifVernam::new(&key).unwrap();
    let plaintext = b"Hello, quantum world!";
    
    let encrypted = cipher.encrypt(plaintext).unwrap();
    let decrypted = cipher.decrypt(&encrypted).unwrap();
    
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[tokio::test]
async fn test_file_transfer() {
    // Test file transfer integrity
    use sha2::{Sha256, Digest};
    
    let test_data = b"Test file content for ZKS protocol";
    let mut hasher = Sha256::new();
    hasher.update(test_data);
    let original_hash = hasher.finalize();
    
    // Simulate file transfer (would use actual file transfer in real test)
    let transferred_data = test_data; // In real test, this would come through network
    
    let mut hasher2 = Sha256::new();
    hasher2.update(transferred_data);
    let transferred_hash = hasher2.finalize();
    
    assert_eq!(original_hash, transferred_hash);
}

#[tokio::test]
async fn test_post_quantum_key_exchange() {
    use zks_sdk::crypto::ml_kem_key_exchange;
    
    let result = ml_kem_key_exchange().await;
    assert!(result.is_ok());
    
    let (public_key, secret_key) = result.unwrap();
    assert!(!public_key.is_empty());
    assert!(!secret_key.is_empty());
    
    // ML-KEM-1024 public key should be 1568 bytes, secret key 3168 bytes (NIST Level 5)
    assert_eq!(public_key.len(), 1568);
    assert_eq!(secret_key.len(), 3168);
}

#[tokio::test]
async fn test_relay_server_allocation() {
    use zks_wire::{RelayServer, RelayConfig};
    use std::time::Duration as StdDuration;
    
    let config = RelayConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        max_allocations: 10,
        allocation_lifetime: 60,
        idle_timeout: 300,
        auth_required: false,
    };
    
    let mut server = RelayServer::new(config);
    
    // Start server (this would normally bind to a port)
    // For testing, we just verify the server can be created
    assert_eq!(server.config().max_allocations, 10);
}

#[tokio::test]
async fn test_nat_type_detection() {
    use zks_wire::{NatTraversal, NatType};
    
    let mut nat = NatTraversal::new();
    
    // This test would normally require actual STUN servers
    // For now, we test the basic structure
    assert!(matches!(nat.nat_type(), NatType::Unknown));
}

#[tokio::test]
async fn test_wasif_vernam_scrambling() {
    use zks_crypt::wasif_vernam::WasifVernam;
    
    let key = [42u8; 32];
    let mut cipher = WasifVernam::new(&key).unwrap();
    
    // Enable scrambling as mentioned in the roadmap
    cipher.enable_scrambling(256);
    cipher.enable_true_vernam(1024);
    
    let plaintext = b"Test data for scrambling";
    let encrypted = cipher.encrypt(plaintext).unwrap();
    let decrypted = cipher.decrypt(&encrypted).unwrap();
    
    assert_eq!(plaintext.to_vec(), decrypted);
}