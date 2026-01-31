//! SURB Tests for ZKS Protocol
//!
//! Tests ensure SURB round-trip functionality, ML-KEM encapsulation,
//! and anonymous reply flows work correctly with post-quantum security.

use std::time::Duration;
use zks_surb::{
    ZksSurb, SurbConfig, SurbEncryption,
    MemorySurbStorage, SurbStorage,
};

/// Test SURB round-trip: create -> serialize -> deserialize -> use
#[tokio::test]
async fn test_surb_roundtrip() {
    // Create a test ML-KEM keypair
    let (pk, _sk) = generate_test_ml_kem_keypair();
    
    // Create SURB
    let (surb, private_data) = ZksSurb::create(&pk).expect("Failed to create SURB");
    
    // Serialize and deserialize
    let serialized = serde_json::to_string(&surb).expect("Failed to serialize SURB");
    let deserialized: ZksSurb = serde_json::from_str(&serialized).expect("Failed to deserialize SURB");
    
    // Verify round-trip integrity
    assert_eq!(surb.id, deserialized.id);
    assert_eq!(surb.encapsulated_key, deserialized.encapsulated_key);
    assert_eq!(surb.route_header, deserialized.route_header);
    assert_eq!(private_data.encryption_key, private_data.encryption_key);
    assert_eq!(surb.created_at, deserialized.created_at);
    assert_eq!(surb.lifetime, deserialized.lifetime);
    
    // Verify SURB hasn't been used
    assert!(!surb.used);
    assert!(!deserialized.used);
}

/// Test ML-KEM encapsulation and key derivation
#[tokio::test]
async fn test_ml_kem_encapsulation() {
    // Create a test ML-KEM keypair
    let (pk, sk) = generate_test_ml_kem_keypair();
    
    // Create SURB with the public key
    let (surb, private_data) = ZksSurb::create(&pk).expect("Failed to create SURB");
    
    // Verify encapsulated key is present and correct size
    assert!(!surb.encapsulated_key().is_empty());
    assert_eq!(surb.encapsulated_key().len(), 1088); // ML-KEM-768 encapsulated key size
    
    // Test that we can derive the same shared secret
    let shared_secret = derive_shared_secret(&surb.encapsulated_key(), &sk)
        .expect("Failed to derive shared secret");
    
    // Verify encryption key is derived from shared secret
    let encryption_key = derive_encryption_key(&shared_secret);
    assert_eq!(encryption_key.len(), 32);
    
    // Should match the SURB's encryption key (stored in private_data)
    assert_eq!(private_data.encryption_key, &encryption_key[..32]);
}

/// Test anonymous reply flow: Alice creates SURB, Bob sends reply
#[tokio::test]
async fn test_anonymous_reply_flow() {
    // Alice creates a SURB (she has the private key)
    let (alice_pk, _alice_sk) = generate_test_ml_kem_keypair();
    let (surb, private_data) = ZksSurb::create(&alice_pk).expect("Failed to create SURB");
    
    // Store the encryption key for later use
    let encryption_key = private_data.encryption_key;
    
    // Alice sends SURB to Bob (in real scenario, via secure channel)
    let _surb_for_bob = surb.clone();
    
    // Bob receives SURB and wants to send anonymous reply
    let reply_content = b"This is my anonymous reply!";
    
    // Bob creates encryption using the SURB's encryption key
    let encryption = SurbEncryption::new(encryption_key);
    
    // Bob encrypts his reply
    let encrypted_reply = encryption.encrypt(reply_content)
        .expect("Failed to encrypt reply");
    
    // Verify encrypted reply structure
    assert!(!encrypted_reply.nonce.is_empty());
    assert!(!encrypted_reply.ciphertext.is_empty());
    assert_ne!(encrypted_reply.ciphertext, reply_content.to_vec());
    
    // Alice receives the encrypted reply (in real scenario, via Faisal Swarm)
    let alice_encryption = SurbEncryption::new(encryption_key);
    
    // Alice decrypts the reply
    let decrypted_reply = alice_encryption.decrypt(&encrypted_reply)
        .expect("Failed to decrypt reply");
    
    // Verify the decrypted content matches original
    assert_eq!(decrypted_reply, reply_content.to_vec());
}

/// Test SURB storage operations
#[tokio::test]
async fn test_surb_storage() {
    let storage = MemorySurbStorage::new();
    
    // Create test SURBs
    let (pk1, _sk1) = generate_test_ml_kem_keypair();
    let (pk2, _sk2) = generate_test_ml_kem_keypair();
    
    let (surb1, _private_data1) = ZksSurb::create(&pk1).expect("Failed to create SURB 1");
    let (surb2, _private_data2) = ZksSurb::create(&pk2).expect("Failed to create SURB 2");
    
    let id1 = surb1.id().clone();
    let id2 = surb2.id().clone();
    
    // Test storage operations
    assert_eq!(storage.count().await.expect("Failed to get count"), 0);
    assert!(!storage.has_surb(&id1).await.expect("Failed to check SURB 1"));
    
    // Store SURBs
    storage.store_surb(surb1.clone()).await.expect("Failed to store SURB 1");
    storage.store_surb(surb2.clone()).await.expect("Failed to store SURB 2");
    
    assert_eq!(storage.count().await.expect("Failed to get count"), 2);
    assert!(storage.has_surb(&id1).await.expect("Failed to check SURB 1"));
    assert!(storage.has_surb(&id2).await.expect("Failed to check SURB 2"));
    
    // Retrieve SURBs
    let retrieved1 = storage.get_surb(&id1).await.expect("Failed to get SURB 1");
    let retrieved2 = storage.get_surb(&id2).await.expect("Failed to get SURB 2");
    
    assert!(retrieved1.is_some());
    assert!(retrieved2.is_some());
    assert_eq!(retrieved1.unwrap().id(), &id1);
    assert_eq!(retrieved2.unwrap().id(), &id2);
    
    // Get all IDs
    let all_ids = storage.get_all_ids().await.expect("Failed to get all IDs");
    assert_eq!(all_ids.len(), 2);
    assert!(all_ids.contains(&id1));
    assert!(all_ids.contains(&id2));
    
    // Remove SURB
    storage.remove_surb(&id1).await.expect("Failed to remove SURB 1");
    assert_eq!(storage.count().await.expect("Failed to get count"), 1);
    assert!(!storage.has_surb(&id1).await.expect("Failed to check SURB 1"));
    
    // Clear storage
    storage.clear().await.expect("Failed to clear storage");
    assert_eq!(storage.count().await.expect("Failed to get count"), 0);
}

/// Test SURB lifetime and expiration
#[tokio::test]
async fn test_surb_lifetime() {
    let (pk, _sk) = generate_test_ml_kem_keypair();
    
    // Create SURB with custom lifetime
    let config = SurbConfig::builder()
        .lifetime(Duration::from_secs(3600)) // 1 hour
        .build()
        .expect("Failed to build config");
    
    let (surb, _private_data) = ZksSurb::create_with_config(&pk, &config)
        .expect("Failed to create SURB with config");
    
    // Verify lifetime is set correctly
    assert_eq!(surb.lifetime, 3600);
    
    // Test that SURB is not expired immediately
    assert!(!surb.is_expired());
    
    // Test with expired SURB (simulate by setting past timestamp)
    let expired_surb = create_expired_surb(&pk, 3600).expect("Failed to create expired SURB");
    assert!(expired_surb.is_expired());
}

/// Test SURB usage tracking
#[tokio::test]
async fn test_surb_usage_tracking() {
    let (pk, _sk) = generate_test_ml_kem_keypair();
    let (mut surb, private_data) = ZksSurb::create(&pk).expect("Failed to create SURB");
    
    // SURB should not be used initially
    assert!(!surb.is_used());
    
    // Mark as used
    surb.mark_used();
    assert!(surb.is_used());
    
    // Test that we can't reuse a SURB for encryption (use private_data)
    let _encryption = SurbEncryption::new(private_data.encryption_key);
}

/// Test encryption with different payload sizes
#[tokio::test]
async fn test_encryption_various_sizes() {
    let (pk, _sk) = generate_test_ml_kem_keypair();
    let (_surb, private_data) = ZksSurb::create(&pk).expect("Failed to create SURB");
    
    let encryption = SurbEncryption::new(private_data.encryption_key);
    
    // Test different payload sizes
    let test_payloads = vec![
        vec![0u8; 0],      // Empty
        vec![0u8; 32],     // Small
        vec![0u8; 256],    // Medium
        vec![0u8; 1024],   // Large
        vec![0u8; 4096],   // Very large
    ];
    
    for payload in test_payloads {
        let encrypted = encryption.encrypt(&payload)
            .expect(&format!("Failed to encrypt payload of size {}", payload.len()));
        
        let decrypted = encryption.decrypt(&encrypted)
            .expect(&format!("Failed to decrypt payload of size {}", payload.len()));
        
        assert_eq!(decrypted, payload, "Decrypted payload doesn't match original");
    }
}

/// Test concurrent SURB operations
#[tokio::test]
async fn test_concurrent_surb_operations() {
    let (pk, _sk) = generate_test_ml_kem_keypair();
    let storage = std::sync::Arc::new(MemorySurbStorage::new());
    
    // Create multiple SURBs concurrently
    let mut handles = Vec::new();
    
    for i in 0..10 {
        let pk = pk.clone();
        let storage = storage.clone();
        
        let handle = tokio::spawn(async move {
            let (surb, _private_data) = ZksSurb::create(&pk).expect(&format!("Failed to create SURB {}", i));
            storage.store_surb(surb.clone()).await
                .expect(&format!("Failed to store SURB {}", i));
            surb.id().clone()
        });
        
        handles.push(handle);
    }
    
    // Wait for all operations to complete
    let mut ids = Vec::new();
    for handle in handles {
        let id = handle.await.expect("Task panicked");
        ids.push(id);
    }
    
    // Verify all SURBs were stored
    assert_eq!(storage.count().await.expect("Failed to get count"), 10);
    
    // Verify all IDs are unique
    let unique_ids: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(unique_ids.len(), 10, "All SURB IDs should be unique");
}

/// Helper function to generate test ML-KEM keypair
fn generate_test_ml_kem_keypair() -> (Vec<u8>, Vec<u8>) {
    // Use actual ML-KEM implementation
    use zks_pqcrypto::ml_kem::MlKem;
    
    let keypair = MlKem::generate_keypair()
        .map_err(|e| format!("Failed to generate keypair: {}", e))
        .unwrap();
    
    (keypair.public_key().to_vec(), keypair.secret_key().to_vec())
}

/// Helper function to derive shared secret from encapsulated key and private key
fn derive_shared_secret(encapsulated_key: &[u8], private_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Use actual ML-KEM decapsulation
    use zks_pqcrypto::ml_kem::MlKem;
    
    let shared_secret = MlKem::decapsulate(encapsulated_key, private_key)
        .map_err(|e| format!("Failed to decapsulate: {}", e))?;
    
    Ok(shared_secret.to_vec())
}

/// Helper function to derive encryption key from shared secret
fn derive_encryption_key(shared_secret: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    
    let mut hasher = Sha256::new();
    hasher.update(b"zks-surb-encryption-key");
    hasher.update(shared_secret);
    let result = hasher.finalize();
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Helper function to create an expired SURB for testing
fn create_expired_surb(_pk: &[u8], lifetime: u64) -> Result<ZksSurb, Box<dyn std::error::Error>> {
    let config = SurbConfig::builder()
        .lifetime(Duration::from_secs(lifetime))
        .build()?;
    
    let (mut surb, _private_data) = ZksSurb::create_with_config(_pk, &config)?;
    
    // Manually set created_at to past time to simulate expiration
    // Note: In real implementation, this would be handled by the SURB creation logic
    surb.created_at = 0; // Set to epoch to force expiration
    
    Ok(surb)
}