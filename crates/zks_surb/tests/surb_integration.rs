use zks_surb::{ZksSurb, ReplyRequest, SurbConfig, surb_utils};
use zks_pqcrypto::ml_kem::MlKem;

#[tokio::test]
async fn test_surb_creation() {
    // Generate recipient keypair
    let recipient_keypair = MlKem::generate_keypair().unwrap();
    let recipient_pk = recipient_keypair.public_key();
    
    // Create SURB
    let (surb, _private_data) = ZksSurb::create(recipient_pk).unwrap();
    
    // Verify SURB properties
    assert_eq!(surb.encapsulated_key.len(), 1088); // ML-KEM-768 encapsulated key size
    assert!(!surb.used);
    assert!(surb.is_valid());
}

#[tokio::test]
async fn test_surb_with_config() {
    let recipient_keypair = MlKem::generate_keypair().unwrap();
    let recipient_pk = recipient_keypair.public_key();
    
    let config = SurbConfig::maximum_anonymity();
    let (surb, _private_data) = ZksSurb::create_with_config(recipient_pk, &config).unwrap();
    
    assert!(surb.is_valid());
    
    // Verify route header was created (should not be empty for 5 hops)
    assert!(!surb.route_header.is_empty(), "Route header should not be empty");
    assert!(surb.route_header.len() > 100, "Route header should be substantial for 5 hops");
}

#[tokio::test]
async fn test_reply_request() {
    let recipient_keypair = MlKem::generate_keypair().unwrap();
    let recipient_pk = recipient_keypair.public_key();
    
    let (surb, _private_data) = ZksSurb::create(recipient_pk).unwrap();
    let reply_content = b"Anonymous reply from Bob";
    
    let reply_request = ReplyRequest::from_surb(surb, reply_content).unwrap();
    
    assert_eq!(reply_request.content(), reply_content);
    assert!(reply_request.encrypted_reply().is_none()); // Not encrypted yet
}

#[tokio::test]
async fn test_reply_encryption() {
    let recipient_keypair = MlKem::generate_keypair().unwrap();
    let recipient_pk = recipient_keypair.public_key();
    
    let (surb, _private_data) = ZksSurb::create(recipient_pk).unwrap();
    let reply_content = b"Secret anonymous message";
    
    let mut reply_request = ReplyRequest::from_surb(surb, reply_content).unwrap();
    reply_request.encrypt_reply().unwrap();
    
    assert!(reply_request.encrypted_reply().is_some());
}

#[tokio::test]
async fn test_surb_serialization() {
    let recipient_keypair = MlKem::generate_keypair().unwrap();
    let recipient_pk = recipient_keypair.public_key();
    
    let (surb, _private_data) = ZksSurb::create(recipient_pk).unwrap();
    
    // Test bytes serialization
    let bytes = surb.to_bytes().unwrap();
    let deserialized = ZksSurb::from_bytes(&bytes).unwrap();
    assert_eq!(surb.id(), deserialized.id());
    
    // Test base64 serialization
    let base64 = surb.to_base64().unwrap();
    let deserialized = ZksSurb::from_base64(&base64).unwrap();
    assert_eq!(surb.id(), deserialized.id());
}

#[tokio::test]
async fn test_surb_expiration() {
    let recipient_keypair = MlKem::generate_keypair().unwrap();
    let recipient_pk = recipient_keypair.public_key();
    
    let config = SurbConfig::minimal_overhead(); // Short lifetime
    let (surb, _private_data) = ZksSurb::create_with_config(recipient_pk, &config).unwrap();
    
    assert!(surb.is_valid());
    
    // Mark as used
    let mut used_surb = surb.clone();
    used_surb.mark_used();
    assert!(!used_surb.is_valid());
}

#[tokio::test]
async fn test_multiple_surbs() {
    let recipient_keypair = MlKem::generate_keypair().unwrap();
    let recipient_pk = recipient_keypair.public_key();
    
    let (surbs, _private_data_list) = surb_utils::generate_surbs(5, recipient_pk).unwrap();
    
    assert_eq!(surbs.len(), 5);
    
    // Verify all SURBs are unique
    let ids: Vec<_> = surbs.iter().map(|s| s.id.clone()).collect();
    let unique_ids: std::collections::HashSet<_> = ids.iter().collect();
    assert_eq!(unique_ids.len(), 5);
}

#[tokio::test]
async fn test_surb_validation() {
    let recipient_keypair = MlKem::generate_keypair().unwrap();
    let recipient_pk = recipient_keypair.public_key();
    
    let (surbs, _private_data_list) = surb_utils::generate_surbs(3, recipient_pk).unwrap();
    let valid = surb_utils::validate_surbs(&surbs);
    
    assert_eq!(valid.len(), 3);
    assert!(valid.iter().all(|&v| v)); // All should be valid
}