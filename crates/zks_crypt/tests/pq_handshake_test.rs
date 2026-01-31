use zks_pqcrypto::MlKem;
use zks_crypt::wasif_vernam::WasifVernam;

/// Test 1: ML-KEM Key Generation
/// Verify ML-KEM keypair generation produces correct key sizes
#[test]
fn test_ml_kem_key_generation() {
    let keypair = MlKem::generate_keypair().expect("Failed to generate ML-KEM keypair");
    
    // ML-KEM-1024 public key should be 1568 bytes (upgraded from ML-KEM-768's 1184)
    assert_eq!(keypair.public_key.len(), 1568, "Public key should be 1568 bytes");
    
    // ML-KEM-1024 secret key should be 3168 bytes (upgraded from ML-KEM-768's 2400)
    assert_eq!(keypair.secret_key().len(), 3168, "Secret key should be 3168 bytes");
    
    // Keys should not be all zeros (sanity check)
    assert!(!keypair.public_key.iter().all(|&b| b == 0), "Public key should not be all zeros");
    assert!(!keypair.secret_key().iter().all(|&b| b == 0), "Secret key should not be all zeros");
}

/// Test 2: ML-KEM Encapsulation and Decapsulation
/// Test the complete ML-KEM key exchange workflow
#[test]
fn test_ml_kem_encapsulation_decapsulation() {
    // Alice generates keypair
    let alice_keypair = MlKem::generate_keypair().expect("Failed to generate Alice's keypair");
    let alice_public_key = alice_keypair.public_key.clone();
    let alice_secret_key = alice_keypair.secret_key().to_vec();
    
    // Bob encapsulates using Alice's public key
    let bob_encapsulation = MlKem::encapsulate(&alice_public_key)
        .expect("Failed to encapsulate");
    
    // Verify encapsulation produces correct sizes
    assert_eq!(bob_encapsulation.ciphertext.len(), 1568, "Ciphertext should be 1568 bytes (ML-KEM-1024)");
    assert_eq!(bob_encapsulation.shared_secret.len(), 32, "Shared secret should be 32 bytes");
    
    // Alice decapsulates using her secret key and Bob's ciphertext
    let alice_shared_secret = MlKem::decapsulate(&bob_encapsulation.ciphertext, &alice_secret_key)
        .expect("Failed to decapsulate");
    
    // Both should have the same shared secret
    assert_eq!(
        bob_encapsulation.shared_secret.as_ref() as &[u8],
        alice_shared_secret.as_ref() as &[u8],
        "Shared secrets should match"
    );
}

/// Test 3: ML-KEM Shared Secret Randomness
/// Verify that shared secrets appear statistically random
#[test]
fn test_ml_kem_shared_secret_randomness() {
    let mut shared_secrets = Vec::new();
    
    // Generate multiple shared secrets
    for _ in 0..10 {
        let keypair = MlKem::generate_keypair().expect("Failed to generate keypair");
        let encapsulation = MlKem::encapsulate(&keypair.public_key)
            .expect("Failed to encapsulate");
        shared_secrets.push(encapsulation.shared_secret);
    }
    
    // All shared secrets should be different (high probability)
    let mut unique_secrets = std::collections::HashSet::new();
    for secret in &shared_secrets {
        unique_secrets.insert(secret.as_ref() as &[u8]);
    }
    
    // With 10 random 32-byte secrets, probability of collision is negligible
    assert_eq!(unique_secrets.len(), 10, "All shared secrets should be unique");
    
    // Test statistical randomness of first secret
    let first_secret = &shared_secrets[0];
    let ones: u32 = first_secret.iter().map(|b: &u8| b.count_ones()).sum();
    let total_bits = (first_secret.len() * 8) as f64;
    let ratio = ones as f64 / total_bits;
    
    // Should be close to 50% for good randomness
    assert!((ratio - 0.5).abs() < 0.2, "Shared secret should appear random: {:.4}", ratio);
}

/// Test 4: Post-Quantum Handshake Integration
/// Test ML-KEM integration with Wasif-Vernam cipher
#[test]
fn test_post_quantum_handshake_integration() {
    // Simulate a post-quantum handshake between two parties
    
    // Alice generates keypair
    let alice_keypair = MlKem::generate_keypair().expect("Failed to generate Alice's keypair");
    let alice_public_key = alice_keypair.public_key.clone();
    
    // Bob encapsulates using Alice's public key
    let bob_encapsulation = MlKem::encapsulate(&alice_public_key)
        .expect("Failed to encapsulate");
    
    // Alice decapsulates to get shared secret
    let alice_shared_secret = MlKem::decapsulate(
        &bob_encapsulation.ciphertext,
        alice_keypair.secret_key()
    ).expect("Failed to decapsulate");
    
    // Both parties now have the same shared secret
    let shared_secret_bytes = alice_shared_secret.as_ref() as &[u8];
    
    // Use shared secret to derive encryption keys for Wasif-Vernam
    let mut alice_cipher = WasifVernam::new([0u8; 32]).expect("Failed to create cipher");
    let mut bob_cipher = WasifVernam::new([0u8; 32]).expect("Failed to create cipher");
    
    // Enable SEQUENCED Vernam mode using the shared secret (desync-resistant)
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&shared_secret_bytes[..32]);
    
    alice_cipher.enable_sequenced_vernam(seed);
    bob_cipher.enable_sequenced_vernam(seed);
    
    // Test encrypted communication using sequenced mode
    let message = b"Post-quantum secure message";
    let encrypted = alice_cipher.encrypt_sequenced(message).expect("Encryption failed");
    let decrypted = bob_cipher.decrypt_sequenced(&encrypted).expect("Decryption failed");
    
    assert_eq!(decrypted, message.to_vec(), "Post-quantum encrypted communication should work");
}

/// Test 5: ML-KEM Error Handling
/// Test error handling for invalid inputs
#[test]
fn test_ml_kem_error_handling() {
    // Test encapsulation with invalid public key size
    let invalid_public_key = vec![0u8; 100]; // Wrong size
    let result = MlKem::encapsulate(&invalid_public_key);
    assert!(result.is_err(), "Should fail with invalid public key size");
    
    // Test decapsulation with invalid inputs
    let valid_keypair = MlKem::generate_keypair().expect("Failed to generate keypair");
    
    // Invalid ciphertext size
    let invalid_ciphertext = vec![0u8; 100]; // Wrong size
    let result = MlKem::decapsulate(&invalid_ciphertext, valid_keypair.secret_key());
    assert!(result.is_err(), "Should fail with invalid ciphertext size");
    
    // Invalid secret key size
    let invalid_secret_key = vec![0u8; 100]; // Wrong size
    let valid_ciphertext = vec![0u8; 1568]; // Correct size for ML-KEM-1024
    let result = MlKem::decapsulate(&valid_ciphertext, &invalid_secret_key);
    assert!(result.is_err(), "Should fail with invalid secret key size");
}

/// Test 6: ML-KEM Performance Baseline
/// Basic performance test for ML-KEM operations
#[test]
fn test_ml_kem_performance_baseline() {
    use std::time::Instant;
    
    // Measure key generation time
    let start = Instant::now();
    let keypair = MlKem::generate_keypair().expect("Failed to generate keypair");
    let keygen_time = start.elapsed();
    
    // Measure encapsulation time
    let start = Instant::now();
    let encapsulation = MlKem::encapsulate(&keypair.public_key)
        .expect("Failed to encapsulate");
    let encaps_time = start.elapsed();
    
    // Measure decapsulation time
    let start = Instant::now();
    let _shared_secret = MlKem::decapsulate(&encapsulation.ciphertext, keypair.secret_key())
        .expect("Failed to decapsulate");
    let decaps_time = start.elapsed();
    
    // Basic sanity checks - operations should complete reasonably quickly
    // (exact thresholds depend on hardware, so we just check they're not extremely slow)
    assert!(keygen_time.as_millis() < 1000, "Key generation should complete within 1 second");
    assert!(encaps_time.as_millis() < 100, "Encapsulation should complete within 100ms");
    assert!(decaps_time.as_millis() < 100, "Decapsulation should complete within 100ms");
    
    println!("ML-KEM Performance:");
    println!("  Key generation: {:?}", keygen_time);
    println!("  Encapsulation: {:?}", encaps_time);
    println!("  Decapsulation: {:?}", decaps_time);
}

/// Test 7: Post-Quantum Forward Secrecy
/// Test that compromising one session doesn't affect future sessions
#[test]
fn test_post_quantum_forward_secrecy() {
    // Generate two different ML-KEM keypairs (simulating different sessions)
    let keypair1 = MlKem::generate_keypair().expect("Failed to generate first keypair");
    let keypair2 = MlKem::generate_keypair().expect("Failed to generate second keypair");
    
    // First session
    let encapsulation1 = MlKem::encapsulate(&keypair1.public_key)
        .expect("Failed to encapsulate first session");
    let shared_secret1 = MlKem::decapsulate(&encapsulation1.ciphertext, keypair1.secret_key())
        .expect("Failed to decapsulate first session");
    
    // Second session
    let encapsulation2 = MlKem::encapsulate(&keypair2.public_key)
        .expect("Failed to encapsulate second session");
    let shared_secret2 = MlKem::decapsulate(&encapsulation2.ciphertext, keypair2.secret_key())
        .expect("Failed to decapsulate second session");
    
    // Shared secrets should be different
    assert_ne!(
        shared_secret1.as_ref() as &[u8],
        shared_secret2.as_ref() as &[u8],
        "Different sessions should produce different shared secrets"
    );
    
    // Compromising first session's secret key shouldn't reveal second session's shared secret
    // (This is a conceptual test - in practice, each session uses fresh keypairs)
    assert_ne!(keypair1.secret_key(), keypair2.secret_key(), 
        "Different sessions should use different keypairs");
}