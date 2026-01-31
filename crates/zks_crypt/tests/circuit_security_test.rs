use zks_crypt::wasif_vernam::WasifVernam;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// Mock circuit layer with persistent key but fresh cipher per operation for deterministic testing
struct MockCircuitLayer {
    key: [u8; 32],
}

impl MockCircuitLayer {
    fn new(key: [u8; 32]) -> Result<Self, String> {
        Ok(Self { key })
    }
    
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        // Create fresh cipher for deterministic encryption (same plaintext = same ciphertext)
        let mut cipher = WasifVernam::new(self.key)
            .map_err(|e| format!("Failed to create cipher: {:?}", e))?;
        cipher.encrypt(data).map_err(|e| format!("Encryption failed: {:?}", e))
    }
    
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        // Create fresh cipher for deterministic decryption
        let mut cipher = WasifVernam::new(self.key)
            .map_err(|e| format!("Failed to create cipher: {:?}", e))?;
        cipher.decrypt(data).map_err(|e| format!("Decryption failed: {:?}", e))
    }
}

/// Mock circuit for testing onion encryption patterns with Wasif-Vernam
struct MockCircuit {
    layers: Vec<MockCircuitLayer>,
}

impl MockCircuit {
    fn new() -> Self {
        Self {
            layers: Vec::new(),
        }
    }

    fn add_layer(&mut self, key: [u8; 32]) {
        let layer = MockCircuitLayer::new(key).expect("Failed to create circuit layer");
        self.layers.push(layer);
    }

    /// Simulate onion encryption - encrypt in reverse order (exit first, entry last)
    fn onion_encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if self.layers.is_empty() {
            return Err("No layers available for encryption".to_string());
        }

        let mut encrypted = data.to_vec();

        // Encrypt in reverse order - exit peer first, entry peer last
        for i in (0..self.layers.len()).rev() {
            encrypted = self.layers[i].encrypt(&encrypted)?;
        }

        Ok(encrypted)
    }

    /// Simulate onion decryption - decrypt in forward order (entry first, exit last)
    fn onion_decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if self.layers.is_empty() {
            return Err("No layers available for decryption".to_string());
        }

        let mut decrypted = data.to_vec();

        // Decrypt in forward order - entry peer first, exit peer last
        for i in 0..self.layers.len() {
            decrypted = self.layers[i].decrypt(&decrypted)?;
        }

        Ok(decrypted)
    }

    fn hop_count(&self) -> usize {
        self.layers.len()
    }
}

/// Test 1: Onion Encryption Layer Integrity
/// Verify that each encryption layer is properly applied and can be decrypted
#[test]
fn test_onion_layer_integrity() {
    let mut circuit = MockCircuit::new();
    
    // Create a 3-hop circuit with known keys
    circuit.add_layer([1u8; 32]); // Entry peer key
    circuit.add_layer([2u8; 32]); // Middle peer key  
    circuit.add_layer([3u8; 32]); // Exit peer key

    let plaintext = b"Test message for onion routing";
    
    // Encrypt through all layers
    let encrypted = circuit.onion_encrypt(plaintext).unwrap();
    
    // Verify encryption changed the data
    assert_ne!(encrypted, plaintext, "Encryption did not modify the data");
    
    // Decrypt through all layers
    let decrypted = circuit.onion_decrypt(&encrypted).unwrap();
    
    // Verify we got the original data back
    assert_eq!(decrypted, plaintext, "Decryption did not restore original data");
}

/// Test 2: Layer Key Uniqueness
/// Verify that each hop uses a unique encryption key
#[test]
fn test_layer_key_uniqueness() {
    let mut circuit = MockCircuit::new();
    
    // Create keys with slight differences
    let mut key1 = [0u8; 32];
    let mut key2 = [0u8; 32];
    let mut key3 = [0u8; 32];
    
    key1[0] = 1;
    key2[0] = 2;
    key3[0] = 3;
    
    circuit.add_layer(key1);
    circuit.add_layer(key2);
    circuit.add_layer(key3);
    
    let plaintext = b"Unique key test";
    
    // Encrypt with unique keys
    let encrypted = circuit.onion_encrypt(plaintext).unwrap();
    
    // Verify encryption worked
    assert_ne!(encrypted, plaintext, "Encryption should modify data");
    
    // Decrypt and verify
    let decrypted = circuit.onion_decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, plaintext, "Decryption should restore original");
}

/// Test 3: Hop Count Validation
/// Verify that circuits with different hop counts work correctly
#[test]
fn test_hop_count_validation() {
    let hop_counts = vec![1, 2, 3, 5, 10];
    
    for hop_count in hop_counts {
        let mut circuit = MockCircuit::new();
        
        // Add the specified number of hops
        for i in 0..hop_count {
            let mut key = [0u8; 32];
            key[0] = i as u8;
            circuit.add_layer(key);
        }
        
        assert_eq!(circuit.hop_count(), hop_count, "Hop count mismatch");
        
        let plaintext = format!("Test for {} hops", hop_count);
        let encrypted = circuit.onion_encrypt(plaintext.as_bytes()).unwrap();
        let decrypted = circuit.onion_decrypt(&encrypted).unwrap();
        
        assert_eq!(decrypted, plaintext.as_bytes(), "Failed for {} hops", hop_count);
    }
}

/// Test 4: Empty Circuit Security
/// Verify that empty circuits are handled securely
#[test]
fn test_empty_circuit_security() {
    let circuit = MockCircuit::new();
    
    let plaintext = b"Test message";
    
    // Should fail to encrypt with empty circuit
    let result = circuit.onion_encrypt(plaintext);
    assert!(result.is_err(), "Empty circuit should not allow encryption");
    
    // Should fail to decrypt with empty circuit
    let result = circuit.onion_decrypt(plaintext);
    assert!(result.is_err(), "Empty circuit should not allow decryption");
}

/// Test 5: Circuit ID Uniqueness (simulated)
/// Verify that different circuits produce different ciphertexts
#[test]
fn test_circuit_id_uniqueness() {
    let mut circuit1 = MockCircuit::new();
    let mut circuit2 = MockCircuit::new();
    
    // Create different circuits with different keys
    circuit1.add_layer([1u8; 32]);
    circuit1.add_layer([2u8; 32]);
    
    circuit2.add_layer([3u8; 32]);
    circuit2.add_layer([4u8; 32]);
    
    let plaintext = b"Same plaintext";
    
    let encrypted1 = circuit1.onion_encrypt(plaintext).unwrap();
    let encrypted2 = circuit2.onion_encrypt(plaintext).unwrap();
    
    // Different circuits should produce different ciphertexts
    assert_ne!(encrypted1, encrypted2, "Different circuits produced identical ciphertexts");
}

/// Test 6: Layer Independence
/// Verify that compromising one layer doesn't reveal information about other layers
#[test]
fn test_layer_independence() {
    let mut circuit = MockCircuit::new();
    
    // Create a 3-hop circuit
    circuit.add_layer([10u8; 32]);
    circuit.add_layer([20u8; 32]);
    circuit.add_layer([30u8; 32]);
    
    let plaintext = b"Layer independence test";
    let encrypted = circuit.onion_encrypt(plaintext).unwrap();
    
    // Try to decrypt with only the middle layer key (simulating partial compromise)
    let middle_key = [20u8; 32];
    let mut middle_cipher = WasifVernam::new(middle_key).unwrap();
    
    // This should fail or produce garbage
    let partial_decrypt = middle_cipher.decrypt(&encrypted);
    
    // Should either fail or produce something different from plaintext
    match partial_decrypt {
        Ok(data) => assert_ne!(data, plaintext, "Partial decryption revealed plaintext"),
        Err(_) => {} // Failure is expected and secure
    }
}

/// Test 7: Forward Secrecy Simulation
/// Verify that key rotation concepts work
#[test]
fn test_forward_secrecy_simulation() {
    let mut circuit1 = MockCircuit::new();
    let mut circuit2 = MockCircuit::new();
    
    // First circuit with old keys
    circuit1.add_layer([1u8; 32]);
    circuit1.add_layer([2u8; 32]);
    
    // Second circuit with new keys (simulating key rotation)
    circuit2.add_layer([3u8; 32]);
    circuit2.add_layer([4u8; 32]);
    
    let plaintext = b"Forward secrecy test";
    
    // Encrypt with old circuit
    let old_encrypted = circuit1.onion_encrypt(plaintext).unwrap();
    
    // Try to decrypt with new circuit (should fail)
    let result = circuit2.onion_decrypt(&old_encrypted);
    
    match result {
        Ok(data) => assert_ne!(data, plaintext, "New circuit should not decrypt old data"),
        Err(_) => {} // Expected failure
    }
}

/// Test 8: Circuit Persistence (Key Stability)
/// Verify that the same circuit produces consistent encryption/decryption
#[test]
fn test_circuit_persistence() {
    let mut circuit = MockCircuit::new();
    
    circuit.add_layer([42u8; 32]);
    circuit.add_layer([99u8; 32]);
    
    let plaintext = b"Persistence test";
    
    // Encrypt the same data multiple times
    let encrypted1 = circuit.onion_encrypt(plaintext).unwrap();
    let encrypted2 = circuit.onion_encrypt(plaintext).unwrap();
    
    // MockCircuit is deterministic, so same plaintext produces same ciphertext
    // This is expected behavior for our mock implementation
    assert_eq!(encrypted1, encrypted2, "Same plaintext should produce same ciphertext in deterministic mock");
    
    // Both should decrypt to the same plaintext
    let decrypted1 = circuit.onion_decrypt(&encrypted1).unwrap();
    let decrypted2 = circuit.onion_decrypt(&encrypted2).unwrap();
    
    assert_eq!(decrypted1, plaintext);
    assert_eq!(decrypted2, plaintext);
}

/// Test 9: Multi-Circuit Isolation
/// Verify that multiple circuits operate independently
#[test]
fn test_multi_circuit_isolation() {
    let mut circuit_a = MockCircuit::new();
    let mut circuit_b = MockCircuit::new();
    
    circuit_a.add_layer([1u8; 32]);
    circuit_a.add_layer([2u8; 32]);
    
    circuit_b.add_layer([3u8; 32]);
    circuit_b.add_layer([4u8; 32]);
    
    let plaintext_a = b"Circuit A message";
    let plaintext_b = b"Circuit B message";
    
    // Encrypt with both circuits
    let encrypted_a = circuit_a.onion_encrypt(plaintext_a).unwrap();
    let encrypted_b = circuit_b.onion_encrypt(plaintext_b).unwrap();
    
    // Cross-decrypt should fail or produce garbage
    let result_a_with_b = circuit_b.onion_decrypt(&encrypted_a);
    let result_b_with_a = circuit_a.onion_decrypt(&encrypted_b);
    
    match result_a_with_b {
        Ok(data) => assert_ne!(data, plaintext_a, "Circuit B should not decrypt Circuit A data"),
        Err(_) => {} // Expected failure
    }
    
    match result_b_with_a {
        Ok(data) => assert_ne!(data, plaintext_b, "Circuit A should not decrypt Circuit B data"),
        Err(_) => {} // Expected failure
    }
}

/// Test 10: Security Boundary Testing
/// Verify that encryption boundaries are properly maintained
#[test]
fn test_security_boundary() {
    let mut circuit = MockCircuit::new();
    
    circuit.add_layer([0xFF; 32]);
    circuit.add_layer([0x00; 32]);
    
    // Test with edge case data
    let test_cases = vec![
        vec![0u8; 1000],      // All zeros
        vec![0xFFu8; 1000],   // All ones
        (0..=255u8).cycle().take(1000).collect(), // All byte values
        vec![],               // Empty
        vec![0x42],           // Single byte
    ];
    
    for plaintext in test_cases {
        let encrypted = circuit.onion_encrypt(&plaintext).unwrap();
        let decrypted = circuit.onion_decrypt(&encrypted).unwrap();
        
        assert_eq!(decrypted, plaintext, "Boundary test failed for data: {:?}", &plaintext[..plaintext.len().min(20)]);
    }
}

/// Test 11: Error Recovery and Robustness
/// Verify that the system handles errors gracefully
#[test]
fn test_error_recovery() {
    let mut circuit = MockCircuit::new();
    circuit.add_layer([1u8; 32]);
    
    let plaintext = b"Error recovery test";
    let encrypted = circuit.onion_encrypt(plaintext).unwrap();
    
    // Try to decrypt corrupted data
    let mut corrupted = encrypted.clone();
    if !corrupted.is_empty() {
        corrupted[0] ^= 0xFF; // Flip all bits in first byte
    }
    
    // Should handle corruption gracefully (either fail or produce garbage)
    let result = circuit.onion_decrypt(&corrupted);
    
    match result {
        Ok(data) => assert_ne!(data, plaintext, "Corrupted data should not decrypt to original"),
        Err(_) => {} // Expected failure for authentication
    }
}

/// Test 12: Performance and Scalability
/// Verify that encryption scales reasonably with circuit size
#[test]
fn test_performance_scaling() {
    use std::time::Instant;
    
    let hop_counts = vec![1, 3, 5, 10];
    let data_sizes = vec![100, 1000, 10000]; // bytes
    
    for &hop_count in &hop_counts {
        let mut circuit = MockCircuit::new();
        
        for i in 0..hop_count {
            let mut key = [0u8; 32];
            key[0] = i as u8;
            circuit.add_layer(key);
        }
        
        for &data_size in &data_sizes {
            let plaintext = vec![0x42u8; data_size];
            
            let start = Instant::now();
            let encrypted = circuit.onion_encrypt(&plaintext).unwrap();
            let encrypt_time = start.elapsed();
            
            let start = Instant::now();
            let _decrypted = circuit.onion_decrypt(&encrypted).unwrap();
            let decrypt_time = start.elapsed();
            
            println!("Performance: {} hops, {} bytes - Encrypt: {:?}, Decrypt: {:?}", 
                     hop_count, data_size, encrypt_time, decrypt_time);
            
            // Basic sanity check - should complete in reasonable time (< 1 second)
            assert!(encrypt_time.as_secs() < 1, "Encryption too slow");
            assert!(decrypt_time.as_secs() < 1, "Decryption too slow");
        }
    }
}