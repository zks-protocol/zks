//! Minimal test to verify Phase 5 integration works
//! 
//! This test runs directly in zks_crypt to avoid the compilation issues in zks_wire.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use crate::high_entropy_cipher::SynchronizedVernamBuffer;
    use crate::drand::DrandEntropy;
    use crate::entropy_provider::{DirectDrandProvider, EntropyProvider};

    #[tokio::test]
    async fn test_phase5_integration_minimal() {
        // Create a drand client
        let drand_client = Arc::new(DrandEntropy::new());
        
        // Create a direct drand provider (this simulates what EntropyGridProvider would do)
        let entropy_provider = Arc::new(DirectDrandProvider::new(drand_client));
        
        // Create TrueVernam buffer with entropy provider (Phase 5 integration)
        let shared_seed = [42u8; 32];
        let starting_round = 1000;
        
        let vernam_buffer = SynchronizedVernamBuffer::new_with_entropy_provider(
            shared_seed,
            starting_round,
            entropy_provider.clone(),
        );
        
        // Test basic functionality using XOR encryption/decryption
        let plaintext = b"Hello, Phase 5 Integration!";
        
        // Encrypt: XOR plaintext with keystream
        let keystream = vernam_buffer.consume(plaintext.len()).await;
        let mut encrypted = plaintext.to_vec();
        for (i, byte) in encrypted.iter_mut().enumerate() {
            *byte ^= keystream[i];
        }
        
        // Create a second buffer with identical configuration for decryption
        // This simulates the receiver having the same shared seed and configuration
        let vernam_buffer_decrypt = SynchronizedVernamBuffer::new_with_entropy_provider(
            shared_seed,
            starting_round,
            entropy_provider,
        );
        
        // Decrypt: XOR ciphertext with synchronized keystream from the second buffer
        let keystream_decrypt = vernam_buffer_decrypt.consume(plaintext.len()).await;
        let mut decrypted = encrypted.clone();
        for (i, byte) in decrypted.iter_mut().enumerate() {
            *byte ^= keystream_decrypt[i];
        }
        
        assert_eq!(plaintext.to_vec(), decrypted);
        println!("✅ Phase 5 Integration Test Passed: TrueVernam with Entropy Provider");
    }

    #[tokio::test]
    #[ignore = "Requires external drand network - run with --ignored"]
    async fn test_entropy_provider_fetch_round() {
        // Create a drand client
        let drand_client = Arc::new(DrandEntropy::new());
        
        // Create a direct drand provider
        let entropy_provider = Arc::new(DirectDrandProvider::new(drand_client));
        
        // Test fetching a round
        let round = entropy_provider.fetch_round(1000).await.unwrap();
        assert_eq!(round.round, 1000);
        assert_eq!(round.randomness.len(), 32);
        
        println!("✅ Entropy Provider Test Passed: Round {} fetched successfully", round.round);
    }
}