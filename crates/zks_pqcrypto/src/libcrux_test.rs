//! Test file to verify libcrux-ml-kem ML-KEM-1024 with incremental feature
//! This is a verification file, not a permanent part of the codebase.

#[cfg(feature = "libcrux-test")]
#[cfg(test)]
mod libcrux_verification {
    use libcrux_ml_kem::mlkem1024::incremental;
    use rand::{CryptoRng, Rng};
    use rand_core::OsRng;

    #[test]
    fn test_incremental_mlkem1024_api_exists() {
        // Verify types exist
        let _ct1_size: usize = incremental::Ciphertext1::len();
        let _ct2_size: usize = incremental::Ciphertext2::len();
        let _pk1_size: usize = incremental::pk1_len();
        let _pk2_size: usize = incremental::pk2_len();
        
        println!("ML-KEM-1024 Incremental API verified:");
        println!("  Ciphertext1 size: {} bytes", _ct1_size);
        println!("  Ciphertext2 size: {} bytes", _ct2_size);
        println!("  PublicKey1 (header) size: {} bytes", _pk1_size);
        println!("  PublicKey2 (ek) size: {} bytes", _pk2_size);
    }

    #[test]
    fn test_incremental_mlkem1024_round_trip() {
        let mut rng = OsRng;
        
        // Generate keypair with split public key
        let keypair = incremental::generate_keypair(
            rand::random::<[u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE]>()
        );
        
        // Phase 1: encapsulate with header only
        let (ct1, encaps_state, ss1) = incremental::encapsulate1(
            &keypair.public_key_1(),
            rand::random::<[u8; 32]>()
        ).expect("encapsulate1 failed");
        
        // Phase 2: complete encapsulation with full public key
        let ct2 = incremental::encapsulate2(
            &keypair.public_key_2(),
            &encaps_state
        );
        
        // Decapsulate
        let ss2 = incremental::decapsulate_compressed_key(
            keypair.private_key_bytes(),
            &ct1,
            &ct2
        );
        
        assert_eq!(ss1.as_ref(), ss2.as_ref(), "Shared secrets must match");
        println!("ML-KEM-1024 incremental round-trip: SUCCESS");
    }
}
