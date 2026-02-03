//! ML-KEM-1024 Incremental API for bandwidth-efficient ratcheting
//!
//! This module provides a two-phase encapsulation API that enables
//! bandwidth savings through ciphertext reuse in ratcheted protocols.
//!
//! Uses seed-based randomness to avoid rand version conflicts.

use libcrux_ml_kem::mlkem1024::incremental;
use rand::RngCore;
use zeroize::Zeroize;

// ============================================================================
// Constants
// ============================================================================

/// Size of Ciphertext1 in bytes
pub const CIPHERTEXT1_SIZE: usize = incremental::Ciphertext1::len();

/// Size of Ciphertext2 in bytes
pub const CIPHERTEXT2_SIZE: usize = incremental::Ciphertext2::len();

/// Size of the header (pk1) in bytes
pub const HEADER_SIZE: usize = incremental::pk1_len();

/// Size of the encapsulation key (pk2) in bytes
pub const ENCAPSULATION_KEY_SIZE: usize = incremental::pk2_len();

/// Size of the shared secret
pub const SHARED_SECRET_SIZE: usize = 32;

/// Size of the encapsulation state
pub const ENCAPS_STATE_SIZE: usize = incremental::encaps_state_len();

// ============================================================================
// Types
// ============================================================================

/// Ciphertext part 1
pub type Ciphertext1 = Vec<u8>;

/// Ciphertext part 2
pub type Ciphertext2 = Vec<u8>;

/// Encapsulation state
pub type EncapsulationState = Vec<u8>;

/// Header (pk1)
pub type Header = Vec<u8>;

/// Encapsulation key (pk2)
pub type EncapsulationKey = Vec<u8>;

/// Decapsulation key
pub type DecapsulationKey = Vec<u8>;

/// Shared secret
pub type Secret = Vec<u8>;

/// Generated keypair with split public key components
#[derive(Debug)]
pub struct Keys {
    /// Encapsulation key (pk2)
    pub ek: EncapsulationKey,
    /// Decapsulation key
    pub dk: DecapsulationKey,
    /// Header (pk1)
    pub hdr: Header,
}

impl Zeroize for Keys {
    fn zeroize(&mut self) {
        self.ek.zeroize();
        self.dk.zeroize();
        self.hdr.zeroize();
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ============================================================================
// Core Functions
// ============================================================================

/// Validate that an encapsulation key matches its header
pub fn ek_matches_header(ek: &EncapsulationKey, hdr: &Header) -> bool {
    incremental::validate_pk_bytes(hdr, ek).is_ok()
}

/// Generate a new keypair and associated header.
/// 
/// Uses OS random number generator for seed.
pub fn generate() -> Keys {
    let mut seed = [0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    
    let key_pair = incremental::KeyPairCompressedBytes::from_seed(seed);
    
    // Zeroize seed after use
    seed.zeroize();
    
    Keys {
        hdr: key_pair.pk1().to_vec(),
        ek: key_pair.pk2().to_vec(),
        dk: key_pair.sk().to_vec(),
    }
}

/// Generate a new keypair from a seed (for deterministic key generation).
pub fn generate_from_seed(seed: &[u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE]) -> Keys {
    let key_pair = incremental::KeyPairCompressedBytes::from_seed(*seed);
    
    Keys {
        hdr: key_pair.pk1().to_vec(),
        ek: key_pair.pk2().to_vec(),
        dk: key_pair.sk().to_vec(),
    }
}

/// Encapsulate phase 1: use header only.
/// 
/// Uses OS random for encapsulation randomness.
pub fn encaps1(hdr: &Header) -> Result<(Ciphertext1, EncapsulationState, Secret), &'static str> {
    // Generate random encapsulation seed
    let mut randomness = [0u8; SHARED_SECRET_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut randomness);
    
    let mut encaps_state = vec![0u8; ENCAPS_STATE_SIZE];
    let mut shared_secret = vec![0u8; SHARED_SECRET_SIZE];
    
    // Use the non-rng version with explicit randomness
    let ct1 = incremental::encapsulate1(
        hdr,
        randomness,
        &mut encaps_state,
        &mut shared_secret,
    ).map_err(|_| "encapsulate1 failed")?;
    
    // Zeroize randomness
    randomness.zeroize();
    
    Ok((ct1.value.to_vec(), encaps_state, shared_secret))
}

/// Encapsulate phase 2: complete with full public key.
pub fn encaps2(ek: &EncapsulationKey, es: &EncapsulationState) -> Result<Ciphertext2, &'static str> {
    let es_arr: &[u8; ENCAPS_STATE_SIZE] = es.as_slice()
        .try_into()
        .map_err(|_| "invalid encaps state size")?;
    let ek_arr: &[u8; ENCAPSULATION_KEY_SIZE] = ek.as_slice()
        .try_into()
        .map_err(|_| "invalid ek size")?;
    
    let ct2 = incremental::encapsulate2(es_arr, ek_arr);
    Ok(ct2.value.to_vec())
}

/// Decapsulate ciphertext to get shared secret.
pub fn decaps(dk: &DecapsulationKey, ct1: &Ciphertext1, ct2: &Ciphertext2) -> Result<Secret, &'static str> {
    let ct1_arr: [u8; CIPHERTEXT1_SIZE] = ct1.as_slice()
        .try_into()
        .map_err(|_| "invalid ct1 size")?;
    let ct2_arr: [u8; CIPHERTEXT2_SIZE] = ct2.as_slice()
        .try_into()
        .map_err(|_| "invalid ct2 size")?;
    
    let ct1 = incremental::Ciphertext1 { value: ct1_arr };
    let ct2 = incremental::Ciphertext2 { value: ct2_arr };
    
    let dk_arr: &[u8; incremental::COMPRESSED_KEYPAIR_LEN] = dk.as_slice()
        .try_into()
        .map_err(|_| "invalid dk size")?;
    
    let ss = incremental::decapsulate_compressed_key(dk_arr, &ct1, &ct2);
    Ok(ss.to_vec())
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get the total bytes per ratchet step
pub const fn total_ratchet_bytes() -> usize {
    CIPHERTEXT1_SIZE + CIPHERTEXT2_SIZE
}

/// Get bandwidth savings vs naive ML-KEM-1024
pub fn bandwidth_savings_percent() -> f64 {
    const NAIVE_BYTES: usize = 1568 + 1568;
    let incremental = total_ratchet_bytes();
    if incremental >= NAIVE_BYTES { 0.0 }
    else { ((NAIVE_BYTES - incremental) as f64 / NAIVE_BYTES as f64) * 100.0 }
}

/// Print size information
pub fn print_sizes() {
    println!("ML-KEM-1024 Incremental Sizes:");
    println!("  Header: {} bytes", HEADER_SIZE);
    println!("  EK: {} bytes", ENCAPSULATION_KEY_SIZE);
    println!("  CT1: {} bytes", CIPHERTEXT1_SIZE);
    println!("  CT2: {} bytes", CIPHERTEXT2_SIZE);
    println!("  State: {} bytes", ENCAPS_STATE_SIZE);
    println!("  Total per-ratchet: {} bytes", total_ratchet_bytes());
    println!("  Savings vs naive: {:.1}%", bandwidth_savings_percent());
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sizes() {
        print_sizes();
        assert!(HEADER_SIZE > 0);
        assert!(ENCAPSULATION_KEY_SIZE > 0);
        assert!(CIPHERTEXT1_SIZE > 0);
        assert!(CIPHERTEXT2_SIZE > 0);
    }
    
    #[test]
    fn test_keypair() {
        let keys = generate();
        assert_eq!(keys.hdr.len(), HEADER_SIZE);
        assert_eq!(keys.ek.len(), ENCAPSULATION_KEY_SIZE);
    }
    
    #[test]
    fn incremental_round_trip() {
        let keys = generate();
        let (ct1, es, ss1) = encaps1(&keys.hdr).expect("encaps1");
        let ct2 = encaps2(&keys.ek, &es).expect("encaps2");
        let ss2 = decaps(&keys.dk, &ct1, &ct2).expect("decaps");
        assert_eq!(ss1, ss2);
    }
    
    #[test]
    fn test_ek_header_match() {
        let keys = generate();
        assert!(ek_matches_header(&keys.ek, &keys.hdr));
        
        let keys2 = generate();
        assert!(!ek_matches_header(&keys.ek, &keys2.hdr));
    }
}
