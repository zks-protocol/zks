//! ZKS Protocol Cryptographic Primitives
//! 
//! This crate provides the core cryptographic primitives used by the ZKS Protocol,
//! including the Wasif Vernam cipher, anti-replay protection, ciphertext scrambling,
//! key rotation, and 256-bit post-quantum computational security.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod anti_replay;
pub mod constant_time;
pub mod drand;
/// Entropy block storage and management for ZKS Protocol
pub mod entropy_block;
/// Entropy provider trait for abstraction
pub mod entropy_provider;
/// Erasure-coded ratchet for packet loss tolerance
pub mod erasure_ratchet;
/// Hybrid Computational Encryption: 256-bit post-quantum computational security for any file size
/// 
/// **SECURITY NOTE**: Despite the legacy "OTP" naming, this provides COMPUTATIONAL security,
/// NOT information-theoretic (Shannon) security. The entropy is derived from drand BLS signatures
/// and local CSPRNG, both of which are computationally secure.
/// 
/// **RENAMED**: This module was formerly `hybrid_otp`. The old name is deprecated.
#[path = "hybrid_computational.rs"]
pub mod hybrid_computational;
/// Backward compatibility alias for `hybrid_computational` (DEPRECATED - use `hybrid_computational`)
#[deprecated(since = "2.0.0", note = "Renamed to `hybrid_computational` to avoid misleading OTP terminology")]
pub use hybrid_computational as hybrid_otp;
/// Hybrid ratchet with ML-KEM asymmetric ratchet for break-in recovery
/// 
/// **COMPARISON TO SIGNAL**: Provides session-level forward secrecy (default 10 minutes).
/// Signal's Double Ratchet provides per-message forward secrecy. See module docs for details.
pub mod hybrid_ratchet;
pub mod recursive_chain;
pub mod scramble;
pub mod session_rotation;
pub mod true_entropy;
/// High-Entropy Computational Cipher: 256-bit post-quantum computational security
/// 
/// **SECURITY NOTE**: Despite the legacy "Vernam" naming, this provides COMPUTATIONAL security,
/// NOT information-theoretic (Shannon OTP) security.
/// 
/// **RENAMED**: This module was formerly `true_vernam`. The old name is deprecated.
#[path = "high_entropy_cipher.rs"]
pub mod high_entropy_cipher;
/// Backward compatibility alias for `high_entropy_cipher` (DEPRECATED - use `high_entropy_cipher`)
#[deprecated(since = "2.0.0", note = "Renamed to `high_entropy_cipher` to avoid misleading OTP terminology")]
pub use high_entropy_cipher as true_vernam;
pub mod wasif_vernam;

pub mod prelude;

#[cfg(test)]
mod phase5_test;

#[cfg(test)]
mod debug_tests {
    use crate::wasif_vernam::WasifVernam;
    
    #[test]
    fn test_wasif_new_debug() {
        let key = [0u8; 32];
        match WasifVernam::new(key) {
            Ok(_cipher) => println!("WasifVernam::new succeeded"),
            Err(e) => println!("WasifVernam::new failed: {:?}", e),
        }
    }
    
    #[test]
    fn test_wasif_encrypt_decrypt() {
        let key = [0x42; 32]; // Use a non-zero key
        let mut cipher = WasifVernam::new(key).unwrap();
        
        // Must set base_iv before encryption (required for bidirectional safety)
        cipher.derive_base_iv(&key, true);
        
        let plaintext = b"Hello, quantum world!";
        
        println!("Plaintext: {:?}", plaintext);
        println!("Plaintext len: {}", plaintext.len());
        
        match cipher.encrypt(plaintext) {
            Ok(encrypted) => {
                println!("Encrypted successfully, len: {}", encrypted.len());
                match cipher.decrypt(&encrypted) {
                    Ok(decrypted) => {
                        println!("Decrypted successfully: {:?}", decrypted);
                        assert_eq!(plaintext.to_vec(), decrypted);
                    },
                    Err(e) => {
                        println!("Decrypt failed: {:?}", e);
                        panic!("Decrypt failed");
                    }
                }
            },
            Err(e) => {
                println!("Encrypt failed: {:?}", e);
                panic!("Encrypt failed");
            }
        }
    }
}