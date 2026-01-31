//! ZKS Protocol Cryptographic Primitives
//! 
//! This crate provides the core cryptographic primitives used by the ZKS Protocol,
//! including the Wasif Vernam cipher, anti-replay protection, ciphertext scrambling,
//! key rotation, and TRUE Vernam mode for information-theoretic security.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod anti_replay;
pub mod constant_time;
pub mod drand;
/// Entropy block storage and management for ZKS Protocol
pub mod entropy_block;
/// Entropy provider trait for abstraction
pub mod entropy_provider;
/// Hybrid TRUE OTP: Information-theoretic security for any file size
pub mod hybrid_otp;
pub mod recursive_chain;
pub mod scramble;
pub mod session_rotation;
pub mod true_entropy;
pub mod true_vernam;
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