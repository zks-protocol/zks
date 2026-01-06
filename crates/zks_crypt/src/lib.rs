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
pub mod recursive_chain;
pub mod scramble;
pub mod true_vernam;
pub mod wasif_vernam;

pub mod prelude;

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