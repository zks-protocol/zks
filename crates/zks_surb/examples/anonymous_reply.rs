//! Anonymous Reply Example
//!
//! This example demonstrates how to use SURBs (Single-Use Reply Blocks)
//! for anonymous bidirectional communication in ZKS Protocol.
//!
//! Run with: cargo run --example anonymous_reply

use zks_surb::{
    ZksSurb, ReplyRequest, SurbEncryption, SurbConfig,
};
use zks_pqcrypto::ml_kem::MlKem;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ZKS Anonymous Reply (SURB) Example ===\n");

    // Scenario: Alice wants Bob to be able to reply anonymously

    // 1. Alice generates her ML-KEM keypair
    println!("1. Alice generates ML-KEM keypair...");
    let alice_keypair = MlKem::generate_keypair()?;
    println!("   ✅ Public key: {} bytes", alice_keypair.public_key().len());

    // 2. Alice creates a SURB for Bob
    println!("\n2. Alice creates a SURB...");
    let (surb, private_data) = ZksSurb::create(alice_keypair.public_key())?;
    
    println!("   SURB ID: {}", surb.id().to_hex());
    println!("   Encapsulated key: {} bytes", surb.encapsulated_key().len());
    println!("   Route header: {} bytes", surb.route_header().len());
    println!("   Lifetime: {} seconds", surb.lifetime);
    println!("   ✅ SURB created successfully!");

    // 3. Alice keeps the private data (encryption key)
    println!("\n3. Alice keeps private data...");
    println!("   ⚠️ Encryption key is NEVER sent to Bob");
    println!("   Alice will use this to decrypt Bob's reply");

    // 4. Alice sends SURB to Bob (via Faisal Swarm)
    println!("\n4. Alice sends SURB to Bob...");
    let surb_bytes = surb.to_bytes()?;
    println!("   Serialized SURB: {} bytes", surb_bytes.len());
    println!("   (In production: sent through Faisal Swarm circuit)");

    // 5. Bob receives SURB and creates anonymous reply
    println!("\n5. Bob receives SURB and prepares reply...");
    let received_surb = ZksSurb::from_bytes(&surb_bytes)?;
    
    // Verify SURB is still valid
    if !received_surb.is_valid() {
        println!("   ❌ SURB is expired or already used!");
        return Ok(());
    }
    println!("   ✅ SURB is valid");

    // Bob creates reply content
    let reply_content = b"Hello Alice! This is my anonymous reply.";
    println!("   Reply content: {:?}", String::from_utf8_lossy(reply_content));

    // 6. Bob encrypts the reply using the SURB
    println!("\n6. Bob encrypts the reply...");
    
    // Bob needs to derive encryption key from encapsulated key
    // In this example, we simulate Bob decapsulating the key
    let bob_encryption = simulate_bob_encryption(&received_surb)?;
    let encrypted_reply = bob_encryption.encrypt(reply_content)?;
    
    println!("   Encrypted reply nonce: {} bytes", encrypted_reply.nonce.len());
    println!("   Encrypted ciphertext: {} bytes", encrypted_reply.ciphertext.len());
    println!("   ✅ Reply encrypted (ChaCha20-Poly1305)");

    // 7. Bob sends encrypted reply through SURB route
    println!("\n7. Bob sends reply through SURB route...");
    println!("   Route: Exit → Middle → Guard → Alice");
    println!("   (Uses Faisal Swarm onion routing)");

    // 8. Alice receives and decrypts the reply
    println!("\n8. Alice decrypts the reply...");
    let alice_encryption = SurbEncryption::new(private_data.encryption_key);
    let decrypted = alice_encryption.decrypt(&encrypted_reply)?;
    
    println!("   Decrypted reply: {:?}", String::from_utf8_lossy(&decrypted));
    println!("   ✅ Anonymous reply received successfully!");

    // 9. SURB is now marked as used
    println!("\n9. SURB usage tracking...");
    let mut used_surb = received_surb;
    used_surb.mark_used();
    println!("   SURB marked as used: {}", used_surb.is_used());
    println!("   ⚠️ Each SURB can only be used ONCE");

    // Summary
    println!("\n=== Example Complete ===");
    println!("\nSURB provides:");
    println!("  • Anonymous replies (Bob doesn't know Alice's identity)");
    println!("  • Post-quantum security (ML-KEM key encapsulation)");
    println!("  • Single-use (prevents replay attacks)");
    println!("  • Time-limited (configurable expiry)");
    println!("  • Faisal Swarm integration (onion routing)");

    Ok(())
}

/// Simulate Bob's side of the encryption
/// 
/// In a real implementation, Bob would:
/// 1. Decapsulate the ML-KEM ciphertext to get shared secret
/// 2. Derive encryption key from shared secret
/// 
/// For this example, we use a fixed key derivation
fn simulate_bob_encryption(surb: &ZksSurb) -> Result<SurbEncryption, Box<dyn std::error::Error>> {
    use sha2::{Sha256, Digest};
    
    // Derive key from encapsulated key (simulated)
    // In production, Bob would decapsulate using his private key
    let mut hasher = Sha256::new();
    hasher.update(b"zks-surb-encryption-key");
    hasher.update(surb.encapsulated_key());
    let result = hasher.finalize();
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    
    Ok(SurbEncryption::new(key))
}
