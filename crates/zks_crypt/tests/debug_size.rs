use zks_crypt::wasif_vernam::WasifVernam;

#[test]
fn debug_size_calculation() {
    let key = [1u8; 32];
    let mut cipher = WasifVernam::new(key).unwrap();
    
    let plaintext_sizes = vec![64, 128, 256];
    
    for size in plaintext_sizes {
        let plaintext = vec![0x42u8; size];
        println!("Plaintext size: {}", plaintext.len());
        
        let encrypted = cipher.encrypt(&plaintext).unwrap();
        println!("Encrypted size: {}", encrypted.len());
        println!("Size difference: {}", encrypted.len() - plaintext.len());
        println!("---");
    }
}