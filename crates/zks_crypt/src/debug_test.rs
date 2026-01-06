#[cfg(test)]
mod test_debug {
    use super::*;
    
    #[test]
    fn test_wasif_new() {
        let key = [0u8; 32];
        match WasifVernam::new(key) {
            Ok(_cipher) => println!("WasifVernam::new succeeded"),
            Err(e) => println!("WasifVernam::new failed: {:?}", e),
        }
    }
}