use wasm_bindgen::prelude::*;

// Re-export essential ZKS types
pub use zks_pqcrypto::ml_dsa::{MlDsa, MlDsaKeypair};

/// Utility functions for encryption/decryption and post-quantum crypto
#[wasm_bindgen]
pub struct ZksWasmUtils;

#[wasm_bindgen]
impl ZksWasmUtils {
    /// Generate a random 32-byte key
    #[wasm_bindgen]
    pub fn generate_key() -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        key.to_vec()
    }

    /// Generate a new ML-DSA keypair for post-quantum signatures
    #[wasm_bindgen]
    pub fn generate_ml_dsa_keypair() -> std::result::Result<JsValue, JsValue> {
        let keypair = MlDsa::generate_keypair()
            .map_err(|e| JsValue::from_str(&format!("Failed to generate keypair: {}", e)))?;
        
        let result = serde_wasm_bindgen::to_value(&serde_json::json!({
            "verifying_key": keypair.verifying_key(),
            "signing_key": keypair.signing_key()
        })).map_err(|e| JsValue::from_str(&format!("Failed to serialize keypair: {}", e)))?;
        
        Ok(result)
    }

    /// Sign data using ML-DSA (post-quantum signatures)
    #[wasm_bindgen]
    pub fn ml_dsa_sign(message: &[u8], signing_key: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
        MlDsa::sign(message, signing_key)
            .map_err(|e| JsValue::from_str(&format!("Failed to sign message: {}", e)))
    }

    /// Verify ML-DSA signature
    #[wasm_bindgen]
    pub fn ml_dsa_verify(message: &[u8], signature: &[u8], verifying_key: &[u8]) -> std::result::Result<(), JsValue> {
        MlDsa::verify(message, signature, verifying_key)
            .map_err(|e| JsValue::from_str(&format!("Signature verification failed: {}", e)))
    }
}

/// Quick ML-DSA keypair generation
#[wasm_bindgen]
pub fn quick_ml_dsa_keypair() -> std::result::Result<JsValue, JsValue> {
    ZksWasmUtils::generate_ml_dsa_keypair()
}