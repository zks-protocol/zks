//! WASM tests for ZKS Protocol

use wasm_bindgen_test::*;
use zks_wasm::{ZksWasmUtils, quick_ml_dsa_keypair};
use wasm_bindgen::JsValue;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_key_generation() {
    let key = ZksWasmUtils::generate_key();
    assert_eq!(key.len(), 32);
}

#[wasm_bindgen_test]
fn test_ml_dsa_keypair_generation() {
    let keypair = quick_ml_dsa_keypair().unwrap();
    
    // Convert JsValue to proper structure
    let keypair_obj = js_sys::Object::from(keypair);
    let signing_key = js_sys::Reflect::get(&keypair_obj, &JsValue::from_str("signing_key")).unwrap();
    let verifying_key = js_sys::Reflect::get(&keypair_obj, &JsValue::from_str("verifying_key")).unwrap();
    
    assert!(signing_key.as_string().unwrap().len() > 0);
    assert!(verifying_key.as_string().unwrap().len() > 0);
}

#[wasm_bindgen_test]
fn test_ml_dsa_sign_and_verify() {
    let message = b"Hello, WASM!";
    
    // Generate keypair
    let keypair = quick_ml_dsa_keypair().unwrap();
    let keypair_obj = js_sys::Object::from(keypair);
    let signing_key = js_sys::Reflect::get(&keypair_obj, &JsValue::from_str("signing_key")).unwrap();
    let verifying_key = js_sys::Reflect::get(&keypair_obj, &JsValue::from_str("verifying_key")).unwrap();
    
    // Convert hex strings to bytes
    let signing_key_hex = signing_key.as_string().unwrap();
    let signing_key_bytes = hex_to_bytes(&signing_key_hex);
    
    // Sign message
    let signature = ZksWasmUtils::ml_dsa_sign(message, &signing_key_bytes).unwrap();
    assert!(signature.len() > 0);
    
    // Convert verifying key to bytes
    let verifying_key_hex = verifying_key.as_string().unwrap();
    let verifying_key_bytes = hex_to_bytes(&verifying_key_hex);
    
    // Verify signature
    ZksWasmUtils::ml_dsa_verify(message, &signature, &verifying_key_bytes).unwrap();
}

#[wasm_bindgen_test]
fn test_ml_dsa_invalid_signature() {
    let message = b"Original message";
    let wrong_message = b"Wrong message";
    
    let keypair = quick_ml_dsa_keypair().unwrap();
    let keypair_obj = js_sys::Object::from(keypair);
    let signing_key = js_sys::Reflect::get(&keypair_obj, &JsValue::from_str("signing_key")).unwrap();
    let verifying_key = js_sys::Reflect::get(&keypair_obj, &JsValue::from_str("verifying_key")).unwrap();
    
    let signing_key_hex = signing_key.as_string().unwrap();
    let signing_key_bytes = hex_to_bytes(&signing_key_hex);
    
    let signature = ZksWasmUtils::ml_dsa_sign(message, &signing_key_bytes).unwrap();
    
    let verifying_key_hex = verifying_key.as_string().unwrap();
    let verifying_key_bytes = hex_to_bytes(&verifying_key_hex);
    
    // This should fail
    let result = ZksWasmUtils::ml_dsa_verify(wrong_message, &signature, &verifying_key_bytes);
    assert!(result.is_err());
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..hex.len() / 2 {
        let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        bytes.push(byte);
    }
    bytes
}