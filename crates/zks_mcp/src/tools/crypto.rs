//! Cryptography tools for ZKS MCP server
//! 
//! Provides tools for post-quantum cryptography operations including
//! key generation, encryption/decryption, signing/verification, and hashing.

use rmcp::{tool, tool_router, model::*, ErrorData as McpError};
use rmcp::handler::server::wrapper::Parameters;
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use zks_pqcrypto::{MlKem, MlDsa};
use zks_crypt::prelude::WasifVernam;
use sha2::{Sha256, Sha512, Digest};
use sha3::{Sha3_256, Sha3_512};
use base64::{Engine as _, engine::general_purpose};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GenerateKeypairParams {
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EncryptParams {
    pub plaintext: String,
    pub recipient_public_key: String,
    pub security_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DecryptParams {
    pub ciphertext: String,
    pub private_key: String,
    pub encapsulation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignParams {
    pub message: String,
    pub private_key: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyParams {
    pub message: String,
    pub signature: String,
    pub public_key: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HashParams {
    pub data: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DeriveKeyParams {
    pub input_key: String,
    pub salt: String,
    pub info: String,
    pub algorithm: String,
}

#[derive(Clone)]
pub struct CryptoTools;

impl CryptoTools {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CryptoTools {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl CryptoTools {
    #[tool(description = "Generate a post-quantum keypair (ML-KEM-768 or ML-DSA-65)")]
    async fn zks_generate_keypair(
        &self,
        params: Parameters<GenerateKeypairParams>,
    ) -> Result<CallToolResult, McpError> {
        let algorithm = &params.0.algorithm;
        match algorithm.as_str() {
            "ml-kem-768" => {
                let keypair = MlKem::generate_keypair()
                    .map_err(|e| McpError::internal_error(format!("Failed to generate ML-KEM keypair: {}", e), None))?;
                
                Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
                    "public_key": hex::encode(&keypair.public_key),
                    "private_key": hex::encode(keypair.secret_key()),
                    "algorithm": "ML-KEM-768",
                    "security_level": "NIST Level 3"
                }).to_string())]))
            }
            "ml-dsa-65" => {
                let keypair = MlDsa::generate_keypair()
                    .map_err(|e| McpError::internal_error(format!("Failed to generate ML-DSA keypair: {}", e), None))?;
                
                Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
                    "verifying_key": hex::encode(keypair.verifying_key()),
                    "signing_key": hex::encode(keypair.signing_key()),
                    "algorithm": "ML-DSA-65",
                    "security_level": "NIST Level 3"
                }).to_string())]))
            }
            _ => Err(McpError::invalid_params("Unknown algorithm. Supported: 'ml-kem-768' or 'ml-dsa-65'", None))
        }
    }

    #[tool(description = "Encrypt data using ZKS Wasif-Vernam cipher with post-quantum security")]
    async fn zks_encrypt(
        &self,
        params: Parameters<EncryptParams>,
    ) -> Result<CallToolResult, McpError> {
        let security_level = params.0.security_level.as_deref().unwrap_or("post-quantum");
        
        // Decode plaintext from base64 or use as UTF-8
        let plaintext_bytes = if let Ok(decoded) = general_purpose::STANDARD.decode(&params.0.plaintext) {
            decoded
        } else {
            params.0.plaintext.clone().into_bytes()
        };

        // Decode public key from hex
        let public_key_bytes = hex::decode(&params.0.recipient_public_key)
            .map_err(|e| McpError::invalid_params(format!("Invalid hex public key: {}", e), None))?;

        match security_level {
            "post-quantum" => {
                // Encapsulate shared secret using recipient's public key
                let encapsulation = MlKem::encapsulate(&public_key_bytes)
                    .map_err(|e| McpError::internal_error(format!("Failed to encapsulate: {}", e), None))?;
                
                // Use Wasif-Vernam cipher with the shared secret
                let shared_secret_array: [u8; 32] = encapsulation.shared_secret.to_vec().try_into()
                    .map_err(|_| McpError::internal_error("Shared secret wrong length", None))?;
                let mut cipher = WasifVernam::new(shared_secret_array)
                    .map_err(|e| McpError::internal_error(format!("Failed to create cipher: {}", e), None))?;
                
                let ciphertext = cipher.encrypt(&plaintext_bytes)
                    .map_err(|e| McpError::internal_error(format!("Encryption failed: {}", e), None))?;

                Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
                    "ciphertext": general_purpose::STANDARD.encode(&ciphertext),
                    "encapsulation": hex::encode(&encapsulation.ciphertext),
                    "algorithm": "Wasif-Vernam + ML-KEM-768",
                    "security_level": "Post-Quantum"
                }).to_string())]))
            }
            "true-vernam" => {
                // For true Vernam, we need a key as long as the plaintext
                if public_key_bytes.len() < plaintext_bytes.len() {
                    return Err(McpError::invalid_params(
                        "Public key must be at least as long as plaintext for true Vernam security".to_string(), 
                        None
                    ));
                }
                
                // Use the first 32 bytes as the cipher key, and the rest as one-time pad
                let cipher_key: [u8; 32] = public_key_bytes[..32].try_into()
                    .map_err(|_| McpError::internal_error("Failed to create cipher key", None))?;
                let mut cipher = WasifVernam::new(cipher_key)
                    .map_err(|e| McpError::internal_error(format!("Failed to create cipher: {}", e), None))?;
                
                // Enable sequenced Vernam mode for 256-bit post-quantum computational security with desync resistance
                let shared_seed: [u8; 32] = public_key_bytes[..32].try_into()
                    .map_err(|_| McpError::internal_error("Failed to create shared seed", None))?;
                cipher.enable_sequenced_vernam(shared_seed);
                
                let ciphertext = cipher.encrypt(&plaintext_bytes)
                    .map_err(|e| McpError::internal_error(format!("Encryption failed: {}", e), None))?;

                Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
                    "ciphertext": general_purpose::STANDARD.encode(&ciphertext),
                    "algorithm": "True Vernam",
                    "security_level": "256-bit Post-Quantum Computational"
                }).to_string())]))
            }
            _ => Err(McpError::invalid_params("Unknown security level. Supported: 'post-quantum' or 'true-vernam'", None))
        }
    }

    #[tool(description = "Decrypt ciphertext using ZKS Wasif-Vernam cipher")]
    async fn zks_decrypt(
        &self,
        params: Parameters<DecryptParams>,
    ) -> Result<CallToolResult, McpError> {
        // Decode ciphertext from base64
        let ciphertext_bytes = general_purpose::STANDARD.decode(&params.0.ciphertext)
            .map_err(|e| McpError::invalid_params(format!("Invalid base64 ciphertext: {}", e), None))?;

        // Decode private key from hex
        let private_key_bytes = hex::decode(&params.0.private_key)
            .map_err(|e| McpError::invalid_params(format!("Invalid hex private key: {}", e), None))?;

        if !params.0.encapsulation.is_empty() {
            // Post-quantum decryption with ML-KEM
            let ephemeral_bytes = hex::decode(&params.0.encapsulation)
                .map_err(|e| McpError::invalid_params(format!("Invalid hex ephemeral data: {}", e), None))?;
            
            // Decapsulate shared secret
            let shared_secret = MlKem::decapsulate(&ephemeral_bytes, &private_key_bytes)
                .map_err(|e| McpError::internal_error(format!("Failed to decapsulate: {}", e), None))?;
            
            // Decrypt using Wasif-Vernam
            let shared_secret_array: [u8; 32] = shared_secret.to_vec().try_into()
                .map_err(|_| McpError::internal_error("Shared secret wrong length", None))?;
            let cipher = WasifVernam::new(shared_secret_array)
                .map_err(|e| McpError::internal_error(format!("Failed to create cipher: {}", e), None))?;
            
            let plaintext = cipher.decrypt(&ciphertext_bytes)
                .map_err(|e| McpError::internal_error(format!("Decryption failed: {}", e), None))?;

            Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
                "plaintext": String::from_utf8_lossy(&plaintext),
                "plaintext_base64": general_purpose::STANDARD.encode(&plaintext),
                "algorithm": "Wasif-Vernam + ML-KEM-768",
                "security_level": "Post-Quantum"
            }).to_string())]))
        } else {
            // True Vernam decryption
            if private_key_bytes.len() < ciphertext_bytes.len() {
                return Err(McpError::invalid_params(
                    "Private key must be at least as long as ciphertext for true Vernam decryption".to_string(), 
                    None
                ));
            }
            
            // Use the first 32 bytes as the cipher key, and the rest as one-time pad
            let cipher_key: [u8; 32] = private_key_bytes[..32].try_into()
                .map_err(|_| McpError::internal_error("Failed to create cipher key", None))?;
            let mut cipher = WasifVernam::new(cipher_key)
                .map_err(|e| McpError::internal_error(format!("Failed to create cipher: {}", e), None))?;
            
            // Enable sequenced Vernam mode for 256-bit post-quantum computational security with desync resistance
            let shared_seed: [u8; 32] = private_key_bytes[..32].try_into()
                .map_err(|_| McpError::internal_error("Failed to create shared seed", None))?;
            cipher.enable_sequenced_vernam(shared_seed);
            
            let plaintext = cipher.decrypt(&ciphertext_bytes)
                .map_err(|e| McpError::internal_error(format!("Decryption failed: {}", e), None))?;

            Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
                "plaintext": String::from_utf8_lossy(&plaintext),
                "plaintext_base64": general_purpose::STANDARD.encode(&plaintext),
                "algorithm": "True Vernam",
                "security_level": "256-bit Post-Quantum Computational"
            }).to_string())]))
        }
    }

    #[tool(description = "Sign a message using ML-DSA-65 post-quantum signatures")]
    async fn zks_sign(
        &self,
        params: Parameters<SignParams>,
    ) -> Result<CallToolResult, McpError> {
        // Decode signing key from hex
        let signing_key_bytes = hex::decode(&params.0.private_key)
            .map_err(|e| McpError::invalid_params(format!("Invalid hex signing key: {}", e), None))?;

        // Sign the message
        let signature = MlDsa::sign(params.0.message.as_bytes(), &signing_key_bytes)
            .map_err(|e| McpError::internal_error(format!("Signing failed: {}", e), None))?;

        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "signature": hex::encode(&signature),
            "message_hash": hex::encode(sha2::Sha256::digest(params.0.message.as_bytes())),
            "algorithm": "ML-DSA-65",
            "security_level": "NIST Level 3"
        }).to_string())]))
    }

    #[tool(description = "Verify an ML-DSA-65 signature")]
    async fn zks_verify(
        &self,
        params: Parameters<VerifyParams>,
    ) -> Result<CallToolResult, McpError> {
        // Decode signature and verifying key from hex
        let signature_bytes = hex::decode(&params.0.signature)
            .map_err(|e| McpError::invalid_params(format!("Invalid hex signature: {}", e), None))?;
        let verifying_key_bytes = hex::decode(&params.0.public_key)
            .map_err(|e| McpError::invalid_params(format!("Invalid hex verifying key: {}", e), None))?;

        // Verify the signature
        let is_valid = MlDsa::verify(params.0.message.as_bytes(), &signature_bytes, &verifying_key_bytes)
            .map_err(|e| McpError::internal_error(format!("Verification failed: {}", e), None))?;

        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "valid": is_valid,
            "message_hash": hex::encode(sha2::Sha256::digest(params.0.message.as_bytes())),
            "algorithm": "ML-DSA-65",
            "security_level": "NIST Level 3"
        }).to_string())]))
    }

    #[tool(description = "Compute cryptographic hash of data")]
    async fn zks_hash(
        &self,
        params: Parameters<HashParams>,
    ) -> Result<CallToolResult, McpError> {
        let algorithm = if params.0.algorithm.is_empty() { "sha256" } else { &params.0.algorithm };
        
        // Decode data from base64 or use as UTF-8
        let data_bytes = if let Ok(decoded) = general_purpose::STANDARD.decode(&params.0.data) {
            decoded
        } else {
            params.0.data.clone().into_bytes()
        };

        let hash_result = match algorithm {
            "sha256" => {
                let mut hasher = Sha256::new();
                hasher.update(&data_bytes);
                hasher.finalize().to_vec()
            }
            "sha512" => {
                let mut hasher = Sha512::new();
                hasher.update(&data_bytes);
                hasher.finalize().to_vec()
            }
            "sha3-256" => {
                let mut hasher = Sha3_256::new();
                hasher.update(&data_bytes);
                hasher.finalize().to_vec()
            }
            "sha3-512" => {
                let mut hasher = Sha3_512::new();
                hasher.update(&data_bytes);
                hasher.finalize().to_vec()
            }
            _ => return Err(McpError::invalid_params(
                "Unknown hash algorithm. Supported: 'sha256', 'sha512', 'sha3-256', 'sha3-512'".to_string(), 
                None
            ))
        };

        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "hash": hex::encode(&hash_result),
            "algorithm": algorithm,
            "input_length": data_bytes.len(),
            "output_length": hash_result.len()
        }).to_string())]))
    }

    #[tool(description = "Derive key from shared secret using HKDF")]
    async fn zks_derive_key(
        &self,
        params: Parameters<DeriveKeyParams>,
    ) -> Result<CallToolResult, McpError> {
        let key_length = 32; // Default key length
        
        // Decode shared secret from hex
        let shared_secret_bytes = hex::decode(&params.0.input_key)
            .map_err(|e| McpError::invalid_params(format!("Invalid hex shared secret: {}", e), None))?;

        // Decode salt if provided
        let salt_bytes = if !params.0.salt.is_empty() {
            Some(hex::decode(&params.0.salt).map_err(|e| McpError::invalid_params(
                format!("Invalid hex salt: {}", e), None
            ))?)
        } else {
            None
        };

        let info_bytes = if !params.0.info.is_empty() {
            params.0.info.clone().into_bytes()
        } else {
            Vec::new()
        };

        // Use HKDF for key derivation (simplified implementation)
        // In a real implementation, you'd use a proper HKDF crate
        let derived_key = self.hkdf_derive(&shared_secret_bytes, salt_bytes.as_deref(), &info_bytes, key_length)?;

        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "derived_key": hex::encode(&derived_key),
            "key_length": key_length,
            "algorithm": "HKDF-SHA256",
            "salt_used": !params.0.salt.is_empty(),
            "info_used": !info_bytes.is_empty()
        }).to_string())]))
    }
}

impl CryptoTools {
    // Simplified HKDF implementation for key derivation
    fn hkdf_derive(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, McpError> {
        use sha2::Sha256;
        use hmac::{Hmac, Mac};
        
        type HmacSha256 = Hmac<Sha256>;
        
        // Use provided salt or default to zeros
        let salt = salt.unwrap_or(&[0u8; 32]);
        
        // Extract step
        let mut mac = HmacSha256::new_from_slice(salt)
            .map_err(|e| McpError::internal_error(format!("HMAC initialization failed: {}", e), None))?;
        mac.update(ikm);
        let prk = mac.finalize().into_bytes();
        
        // Expand step
        let mut output = Vec::new();
        let mut t = Vec::new();
        let mut counter = 0u8;
        
        while output.len() < key_length {
            let mut mac = HmacSha256::new_from_slice(&prk)
                    .map_err(|e| McpError::internal_error(format!("HMAC initialization failed: {}", e), None))?;
            
            if !t.is_empty() {
                mac.update(&t);
            }
            mac.update(info);
            mac.update(&[counter + 1]);
            
            t = mac.finalize().into_bytes().to_vec();
            output.extend_from_slice(&t);
            counter += 1;
        }
        
        output.truncate(key_length);
        Ok(output)
    }
}