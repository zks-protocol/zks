//! Unified cryptographic facade for ZKS SDK

use tracing::debug;
use zks_pqcrypto::ml_kem::MlKem;
use zks_pqcrypto::ml_dsa::MlDsa;

use crate::error::{Result, SdkError};

// Note: Insecure local WasifVernam implementation removed - use zks_crypt::wasif_vernam::WasifVernam instead

/// Session key derivation using HKDF
pub fn derive_session_key(
    shared_secret: &[u8],
    entropy: &[u8],
    info: &str,
) -> Result<[u8; 32]> {
    use sha2::Sha256;
    use hkdf::Hkdf;
    
    let hkdf = Hkdf::<Sha256>::new(Some(entropy), shared_secret);
    let mut key = [0u8; 32];
    
    hkdf.expand(info.as_bytes(), &mut key)
        .map_err(|e| SdkError::CryptoError(format!("HKDF expansion failed: {}", e).into()))?;
    
    debug!("Derived session key using HKDF");
    
    Ok(key)
}

/// Generate random bytes using TRUE entropy (drand + OsRng) for cryptographic operations
/// 
/// # Security
/// Uses TrueEntropy which combines drand beacon + local CSPRNG via XOR
/// for information-theoretic security. Unbreakable if ANY source is uncompromised.
pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>> {
    // SECURITY: Use TrueEntropy for information-theoretic security
    // Combines drand (BLS verified) + OsRng via XOR - unbreakable if either is secure
    use zks_crypt::true_entropy::get_sync_entropy;
    let bytes = get_sync_entropy(len);
    debug!("Generated {} TRUE random bytes (drand XOR OsRng)", len);
    Ok(bytes.to_vec())
}

/// Post-quantum key exchange using ML-KEM
pub async fn ml_kem_key_exchange() -> Result<(Vec<u8>, Vec<u8>)> {
    debug!("Performing ML-KEM key exchange");
    
    // Generate ML-KEM keypair using zks_pqcrypto
    let keypair = MlKem::generate_keypair()
        .map_err(|e| SdkError::CryptoError(format!("Failed to generate ML-KEM keypair: {}", e)))?;
    
    // Extract public and secret keys as bytes
    let public_key = keypair.public_key().to_vec();
    let secret_key = keypair.secret_key().to_vec();
    
    debug!("Generated ML-KEM keypair (public: {} bytes, secret: {} bytes)", public_key.len(), secret_key.len());
    
    Ok((public_key, secret_key))
}

/// Post-quantum signature generation using ML-DSA
pub async fn ml_dsa_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    debug!("Signing message with ML-DSA-87");
    
    // Validate secret key length
    const ML_DSA_SECRET_KEY_SIZE: usize = 4896; // ML-DSA-87 secret key size
    if secret_key.len() != ML_DSA_SECRET_KEY_SIZE {
        return Err(SdkError::CryptoError(
            format!("Invalid ML-DSA-87 secret key size: expected {} bytes, got {}", ML_DSA_SECRET_KEY_SIZE, secret_key.len()).into()
        ));
    }
    
    // Sign the message using the provided secret key
    let signature = MlDsa::sign(message, secret_key)
        .map_err(|e| SdkError::CryptoError(format!("Failed to sign message: {}", e)))?;
    
    debug!("Generated ML-DSA signature ({} bytes)", signature.len());
    
    Ok(signature)
}

/// Post-quantum signature verification using ML-DSA
pub async fn ml_dsa_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    debug!("Verifying ML-DSA signature");
    
    // Verify the signature using the public key
    let result = MlDsa::verify(message, signature, public_key);
    
    match result {
        Ok(()) => {
            debug!("ML-DSA signature verification successful");
            Ok(true)
        }
        Err(e) => {
            debug!("ML-DSA signature verification failed: {}", e);
            Ok(false)
        }
    }
}

/// Generate a new ML-DSA keypair
pub async fn ml_dsa_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    debug!("Generating ML-DSA keypair");
    
    let keypair = MlDsa::generate_keypair()
        .map_err(|e| SdkError::CryptoError(format!("Failed to generate ML-DSA keypair: {}", e)))?;
    
    let public_key = keypair.verifying_key.clone();
    let secret_key = keypair.signing_key().to_vec();
    
    debug!("Generated ML-DSA keypair (vk: {} bytes, sk: {} bytes)", public_key.len(), secret_key.len());
    
    Ok((public_key, secret_key))
}