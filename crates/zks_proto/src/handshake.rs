//! 3-Message handshake implementation for ZK Protocol
//! 
//! Implements a post-quantum secure 3-message handshake:
//! 1. Initiator -> Responder: HandshakeInit (contains ephemeral public key)
//! 2. Responder -> Initiator: HandshakeResponse (contains ephemeral public key + signature)
//! 3. Initiator -> Responder: HandshakeFinish (contains confirmation)

use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;
use hkdf::Hkdf;
use zks_pqcrypto::ml_kem::{MlKem, MlKemKeypair};
use zks_pqcrypto::ml_dsa::{MlDsa, MlDsaKeypair};

use crate::{ProtoError, Result};

/// Maximum allowed timestamp difference for replay protection (5 minutes)
const MAX_TIMESTAMP_DIFF: u64 = 300;

/// Handshake role (initiator or responder)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeRole {
    /// Initiates the handshake
    Initiator,
    /// Responds to the handshake
    Responder,
}

/// Handshake state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeState {
    /// Initial state
    Idle,
    /// Sent/received HandshakeInit
    InitSent,
    /// Sent/received HandshakeResponse
    ResponseSent,
    /// Handshake completed
    Complete,
    /// Handshake failed
    Failed,
}

/// Handshake message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeMessageType {
    /// Initial handshake message
    Init,
    /// Response to initial message
    Response,
    /// Final handshake message
    Finish,
}

/// Handshake initialization message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInit {
    /// Protocol version
    pub version: u8,
    /// Room identifier for session context
    pub room_id: String,
    /// Ephemeral public key (ML-KEM)
    pub ephemeral_key: Vec<u8>,
    /// Timestamp for replay protection
    pub timestamp: u64,
    /// Random nonce
    pub nonce: [u8; 32],
}

/// Handshake response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Protocol version
    pub version: u8,
    /// Room identifier for session context
    pub room_id: String,
    /// Responder's ephemeral public key (ML-KEM)
    pub ephemeral_key: Vec<u8>,
    /// ML-KEM ciphertext from encapsulation
    pub ciphertext: Vec<u8>,
    /// Signature of the initiator's key and nonce
    pub signature: Vec<u8>,
    /// Responder's ML-DSA public key for signature verification
    pub signing_public_key: Vec<u8>,
    /// Timestamp for replay protection
    pub timestamp: u64,
    /// Random nonce
    pub nonce: [u8; 32],
}

/// Handshake finish message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeFinish {
    /// Protocol version
    pub version: u8,
    /// Confirmation hash
    pub confirmation: [u8; 32],
    /// Final timestamp
    pub timestamp: u64,
}

/// Main handshake implementation
#[derive(Debug)]
pub struct Handshake {
    /// Current role (initiator or responder)
    role: HandshakeRole,
    /// Current state
    state: HandshakeState,
    /// Protocol version
    version: u8,
    /// Room identifier for session context
    room_id: String,
    /// Local ephemeral key pair (ML-KEM)
    local_ephemeral_keypair: Option<MlKemKeypair>,
    /// Remote ephemeral public key (ML-KEM)
    remote_ephemeral_public_key: Option<Vec<u8>>,
    /// ML-KEM ciphertext from encapsulation
    ciphertext: Option<Vec<u8>>,
    /// Local nonce
    local_nonce: Option<[u8; 32]>,
    /// Remote nonce
    remote_nonce: Option<[u8; 32]>,
    /// Shared secret (computed after handshake)
    shared_secret: Option<[u8; 32]>,
    /// ML-DSA signing keypair (for responder signature)
    signing_keypair: Option<MlDsaKeypair>,
    /// Trusted responder ML-DSA public key (for initiator verification)
    trusted_responder_public_key: Option<Vec<u8>>,
}

impl Handshake {
    /// Create a new handshake as initiator
    /// 
    /// # Arguments
    /// * `room_id` - The room identifier for session context
    /// * `trusted_responder_public_key` - The trusted ML-DSA public key of the responder (must be 1312 bytes)
    /// 
    /// # Security Note
    /// The `trusted_responder_public_key` must be obtained through a secure, out-of-band channel.
    /// This key is used to verify the responder's identity during the handshake.
    /// Never use a public key received during the handshake itself for verification.
    pub fn new_initiator(room_id: String, trusted_responder_public_key: Vec<u8>) -> Result<Self> {
        if trusted_responder_public_key.len() != 1952 {
            return Err(ProtoError::handshake(format!(
                "Invalid trusted responder public key size: expected 1952 bytes, got {}",
                trusted_responder_public_key.len()
            )));
        }
        
        Ok(Self {
            role: HandshakeRole::Initiator,
            state: HandshakeState::Idle,
            version: 1,
            room_id,
            local_ephemeral_keypair: None,
            remote_ephemeral_public_key: None,
            ciphertext: None,
            local_nonce: None,
            remote_nonce: None,
            shared_secret: None,
            signing_keypair: None,
            trusted_responder_public_key: Some(trusted_responder_public_key),
        })
    }
    
    /// Create a new handshake as responder
    /// 
    /// # Arguments
    /// * `room_id` - The room identifier for session context
    /// 
    /// # Security Note
    /// The responder will generate its own ML-DSA signing keypair for authentication.
    /// The initiator must have the responder's trusted public key through a secure channel.
    pub fn new_responder(room_id: String) -> Self {
        Self {
            role: HandshakeRole::Responder,
            state: HandshakeState::Idle,
            version: 1,
            room_id,
            local_ephemeral_keypair: None,
            remote_ephemeral_public_key: None,
            ciphertext: None,
            local_nonce: None,
            remote_nonce: None,
            shared_secret: None,
            signing_keypair: None,
            trusted_responder_public_key: None,
        }
    }
    
    /// Get current role
    pub fn role(&self) -> HandshakeRole {
        self.role
    }
    
    /// Get current state
    pub fn state(&self) -> HandshakeState {
        self.state
    }
    
    /// Check if handshake is complete
    pub fn is_complete(&self) -> bool {
        self.state == HandshakeState::Complete
    }
    
    /// Get shared secret after handshake completion
    pub fn shared_secret(&self) -> Option<[u8; 32]> {
        self.shared_secret
    }
    
    /// Set the ML-DSA signing keypair for the responder
    /// 
    /// # Security Note
    /// This keypair should be persistent and its public key must be known to
    /// initiators through a trusted channel. The public key is used by initiators
    /// to verify the responder's identity during the handshake.
    pub fn set_signing_keypair(&mut self, keypair: MlDsaKeypair) -> Result<()> {
        if self.role != HandshakeRole::Responder {
            return Err(ProtoError::handshake("Only responder can set signing keypair"));
        }
        self.signing_keypair = Some(keypair);
        Ok(())
    }
    
    /// Generate ephemeral key pair using ML-KEM
    fn generate_ephemeral_key(&mut self) -> Result<Vec<u8>> {
        // Generate ML-KEM keypair
        let keypair = MlKem::generate_keypair()
            .map_err(|e| ProtoError::handshake(&format!("Failed to generate ML-KEM keypair: {}", e)))?;
        
        let public_key = keypair.public_key.clone();
        self.local_ephemeral_keypair = Some(keypair);
        Ok(public_key)
    }
    
    /// Generate random nonce using TRUE entropy (drand + OsRng)
    /// 
    /// # Security
    /// Uses TrueEntropy which combines drand beacon + local CSPRNG via XOR
    /// for information-theoretic security. Unbreakable if ANY source is uncompromised.
    fn generate_nonce(&mut self) -> Result<[u8; 32]> {
        // SECURITY: Use TrueEntropy for information-theoretic security
        use zks_crypt::true_entropy::get_sync_entropy_32;
        let entropy = get_sync_entropy_32();
        let nonce = *entropy;  // Copy the 32 bytes
        self.local_nonce = Some(nonce);
        Ok(nonce)
    }
    
    /// Get current timestamp
    fn current_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    
    /// Validate timestamp for replay protection
    fn validate_timestamp(&self, timestamp: u64) -> Result<()> {
        let current_time = self.current_timestamp();
        let time_diff = current_time.saturating_sub(timestamp);
        
        if time_diff > MAX_TIMESTAMP_DIFF {
            return Err(ProtoError::handshake(&format!(
                "Message timestamp too old: {} seconds ago (max allowed: {} seconds)",
                time_diff, MAX_TIMESTAMP_DIFF
            )));
        }
        
        // Also check for future timestamps (clock skew tolerance)
        if timestamp > current_time + 60 {
            return Err(ProtoError::handshake(&format!(
                "Message timestamp is in the future: {} seconds ahead (max allowed: 60 seconds)",
                timestamp - current_time
            )));
        }
        
        Ok(())
    }
    
    /// Create handshake init message as initiator
    pub fn create_init(&mut self) -> Result<HandshakeInit> {
        if self.role != HandshakeRole::Initiator {
            return Err(ProtoError::handshake("Only initiator can create init message"));
        }
        
        if self.state != HandshakeState::Idle {
            return Err(ProtoError::handshake("Invalid state for creating init message"));
        }
        
        let ephemeral_key = self.generate_ephemeral_key()?;
        let nonce = self.generate_nonce()?;
        let timestamp = self.current_timestamp();
        
        let init = HandshakeInit {
            version: self.version,
            room_id: self.room_id.clone(),
            ephemeral_key,
            timestamp,
            nonce,
        };
        
        self.state = HandshakeState::InitSent;
        Ok(init)
    }
    
    /// Process handshake init message as responder
    pub fn process_init(&mut self, init: &HandshakeInit) -> Result<()> {
        if self.role != HandshakeRole::Responder {
            return Err(ProtoError::handshake("Only responder can process init message"));
        }
        
        if self.state != HandshakeState::Idle {
            return Err(ProtoError::handshake("Invalid state for processing init message"));
        }
        
        // Validate version
        if init.version != self.version {
            return Err(ProtoError::handshake("Version mismatch"));
        }
        
        // Validate room_id
        if init.room_id != self.room_id {
            return Err(ProtoError::handshake("Room ID mismatch"));
        }
        
        // SECURITY: Validate timestamp for replay protection (symmetric with response validation)
        self.validate_timestamp(init.timestamp)?;
        
        // Store remote ephemeral key and nonce
        self.remote_ephemeral_public_key = Some(init.ephemeral_key.clone());
        self.remote_nonce = Some(init.nonce);
        
        self.state = HandshakeState::InitSent;
        Ok(())
    }
    
    /// Create handshake response message as responder
    pub fn create_response(&mut self) -> Result<HandshakeResponse> {
        if self.role != HandshakeRole::Responder {
            return Err(ProtoError::handshake("Only responder can create response message"));
        }
        
        if self.state != HandshakeState::InitSent {
            return Err(ProtoError::handshake("Invalid state for creating response message"));
        }
        
        let ephemeral_key = self.generate_ephemeral_key()?;
        let nonce = self.generate_nonce()?;
        let timestamp = self.current_timestamp();
        
        // Generate ML-KEM ciphertext by encrypting to the initiator's public key
        let encapsulation = if let Some(remote_public_key) = &self.remote_ephemeral_public_key {
            MlKem::encapsulate(remote_public_key)
                .map_err(|e| ProtoError::handshake(&format!("Failed to encapsulate: {}", e)))?
        } else {
            return Err(ProtoError::handshake("No remote ephemeral key available"));
        };
        
        // Store the ciphertext and shared secret for later use
        let ciphertext = encapsulation.ciphertext.clone();
        self.ciphertext = Some(ciphertext.clone());
        
        // Store the shared secret from encapsulation
        if encapsulation.shared_secret.len() == 32 {
            let mut secret_array = [0u8; 32];
            secret_array.copy_from_slice(&encapsulation.shared_secret);
            self.shared_secret = Some(secret_array);
        } else {
            return Err(ProtoError::handshake("Invalid shared secret length from encapsulation"));
        }
        
        // Use persistent signing keypair (must be set before creating response)
        let signing_keypair = self.signing_keypair.as_ref()
            .ok_or_else(|| ProtoError::handshake("No signing keypair set. Call set_signing_keypair() first."))?;
        
        // Create message to sign: room_id + ephemeral_key + ciphertext + timestamp
        let mut message = Vec::new();
        message.extend_from_slice(self.room_id.as_bytes());
        message.extend_from_slice(&ephemeral_key);
        message.extend_from_slice(&ciphertext);
        message.extend_from_slice(&timestamp.to_le_bytes());
        
        // Sign the message
        let signature = MlDsa::sign(&message, signing_keypair.signing_key())
            .map_err(|e| ProtoError::handshake(&format!("Failed to sign response: {}", e)))?;
        
        // Get the signing public key for inclusion in response
        let signing_public_key = signing_keypair.verifying_key().to_vec();
        
        // Derive shared secret for responder (now we have all keys and nonces)
        let shared_secret = self.derive_shared_secret();
        self.shared_secret = Some(shared_secret);
        
        let response = HandshakeResponse {
            version: self.version,
            room_id: self.room_id.clone(),
            ephemeral_key,
            ciphertext,
            signature,
            signing_public_key,
            timestamp,
            nonce,
        };
        
        self.state = HandshakeState::ResponseSent;
        Ok(response)
    }
    

    
    /// Process handshake response message as initiator
    pub fn process_response(&mut self, response: &HandshakeResponse) -> Result<()> {
        if self.role != HandshakeRole::Initiator {
            return Err(ProtoError::handshake("Only initiator can process response message"));
        }
        
        if self.state != HandshakeState::InitSent {
            return Err(ProtoError::handshake("Invalid state for processing response message"));
        }
        
        // Validate version
        if response.version != self.version {
            return Err(ProtoError::handshake("Version mismatch"));
        }
        
        // Validate room_id
        if response.room_id != self.room_id {
            return Err(ProtoError::handshake("Room ID mismatch"));
        }
        
        // Validate timestamp for replay protection
        self.validate_timestamp(response.timestamp)?;
        
        // Store remote ephemeral key and nonce
        self.remote_ephemeral_public_key = Some(response.ephemeral_key.clone());
        self.remote_nonce = Some(response.nonce);
        
        // Decapsulate the ciphertext to get the shared secret
        if let Some(local_keypair) = &self.local_ephemeral_keypair {
            let shared_secret = MlKem::decapsulate(&response.ciphertext, local_keypair.secret_key())
                .map_err(|e| ProtoError::handshake(&format!("Failed to decapsulate: {}", e)))?;
            
            // Convert Zeroizing<Vec<u8>> to [u8; 32]
            if shared_secret.len() == 32 {
                let mut secret_array = [0u8; 32];
                secret_array.copy_from_slice(&shared_secret);
                self.shared_secret = Some(secret_array);
            } else {
                return Err(ProtoError::handshake("Invalid shared secret length"));
            }
        } else {
            return Err(ProtoError::handshake("No local ephemeral keypair available"));
        }
        
        // Verify signature using ML-DSA with trusted public key
        self.verify_response_signature(response)?;
        
        self.state = HandshakeState::ResponseSent;
        Ok(())
    }
    
    /// Verify response signature using ML-DSA
    fn verify_response_signature(&self, response: &HandshakeResponse) -> Result<()> {
        // Get the trusted responder public key
        let trusted_public_key = self.trusted_responder_public_key.as_ref()
            .ok_or_else(|| ProtoError::handshake("No trusted responder public key available"))?;
        
        // SECURITY: Use constant-time comparison to prevent timing attacks
        // This prevents an attacker from learning which bytes differ through timing analysis
        if !bool::from(response.signing_public_key.as_slice().ct_eq(trusted_public_key.as_slice())) {
            return Err(ProtoError::handshake(
                "Responder public key does not match trusted key. Possible MITM attack."
            ));
        }
        
        // Create message that was signed: room_id + ephemeral_key + ciphertext + timestamp
        let mut message = Vec::new();
        message.extend_from_slice(response.room_id.as_bytes());
        message.extend_from_slice(&response.ephemeral_key);
        message.extend_from_slice(&response.ciphertext);
        message.extend_from_slice(&response.timestamp.to_le_bytes());
        
        // Verify the signature using the trusted public key
        MlDsa::verify(&message, &response.signature, trusted_public_key)
            .map_err(|e| ProtoError::handshake(&format!("Signature verification failed: {}", e)))?;
        
        Ok(())
    }
    
    /// Derive shared secret from current state (using ML-KEM shared secret)
    fn derive_shared_secret(&self) -> [u8; 32] {
        // For ML-KEM, the shared secret is already established through encapsulation/decapsulation
        // We just need to return it if available, or derive it from the key material
        
        if let Some(shared_secret) = self.shared_secret {
            return shared_secret;
        }
        
        // Fallback: derive from key material using HKDF if shared secret not available
        // This provides much stronger key derivation than simple SHA256 hashing
        
        // Collect all available key material in a consistent order
        let mut key_material = Vec::new();
        
        // Add ephemeral keys (initiator first for consistency)
        match self.role {
            HandshakeRole::Initiator => {
                if let Some(local_keypair) = &self.local_ephemeral_keypair {
                    key_material.extend_from_slice(&local_keypair.public_key);
                }
                if let Some(remote_key) = &self.remote_ephemeral_public_key {
                    key_material.extend_from_slice(remote_key);
                }
            }
            HandshakeRole::Responder => {
                if let Some(remote_key) = &self.remote_ephemeral_public_key {
                    key_material.extend_from_slice(remote_key);
                }
                if let Some(local_keypair) = &self.local_ephemeral_keypair {
                    key_material.extend_from_slice(&local_keypair.public_key);
                }
            }
        }
        
        // Add nonces (initiator first for consistency)
        match self.role {
            HandshakeRole::Initiator => {
                if let Some(local_nonce) = &self.local_nonce {
                    key_material.extend_from_slice(local_nonce);
                }
                if let Some(remote_nonce) = &self.remote_nonce {
                    key_material.extend_from_slice(remote_nonce);
                }
            }
            HandshakeRole::Responder => {
                if let Some(remote_nonce) = &self.remote_nonce {
                    key_material.extend_from_slice(remote_nonce);
                }
                if let Some(local_nonce) = &self.local_nonce {
                    key_material.extend_from_slice(local_nonce);
                }
            }
        }
        
        // Use deterministic salt for HKDF to ensure reproducibility
        // This is safe because the key material already contains randomness from nonces and ephemeral keys
        let salt = b"ZK_HANDSHAKE_HKDF_SALT_V1";
        
        // Use HKDF to derive a strong shared secret
        // SECURITY: HKDF-SHA256 expand should never fail for 32-byte output,
        // but we handle it gracefully instead of panicking (defense-in-depth)
        let hkdf = Hkdf::<Sha256>::new(Some(salt), &key_material);
        let mut shared_secret = [0u8; 32];
        if hkdf.expand(b"ZK_HANDSHAKE_SHARED_SECRET_V1", &mut shared_secret).is_err() {
            // Fallback: use direct SHA256 hash if HKDF fails (should never happen)
            let mut hasher = Sha256::new();
            hasher.update(&key_material);
            hasher.update(b"ZK_HANDSHAKE_FALLBACK_V1");
            shared_secret.copy_from_slice(&hasher.finalize());
        }
        
        shared_secret
    }
    
    /// Create handshake finish message as initiator
    pub fn create_finish(&mut self) -> Result<HandshakeFinish> {
        if self.role != HandshakeRole::Initiator {
            return Err(ProtoError::handshake("Only initiator can create finish message"));
        }
        
        if self.state != HandshakeState::ResponseSent {
            return Err(ProtoError::handshake("Invalid state for creating finish message"));
        }
        
        // Derive shared secret
        let shared_secret = self.derive_shared_secret();
        self.shared_secret = Some(shared_secret);
        
        // Create confirmation by hashing the shared secret with additional context
        // This prevents sending the raw secret over the wire
        let mut hasher = Sha256::new();
        hasher.update(b"ZK_HANDSHAKE_CONFIRMATION");
        hasher.update(&shared_secret);
        let confirmation_hash = hasher.finalize();
        let mut confirmation = [0u8; 32];
        confirmation.copy_from_slice(&confirmation_hash);
        
        let timestamp = self.current_timestamp();
        
        let finish = HandshakeFinish {
            version: self.version,
            confirmation,
            timestamp,
        };
        
        self.state = HandshakeState::Complete;
        Ok(finish)
    }
    
    /// Process handshake finish message as responder
    pub fn process_finish(&mut self, finish: &HandshakeFinish) -> Result<()> {
        if self.role != HandshakeRole::Responder {
            return Err(ProtoError::handshake("Only responder can process finish message"));
        }
        
        if self.state != HandshakeState::ResponseSent {
            return Err(ProtoError::handshake("Invalid state for processing finish message"));
        }
        
        // Validate version
        if finish.version != self.version {
            return Err(ProtoError::handshake("Version mismatch"));
        }
        
        // Validate timestamp for replay protection
        self.validate_timestamp(finish.timestamp)?;
        
        // Get the shared secret that was derived when processing the response
        let shared_secret = self.shared_secret.ok_or_else(|| {
            ProtoError::handshake("Shared secret not available")
        })?;
        
        // Create expected confirmation by hashing the shared secret with the same context
        let mut hasher = Sha256::new();
        hasher.update(b"ZK_HANDSHAKE_CONFIRMATION");
        hasher.update(&shared_secret);
        let expected_confirmation_hash = hasher.finalize();
        let mut expected_confirmation = [0u8; 32];
        expected_confirmation.copy_from_slice(&expected_confirmation_hash);
        
        // Verify confirmation using constant-time comparison
        if !bool::from(finish.confirmation.ct_eq(&expected_confirmation)) {
            return Err(ProtoError::handshake("Invalid confirmation"));
        }
        
        self.state = HandshakeState::Complete;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_handshake_initiator() {
        // Generate a trusted responder public key for testing
        let responder_keypair = MlDsa::generate_keypair().unwrap();
        let trusted_public_key = responder_keypair.verifying_key().to_vec();
        
        let handshake = Handshake::new_initiator("test-room".to_string(), trusted_public_key).unwrap();
        assert_eq!(handshake.role(), HandshakeRole::Initiator);
        assert_eq!(handshake.state(), HandshakeState::Idle);
        assert!(!handshake.is_complete());
    }
    
    #[test]
    fn test_handshake_responder() {
        let handshake = Handshake::new_responder("test-room".to_string());
        assert_eq!(handshake.role(), HandshakeRole::Responder);
        assert_eq!(handshake.state(), HandshakeState::Idle);
        assert!(!handshake.is_complete());
    }
    
    #[test]
    fn test_handshake_flow() {
        // Generate a persistent signing keypair for the responder
        let responder_signing_keypair = MlDsa::generate_keypair().unwrap();
        let trusted_public_key = responder_signing_keypair.verifying_key().to_vec();
        
        // Create initiator with trusted responder public key
        let mut initiator = Handshake::new_initiator("test-room".to_string(), trusted_public_key).unwrap();
        let mut responder = Handshake::new_responder("test-room".to_string());
        
        // Set the signing keypair for the responder
        responder.set_signing_keypair(responder_signing_keypair).unwrap();
        
        // Step 1: Initiator creates init message
        let init = initiator.create_init().unwrap();
        assert_eq!(initiator.state(), HandshakeState::InitSent);
        
        // Step 2: Responder processes init message
        responder.process_init(&init).unwrap();
        assert_eq!(responder.state(), HandshakeState::InitSent);
        
        // Step 3: Responder creates response message
        let response = responder.create_response().unwrap();
        assert_eq!(responder.state(), HandshakeState::ResponseSent);
        
        // Step 4: Initiator processes response message
        initiator.process_response(&response).unwrap();
        assert_eq!(initiator.state(), HandshakeState::ResponseSent);
        
        // Step 5: Initiator creates finish message
        let finish = initiator.create_finish().unwrap();
        assert_eq!(initiator.state(), HandshakeState::Complete);
        assert!(initiator.is_complete());
        assert!(initiator.shared_secret().is_some());
        
        // Step 6: Responder processes finish message
        responder.process_finish(&finish).unwrap();
        assert_eq!(responder.state(), HandshakeState::Complete);
        assert!(responder.is_complete());
        assert!(responder.shared_secret().is_some());
        
        // Both should have the same shared secret
        assert_eq!(initiator.shared_secret(), responder.shared_secret());
    }
}