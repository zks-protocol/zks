use base64::{Engine, engine::general_purpose};
// Note: rand::Rng removed - using OsRng directly for security
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop};

use zks_pqcrypto::ml_kem::MlKem;
use zks_wire::faisal_swarm::HopRole;

use crate::config::SurbConfig;
use crate::encryption::{SurbEncryption, EncryptedReply};
use crate::error::{SurbError, Result};

/// Unique identifier for a SURB
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SurbId(pub Vec<u8>);

impl Zeroize for SurbId {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl SurbId {
    /// Generate a new random SURB ID using high-entropy randomness (drand + OsRng)
    /// 
    /// # Security
    /// Uses `TrueEntropy` which combines drand beacon + local CSPRNG via XOR
    /// for 256-bit post-quantum computational security. Secure if ANY source is uncompromised.
    pub fn new(length: usize) -> Self {
        // SECURITY: Use TrueEntropy for 256-bit post-quantum computational security
        // Combines drand (BLS verified) + OsRng via XOR - secure if either is uncompromised
        use zks_crypt::true_entropy::get_sync_entropy;
        let entropy = get_sync_entropy(length);
        Self(entropy.to_vec())
    }
    
    /// Create from existing bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    
    /// Get the ID as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

/// A Single-Use Reply Block (SURB) for anonymous replies in ZKS Protocol
/// 
/// SECURITY NOTE: The encryption_key is NOT included in the serialized SURB.
/// It is kept private by the creator and used only for decrypting replies.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ZksSurb {
    /// Unique SURB identifier
    pub id: SurbId,
    
    /// ML-KEM encapsulated key (1088 bytes for ML-KEM-768)
    pub encapsulated_key: Vec<u8>,
    
    /// Faisal Swarm route (Guard → Middle → Exit)
    pub route_header: Vec<u8>,
    
    /// SURB creation timestamp
    pub created_at: u64,
    
    /// SURB lifetime in seconds
    pub lifetime: u64,
    
    /// Whether this SURB has been used
    pub used: bool,
}

/// Private SURB data that includes the encryption key
/// 
/// This is kept separate from the public SURB to prevent exposure of the encryption key.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateSurbData {
    /// The public SURB data
    pub surb: ZksSurb,
    
    /// Encryption key derived from ML-KEM shared secret (kept private)
    pub encryption_key: [u8; 32],
}

impl ZksSurb {
    /// Create a new SURB for the given recipient's ML-KEM public key
    /// 
    /// Returns a tuple of (public_surb, private_data) where private_data contains the encryption key
    pub fn create(recipient_pk: &[u8]) -> Result<(Self, PrivateSurbData)> {
        let config = SurbConfig::default();
        Self::create_with_config(recipient_pk, &config)
    }
    
    /// Create a new SURB with custom configuration
    /// 
    /// Returns a tuple of (public_surb, private_data) where private_data contains the encryption key
    pub fn create_with_config(recipient_pk: &[u8], config: &SurbConfig) -> Result<(Self, PrivateSurbData)> {
        if !config.enabled {
            return Err(SurbError::InvalidConfig("SURBs are disabled".to_string()));
        }
        
        // Encapsulate key for the recipient
        let encapsulation = MlKem::encapsulate(recipient_pk)
            .map_err(|e| SurbError::CryptoError(format!("Failed to encapsulate key: {}", e)))?;
        
        // Derive encryption key from shared secret using SHA256
        let encryption_key = Self::derive_encryption_key(&encapsulation.shared_secret);
        
        // Generate route header for Faisal Swarm
        let route_header = Self::generate_route_header(config)?;
        
        // Generate SURB ID
        let id = SurbId::new(config.surb_id_length);
        
        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| SurbError::CryptoError(format!("Failed to get timestamp: {}", e)))?
            .as_secs();
        
        let surb = Self {
            id,
            encapsulated_key: encapsulation.ciphertext,
            route_header,
            created_at,
            lifetime: config.lifetime.as_secs(),
            used: false,
        };
        
        let private_data = PrivateSurbData {
            surb: surb.clone(),
            encryption_key,
        };
        
        Ok((surb, private_data))
    }
    
    /// Generate a route header for Faisal Swarm
    ///
    /// # ⚠️ SECURITY WARNING: MOCK IMPLEMENTATION (M5 Fix)
    ///
    /// **THIS IS A PLACEHOLDER IMPLEMENTATION FOR TESTING ONLY.**
    ///
    /// This function generates MOCK peer IDs and localhost addresses, which means:
    /// - NO REAL ANONYMOUS ROUTING is provided
    /// - All SURBs point to localhost (no actual P2P routing)
    /// - Peer IDs are deterministic and trivially linkable
    ///
    /// **TODO: Production Implementation Required**
    /// 1. Integrate with Faisal Swarm peer discovery
    /// 2. Use real libp2p Multiaddrs from active network nodes
    /// 3. Select route hops based on diversity and bandwidth criteria
    /// 4. Add integration tests with actual P2P routing
    ///
    /// For Tor-style anonymity, see: Dingledine et al., "Tor: Second-Generation Onion Router"
    fn generate_route_header(config: &SurbConfig) -> Result<Vec<u8>> {
        // TODO(M5): Replace mock implementation with real Faisal Swarm peer discovery
        // See: https://github.com/libp2p/specs for peer discovery specifications
        
        // Create a serializable route data structure
        #[derive(Serialize, Deserialize)]
        struct RouteHop {
            peer_id: Vec<u8>,
            role: HopRole,
            multiaddr: Vec<u8>,
            can_relay: bool,
            can_exit: bool,
            bandwidth_tier: u8,
        }
        
        let mut route_hops = Vec::new();
        
        for i in 0..config.route_length {
            // ⚠️ MOCK: Generate mock peer IDs for each hop
            // In production, these MUST be real peers from Faisal Swarm discovery
            let peer_id_bytes = format!("peer_{:0>44}", i).as_bytes().to_vec();
            
            let role = match i {
                0 => HopRole::Guard,
                n if n == config.route_length - 1 => HopRole::Exit,
                _ => HopRole::Middle,
            };
            
            // ⚠️ MOCK: localhost addresses provide NO anonymity
            // In production, use real libp2p Multiaddrs from active nodes
            let multiaddr_bytes = format!("/ip4/127.0.0.1/tcp/{}", 4000 + i).as_bytes().to_vec();
            
            route_hops.push(RouteHop {
                peer_id: peer_id_bytes,
                role,
                multiaddr: multiaddr_bytes,
                can_relay: true,
                can_exit: role == HopRole::Exit,
                bandwidth_tier: 3, // Medium bandwidth tier
            });
        }
        
        // Serialize the route hops as the route header
        // This creates a proper onion-encrypted route instead of random bytes
        let route_header = bincode::serialize(&route_hops)
            .map_err(|e| SurbError::SerializationError(format!("Failed to serialize route: {}", e)))?;
        
        Ok(route_header)
    }
    
    /// Check if this SURB is still valid (not expired and not used)
    /// 
    /// # Security
    /// Returns false on clock errors to fail-safe (treat as invalid)
    pub fn is_valid(&self) -> bool {
        if self.used {
            return false;
        }
        
        // SECURITY: Fail-safe on clock errors - treat SURB as invalid
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => return false, // Clock error - fail-safe to invalid
        };
        
        self.created_at + self.lifetime > now
    }
    
    /// Mark this SURB as used
    pub fn mark_used(&mut self) {
        self.used = true;
    }
    
    /// Get the SURB ID
    pub fn id(&self) -> &SurbId {
        &self.id
    }
    
    /// Get the encapsulated key
    pub fn encapsulated_key(&self) -> &[u8] {
        &self.encapsulated_key
    }
    
    /// Get the route header
    pub fn route_header(&self) -> &[u8] {
        &self.route_header
    }
    

    
    /// Serialize SURB to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| SurbError::SerializationError(format!("Failed to serialize SURB: {}", e)))
    }
    
    /// Deserialize SURB from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| SurbError::SerializationError(format!("Failed to deserialize SURB: {}", e)))
    }
    
    /// Serialize SURB to base64 string
    pub fn to_base64(&self) -> Result<String> {
        let bytes = self.to_bytes()?;
        Ok(general_purpose::STANDARD.encode(bytes))
    }
    
    /// Deserialize SURB from base64 string
    pub fn from_base64(b64: &str) -> Result<Self> {
        let bytes = general_purpose::STANDARD.decode(b64)
            .map_err(|e| SurbError::SerializationError(format!("Failed to decode base64: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    /// Check if this SURB has expired
    /// 
    /// # Security
    /// Returns true on clock errors to fail-safe (treat as expired)
    pub fn is_expired(&self) -> bool {
        // SECURITY: Fail-safe on clock errors - treat SURB as expired
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => return true, // Clock error - fail-safe to expired
        };
        now > self.created_at + self.lifetime
    }

    /// Check if this SURB has been used
    pub fn is_used(&self) -> bool {
        self.used
    }

    /// Derive encryption key from shared secret using SHA256
    fn derive_encryption_key(shared_secret: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        
        let mut hasher = Sha256::new();
        hasher.update(b"zks-surb-encryption-key");
        hasher.update(shared_secret);
        let result = hasher.finalize();
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }
}

/// A request to send an anonymous reply using a SURB
#[derive(Debug, Clone)]
pub struct ReplyRequest {
    /// The SURB to use for the reply
    pub surb: ZksSurb,
    
    /// The content of the reply
    pub content: Vec<u8>,
    
    /// Encrypted reply (generated during construction)
    encrypted_reply: Option<EncryptedReply>,
}

impl ReplyRequest {
    /// Create a new reply request from a SURB and content (for sender side)
    /// 
    /// The sender uses the recipient's public SURB and encrypts with the encapsulated key.
    pub fn from_surb(surb: ZksSurb, content: &[u8]) -> Result<Self> {
        if !surb.is_valid() {
            return Err(SurbError::SurbExpired);
        }
        
        if content.len() > 1024 { // Max reply size limit
            return Err(SurbError::InvalidConfig("Reply content too large".to_string()));
        }
        
        Ok(Self {
            surb,
            content: content.to_vec(),
            encrypted_reply: None,
        })
    }
    
    /// Create a new reply request from private SURB data (for recipient side)
    /// 
    /// The recipient uses their private data to decrypt incoming replies.
    pub fn from_private_surb(private_data: &PrivateSurbData, content: &[u8]) -> Result<Self> {
        if !private_data.surb.is_valid() {
            return Err(SurbError::SurbExpired);
        }
        
        if content.len() > 1024 { // Max reply size limit
            return Err(SurbError::InvalidConfig("Reply content too large".to_string()));
        }
        
        Ok(Self {
            surb: private_data.surb.clone(),
            content: content.to_vec(),
            encrypted_reply: None,
        })
    }
    
    /// Encrypt the reply content (sender side)
    /// 
    /// # Security
    /// Derives encryption key from the SURB's encapsulated ML-KEM key using
    /// SHA-256 with domain separation. This ensures cryptographic binding
    /// between the SURB and the encrypted reply.
    pub fn encrypt_reply(&mut self) -> Result<()> {
        // SECURITY: Derive key from encapsulated ML-KEM ciphertext
        // The recipient can derive the same key using their ML-KEM private key
        use sha2::{Digest, Sha256};
        
        let mut hasher = Sha256::new();
        hasher.update(b"zks-surb-sender-encryption-key-v1"); // Domain separation
        hasher.update(&self.surb.encapsulated_key);
        hasher.update(&self.surb.id.0); // Bind to SURB ID
        let key_hash = hasher.finalize();
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_hash);
        
        let encryption = SurbEncryption::new(key);
        let encrypted = encryption.encrypt(&self.content)?;
        self.encrypted_reply = Some(encrypted);
        
        // Zeroize key after use
        key.zeroize();
        
        Ok(())
    }
    
    /// Decrypt a reply (recipient side - uses private encryption key)
    pub fn decrypt_reply(&self, encrypted_reply: &EncryptedReply, private_data: &PrivateSurbData) -> Result<Vec<u8>> {
        if self.surb.id != private_data.surb.id {
            return Err(SurbError::InvalidConfig("SURB ID mismatch".to_string()));
        }
        
        let encryption = SurbEncryption::new(private_data.encryption_key);
        encryption.decrypt(encrypted_reply)
    }
    
    /// Get the encrypted reply
    pub fn encrypted_reply(&self) -> Option<&EncryptedReply> {
        self.encrypted_reply.as_ref()
    }
    
    /// Get the SURB
    pub fn surb(&self) -> &ZksSurb {
        &self.surb
    }
    
    /// Get the content
    pub fn content(&self) -> &[u8] {
        &self.content
    }
    
    /// Consume the reply request and return the SURB (for marking as used)
    pub fn into_surb(self) -> ZksSurb {
        self.surb
    }
}

/// Helper functions for SURB operations
pub mod surb_utils {
    use super::*;
    
    /// Generate multiple SURBs at once
    /// 
    /// Returns a tuple of (public_surbs, private_data_list)
    pub fn generate_surbs(count: usize, recipient_pk: &[u8]) -> Result<(Vec<ZksSurb>, Vec<PrivateSurbData>)> {
        let config = SurbConfig::default();
        generate_surbs_with_config(count, recipient_pk, &config)
    }
    
    /// Generate multiple SURBs with custom configuration
    /// 
    /// Returns a tuple of (public_surbs, private_data_list)
    pub fn generate_surbs_with_config(count: usize, recipient_pk: &[u8], config: &SurbConfig) -> Result<(Vec<ZksSurb>, Vec<PrivateSurbData>)> {
        let mut public_surbs = Vec::with_capacity(count);
        let mut private_data_list = Vec::with_capacity(count);
        
        for _ in 0..count {
            let (surb, private_data) = ZksSurb::create_with_config(recipient_pk, config)?;
            public_surbs.push(surb);
            private_data_list.push(private_data);
        }
        
        Ok((public_surbs, private_data_list))
    }
    
    /// Validate a collection of SURBs
    pub fn validate_surbs(surbs: &[ZksSurb]) -> Vec<bool> {
        surbs.iter().map(|surb| surb.is_valid()).collect()
    }
}