//! Swarm circuit implementation for onion routing in ZK Protocol
//! 
//! Provides secure multi-hop routing through the swarm network with layered encryption.

use serde::{Serialize, Deserialize};
use tracing::{debug, info};
use zeroize::Zeroizing;

use crate::{WireError, Result};
use crate::swarm::{PeerId, Peer};
use zks_crypt::wasif_vernam::WasifVernam;

/// Represents a circuit through the swarm for onion routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmCircuit {
    /// Entry peer (first hop)
    pub entry_peer: PeerId,
    /// Middle peers (intermediate hops)
    pub middle_peers: Vec<PeerId>,
    /// Exit peer (last hop)
    pub exit_peer: PeerId,
    /// Layer keys for encryption (one per hop) - private for security
    #[serde(serialize_with = "serialize_layer_keys", deserialize_with = "deserialize_layer_keys")]
    layer_keys: Vec<Zeroizing<[u8; 32]>>,
    /// Circuit ID for tracking
    pub circuit_id: [u8; 16],
}

impl SwarmCircuit {
    /// Create a new empty circuit
    pub fn new() -> Self {
        Self {
            entry_peer: PeerId::new(),
            middle_peers: Vec::new(),
            exit_peer: PeerId::new(),
            layer_keys: Vec::new(),
            circuit_id: Self::generate_circuit_id(),
        }
    }
    
    /// Generate a unique circuit ID using cryptographically secure random
    fn generate_circuit_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        getrandom::getrandom(&mut id).expect("Failed to generate random circuit ID");
        id
    }

    /// Get a copy of a layer key (for encryption/decryption operations)
    /// This creates a copy of the key for use in cryptographic operations
    fn get_layer_key(&self, index: usize) -> Option<[u8; 32]> {
        self.layer_keys.get(index).map(|key| **key)
    }

    /// Get the number of layer keys
    pub fn layer_key_count(&self) -> usize {
        self.layer_keys.len()
    }

    /// Set layer keys (replaces existing keys)
    pub fn set_layer_keys(&mut self, keys: Vec<[u8; 32]>) {
        self.layer_keys = keys.into_iter().map(Zeroizing::new).collect();
    }

    /// Add a layer key
    pub fn add_layer_key(&mut self, key: [u8; 32]) {
        self.layer_keys.push(Zeroizing::new(key));
    }
    
    /// Get all peers in the circuit (entry, middle, exit)
    pub fn all_peers(&self) -> Vec<PeerId> {
        let mut peers = vec![self.entry_peer];
        peers.extend(&self.middle_peers);
        peers.push(self.exit_peer);
        peers
    }
    
    /// Get the number of hops in the circuit
    pub fn hop_count(&self) -> usize {
        1 + self.middle_peers.len() + 1 // entry + middle + exit
    }
    
    /// Onion encrypt data for transmission through the circuit
    /// Data is encrypted in reverse order (exit first, entry last)
    pub fn onion_encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.layer_keys.is_empty() {
            return Err(WireError::other("No layer keys available for encryption"));
        }
        
        let mut encrypted = data.to_vec();
        
        // Encrypt in reverse order - exit peer first, entry peer last
        for i in (0..self.layer_keys.len()).rev() {
            if let Some(key) = self.get_layer_key(i) {
                let mut cipher = WasifVernam::new(key)
                    .map_err(|e| WireError::other(&format!("Failed to create cipher: {}", e)))?;
                encrypted = cipher.encrypt(&encrypted)
                    .map_err(|e| WireError::other(&format!("Encryption failed: {}", e)))?;
            } else {
                return Err(WireError::other("Failed to get layer key"));
            }
        }
        
        debug!("Onion encrypted {} bytes through {} hops", data.len(), self.hop_count());
        Ok(encrypted)
    }
    
    /// Onion decrypt data received from the circuit
    /// Data is decrypted in forward order (entry first, exit last)
    pub fn onion_decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.layer_keys.is_empty() {
            return Err(WireError::other("No layer keys available for decryption"));
        }
        
        let mut decrypted = data.to_vec();
        
        // Decrypt in forward order - entry peer first, exit peer last
        for i in 0..self.layer_keys.len() {
            if let Some(key) = self.get_layer_key(i) {
                let cipher = WasifVernam::new(key)
                    .map_err(|e| WireError::other(&format!("Failed to create cipher: {}", e)))?;
                decrypted = cipher.decrypt(&decrypted)
                    .map_err(|e| WireError::other(&format!("Decryption failed: {}", e)))?;
            } else {
                return Err(WireError::other("Failed to get layer key"));
            }
        }
        
        debug!("Onion decrypted {} bytes through {} hops", data.len(), self.hop_count());
        Ok(decrypted)
    }
    
    /// Create a single-hop cipher for a specific peer in the circuit
    pub fn get_peer_cipher(&self, peer_index: usize) -> Result<WasifVernam> {
        if peer_index >= self.layer_keys.len() {
            return Err(WireError::other("Peer index out of range"));
        }
        
        if let Some(key) = self.get_layer_key(peer_index) {
            WasifVernam::new(key)
                .map_err(|e| WireError::other(&format!("Failed to create cipher: {}", e)))
        } else {
            Err(WireError::other("Failed to get layer key"))
        }
    }
}

impl Default for SwarmCircuit {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating swarm circuits
pub struct CircuitBuilder {
    /// Minimum number of hops required
    min_hops: u8,
    /// Maximum number of hops allowed
    max_hops: u8,
    /// Preferred peers (if available)
    preferred_peers: Vec<PeerId>,
    /// Exclude these peers from selection
    exclude_peers: Vec<PeerId>,
}

impl CircuitBuilder {
    /// Create a new circuit builder
    pub fn new() -> Self {
        Self {
            min_hops: 3,  // Default: entry + 1 middle + exit
            max_hops: 8,  // Maximum 8 hops for performance
            preferred_peers: Vec::new(),
            exclude_peers: Vec::new(),
        }
    }
    
    /// Set minimum number of hops
    pub fn min_hops(mut self, hops: u8) -> Self {
        self.min_hops = hops;
        self
    }
    
    /// Set maximum number of hops
    pub fn max_hops(mut self, hops: u8) -> Self {
        self.max_hops = hops;
        self
    }
    
    /// Add preferred peers to use if available
    pub fn preferred_peers(mut self, peers: Vec<PeerId>) -> Self {
        self.preferred_peers = peers;
        self
    }
    
    /// Exclude specific peers from the circuit
    pub fn exclude_peers(mut self, peers: Vec<PeerId>) -> Self {
        self.exclude_peers = peers;
        self
    }
    
    /// Build a circuit with the specified parameters
    pub async fn build(self, available_peers: &[Peer]) -> Result<SwarmCircuit> {
        info!("Building circuit with {}-{} hops", self.min_hops, self.max_hops);
        
        // Filter out excluded peers
        let mut candidates: Vec<&Peer> = available_peers.iter()
            .filter(|peer| !self.exclude_peers.contains(&peer.id))
            .collect();
        
        if candidates.len() < self.min_hops as usize {
            return Err(WireError::other(&format!(
                "Not enough peers available. Need {}, have {}",
                self.min_hops, candidates.len()
            )));
        }
        
        // Shuffle candidates for randomness
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        candidates.shuffle(&mut rng);
        
        // Select peers for the circuit
        let mut circuit = SwarmCircuit::new();
        let target_hops = std::cmp::max(self.min_hops as usize, std::cmp::min(candidates.len(), self.max_hops as usize));
        
        // Select entry peer
        if let Some(entry_peer) = candidates.pop() {
            circuit.entry_peer = entry_peer.id;
        }
        
        // Select middle peers
        let middle_count = target_hops.saturating_sub(2); // Subtract entry and exit
        for _ in 0..middle_count {
            if let Some(middle_peer) = candidates.pop() {
                circuit.middle_peers.push(middle_peer.id);
            }
        }
        
        // Select exit peer
        if let Some(exit_peer) = candidates.pop() {
            circuit.exit_peer = exit_peer.id;
        }
        
        info!("Built circuit with {} hops: entry={}, middle={:?}, exit={}", 
               circuit.hop_count(), circuit.entry_peer, circuit.middle_peers, circuit.exit_peer);
        
        Ok(circuit)
    }
}

impl Default for CircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swarm::PeerState;
    
    #[test]
    fn test_circuit_creation() {
        let circuit = SwarmCircuit::new();
        assert_eq!(circuit.hop_count(), 2); // entry + exit (no middle peers)
        assert!(!circuit.circuit_id.is_empty());
    }
    
    #[test]
    fn test_circuit_all_peers() {
        let mut circuit = SwarmCircuit::new();
        circuit.middle_peers.push(PeerId::new());
        circuit.middle_peers.push(PeerId::new());
        
        let all_peers = circuit.all_peers();
        assert_eq!(all_peers.len(), 4); // entry + 2 middle + exit
    }
    
    #[tokio::test]
    async fn test_onion_encryption() {
        let mut circuit = SwarmCircuit::new();
        circuit.set_layer_keys(vec![[1u8; 32], [2u8; 32], [3u8; 32]]);
        
        let plaintext = b"Hello, onion routing!";
        let encrypted = circuit.onion_encrypt(plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        
        let decrypted = circuit.onion_decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[tokio::test]
    async fn test_circuit_builder() {
        let mut peers = Vec::new();
        for i in 0..5 {
            peers.push(Peer {
                id: PeerId::new(),
                addresses: vec![format!("127.0.0.1:{}", 8000 + i).parse().unwrap()],
                last_seen: 0,
                state: PeerState::Connected,
                protocol_version: 1,
            });
        }
        
        let builder = CircuitBuilder::new()
            .min_hops(3)
            .max_hops(4);
        
        let circuit = builder.build(&peers).await.unwrap();
        assert!(circuit.hop_count() >= 3);
        assert!(circuit.hop_count() <= 4);
    }
}

// Custom serialization for layer keys
fn serialize_layer_keys<S>(keys: &Vec<Zeroizing<[u8; 32]>>, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let raw_keys: Vec<[u8; 32]> = keys.iter().map(|key| **key).collect();
    raw_keys.serialize(serializer)
}

fn deserialize_layer_keys<'de, D>(deserializer: D) -> std::result::Result<Vec<Zeroizing<[u8; 32]>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw_keys: Vec<[u8; 32]> = Vec::deserialize(deserializer)?;
    Ok(raw_keys.into_iter().map(Zeroizing::new).collect())
}