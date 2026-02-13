//! Faisal Swarm Circuit Manager
//!
//! Manages the lifecycle of Faisal Swarm circuits using libp2p relay.

use super::*;
use crate::error::WireError;
use crate::faisal_swarm::cells::{
    CellCommand, FaisalSwarmCell, RelayCommand, RelayPayload, CELL_PAYLOAD_SIZE,
};
use crate::faisal_swarm::encryption::create_encryption_manager_from_secrets;
use crate::p2p::{FaisalSwarmRequest, FaisalSwarmResponse};
use crate::signaling::{PeerInfo, SignalingClientTrait};
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, instrument, span, Level};
use zeroize::Zeroizing;

/// Retry configuration for network operations
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 2.0,
        }
    }
}

/// Retry an async operation with exponential backoff
async fn retry_with_backoff<T, F, Fut>(operation: F, retry_config: &RetryConfig) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut delay = retry_config.initial_delay;

    for attempt in 1..=retry_config.max_attempts {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(err) if attempt < retry_config.max_attempts => {
                debug!(
                    "Attempt {} failed: {}, retrying in {:?}",
                    attempt, err, delay
                );
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(
                    Duration::from_millis(
                        (delay.as_millis() as f64 * retry_config.backoff_multiplier) as u64,
                    ),
                    retry_config.max_delay,
                );
            }
            Err(err) => return Err(err),
        }
    }

    unreachable!("Retry loop should have returned by now")
}

/// Circuit manager statistics for monitoring and debugging
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub total_circuits: usize,
    pub ready_circuits: usize,
    pub building_circuits: usize,
    pub failed_circuits: usize,
}

/// Coordinates circuit building, peer selection, and circuit lifecycle
/// for the Faisal Swarm topology.
pub struct FaisalSwarmManager<S: SignalingClientTrait> {
    /// Active circuits
    circuits: RwLock<HashMap<CircuitId, FaisalSwarmCircuit>>,

    /// Next circuit ID
    next_id: AtomicU32,

    /// Signaling client (for swarm peer discovery)
    signaling: Arc<S>,

    /// Native P2P transport for network operations
    p2p_transport: Arc<RwLock<crate::p2p::NativeP2PTransport>>,

    /// Retry configuration for network operations
    retry_config: RetryConfig,

    /// Active streams for data routing (CircuitId, StreamId) -> Sender
    streams: Arc<RwLock<HashMap<(CircuitId, u16), mpsc::UnboundedSender<Vec<u8>>>>>,
}

impl<S: SignalingClientTrait> FaisalSwarmManager<S> {
    /// Create a new Faisal Swarm manager for circuit management
    ///
    /// # Arguments
    /// * `signaling` - Signaling client for peer discovery
    /// * `p2p_transport` - Native P2P transport for network operations
    pub fn new(
        signaling: Arc<S>,
        p2p_transport: Arc<RwLock<crate::p2p::NativeP2PTransport>>,
    ) -> Self {
        Self::with_retry_config(signaling, p2p_transport, RetryConfig::default())
    }

    /// Create a new Faisal Swarm manager for circuit management with custom retry configuration
    ///
    /// # Arguments
    /// * `signaling` - Signaling client for peer discovery
    /// * `p2p_transport` - Native P2P transport for network operations
    /// * `retry_config` - Custom retry configuration for network operations
    pub fn with_retry_config(
        signaling: Arc<S>,
        p2p_transport: Arc<RwLock<crate::p2p::NativeP2PTransport>>,
        retry_config: RetryConfig,
    ) -> Self {
        Self {
            circuits: RwLock::new(HashMap::new()),
            next_id: AtomicU32::new(0x80000001),
            signaling,
            p2p_transport,
            retry_config,
            streams: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get circuit statistics for monitoring
    pub async fn get_circuit_stats(&self) -> CircuitStats {
        let circuits = self.circuits.read().await;
        let total_circuits = circuits.len();
        let ready_circuits = circuits
            .values()
            .filter(|c| c.state == CircuitState::Ready)
            .count();
        let building_circuits = circuits
            .values()
            .filter(|c| c.state == CircuitState::Building)
            .count();

        CircuitStats {
            total_circuits,
            ready_circuits,
            building_circuits,
            failed_circuits: total_circuits - ready_circuits - building_circuits,
        }
    }
}

#[async_trait::async_trait]
impl<S: SignalingClientTrait> crate::PeerProvider for FaisalSwarmManager<S> {
    async fn get_available_peers(
        &self,
        room_id: &str,
    ) -> std::result::Result<Vec<PeerInfo>, WireError> {
        self.signaling
            .discover_peers(room_id)
            .await
            .map_err(|e| WireError::other(&format!("Failed to discover peers for SURB: {}", e)))
    }
}

impl<S: SignalingClientTrait> FaisalSwarmManager<S> {
    // =========================================================================
    // Faisal Swarm Circuit Creation
    // =========================================================================

    /// Create a new Faisal Swarm circuit
    ///
    /// Builds a multi-hop circuit through the peer swarm with Wasif-Vernam
    /// encryption at each layer.
    ///
    /// # Arguments
    /// * `room_id` - Swarm room for peer discovery
    /// * `hops` - Number of hops (3 recommended for Tor-level anonymity)
    ///
    /// # Returns
    /// Circuit ID if successful
    #[instrument(skip(self), fields(room_id, hops, circuit_id))]
    pub async fn create_circuit(&self, room_id: &str, hops: usize) -> Result<CircuitId> {
        let span = span!(
            Level::INFO,
            "create_circuit",
            room_id = room_id,
            hops = hops
        );
        let _enter = span.enter();

        info!(
            "🔧 Creating {}-hop Faisal Swarm circuit in room {}",
            hops, room_id
        );

        // Allocate circuit ID
        let circuit_id = self.allocate_circuit_id();
        tracing::Span::current().record("circuit_id", &circuit_id);

        // 1. Discover peers in the swarm
        let available_peers = self.discover_swarm_peers(room_id).await?;

        if available_peers.len() < hops {
            return Err(SwarmError::NotEnoughPeers(format!(
                "Need {} peers, found {}",
                hops,
                available_peers.len()
            )));
        }

        // 2. Select peers using Faisal Swarm path selection
        let selected_hops = self.select_swarm_path(&available_peers, hops).await?;

        // 3. Create circuit structure
        let circuit = FaisalSwarmCircuit {
            id: circuit_id,
            hops: selected_hops,
            layers: Vec::new(),
            state: CircuitState::Building,
            created_at: Instant::now(),
            encryption: None,
        };

        // Insert circuit with minimal lock time
        {
            let start = Instant::now();
            let mut circuits = self.circuits.write().await;
            debug!("Circuit write lock acquired in {:?}", start.elapsed());
            circuits.insert(circuit_id, circuit);
        }

        // 4. Build circuit via libp2p relay
        self.build_swarm_circuit(circuit_id).await?;

        // 5. Mark as ready
        {
            let start = Instant::now();
            let mut circuits = self.circuits.write().await;
            debug!("Circuit write lock acquired in {:?}", start.elapsed());
            if let Some(circuit) = circuits.get_mut(&circuit_id) {
                circuit.state = CircuitState::Ready;
                info!("✅ Faisal Swarm circuit {} is ready!", circuit_id);
            }
        }

        Ok(circuit_id)
    }

    // =========================================================================
    // Swarm Peer Discovery & Selection
    // =========================================================================

    /// Discover peers in the swarm that can relay
    async fn discover_swarm_peers(&self, room_id: &str) -> Result<Vec<PeerInfo>> {
        info!("🔍 Discovering Faisal Swarm peers in room {}", room_id);

        let peers = self
            .signaling
            .discover_peers(room_id)
            .await
            .map_err(|e| SwarmError::Libp2p(e.to_string()))?;

        // Filter for peers with relay capability
        let swarm_peers: Vec<_> = peers
            .into_iter()
            .filter(|p| p.capabilities.supports_relay)
            .collect();

        info!("Found {} relay-capable peers in swarm", swarm_peers.len());
        Ok(swarm_peers)
    }

    /// Select peers for Faisal Swarm circuit path
    async fn select_swarm_path(
        &self,
        available_peers: &[PeerInfo],
        hops: usize,
    ) -> Result<Vec<SwarmHop>> {
        use rand::seq::SliceRandom;

        // SECURITY: Use TrueEntropy for 256-bit post-quantum computational security in path selection
        use zks_crypt::true_entropy::TrueEntropyRng;
        let mut rng = TrueEntropyRng;
        let mut selected = available_peers.to_vec();
        selected.shuffle(&mut rng);

        let mut circuit_hops = Vec::with_capacity(hops);

        for (i, peer) in selected.iter().take(hops).enumerate() {
            let role = match i {
                0 => HopRole::Guard,
                n if n == hops - 1 => HopRole::Exit,
                _ => HopRole::Middle,
            };

            let peer_id = PeerId::from_bytes(&peer.peer_id.as_bytes())
                .map_err(|e| SwarmError::Libp2p(e.to_string()))?;

            let multiaddr = peer
                .addresses
                .first()
                .ok_or_else(|| SwarmError::Libp2p("No address for peer".into()))?
                .parse()
                .map_err(|e| SwarmError::Libp2p(format!("Invalid multiaddr: {}", e)))?;

            circuit_hops.push(SwarmHop {
                peer_id,
                role,
                multiaddr,
                capabilities: SwarmCapabilities {
                    can_relay: peer.capabilities.supports_relay,
                    can_exit: peer.capabilities.supports_onion_routing,
                    bandwidth_tier: 3,
                },
            });
        }

        info!("📍 Faisal Swarm path selected:");
        for (i, hop) in circuit_hops.iter().enumerate() {
            info!("  Hop {}: {:?} - {}", i + 1, hop.role, hop.peer_id);
        }

        Ok(circuit_hops)
    }

    // =========================================================================
    // Swarm Circuit Building
    // =========================================================================

    /// Build Faisal Swarm circuit using libp2p relay protocol
    async fn build_swarm_circuit(&self, circuit_id: CircuitId) -> Result<()> {
        // Get circuit info first, then release the lock
        let guard_info = {
            let circuits = self.circuits.read().await;
            let circuit = circuits
                .get(&circuit_id)
                .ok_or(SwarmError::NotFound(circuit_id))?;

            info!("🔗 Building Faisal Swarm circuit {}", circuit_id);

            // Get the first hop info
            if circuit.hops.is_empty() {
                return Err(SwarmError::InvalidArgument(
                    "Circuit has no hops".to_string(),
                ));
            }

            let guard = &circuit.hops[0];
            info!("  → Connecting to Guard: {}", guard.peer_id);

            (guard.peer_id, guard.multiaddr.clone())
        };

        // Connect to first hop (Guard) without holding circuit lock
        self.connect_to_swarm_peer(&guard_info.0, &guard_info.1, circuit_id)
            .await?;

        // Perform ML-KEM handshake with Guard (post-quantum secure)
        let layer0 = self.handshake_with_swarm_peer(circuit_id, 0).await?;

        // Add the first layer to the circuit and Initialize Encryption
        {
            let mut circuits = self.circuits.write().await;
            if let Some(circuit) = circuits.get_mut(&circuit_id) {
                circuit.layers.push(layer0.clone());

                // Initialize encryption with first layer
                let shared_secrets = vec![layer0.shared_secret];
                let encryption =
                    create_encryption_manager_from_secrets(&shared_secrets).map_err(|e| {
                        SwarmError::Encryption(format!(
                            "Failed to create encryption manager: {:?}",
                            e
                        ))
                    })?;

                circuit.encryption = Some(Arc::new(tokio::sync::Mutex::new(encryption)));
            } else {
                return Err(SwarmError::NotFound(circuit_id));
            }
        }

        // Extend circuit to remaining hops
        // We need to re-fetch hop count as it might change? No, fixed at creation.
        let hop_count = self.get_circuit_hop_count(circuit_id).await?;

        for hop_idx in 1..hop_count {
            info!("  → Extending Faisal Swarm circuit to hop {}", hop_idx + 1);

            // Extend circuit - returns new layer
            let new_layer = self.extend_swarm_circuit(circuit_id, hop_idx).await?;

            // Update circuit with new layer and update encryption
            let mut circuits = self.circuits.write().await;
            if let Some(circuit) = circuits.get_mut(&circuit_id) {
                circuit.layers.push(new_layer);

                // Re-initialize encryption with ALL layers (including new one)
                let shared_secrets: Vec<[u8; 32]> = circuit
                    .layers
                    .iter()
                    .map(|layer| layer.shared_secret)
                    .collect();

                let encryption =
                    create_encryption_manager_from_secrets(&shared_secrets).map_err(|e| {
                        SwarmError::Encryption(format!(
                            "Failed to update encryption manager: {:?}",
                            e
                        ))
                    })?;

                circuit.encryption = Some(Arc::new(tokio::sync::Mutex::new(encryption)));
                info!(
                    "✅ Encryption manager updated for {} hops",
                    circuit.layers.len()
                );
            }
        }

        Ok(())
    }

    /// Connect to a swarm peer via libp2p
    async fn connect_to_swarm_peer(
        &self,
        peer_id: &PeerId,
        multiaddr: &Multiaddr,
        circuit_id: CircuitId,
    ) -> Result<()> {
        info!(
            "Connecting to swarm peer {} at {} for circuit {}",
            peer_id, multiaddr, circuit_id
        );

        let p2p_transport = self.p2p_transport.read().await;

        // Dial the peer
        p2p_transport
            .dial(multiaddr.clone())
            .await
            .map_err(|e| SwarmError::Network(format!("Failed to dial peer: {}", e)))?;

        // Wait for connection to be established
        // In a real implementation, we'd listen for connection events
        // For now, we'll use a simplified approach with a timeout
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Check if we're connected to the peer
        if !p2p_transport.is_connected(peer_id).await {
            return Err(SwarmError::Network(format!(
                "Failed to establish connection to peer {}",
                peer_id
            )));
        }

        info!(
            "✅ Successfully connected to peer {} at {} for circuit {}",
            peer_id, multiaddr, circuit_id
        );

        Ok(())
    }

    /// Perform post-quantum handshake with swarm peer
    async fn handshake_with_swarm_peer(
        &self,
        circuit_id: CircuitId,
        hop_idx: usize,
    ) -> Result<SwarmLayer> {
        let circuits = self.circuits.read().await;
        let circuit = circuits
            .get(&circuit_id)
            .ok_or(SwarmError::NotFound(circuit_id))?;

        let hop = &circuit.hops[hop_idx];

        info!(
            "🤝 ML-KEM handshake with swarm peer {} ({})",
            hop_idx, hop.peer_id
        );

        // Generate ML-KEM keypair (post-quantum)
        // Note: This requires zks_pqcrypto crate integration
        let shared_secret_vec = self
            .perform_post_quantum_handshake(&hop.peer_id, circuit)
            .await?;

        // Convert Zeroizing<Vec<u8>> to [u8; 32]
        let mut shared_secret = [0u8; 32];
        if shared_secret_vec.len() == 32 {
            shared_secret.copy_from_slice(&shared_secret_vec);
        } else {
            return Err(SwarmError::HandshakeFailed(
                "Invalid shared secret length".to_string(),
            ));
        }

        // Derive Wasif-Vernam keys using HKDF
        let (forward_key, backward_key) = self.derive_vernam_keys(&shared_secret)?;

        // Create Wasif-Vernam layer for this hop
        let mut layer = SwarmLayer::new(hop.peer_id, forward_key, backward_key)?;
        layer.shared_secret = shared_secret;

        info!("✅ Wasif-Vernam layer established for hop {}", hop_idx);

        Ok(layer)
    }

    /// Perform post-quantum handshake (ML-KEM) via libp2p request-response
    ///
    /// This is the REAL implementation that exchanges ML-KEM public keys
    /// over the libp2p Faisal Swarm protocol and derives a shared secret.
    #[instrument(skip(self, circuit), fields(peer_id = peer_id.to_string(), circuit_id = circuit.id))]
    async fn perform_post_quantum_handshake(
        &self,
        peer_id: &PeerId,
        circuit: &FaisalSwarmCircuit,
    ) -> Result<Zeroizing<Vec<u8>>> {
        use zks_pqcrypto::MlKem;

        info!(
            "🤝 Performing REAL post-quantum ML-KEM handshake with peer: {}",
            peer_id
        );

        // 1. Generate ML-KEM keypair (post-quantum secure)
        let keypair = MlKem::generate_keypair().map_err(|e| {
            SwarmError::HandshakeFailed(format!("ML-KEM key generation failed: {:?}", e))
        })?;

        let public_key = keypair.public_key();
        debug!(
            "📤 Sending ML-KEM public key ({} bytes) to peer {}",
            public_key.len(),
            peer_id
        );

        // 2. Create handshake request with our public key
        let request = FaisalSwarmRequest {
            circuit_id: circuit.id,
            data: public_key.to_vec(),
        };

        // 3. Send request via NativeP2PTransport with retry logic
        let response = retry_with_backoff(
            || async {
                let p2p_transport = self.p2p_transport.read().await;
                p2p_transport
                    .send_faisal_request(*peer_id, request.clone())
                    .await
                    .map_err(|e| SwarmError::Network(format!("Handshake request failed: {}", e)))
            },
            &self.retry_config,
        )
        .await?;

        if !response.success {
            return Err(SwarmError::HandshakeFailed(format!(
                "Peer {} rejected handshake",
                peer_id
            )));
        }

        // 5. Decapsulate the ciphertext to get shared secret
        let ciphertext = &response.data;
        if ciphertext.len() != zks_pqcrypto::ml_kem::CIPHERTEXT_SIZE {
            return Err(SwarmError::HandshakeFailed(format!(
                "Invalid ciphertext size: expected {}, got {}",
                zks_pqcrypto::ml_kem::CIPHERTEXT_SIZE,
                ciphertext.len()
            )));
        }

        let shared_secret = MlKem::decapsulate(ciphertext, keypair.secret_key()).map_err(|e| {
            SwarmError::HandshakeFailed(format!("ML-KEM decapsulation failed: {:?}", e))
        })?;

        info!("✅ REAL ML-KEM handshake completed with peer {}", peer_id);
        debug!("   Shared secret derived: {} bytes", shared_secret.len());

        Ok(shared_secret)
    }

    /// Extend swarm circuit to next hop using EXTEND protocol
    async fn extend_swarm_circuit(
        &self,
        circuit_id: CircuitId,
        hop_idx: usize,
    ) -> Result<SwarmLayer> {
        // Get the hop info first, then release the lock
        let (guard_peer_id, next_hop, layers_len, encryption_mutex) = {
            let circuits = self.circuits.read().await;
            let circuit = circuits
                .get(&circuit_id)
                .ok_or(SwarmError::NotFound(circuit_id))?;

            if hop_idx >= circuit.hops.len() {
                return Err(SwarmError::InvalidArgument(format!(
                    "Invalid hop index: {}",
                    hop_idx
                )));
            }

            let guard = circuit.hops.first().ok_or(SwarmError::InvalidState {
                expected: CircuitState::Building,
                actual: CircuitState::Error("No guard".into()),
            })?;

            let next_hop = &circuit.hops[hop_idx];

            info!(
                "🔗 Extending Faisal Swarm circuit {} from hop {} to hop {}",
                circuit_id,
                hop_idx,
                hop_idx + 1
            );
            info!("   Next Hop: {}", next_hop.peer_id);

            let encryption = circuit.encryption.clone().ok_or(SwarmError::InvalidState {
                expected: CircuitState::Building,
                actual: CircuitState::Error("No encryption (should be init after guard)".into()),
            })?;

            (
                guard.peer_id,
                next_hop.clone(),
                circuit.layers.len(),
                encryption,
            )
        };

        // Match the Extend command format in relay.rs:
        // [cmd:1][peer_id_len:2][peer_id_bytes][addr_len:2][addr_bytes][pk_len:2][pk_bytes]
        // cmd = 0x04 for Extend

        // 1. Generate ML-KEM keypair for handshake with next hop
        use zks_pqcrypto::MlKem;
        let keypair = MlKem::generate_keypair().map_err(|e| {
            SwarmError::HandshakeFailed(format!("ML-KEM key generation failed: {:?}", e))
        })?;

        let client_pk = keypair.public_key();

        // 2. Construct the binary payload
        let mut payload = Vec::new();
        payload.push(0x04); // Command: EXTEND

        // Peer ID
        let peer_id_bytes = next_hop.peer_id.to_bytes();
        payload.extend_from_slice(&(peer_id_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(&peer_id_bytes);

        // Multiaddr
        let addr_bytes = next_hop.multiaddr.to_string().into_bytes();
        payload.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(&addr_bytes);

        // Public Key
        payload.extend_from_slice(&(client_pk.len() as u16).to_be_bytes());
        payload.extend_from_slice(&client_pk);

        // 3. Encrypt payload with existing layers (Onion encryption)
        // We need to lock encryption
        let mut encryption = encryption_mutex.lock().await;

        let encrypted_payload = encryption
            .encrypt_onion_layers(&payload, layers_len)
            .map_err(|e| {
                SwarmError::Encryption(format!("Extend payload encryption failed: {:?}", e))
            })?;

        // 4. Send to Guard
        let request = FaisalSwarmRequest {
            circuit_id,
            data: encrypted_payload,
        };

        // Retry logic for the extension request
        let response = retry_with_backoff(
            || async {
                let p2p_transport = self.p2p_transport.read().await;
                p2p_transport
                    .send_faisal_request(guard_peer_id, request.clone())
                    .await
                    .map_err(|e| {
                        SwarmError::Network(format!("Extend request to guard failed: {}", e))
                    })
            },
            &self.retry_config,
        )
        .await?;

        if !response.success {
            return Err(SwarmError::HandshakeFailed(
                "Extend request rejected by network".into(),
            ));
        }

        // 5. Decrypt response (onion decryption)
        // Decrypt iteratively
        let mut decrypted: Vec<u8> = response.data;

        // IMPORTANT: Decrypt in correct order.
        // If relay encrypted with R2 then R1 then R0 (Guardian), we must decrypt R0 then R1 then R2.
        // Assuming `decrypt_onion_layer` handles the correct sequence if we pass the index.
        // In `encryption.rs`, `decrypt_onion_layer` typically uses the cipher for that layer.
        // Loop 0 to layers_len-1.
        for i in 0..layers_len {
            decrypted = encryption.decrypt_onion_layer(&decrypted, i).map_err(|e| {
                SwarmError::Encryption(format!(
                    "Extend response decryption failed at hop {}: {:?}",
                    i, e
                ))
            })?;
        }

        // 6. This decrypted data IS the ciphertext from the next hop (ML-KEM encapsulated secret)
        // Check size
        if decrypted.len() != zks_pqcrypto::ml_kem::CIPHERTEXT_SIZE {
            return Err(SwarmError::HandshakeFailed(format!(
                "Invalid ML-KEM ciphertext size from next hop: expected {}, got {}",
                zks_pqcrypto::ml_kem::CIPHERTEXT_SIZE,
                decrypted.len()
            )));
        }

        // 7. Decapsulate
        let shared_secret = MlKem::decapsulate(&decrypted, keypair.secret_key()).map_err(|e| {
            SwarmError::HandshakeFailed(format!("ML-KEM decapsulation failed: {:?}", e))
        })?;

        // 8. Derive keys and return layer
        let shared_secret_vec: &Vec<u8> = shared_secret.as_ref();
        let shared_secret_array: [u8; 32] = shared_secret_vec
            .as_slice()
            .try_into()
            .map_err(|_| SwarmError::HandshakeFailed("Invalid shared secret length".to_string()))?;

        let (forward_key, backward_key) = self.derive_vernam_keys(&shared_secret_array)?;

        let mut new_layer = SwarmLayer::new(next_hop.peer_id, forward_key, backward_key)?;
        new_layer.shared_secret = shared_secret_array;

        info!(
            "✅ Circuit {} successfully extended to hop {} with REAL ML-KEM handshake",
            circuit_id,
            hop_idx + 1
        );
        Ok(new_layer)
    }

    /// Create EXTEND payload for next hop
    fn create_extend_payload(&self, next_hop: &SwarmHop) -> Result<Vec<u8>> {
        use serde_json;

        #[derive(Serialize, Deserialize)]
        struct ExtendPayload {
            peer_id: String,
            multiaddr: String,
            role: String,
            capabilities: SwarmCapabilities,
        }

        let payload = ExtendPayload {
            peer_id: next_hop.peer_id.to_string(),
            multiaddr: next_hop.multiaddr.to_string(),
            role: format!("{:?}", next_hop.role),
            capabilities: next_hop.capabilities.clone(),
        };

        serde_json::to_vec(&payload).map_err(|e| {
            SwarmError::Serialization(format!("Failed to serialize EXTEND payload: {}", e))
        })
    }

    /// Derive Wasif-Vernam keys from shared secret
    fn derive_vernam_keys(&self, shared_secret: &[u8]) -> Result<([u8; 32], [u8; 32])> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut key_material = [0u8; 64];

        hkdf.expand(b"FAISAL-SWARM-WASIF-VERNAM", &mut key_material)
            .map_err(|e| SwarmError::Encryption(format!("HKDF failed: {}", e)))?;

        let forward_key = key_material[0..32]
            .try_into()
            .map_err(|_| SwarmError::Encryption("Invalid forward key length".into()))?;
        let backward_key = key_material[32..64]
            .try_into()
            .map_err(|_| SwarmError::Encryption("Invalid backward key length".into()))?;

        Ok((forward_key, backward_key))
    }

    // =========================================================================
    // Circuit Usage
    // =========================================================================

    /// Send data through Faisal Swarm circuit using onion encryption
    #[instrument(skip(self, data), fields(circuit_id = circuit_id))]
    pub async fn send_via_swarm(&self, circuit_id: CircuitId, data: &[u8]) -> Result<Vec<u8>> {
        let span = span!(
            Level::INFO,
            "send_via_swarm",
            circuit_id = circuit_id,
            data_len = data.len()
        );
        let _enter = span.enter();

        // Get circuit info first with read lock
        let start = Instant::now();
        let (guard_hop_peer_id, encrypted_data) = {
            let circuits = self.circuits.read().await;
            debug!("Circuit read lock acquired in {:?}", start.elapsed());
            let circuit = circuits
                .get(&circuit_id)
                .ok_or(SwarmError::NotFound(circuit_id))?;

            if circuit.state != CircuitState::Ready {
                return Err(SwarmError::InvalidState {
                    expected: CircuitState::Ready,
                    actual: circuit.state.clone(),
                });
            }

            // Clone the circuit data needed for encryption
            let hops = circuit.hops.clone();
            let layers_len = circuit.layers.len();
            let encryption_mutex =
                circuit
                    .encryption
                    .clone()
                    .ok_or_else(|| SwarmError::InvalidState {
                        expected: CircuitState::Ready,
                        actual: CircuitState::Error("Encryption manager not initialized".into()),
                    })?;

            // Acquire lock on encryption manager to update counters safely
            let mut encryption = encryption_mutex.lock().await;

            // Perform proper onion encryption - encrypt in reverse order (Exit → Guard)
            let encrypted = encryption
                .encrypt_onion_layers(data, layers_len)
                .map_err(|e| SwarmError::Encryption(format!("Onion encryption failed: {:?}", e)))?;

            // Get guard hop info (first hop in the circuit)
            // CRITICAL FIX: Send to GUARD (first hop), not EXIT (last hop)
            if let Some(guard_hop) = hops.first() {
                (guard_hop.peer_id, encrypted)
            } else {
                return Err(SwarmError::InvalidState {
                    expected: CircuitState::Ready,
                    actual: circuit.state.clone(),
                });
            }
        };

        // Send through Faisal Swarm protocol using libp2p request-response
        // Send to the guard node (first hop) of the circuit
        let request = FaisalSwarmRequest {
            circuit_id,
            data: encrypted_data.clone(),
        };

        // Retry the send operation with exponential backoff
        let response = retry_with_backoff(
            || async {
                let p2p_transport = self.p2p_transport.read().await;
                p2p_transport
                    .send_faisal_request(guard_hop_peer_id, request.clone())
                    .await
                    .map_err(|e| SwarmError::Network(format!("Faisal Swarm send failed: {}", e)))
            },
            &self.retry_config,
        )
        .await?;

        if !response.success {
            return Err(SwarmError::Network(format!(
                "Faisal Swarm send failed for circuit {}",
                circuit_id
            )));
        }

        info!(
            "Sent {} bytes through Faisal Swarm circuit {} via libp2p",
            encrypted_data.len(),
            circuit_id
        );
        Ok(response.data)
    }

    /// Receive and decrypt data from Faisal Swarm circuit (network version)
    /// This method receives data from the network and decrypts it
    #[instrument(skip(self), fields(circuit_id = circuit_id))]
    pub async fn receive_from_swarm_network(&self, circuit_id: CircuitId) -> Result<Vec<u8>> {
        let start = Instant::now();
        let (guard_hop_peer_id, encryption_mutex, layers_len) = {
            let circuits = self.circuits.read().await;
            debug!("Circuit read lock acquired in {:?}", start.elapsed());
            let circuit = circuits
                .get(&circuit_id)
                .ok_or(SwarmError::NotFound(circuit_id))?;

            if circuit.state != CircuitState::Ready {
                return Err(SwarmError::InvalidState {
                    expected: CircuitState::Ready,
                    actual: circuit.state.clone(),
                });
            }

            // Get guard hop for sending request (must enter via Guard)
            let guard_hop = circuit
                .hops
                .first()
                .ok_or_else(|| SwarmError::InvalidState {
                    expected: CircuitState::Ready,
                    actual: circuit.state.clone(),
                })?;

            let layers_len = circuit.layers.len();
            let encryption_mutex =
                circuit
                    .encryption
                    .clone()
                    .ok_or_else(|| SwarmError::InvalidState {
                        expected: CircuitState::Ready,
                        actual: CircuitState::Error("Encryption manager not initialized".into()),
                    })?;

            (guard_hop.peer_id, encryption_mutex, layers_len)
        };

        // Lock encryption manager
        let mut encryption = encryption_mutex.lock().await;

        // Encrypt "RECV" request onion style
        let encrypted_request_data = encryption
            .encrypt_onion_layers(b"RECV", layers_len)
            .map_err(|e| SwarmError::Encryption(format!("Request encryption failed: {:?}", e)))?;

        // Create request to receive data
        let request = FaisalSwarmRequest {
            circuit_id,
            data: encrypted_request_data,
        };

        // Send to GUARD
        let response = retry_with_backoff(
            || async {
                let p2p_transport = self.p2p_transport.read().await;
                p2p_transport
                    .send_faisal_request(guard_hop_peer_id, request.clone())
                    .await
                    .map_err(|e| SwarmError::Network(format!("Faisal Swarm receive failed: {}", e)))
            },
            &self.retry_config,
        )
        .await?;

        if !response.success {
            return Err(SwarmError::Network(format!(
                "Faisal Swarm receive failed for circuit {}",
                circuit_id
            )));
        }

        // Decrypt response layer-by-layer
        // Note: decrypt_onion_layers handles peeling order correctly internally if implemented right,
        // but let's verify encryption.rs implementation.
        // encrypt_onion_layers does: Exit -> Guard.
        // decrypt_onion_layers does: Guard -> Exit? No, we receive from Guard.
        // Wait, encryption.rs has `decrypt_onion_layer` (singular). We need to loop.
        // Or encryption.rs doesn't have `decrypt_onion_layers` (plural)?
        // Let's check encryption.rs content from previous steps.
        // encryption.rs has `decrypt_onion_layer(..., hop_index)`.

        let mut decrypted = response.data;
        for i in 0..layers_len {
            decrypted = encryption.decrypt_onion_layer(&decrypted, i).map_err(|e| {
                SwarmError::Encryption(format!("Onion decryption failed at hop {}: {:?}", i, e))
            })?;
        }

        info!(
            "Received {} bytes from Faisal Swarm circuit {} via libp2p",
            decrypted.len(),
            circuit_id
        );
        Ok(decrypted)
    }

    /// Register a new stream for routing data
    pub async fn register_stream(
        &self,
        circuit_id: CircuitId,
        stream_id: u16,
    ) -> mpsc::UnboundedReceiver<Vec<u8>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut streams = self.streams.write().await;
        streams.insert((circuit_id, stream_id), tx);
        rx
    }

    /// Unregister a stream
    pub async fn unregister_stream(&self, circuit_id: CircuitId, stream_id: u16) {
        let mut streams = self.streams.write().await;
        streams.remove(&(circuit_id, stream_id));
    }

    /// Handle an incoming request as a client (decrypting all layers)
    pub async fn handle_incoming_request(
        &self,
        _peer_id: PeerId,
        request: FaisalSwarmRequest,
    ) -> Result<FaisalSwarmResponse> {
        let circuit_id = request.circuit_id;
        let mut data = request.data;

        // 1. Get circuit info
        let encryption_mutex = {
            let circuits = self.circuits.read().await;
            let circuit = circuits
                .get(&circuit_id)
                .ok_or_else(|| SwarmError::NotFound(circuit_id))?;

            circuit
                .encryption
                .clone()
                .ok_or_else(|| SwarmError::InvalidState {
                    expected: CircuitState::Ready,
                    actual: CircuitState::Error("Encryption not ready".into()),
                })?
        };

        // 2. Decrypt all layers (Guard -> Exit)
        let mut encryption = encryption_mutex.lock().await;

        let layers_len = encryption.backward_ciphers.len();
        for i in 0..layers_len {
            data = encryption.decrypt_onion_layer(&data, i).map_err(|e| {
                SwarmError::Encryption(format!("Onion decryption failed at layer {}: {:?}", i, e))
            })?;
        }

        // 3. Process the decrypted cell
        let cell = FaisalSwarmCell::from_bytes(&data)
            .map_err(|e| SwarmError::Encryption(format!("Cell deserialization failed: {:?}", e)))?;

        match cell.header.command {
            CellCommand::Relay | CellCommand::VernamRelay => {
                let relay_payload = RelayPayload::from_bytes(&cell.payload)
                    .map_err(|_| SwarmError::Protocol("Invalid relay payload".into()))?;

                if relay_payload.relay_command == RelayCommand::Data {
                    let streams = self.streams.read().await;
                    if let Some(tx) = streams.get(&(circuit_id, relay_payload.stream_id)) {
                        let _ = tx.send(relay_payload.data);
                    }
                }
            }
            _ => {
                debug!("Received non-relay cell command: {:?}", cell.header.command);
            }
        }

        Ok(FaisalSwarmResponse {
            success: true,
            data: b"ACK".to_vec(),
        })
    }

    /// Send data through a stream over a circuit
    pub async fn send_stream_data(
        &self,
        circuit_id: CircuitId,
        stream_id: u16,
        data: &[u8],
    ) -> Result<()> {
        // Chunk the data into cells
        for chunk in data.chunks(CELL_PAYLOAD_SIZE - 3) {
            // 3 bytes for RelayPayload header
            let relay_payload = RelayPayload {
                relay_command: RelayCommand::Data,
                stream_id,
                data: chunk.to_vec(),
            };

            // Use send_via_swarm to onion encrypt and send
            self.send_via_swarm(circuit_id, &relay_payload.to_bytes())
                .await?;
        }

        Ok(())
    }

    /// Decrypt data from Faisal Swarm circuit (direct decryption version)
    /// This method takes pre-received data and decrypts it
    #[instrument(skip(self, data), fields(circuit_id = circuit_id))]
    pub async fn decrypt_swarm_data(&self, circuit_id: CircuitId, data: &[u8]) -> Result<Vec<u8>> {
        // Get circuit info first with read lock
        let start = Instant::now();
        let layers = {
            let circuits = self.circuits.read().await;
            debug!("Circuit read lock acquired in {:?}", start.elapsed());
            let circuit = circuits
                .get(&circuit_id)
                .ok_or(SwarmError::NotFound(circuit_id))?;

            if circuit.state != CircuitState::Ready {
                return Err(SwarmError::InvalidState {
                    expected: CircuitState::Ready,
                    actual: circuit.state.clone(),
                });
            }

            circuit.layers.clone()
        };

        // Perform decryption outside of the lock
        let mut decrypted = data.to_vec();

        // Decrypt with all Wasif-Vernam layers (onion decryption) in reverse order
        for layer in layers.iter().rev() {
            decrypted = layer
                .decrypt_backward(&decrypted)
                .map_err(|e| SwarmError::Encryption(format!("Onion decryption failed: {:?}", e)))?;
        }

        info!(
            "Decrypted {} bytes from Faisal Swarm circuit {}",
            decrypted.len(),
            circuit_id
        );
        Ok(decrypted)
    }

    /// Close Faisal Swarm circuit
    pub async fn close_circuit(&self, circuit_id: CircuitId) -> Result<()> {
        let mut circuits = self.circuits.write().await;

        if let Some(mut circuit) = circuits.remove(&circuit_id) {
            circuit.state = CircuitState::Closing;
            info!("🚪 Faisal Swarm circuit {} closed", circuit_id);
        }

        Ok(())
    }

    // =========================================================================
    // Utility Methods
    // =========================================================================

    /// Allocate a new circuit ID
    fn allocate_circuit_id(&self) -> CircuitId {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Get the number of hops in a circuit
    async fn get_circuit_hop_count(&self, circuit_id: CircuitId) -> Result<usize> {
        let circuits = self.circuits.read().await;
        let circuit = circuits
            .get(&circuit_id)
            .ok_or(SwarmError::NotFound(circuit_id))?;
        Ok(circuit.hops.len())
    }

    /// Encrypt cell for specific hop
    fn encrypt_cell_for_hop(
        &self,
        cell: &FaisalSwarmCell,
        hop_idx: usize,
        circuit: &FaisalSwarmCircuit,
    ) -> Result<Vec<u8>> {
        // Serialize cell
        let serialized = serde_json::to_vec(cell)
            .map_err(|e| SwarmError::Serialization(format!("Failed to serialize cell: {}", e)))?;

        // Encrypt with Wasif-Vernam for this hop using the circuit's SwarmLayer
        let encrypted = self.encrypt_data_for_hop(&serialized, hop_idx, circuit)?;

        Ok(encrypted)
    }

    /// Decrypt cell from specific hop (reserved for relay node implementation)
    #[allow(dead_code)]
    fn decrypt_cell_from_hop(
        &self,
        encrypted: &[u8],
        hop_idx: usize,
        circuit: &FaisalSwarmCircuit,
    ) -> Result<FaisalSwarmCell> {
        // Decrypt with Wasif-Vernam for this hop using the circuit's SwarmLayer
        let decrypted = self.decrypt_data_from_hop(encrypted, hop_idx, circuit)?;

        // Deserialize cell
        let cell: FaisalSwarmCell = serde_json::from_slice(&decrypted)
            .map_err(|e| SwarmError::Serialization(format!("Failed to deserialize cell: {}", e)))?;

        Ok(cell)
    }

    /// Encrypt data for specific hop using SwarmLayer Wasif-Vernam cipher
    fn encrypt_data_for_hop(
        &self,
        data: &[u8],
        hop_idx: usize,
        circuit: &FaisalSwarmCircuit,
    ) -> Result<Vec<u8>> {
        if hop_idx >= circuit.layers.len() {
            return Err(SwarmError::Encryption(format!(
                "Invalid hop index {} for circuit with {} layers",
                hop_idx,
                circuit.layers.len()
            )));
        }

        // Use the forward cipher from the SwarmLayer for this hop
        let layer = &circuit.layers[hop_idx];
        let mut cipher = layer.forward_cipher.write().map_err(|e| {
            SwarmError::Encryption(format!("Failed to acquire forward cipher lock: {}", e))
        })?;
        let encrypted = cipher.encrypt(data).map_err(|e| {
            SwarmError::Encryption(format!(
                "Wasif-Vernam encryption failed for hop {}: {:?}",
                hop_idx, e
            ))
        })?;

        info!(
            "Data encrypted with Wasif-Vernam cipher for hop {}: {} → {} bytes",
            hop_idx,
            data.len(),
            encrypted.len()
        );

        Ok(encrypted)
    }

    /// Decrypt data from specific hop using SwarmLayer Wasif-Vernam cipher (reserved for relay node implementation)
    #[allow(dead_code)]
    fn decrypt_data_from_hop(
        &self,
        encrypted: &[u8],
        hop_idx: usize,
        circuit: &FaisalSwarmCircuit,
    ) -> Result<Vec<u8>> {
        if hop_idx >= circuit.layers.len() {
            return Err(SwarmError::Encryption(format!(
                "Invalid hop index {} for circuit with {} layers",
                hop_idx,
                circuit.layers.len()
            )));
        }

        // Use the backward cipher from the SwarmLayer for this hop
        let layer = &circuit.layers[hop_idx];
        let cipher = layer.backward_cipher.write().map_err(|e| {
            SwarmError::Encryption(format!("Failed to acquire backward cipher lock: {}", e))
        })?;
        let decrypted = cipher.decrypt(encrypted).map_err(|e| {
            SwarmError::Encryption(format!(
                "Wasif-Vernam decryption failed for hop {}: {:?}",
                hop_idx, e
            ))
        })?;

        info!(
            "Data decrypted with Wasif-Vernam cipher for hop {}: {} → {} bytes",
            hop_idx,
            encrypted.len(),
            decrypted.len()
        );

        Ok(decrypted)
    }

    /// Get circuit info
    pub async fn get_circuit_info(&self, circuit_id: CircuitId) -> Result<FaisalSwarmCircuit> {
        let circuits = self.circuits.read().await;
        let circuit = circuits
            .get(&circuit_id)
            .ok_or(SwarmError::NotFound(circuit_id))?;

        // Create a summary of the circuit info without cloning the entire structure
        Ok(FaisalSwarmCircuit {
            id: circuit.id,
            hops: circuit.hops.clone(),
            layers: Vec::new(), // Can't clone WasifVernam layers
            state: circuit.state.clone(),
            created_at: circuit.created_at,
            encryption: None,
        })
    }

    /// List all active circuits
    pub async fn list_circuits(&self) -> Vec<CircuitId> {
        let circuits = self.circuits.read().await;
        circuits.keys().cloned().collect()
    }
}
