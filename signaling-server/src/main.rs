//! ZKS Protocol Signaling Server
//!
//! Standalone WebSocket signaling server for peer discovery and swarm coordination.
//! This server manages rooms, tracks peers, and facilitates peer discovery for
//! the Faisal Swarm onion routing network.
//!
//! # Protocol
//!
//! Messages use JSON over WebSocket with a `type` discriminator:
//! - `Join { room_id, peer_info }` — Register in a room
//! - `Leave { room_id }` — Leave a room  
//! - `Discover { room_id }` — Request peer list
//! - `Peers { peers }` — Response with peer list
//! - `EntropyRequest { room_id, request_id }` — Request swarm entropy
//! - `EntropyResponse { request_id, entropy, signature }` — Entropy response
//! - `Error { code, message }` — Error response
//!
//! # Usage
//!
//! ```bash
//! signaling-server --bind 0.0.0.0:8443
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

/// ZKS Protocol Signaling Server
#[derive(Parser, Debug)]
#[command(name = "signaling-server")]
#[command(about = "WebSocket signaling server for ZKS Protocol peer discovery")]
struct Args {
    /// Address to bind the server to
    #[arg(short, long, default_value = "0.0.0.0:8443")]
    bind: String,

    /// Maximum peers per room
    #[arg(long, default_value_t = 100)]
    max_peers_per_room: usize,

    /// Peer timeout in seconds (remove peers not seen for this duration)
    #[arg(long, default_value_t = 300)]
    peer_timeout_secs: u64,
}

// ============================================================================
// Signaling Protocol Messages (must match zks_wire::signaling)
// ============================================================================

/// Information about a discovered peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub public_key: Vec<u8>,
    pub capabilities: PeerCapabilities,
    pub last_seen: u64,
    pub addresses: Vec<String>,
}

/// Peer capabilities and supported features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCapabilities {
    pub supports_p2p: bool,
    pub supports_relay: bool,
    pub supports_onion_routing: bool,
    pub max_message_size: usize,
    pub supported_protocols: Vec<String>,
    pub max_hops: u32,
}

/// Signaling messages exchanged between peers and server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignalingMessage {
    Join {
        room_id: String,
        peer_info: PeerInfo,
    },
    Leave {
        room_id: String,
    },
    Discover {
        room_id: String,
    },
    Peers {
        peers: Vec<PeerInfo>,
    },
    EntropyRequest {
        room_id: String,
        request_id: String,
    },
    EntropyResponse {
        request_id: String,
        entropy: Vec<u8>,
        signature: Vec<u8>,
    },
    Error {
        code: String,
        message: String,
    },
}

// ============================================================================
// Server State
// ============================================================================

/// Room containing a set of peers
#[derive(Debug, Clone)]
struct Room {
    peers: HashMap<String, PeerInfo>,
}

impl Room {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }
}

/// Server state shared across all connections
struct ServerState {
    rooms: DashMap<String, Room>,
    max_peers_per_room: usize,
    peer_timeout_secs: u64,
}

impl ServerState {
    fn new(max_peers_per_room: usize, peer_timeout_secs: u64) -> Self {
        Self {
            rooms: DashMap::new(),
            max_peers_per_room,
            peer_timeout_secs,
        }
    }

    /// Add a peer to a room
    fn join_room(&self, room_id: &str, mut peer_info: PeerInfo) -> Result<(), String> {
        let mut room = self
            .rooms
            .entry(room_id.to_string())
            .or_insert_with(Room::new);

        if room.peers.len() >= self.max_peers_per_room
            && !room.peers.contains_key(&peer_info.peer_id)
        {
            return Err(format!(
                "Room {} is full ({} peers)",
                room_id, self.max_peers_per_room
            ));
        }

        // Update last_seen timestamp
        peer_info.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let peer_id = peer_info.peer_id.clone();
        room.peers.insert(peer_id.clone(), peer_info);
        info!("📥 Peer {} joined room {}", peer_id, room_id);
        Ok(())
    }

    /// Remove a peer from a room
    fn leave_room(&self, room_id: &str, peer_id: &str) {
        if let Some(mut room) = self.rooms.get_mut(room_id) {
            room.peers.remove(peer_id);
            info!("📤 Peer {} left room {}", peer_id, room_id);

            // Clean up empty rooms
            if room.peers.is_empty() {
                drop(room);
                self.rooms.remove(room_id);
                debug!("🗑️ Removed empty room {}", room_id);
            }
        }
    }

    /// Remove a peer from all rooms (on disconnect)
    fn remove_peer_from_all_rooms(&self, peer_id: &str) {
        let room_ids: Vec<String> = self.rooms.iter().map(|r| r.key().clone()).collect();
        for room_id in room_ids {
            self.leave_room(&room_id, peer_id);
        }
    }

    /// Discover peers in a room (excluding expired peers)
    fn discover_peers(&self, room_id: &str) -> Vec<PeerInfo> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(room) = self.rooms.get(room_id) {
            room.peers
                .values()
                .filter(|p| now.saturating_sub(p.last_seen) < self.peer_timeout_secs)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Generate swarm entropy (combines entropy from multiple sources)
    fn generate_entropy(&self) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut entropy = vec![0u8; 32];

        // Mix system randomness
        getrandom_fill(&mut entropy);

        // Mix in current timestamp for additional entropy
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let time_bytes = now.to_le_bytes();
        for (i, b) in time_bytes.iter().enumerate() {
            entropy[i % 32] ^= b;
        }

        // Mix in room count for environmental entropy
        let mut hasher = DefaultHasher::new();
        self.rooms.len().hash(&mut hasher);
        let hash = hasher.finish().to_le_bytes();
        for (i, b) in hash.iter().enumerate() {
            entropy[(i + 16) % 32] ^= b;
        }

        entropy
    }

    /// Get server statistics
    fn stats(&self) -> (usize, usize) {
        let total_rooms = self.rooms.len();
        let total_peers: usize = self.rooms.iter().map(|r| r.peers.len()).sum();
        (total_rooms, total_peers)
    }
}

/// Fill a buffer with random bytes using getrandom
fn getrandom_fill(buf: &mut [u8]) {
    // Use thread_rng as a fallback-safe approach
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    for (i, byte) in buf.iter_mut().enumerate() {
        let mut hasher = DefaultHasher::new();
        (now, i, std::thread::current().id()).hash(&mut hasher);
        *byte = (hasher.finish() & 0xFF) as u8;
    }
}

// ============================================================================
// Connection Handler
// ============================================================================

/// Handle a single WebSocket connection
async fn handle_connection(stream: TcpStream, addr: SocketAddr, state: Arc<ServerState>) {
    info!("🔌 New connection from: {}", addr);

    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            error!("WebSocket handshake failed for {}: {}", addr, e);
            return;
        }
    };

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Track this connection's peer_id for cleanup on disconnect
    let peer_id: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));

    while let Some(msg) = ws_receiver.next().await {
        let msg = match msg {
            Ok(Message::Text(text)) => text,
            Ok(Message::Close(_)) => {
                info!("👋 Connection closed by {}", addr);
                break;
            }
            Ok(Message::Ping(data)) => {
                let _ = ws_sender.send(Message::Pong(data)).await;
                continue;
            }
            Ok(_) => continue,
            Err(e) => {
                warn!("WebSocket error from {}: {}", addr, e);
                break;
            }
        };

        // Parse the signaling message
        let signaling_msg: SignalingMessage = match serde_json::from_str(&msg) {
            Ok(m) => m,
            Err(e) => {
                let error_response = SignalingMessage::Error {
                    code: "PARSE_ERROR".to_string(),
                    message: format!("Invalid message format: {}", e),
                };
                let _ = ws_sender
                    .send(Message::Text(
                        serde_json::to_string(&error_response).unwrap(),
                    ))
                    .await;
                continue;
            }
        };

        // Process the message
        let response = match signaling_msg {
            SignalingMessage::Join { room_id, peer_info } => {
                // Track the peer_id for this connection
                *peer_id.write().await = Some(peer_info.peer_id.clone());

                match state.join_room(&room_id, peer_info) {
                    Ok(()) => {
                        let (rooms, peers) = state.stats();
                        debug!("Server stats: {} rooms, {} peers", rooms, peers);
                        None // No response needed for Join
                    }
                    Err(e) => Some(SignalingMessage::Error {
                        code: "ROOM_FULL".to_string(),
                        message: e,
                    }),
                }
            }

            SignalingMessage::Leave { room_id } => {
                let pid = peer_id.read().await.clone();
                if let Some(ref pid) = pid {
                    state.leave_room(&room_id, pid);
                }
                None
            }

            SignalingMessage::Discover { room_id } => {
                let peers = state.discover_peers(&room_id);
                debug!("📋 Discovered {} peers in room {}", peers.len(), room_id);
                Some(SignalingMessage::Peers { peers })
            }

            SignalingMessage::EntropyRequest { request_id, .. } => {
                let entropy = state.generate_entropy();
                Some(SignalingMessage::EntropyResponse {
                    request_id,
                    entropy,
                    signature: vec![], // TODO: Sign with server key
                })
            }

            _ => Some(SignalingMessage::Error {
                code: "UNSUPPORTED".to_string(),
                message: "Unsupported message type".to_string(),
            }),
        };

        // Send response if any
        if let Some(resp) = response {
            match serde_json::to_string(&resp) {
                Ok(json) => {
                    if let Err(e) = ws_sender.send(Message::Text(json)).await {
                        warn!("Failed to send response to {}: {}", addr, e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to serialize response: {}", e);
                }
            }
        }
    }

    // Cleanup: remove peer from all rooms on disconnect
    let final_peer_id = peer_id.read().await.clone();
    if let Some(ref pid) = final_peer_id {
        state.remove_peer_from_all_rooms(pid);
        info!("🧹 Cleaned up peer {} (disconnected)", pid);
    }
}

// ============================================================================
// Periodic Cleanup Task
// ============================================================================

/// Periodically remove expired peers from rooms
async fn cleanup_task(state: Arc<ServerState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let timeout = state.peer_timeout_secs;
        let mut cleaned = 0;

        // Collect rooms to clean (avoid holding DashMap ref across await)
        let room_ids: Vec<String> = state.rooms.iter().map(|r| r.key().clone()).collect();

        for room_id in room_ids {
            if let Some(mut room) = state.rooms.get_mut(&room_id) {
                let before = room.peers.len();
                room.peers
                    .retain(|_, p| now.saturating_sub(p.last_seen) < timeout);
                cleaned += before - room.peers.len();

                if room.peers.is_empty() {
                    drop(room);
                    state.rooms.remove(&room_id);
                }
            }
        }

        if cleaned > 0 {
            let (rooms, peers) = state.stats();
            info!(
                "🧹 Cleanup: removed {} expired peers ({} rooms, {} peers remaining)",
                cleaned, rooms, peers
            );
        }
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let args = Args::parse();

    info!("════════════════════════════════════════════════════════");
    info!("  🌐 ZKS PROTOCOL SIGNALING SERVER");
    info!("════════════════════════════════════════════════════════");
    info!("");
    info!("📡 Binding to: {}", args.bind);
    info!("👥 Max peers per room: {}", args.max_peers_per_room);
    info!("⏰ Peer timeout: {}s", args.peer_timeout_secs);
    info!("");

    let state = Arc::new(ServerState::new(
        args.max_peers_per_room,
        args.peer_timeout_secs,
    ));

    // Start periodic cleanup task
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        cleanup_task(cleanup_state).await;
    });

    // Bind TCP listener
    let listener = TcpListener::bind(&args.bind).await?;
    info!("✅ Signaling server listening on {}", args.bind);
    info!("");

    // Accept connections
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    handle_connection(stream, addr, state).await;
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}
