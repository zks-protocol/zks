use uniffi;
uniffi::setup_scaffolding!();

use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;
use zks_wire::signaling::{
    PeerCapabilities as WirePeerCapabilities, PeerInfo as WirePeerInfo, SignalingClient,
    SignalingError,
};

const DEFAULT_SIGNALING_URL: &str = "wss://signal.zks-protocol.org";

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ZksError {
    #[error("Not connected")]
    NotConnected,
    #[error("Connection failed: {message}")]
    ConnectionFailed { message: String },
    #[error("Match failed: {message}")]
    MatchFailed { message: String },
    #[error("Async operation failed: {message}")]
    AsyncError { message: String },
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PeerInfo {
    pub peer_id: String,
    pub public_key: Vec<u8>,
    pub endpoint_hint: Option<String>,
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum ConnectionState {
    Disconnected,
    Matching,
    Connected { peer: PeerInfo },
}

#[derive(uniffi::Object)]
pub struct ZksMeetClient {
    peer_id: String,
    state: Arc<RwLock<ConnectionState>>,
    runtime: Arc<Runtime>,
    signaling_client: Arc<RwLock<Option<SignalingClient>>>,
}

impl Default for ZksMeetClient {
    fn default() -> Self {
        Self {
            peer_id: format!("peer_{}", uuid::Uuid::new_v4()),
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            runtime: Arc::new(Runtime::new().unwrap()),
            signaling_client: Arc::new(RwLock::new(None)),
        }
    }
}

#[uniffi::export]
impl ZksMeetClient {
    #[uniffi::constructor]
    pub fn new(peer_id: String) -> Arc<Self> {
        Arc::new(Self {
            peer_id,
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            runtime: Arc::new(Runtime::new().unwrap()),
            signaling_client: Arc::new(RwLock::new(None)),
        })
    }

    #[uniffi::constructor]
    pub fn new_random() -> Arc<Self> {
        Arc::new(Self {
            peer_id: format!("peer_{}", uuid::Uuid::new_v4()),
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            runtime: Arc::new(Runtime::new().unwrap()),
            signaling_client: Arc::new(RwLock::new(None)),
        })
    }

    pub fn get_peer_id(&self) -> String {
        self.peer_id.clone()
    }

    pub fn get_state(&self) -> ConnectionState {
        self.runtime
            .block_on(async { self.state.read().await.clone() })
    }

    pub fn connect_matchmaking(&self, url: String) -> Result<(), ZksError> {
        let runtime = self.runtime.clone();
        let state = self.state.clone();
        let signaling_client = self.signaling_client.clone();
        let peer_id = self.peer_id.clone();

        runtime.block_on(async {
            *state.write().await = ConnectionState::Matching;

            let client = SignalingClient::connect(&url, peer_id)
                .await
                .map_err(signaling_error_to_zks_error)?;

            *signaling_client.write().await = Some(client);
            Ok(())
        })
    }

    pub fn send(&self, _data: Vec<u8>) -> Result<(), ZksError> {
        let runtime = self.runtime.clone();
        let state = self.state.clone();

        runtime.block_on(async {
            let current_state = state.read().await;
            match &*current_state {
                ConnectionState::Connected { peer: _ } => {
                    // TODO: Implement actual P2P data sending
                    // For now, this is a placeholder
                    Ok(())
                }
                _ => Err(ZksError::NotConnected),
            }
        })
    }

    pub fn receive(&self) -> Result<Vec<u8>, ZksError> {
        let runtime = self.runtime.clone();
        let state = self.state.clone();

        runtime.block_on(async {
            let current_state = state.read().await;
            match &*current_state {
                ConnectionState::Connected { peer: _ } => {
                    // TODO: Implement actual P2P data receiving
                    // For now, this is a placeholder
                    Ok(vec![])
                }
                _ => Err(ZksError::NotConnected),
            }
        })
    }

    pub fn skip(&self) -> Result<PeerInfo, ZksError> {
        let runtime = self.runtime.clone();
        let state = self.state.clone();
        let signaling_client = self.signaling_client.clone();

        runtime.block_on(async {
            let current_state = state.read().await;
            match &*current_state {
                ConnectionState::Connected {
                    peer: _current_peer,
                } => {
                    // Disconnect from current peer
                    drop(current_state);

                    // Find new peer
                    let mut client_guard = signaling_client.write().await;
                    if let Some(ref mut client) = *client_guard {
                        let peers = client
                            .discover_peers("zks-meet-global")
                            .await
                            .map_err(signaling_error_to_zks_error)?;

                        if peers.is_empty() {
                            return Err(ZksError::MatchFailed {
                                message: "No more peers available".to_string(),
                            });
                        }

                        let new_peer = &peers[0];
                        let uniffi_peer = wire_peer_to_uniffi_peer(new_peer);

                        *state.write().await = ConnectionState::Connected {
                            peer: uniffi_peer.clone(),
                        };
                        Ok(uniffi_peer)
                    } else {
                        Err(ZksError::NotConnected)
                    }
                }
                _ => Err(ZksError::NotConnected),
            }
        })
    }

    pub fn disconnect(&self) {
        let runtime = self.runtime.clone();
        let state = self.state.clone();
        let signaling_client = self.signaling_client.clone();

        runtime.block_on(async {
            *state.write().await = ConnectionState::Disconnected;
            *signaling_client.write().await = None;
        });
    }

    pub fn find_match(&self, interests: Vec<String>) -> Result<PeerInfo, ZksError> {
        let runtime = self.runtime.clone();
        let state = self.state.clone();
        let signaling_client = self.signaling_client.clone();
        let peer_id = self.peer_id.clone();

        runtime.block_on(async {
            *state.write().await = ConnectionState::Matching;

            let mut client_guard = signaling_client.write().await;

            // Create client if not exists
            if client_guard.is_none() {
                let client = SignalingClient::connect(DEFAULT_SIGNALING_URL, peer_id.clone())
                    .await
                    .map_err(signaling_error_to_zks_error)?;
                *client_guard = Some(client);
            }

            if let Some(ref mut client) = *client_guard {
                let capabilities = WirePeerCapabilities {
                    supported_protocols: interests,
                    ..Default::default()
                };

                client
                    .join_room("zks-meet-global", capabilities)
                    .await
                    .map_err(signaling_error_to_zks_error)?;

                let peers = client
                    .discover_peers("zks-meet-global")
                    .await
                    .map_err(signaling_error_to_zks_error)?;

                if peers.is_empty() {
                    return Err(ZksError::MatchFailed {
                        message: "No matching peers found".to_string(),
                    });
                }

                let selected_peer = &peers[0];
                let uniffi_peer = wire_peer_to_uniffi_peer(selected_peer);

                *state.write().await = ConnectionState::Connected {
                    peer: uniffi_peer.clone(),
                };
                Ok(uniffi_peer)
            } else {
                Err(ZksError::ConnectionFailed {
                    message: "Failed to create signaling client".to_string(),
                })
            }
        })
    }
}

fn wire_peer_to_uniffi_peer(wire_peer: &WirePeerInfo) -> PeerInfo {
    PeerInfo {
        peer_id: wire_peer.peer_id.clone(),
        public_key: wire_peer.public_key.clone(),
        endpoint_hint: wire_peer.addresses.first().cloned(),
    }
}

fn signaling_error_to_zks_error(error: SignalingError) -> ZksError {
    ZksError::ConnectionFailed {
        message: format!("Signaling error: {}", error),
    }
}
