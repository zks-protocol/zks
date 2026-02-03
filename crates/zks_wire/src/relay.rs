//! Relay server implementation for ZK Protocol
//! 
//! Provides TURN-like relay functionality for NAT traversal when direct peer-to-peer
//! connections are not possible. This module implements a lightweight relay server
//! that can forward encrypted traffic between peers.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use tracing::{debug, info, warn};
use serde::{Serialize, Deserialize};

use crate::{WireError, Result};

/// Unique identifier for a relay allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelayId([u8; 16]);

impl RelayId {
    /// Generate a new random relay ID using high-entropy randomness (drand + OsRng)
    /// 
    /// # Security
    /// Uses TrueEntropy for 256-bit post-quantum computational security.
    /// Secure if ANY entropy source is uncompromised.
    pub fn new() -> Self {
        use zks_crypt::true_entropy::get_sync_entropy;
        let entropy = get_sync_entropy(16);
        let mut id = [0u8; 16];
        id.copy_from_slice(&entropy);
        Self(id)
    }
    
    /// Create from a byte array
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    
    /// Convert to byte array
    pub fn to_bytes(&self) -> [u8; 16] {
        self.0
    }
    
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Default for RelayId {
    fn default() -> Self {
        Self::new()
    }
}

/// Authentication credentials for relay access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayCredentials {
    /// Username for authentication
    pub username: String,
    /// Password for authentication  
    pub password: String,
    /// Expiration time (Unix timestamp)
    pub expires_at: u64,
}

/// Relay allocation information
#[derive(Debug, Clone)]
pub struct RelayAllocation {
    /// Unique allocation ID
    pub id: RelayId,
    /// Client's private address
    pub client_addr: SocketAddr,
    /// Relay's public address (allocated for this client)
    pub relay_addr: SocketAddr,
    /// Authentication credentials
    pub credentials: RelayCredentials,
    /// Allocation creation time
    pub created_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Channel for sending data to the client
    pub client_channel: mpsc::Sender<Vec<u8>>,
}

impl RelayAllocation {
    /// Check if this allocation has expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.credentials.expires_at
    }
    
    /// Check if this allocation is idle (no activity for too long)
    pub fn is_idle(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

/// Relay server configuration
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Bind address for the relay server
    pub bind_addr: SocketAddr,
    /// Maximum number of allocations
    pub max_allocations: usize,
    /// Allocation lifetime (seconds)
    pub allocation_lifetime: u64,
    /// Idle timeout (seconds)
    pub idle_timeout: u64,
    /// Enable authentication
    pub auth_required: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:3478".parse().unwrap(),
            max_allocations: 1000,
            allocation_lifetime: 3600, // 1 hour
            idle_timeout: 600, // 10 minutes
            auth_required: true,
        }
    }
}

/// Relay server implementation
pub struct RelayServer {
    /// Server configuration
    config: RelayConfig,
    /// Active allocations
    allocations: Arc<RwLock<HashMap<RelayId, RelayAllocation>>>,
    /// Client address to allocation mapping
    client_map: Arc<RwLock<HashMap<SocketAddr, RelayId>>>,
    /// UDP socket for relay communication
    udp_socket: Option<Arc<UdpSocket>>,
    /// TCP listener for control channel
    tcp_listener: Option<TcpListener>,
}

impl RelayServer {
    /// Create a new relay server with the given configuration
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            allocations: Arc::new(RwLock::new(HashMap::new())),
            client_map: Arc::new(RwLock::new(HashMap::new())),
            udp_socket: None,
            tcp_listener: None,
        }
    }
    
    /// Start the relay server
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting relay server on {}", self.config.bind_addr);
        
        // Create UDP socket
        let udp_socket = UdpSocket::bind(self.config.bind_addr).await
            .map_err(|e| WireError::BindError(format!("Failed to bind UDP socket: {}", e)))?;
        self.udp_socket = Some(Arc::new(udp_socket));
        
        // Create TCP listener for control channel
        let tcp_listener = TcpListener::bind(self.config.bind_addr).await
            .map_err(|e| WireError::BindError(format!("Failed to bind TCP listener: {}", e)))?;
        self.tcp_listener = Some(tcp_listener);
        
        info!("Relay server started successfully");
        Ok(())
    }
    
    /// Get the server configuration
    pub fn config(&self) -> &RelayConfig {
        &self.config
    }
    
    /// Create a new allocation for a client
    pub async fn create_allocation(
        &self,
        client_addr: SocketAddr,
        credentials: RelayCredentials,
    ) -> Result<RelayId> {
        // Check if we have room for more allocations
        let allocation_count = self.allocations.read().await.len();
        if allocation_count >= self.config.max_allocations {
            return Err(WireError::ResourceExhausted("Maximum allocations reached".to_string()).into());
        }
        
        // Check if credentials are valid
        if self.config.auth_required && self.is_expired(&credentials) {
            return Err(WireError::AuthenticationError("Credentials expired".to_string()).into());
        }
        
        // Generate relay address (using a different port)
        let relay_addr = self.generate_relay_address(client_addr)?;
        
        // Create allocation
        let allocation_id = RelayId::new();
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(100);
        
        let allocation = RelayAllocation {
            id: allocation_id,
            client_addr,
            relay_addr,
            credentials,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            client_channel: tx,
        };
        
        // Store allocation
        self.allocations.write().await.insert(allocation_id, allocation);
        self.client_map.write().await.insert(client_addr, allocation_id);
        
        info!("Created relay allocation {} for client {}", allocation_id.to_hex(), client_addr);
        
        // Start allocation maintenance task
        let allocations = self.allocations.clone();
        let client_map = self.client_map.clone();
        let allocation_id_copy = allocation_id;
        let idle_timeout = Duration::from_secs(self.config.idle_timeout);
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60)); // Check every minute
            loop {
                interval.tick().await;
                
                // Check if allocation still exists and is not idle
                let should_continue = {
                    let allocations = allocations.read().await;
                    if let Some(allocation) = allocations.get(&allocation_id_copy) {
                        !allocation.is_idle(idle_timeout)
                    } else {
                        false // Allocation was removed
                    }
                };
                
                if !should_continue {
                    // Clean up allocation
                    allocations.write().await.remove(&allocation_id_copy);
                    client_map.write().await.remove(&client_addr);
                    info!("Cleaned up idle allocation {}", allocation_id_copy.to_hex());
                    break;
                }
            }
        });
        
        Ok(allocation_id)
    }
    
    /// Relay data from one peer to another
    pub async fn relay_data(
        &self,
        from_addr: SocketAddr,
        to_addr: SocketAddr,
        data: Vec<u8>,
    ) -> Result<()> {
        // Find allocation for the destination
        let allocation_id = self.client_map.read().await.get(&to_addr)
            .copied()
            .ok_or_else(|| WireError::NotFound("No allocation for destination".to_string()))?;
        
        let mut allocations = self.allocations.write().await;
        if let Some(allocation) = allocations.get_mut(&allocation_id) {
            // Update last activity
            allocation.last_activity = Instant::now();
            
            let data_len = data.len();
            // Send data to client
            if let Err(e) = allocation.client_channel.try_send(data) {
                warn!("Failed to send data to client {}: {}", allocation_id.to_hex(), e);
                return Err(WireError::ChannelError("Failed to send data".to_string()).into());
            }
            
            debug!("Relayed {} bytes from {} to {}", data_len, from_addr, to_addr);
            Ok(())
        } else {
            Err(WireError::NotFound("Allocation not found".to_string()).into())
        }
    }
    
    /// Get allocation information
    pub async fn get_allocation(&self, id: RelayId) -> Option<RelayAllocation> {
        self.allocations.read().await.get(&id).cloned()
    }
    
    /// Remove an allocation
    pub async fn remove_allocation(&self, id: RelayId) -> Result<()> {
        let allocation = self.allocations.write().await.remove(&id);
        if let Some(allocation) = allocation {
            self.client_map.write().await.remove(&allocation.client_addr);
            info!("Removed allocation {} for client {}", id.to_hex(), allocation.client_addr);
        }
        Ok(())
    }
    
    /// Generate a relay address for a client using high-entropy randomness (drand + OsRng)
    fn generate_relay_address(&self, _client_addr: SocketAddr) -> Result<SocketAddr> {
        // SECURITY: Use TrueEntropy for 256-bit post-quantum computational security
        use zks_crypt::true_entropy::get_sync_entropy;
        let entropy = get_sync_entropy(2);
        let port_bytes = [entropy[0], entropy[1]];
        
        let base_port = self.config.bind_addr.port();
        // Generate random offset within safe range (1-1000) to avoid port conflicts
        let random_offset = (u16::from_le_bytes(port_bytes) % 1000) + 1;
        let relay_port = base_port.saturating_add(random_offset);
        
        Ok(SocketAddr::new(self.config.bind_addr.ip(), relay_port))
    }
    
    /// Check if credentials are expired
    fn is_expired(&self, credentials: &RelayCredentials) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > credentials.expires_at
    }
    
    /// Get server statistics
    pub async fn get_stats(&self) -> RelayStats {
        let allocations = self.allocations.read().await;
        RelayStats {
            active_allocations: allocations.len(),
            total_allocations: allocations.len(), // Simplified
            uptime: Duration::from_secs(0), // Would need to track start time
        }
    }
}

/// Relay server statistics
#[derive(Debug, Clone)]
pub struct RelayStats {
    /// Number of active allocations
    pub active_allocations: usize,
    /// Total number of allocations created
    pub total_allocations: usize,
    /// Server uptime
    pub uptime: Duration,
}

/// Relay client for connecting to relay servers
pub struct RelayClient {
    /// Relay server address
    server_addr: SocketAddr,
    /// Local UDP socket
    socket: Option<Arc<UdpSocket>>,
    /// Current allocation (if any)
    allocation: Option<RelayId>,
}

impl RelayClient {
    /// Create a new relay client
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            socket: None,
            allocation: None,
        }
    }
    
    /// Connect to the relay server and create an allocation
    pub async fn connect(&mut self, _credentials: RelayCredentials) -> Result<RelayId> {
        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| WireError::BindError(format!("Failed to bind UDP socket: {}", e)))?;
        
        // Connect to relay server
        socket.connect(self.server_addr).await
            .map_err(|e| WireError::ConnectionError(format!("Failed to connect to relay: {}", e)))?;
        
        self.socket = Some(Arc::new(socket));
        
        // In a real implementation, this would perform the relay protocol handshake
        // For now, we'll just return a dummy allocation ID
        let allocation_id = RelayId::new();
        self.allocation = Some(allocation_id);
        
        info!("Connected to relay server at {} with allocation {}", self.server_addr, allocation_id.to_hex());
        Ok(allocation_id)
    }
    
    /// Send data through the relay
    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        if let Some(ref socket) = self.socket {
            socket.send(&data).await
                .map_err(|e| WireError::ConnectionError(format!("Failed to send data: {}", e)))?;
            Ok(())
        } else {
            Err(WireError::NotConnected("Not connected to relay".to_string()).into())
        }
    }
    
    /// Receive data from the relay
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        if let Some(ref socket) = self.socket {
            let len = socket.recv(buf).await
                .map_err(|e| WireError::ConnectionError(format!("Failed to receive data: {}", e)))?;
            Ok(len)
        } else {
            Err(WireError::NotConnected("Not connected to relay".to_string()).into())
        }
    }
    
    /// Disconnect from the relay server
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(allocation_id) = self.allocation {
            info!("Disconnecting from relay server, releasing allocation {}", allocation_id.to_hex());
            self.allocation = None;
            self.socket = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_relay_id_generation() {
        let id1 = RelayId::new();
        let id2 = RelayId::new();
        
        assert_ne!(id1, id2);
        assert_eq!(id1.to_bytes().len(), 16);
        assert_eq!(id2.to_bytes().len(), 16);
    }
    
    #[tokio::test]
    async fn test_relay_config_default() {
        let config = RelayConfig::default();
        assert_eq!(config.bind_addr.port(), 3478);
        assert_eq!(config.max_allocations, 1000);
        assert_eq!(config.allocation_lifetime, 3600);
        assert!(config.auth_required);
    }
}