//! P2P connection management

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, warn};

use crate::{
    connection::{ZkConnection, ZksConnection},
    config::ConnectionConfig,
    error::{Result, SdkError},
};

/// P2P connection manager
pub struct P2PConnection {
    connections: Arc<RwLock<HashMap<String, Connection>>>,
    config: ConnectionConfig,
}

enum Connection {
    Zk(ZkConnection),
    Zks(ZksConnection),
}

impl P2PConnection {
    /// Create a new P2P connection manager
    pub fn new(config: ConnectionConfig) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
    
    /// Connect to a peer
    pub async fn connect(&self, peer_id: &str, url: &str) -> Result<()> {
        info!("Connecting to peer: {} at {}", peer_id, url);
        
        let parsed_url = url::Url::parse(url)
            .map_err(|e| SdkError::InvalidUrl(format!("Invalid URL: {}", e)))?;
        
        let connection = match parsed_url.scheme() {
            "zk" => {
                let conn = ZkConnection::connect(url.to_string(), self.config.clone()).await?;
                Connection::Zk(conn)
            }
            "zks" => {
                let conn = ZksConnection::connect(url.to_string(), self.config.clone(), 3, 5).await?;
                Connection::Zks(conn)
            }
            _ => return Err(SdkError::InvalidUrl("Unsupported URL scheme".to_string())),
        };
        
        let mut connections = self.connections.write().await;
        connections.insert(peer_id.to_string(), connection);
        
        info!("Connected to peer: {}", peer_id);
        Ok(())
    }
    
    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: &str) -> Result<()> {
        info!("Disconnecting from peer: {}", peer_id);
        
        let mut connections = self.connections.write().await;
        if let Some(connection) = connections.remove(peer_id) {
            // Properly close the connection based on type
            match connection {
                Connection::Zk(conn) => {
                    info!("Closing ZK connection to peer: {}", peer_id);
                    if let Err(e) = conn.close().await {
                        warn!("Failed to properly close ZK connection: {}", e);
                    }
                    info!("Disconnected from ZK peer: {}", peer_id);
                }
                Connection::Zks(conn) => {
                    info!("Closing ZKS connection to peer: {}", peer_id);
                    if let Err(e) = conn.close().await {
                        warn!("Failed to properly close ZKS connection: {}", e);
                    }
                    info!("Disconnected from ZKS peer: {}", peer_id);
                }
            }
        } else {
            return Err(SdkError::NotConnected);
        }
        
        Ok(())
    }
    
    /// Send data to a peer
    pub async fn send(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        let mut connections = self.connections.write().await;
        
        match connections.get_mut(peer_id) {
            Some(Connection::Zk(conn)) => conn.send(data).await,
            Some(Connection::Zks(conn)) => conn.send(data).await,
            None => Err(SdkError::NotConnected),
        }
    }
    
    /// Send a message to a peer
    pub async fn send_message(&self, peer_id: &str, message: &[u8]) -> Result<()> {
        let mut connections = self.connections.write().await;
        
        match connections.get_mut(peer_id) {
            Some(Connection::Zk(conn)) => conn.send_message(message).await,
            Some(Connection::Zks(conn)) => conn.send_message(message).await,
            None => Err(SdkError::NotConnected),
        }
    }
    
    /// Broadcast data to all connected peers
    pub async fn broadcast(&self, data: &[u8]) -> Result<Vec<String>> {
        let mut connections = self.connections.write().await;
        let mut failed = Vec::new();
        
        for (peer_id, connection) in connections.iter_mut() {
            let result = match connection {
                Connection::Zk(conn) => conn.send(data).await,
                Connection::Zks(conn) => conn.send(data).await,
            };
            
            if let Err(e) = result {
                warn!("Failed to send to peer {}: {}", peer_id, e);
                failed.push(peer_id.clone());
            }
        }
        
        if failed.is_empty() {
            debug!("Broadcast successful to all {} peers", connections.len());
        } else {
            warn!("Broadcast failed to {} peers: {:?}", failed.len(), failed);
        }
        
        Ok(failed)
    }
    
    /// Get list of connected peers
    pub async fn peers(&self) -> Vec<String> {
        let connections = self.connections.read().await;
        connections.keys().cloned().collect()
    }
    
    /// Check if connected to a peer
    pub async fn is_connected(&self, peer_id: &str) -> bool {
        let connections = self.connections.read().await;
        connections.contains_key(peer_id)
    }
    
    /// Get the number of connected peers
    pub async fn peer_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }
    
    /// Disconnect from all peers
    pub async fn disconnect_all(&self) -> Result<()> {
        info!("Disconnecting from all peers");
        
        let mut connections = self.connections.write().await;
        connections.clear();
        
        info!("Disconnected from all peers");
        Ok(())
    }
}

impl Default for P2PConnection {
    fn default() -> Self {
        Self::new(ConnectionConfig::default())
    }
}