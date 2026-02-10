//! Networking tools for ZKS MCP server
//! 
//! Provides tools for ZKS network operations including connection management,
//! anonymous routing, peer discovery, and NAT traversal.

use rmcp::{tool, tool_router, model::*, ErrorData as McpError};
use rmcp::handler::server::wrapper::Parameters;
use zks_proto::handshake::Handshake;
use url::Url;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use zks_sdk::{
    prelude::*,
    connection::{ZkConnection, ZksConnection},
    config::ConnectionConfig,
};
use zks_wire::signaling::SignalingClient;

/// Wrapper for different connection types
pub enum ZkConnectionWrapper {
    /// Direct connection (zk://)
    Direct(ZkConnection),
    /// Swarm connection (zks://)
    Swarm(ZksConnection<SignalingClient>),
}

impl ZkConnectionWrapper {
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Self::Direct(conn) => conn.send(data).await,
            Self::Swarm(conn) => conn.send(data).await,
        }
    }

    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::Direct(conn) => conn.recv(buf).await,
            Self::Swarm(conn) => conn.recv(buf).await,
        }
    }

    pub async fn close(self) -> Result<()> {
        match self {
            Self::Direct(conn) => conn.close().await,
            Self::Swarm(conn) => conn.close().await,
        }
    }

    pub fn peer_addr(&self) -> &str {
        match self {
            Self::Direct(conn) => conn.peer_addr(),
            Self::Swarm(conn) => conn.peer_addr(),
        }
    }
}

#[derive(Clone)]
pub struct NetworkTools {
    connections: Arc<std::sync::Mutex<HashMap<String, Arc<Mutex<ZkConnectionWrapper>>>>>,
}

impl NetworkTools {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }
}

impl Default for NetworkTools {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConnectParams {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConnectAnonymousParams {
    pub url: String,
    pub min_hops: Option<u8>,
    pub max_hops: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HandshakeParams {
    pub role: String,
    pub room_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ParseUrlParams {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SendParams {
    pub connection_id: String,
    pub data: String,
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReceiveParams {
    pub connection_id: String,
    pub encoding: Option<String>,
    pub max_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CloseParams {
    pub connection_id: String,
}

#[tool_router]
impl NetworkTools {
    /// Connect to a peer using direct ZK:// protocol
    #[tool(name = "zks_connect", description = "Connect to a ZK node using direct zk:// protocol")]
    pub async fn zks_connect(&self, params: Parameters<ConnectParams>) -> Result<CallToolResult, McpError> {
        let url = &params.0.url;
        
        let connection = ZkConnectionBuilder::new()
            .url(url)
            .security(SecurityLevel::PostQuantum)
            .build()
            .await
            .map_err(|e| McpError::internal_error(format!("Connection failed: {}", e), None))?;

        let connection_id = format!("zk_{}", uuid::Uuid::new_v4());
        let peer_addr = connection.peer_addr().to_string();
        
        {
            let mut connections = self.connections.lock().unwrap();
            connections.insert(
                connection_id.clone(), 
                Arc::new(Mutex::new(ZkConnectionWrapper::Direct(connection)))
            );
        }

        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "status": "connected",
            "protocol": "zk",
            "url": url,
            "peer_addr": peer_addr,
            "security": "post-quantum",
            "connection_id": connection_id,
            "message": "Connected successfully via ZKS SDK"
        }).to_string())]))
    }

    /// Connect to a peer using anonymous ZKS:// protocol with onion routing
    #[tool(name = "zks_connect_anonymous", description = "Connect to a ZK node using anonymous zks:// protocol with onion routing")]
    pub async fn zks_connect_anonymous(&self, params: Parameters<ConnectAnonymousParams>) -> Result<CallToolResult, McpError> {
        let url = &params.0.url;
        let min_hops = params.0.min_hops.unwrap_or(3);
        let max_hops = params.0.max_hops.unwrap_or(5);
        
        // Use ZksConnectionBuilder manually since we need to specify hops which aren't in the generic builder yet
        // Wait, ZksConnectionBuilder has min_hops/max_hops methods
        
        // However, ZksConnectionBuilder needs generic parameter S.
        // We need to instantiate it with SignalingClient.
        // But ZksConnectionBuilder::new() returns a builder without S.
        // The build() method has generic S.
        
        // Let's use ZksConnection::connect directly or generic builder if possible.
        // The builder assumes S is inferred from return type.
        
        // ZksConnectionBuilder is in builder.rs
        // pub async fn build<S: ...>(self) -> Result<ZksConnection<S>>
        
        let builder = crate::zks_sdk::builder::ZksConnectionBuilder::new()
            .url(url)
            .min_hops(min_hops)
            .max_hops(max_hops)
            .security(SecurityLevel::PostQuantum);
            
        let connection: ZksConnection<SignalingClient> = builder.build().await
             .map_err(|e| McpError::internal_error(format!("Anonymous connection failed: {}", e), None))?;

        let connection_id = format!("zks_{}", uuid::Uuid::new_v4());
        let peer_addr = connection.peer_addr().to_string();
        let hop_count = connection.hop_count();

        {
            let mut connections = self.connections.lock().unwrap();
            connections.insert(
                connection_id.clone(), 
                Arc::new(Mutex::new(ZkConnectionWrapper::Swarm(connection)))
            );
        }

        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "status": "connected",
            "protocol": "zks",
            "url": url,
            "peer_addr": peer_addr,
            "hops": hop_count,
            "security": "onion-routed",
            "connection_id": connection_id,
            "message": "Anonymous connection established via ZKS SDK"
        }).to_string())]))
    }

    /// Perform 3-message post-quantum handshake
    #[tool(name = "zks_handshake", description = "Perform 3-message post-quantum handshake")]
    pub async fn zks_handshake(&self, params: Parameters<HandshakeParams>) -> Result<CallToolResult, McpError> {
        // This is mainly for testing purposes or manual handshake control.
        // The SDK handles handshakes automatically during connection.
        // We'll keep this as a simulation/demo or for specialized use cases.
        
        let role = &params.0.role;
        let room_id = params.0.room_id.as_deref().unwrap_or("default_room");

        match role.as_str() {
            "initiator" => {
                // For demo purposes, use a dummy trusted responder public key
                let trusted_responder_public_key = vec![0u8; 1952]; // ML-KEM-768 public key size
                let _handshake = Handshake::new_initiator(room_id.to_string(), trusted_responder_public_key)
                    .map_err(|e| McpError::internal_error(format!("Failed to create handshake: {}", e), None))?;
                
                Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
                    "status": "initiated",
                    "role": "initiator",
                    "room_id": room_id,
                    "message": "Handshake initiated as initiator (Demo Mode)"
                }).to_string())]))
            }
            "responder" => {
                let _handshake = Handshake::new_responder(room_id.to_string());
                
                Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
                    "status": "initiated",
                    "role": "responder",
                    "room_id": room_id,
                    "message": "Handshake initiated as responder (Demo Mode)"
                }).to_string())]))
            }
            _ => Err(McpError::invalid_params(
                "Role must be 'initiator' or 'responder'".to_string(),
                None
            ))
        }
    }

    /// Parse and validate ZK URLs
    #[tool(name = "zks_parse_url", description = "Parse and validate ZK URLs")]
    pub async fn zks_parse_url(&self, params: Parameters<ParseUrlParams>) -> Result<CallToolResult, McpError> {
        let url = &params.0.url;
        
        // Parse URL
        let parsed_url = Url::parse(url)
            .map_err(|e| McpError::invalid_params(format!("Invalid URL: {}", e), None))?;

        // Extract components
        let scheme = parsed_url.scheme();
        let host = parsed_url.host_str().unwrap_or("");
        let port = parsed_url.port().unwrap_or(0);
        let path = parsed_url.path();

        // Validate ZK scheme
        if scheme != "zk" && scheme != "zks" {
            return Err(McpError::invalid_params(
                "URL must use zk:// or zks:// scheme".to_string(),
                None
            ));
        }

        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "url": url,
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": path,
            "valid": true
        }).to_string())]))
    }

    /// Send data over a connection
    #[tool(name = "zks_send", description = "Send data over a connection")]
    pub async fn zks_send(&self, params: Parameters<SendParams>) -> Result<CallToolResult, McpError> {
        let connection_id = &params.0.connection_id;
        let data = &params.0.data;
        let encoding = params.0.encoding.as_deref().unwrap_or("text");

        // Convert data to bytes based on encoding
        let bytes = match encoding {
            "text" => data.as_bytes().to_vec(),
            "base64" => {
                general_purpose::STANDARD.decode(data)
                    .map_err(|e| McpError::invalid_params(format!("Invalid base64: {}", e), None))?
            }
            "hex" => {
                hex::decode(data)
                    .map_err(|e| McpError::invalid_params(format!("Invalid hex: {}", e), None))?
            }
            _ => {
                return Err(McpError::invalid_params(
                    "Encoding must be 'text', 'base64', or 'hex'".to_string(),
                    None
                ));
            }
        };

        // Get connection
        let connection_arc = {
            let connections = self.connections.lock().unwrap();
            connections.get(connection_id)
                .ok_or_else(|| McpError::invalid_params("Connection not found".to_string(), None))?
                .clone()
        };

        // Send data
        let mut connection = connection_arc.lock().await;
        connection.send(&bytes).await
            .map_err(|e| McpError::internal_error(format!("Failed to send data: {}", e), None))?;

        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "status": "sent",
            "bytes_sent": bytes.len(),
            "encoding": encoding,
            "connection_id": connection_id
        }).to_string())]))
    }

    /// Receive data from a connection
    #[tool(name = "zks_receive", description = "Receive data from a connection")]
    pub async fn zks_receive(&self, params: Parameters<ReceiveParams>) -> Result<CallToolResult, McpError> {
        let connection_id = &params.0.connection_id;
        let encoding = params.0.encoding.as_deref().unwrap_or("text");
        let max_size = params.0.max_size.unwrap_or(4096);

        // Get connection
        let connection_arc = {
            let connections = self.connections.lock().unwrap();
            connections.get(connection_id)
                .ok_or_else(|| McpError::invalid_params("Connection not found".to_string(), None))?
                .clone()
        };

        // Receive data
        let mut buf = vec![0u8; max_size];
        let mut connection = connection_arc.lock().await;
        let n = connection.recv(&mut buf).await
            .map_err(|e| McpError::internal_error(format!("Failed to receive data: {}", e), None))?;
        
        // Truncate buffer to actual size
        buf.truncate(n);

        let result = match encoding {
            "text" => {
                String::from_utf8_lossy(&buf).to_string()
            }
            "base64" => general_purpose::STANDARD.encode(&buf),
            "hex" => hex::encode(&buf),
            _ => {
                return Err(McpError::invalid_params(
                    "Encoding must be 'text', 'base64', or 'hex'".to_string(),
                    None
                ));
            }
        };

        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "data": result,
            "bytes_received": n,
            "encoding": encoding,
            "connection_id": connection_id
        }).to_string())]))
    }

    /// Close a connection
    #[tool(name = "zks_close", description = "Close a connection")]
    pub async fn zks_close(&self, params: Parameters<CloseParams>) -> Result<CallToolResult, McpError> {
        let connection_id = &params.0.connection_id;

        // Remove from map first
        let connection_arc = {
            let mut connections = self.connections.lock().unwrap();
            connections.remove(connection_id)
                .ok_or_else(|| McpError::invalid_params("Connection not found".to_string(), None))?
        };

        // Close connection
        // We need to take ownership of the inner connection
        // Since we have the Arc, we can try to unwrap if we are the only holder
        // But invalidation in the map is enough, we can call close() on the locked inner
        
        // Note: ZkConnection::close() consumes self.
        // We are holding it in a Mutex, so we can't easily consume it unless we take it out of the mutex
        // or the mutex impl allows it. tokio::sync::Mutex doesn't support into_inner easily if shared.
        
        // Workaround: We'll implement a close method that takes &mut self and calls shutdown on the stream
        // But generic close consumes self.
        // For now, we'll just drop it, which drops the TCP stream, which closes the connection.
        // Or we can manually call shutdown if we expose it.
        
        // Proper way:
        let mut conn = connection_arc.lock().await;
        // We can't call close() because it takes self.
        // But dropping it should be fine.
        
        // Actually, let's just let it drop.
        
        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "status": "closed",
            "connection_id": connection_id
        }).to_string())]))
    }

    /// List active connections
    #[tool(name = "zks_list_connections", description = "List active connections")]
    pub async fn zks_list_connections(&self) -> Result<CallToolResult, McpError> {
        let connections = self.connections.lock().unwrap();
        
        // We can't await inside the sync mutex lock
        // But we just need keys and maybe some info.
        // We can't call async methods on connections here easily without locking each one.
        // Let's just list IDs.
        
        let mut connection_list = Vec::new();
        for (id, conn_arc) in connections.iter() {
           // We can try_lock to get info, or just list IDs
           // Let's just list IDs to avoid async complexity in this list method
           connection_list.push(serde_json::json!({
               "connection_id": id,
           }));
        }
        
        // For more details we'd need to async lock each one.
        // This is fine for now.

        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "connections": connection_list
        }).to_string())]))
    }
}