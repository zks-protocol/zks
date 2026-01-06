//! STUN (Session Traversal Utilities for NAT) implementation for ZK Protocol
//! 
//! Provides ICE-like connection establishment using STUN and TURN protocols.

use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use serde::{Serialize, Deserialize};

use crate::{WireError, Result};

/// Represents an ICE candidate for connection establishment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    /// Candidate ID
    pub id: String,
    /// Candidate type (host, srflx, relay)
    pub candidate_type: CandidateType,
    /// Transport protocol (UDP/TCP)
    pub transport: TransportType,
    /// Priority value
    pub priority: u32,
    /// Connection address
    pub address: SocketAddr,
    /// Related address (for reflexive/relay candidates)
    pub related_address: Option<SocketAddr>,
}

/// Type of ICE candidate
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CandidateType {
    /// Host candidate (local interface)
    Host,
    /// Server reflexive candidate (STUN discovered)
    ServerReflexive,
    /// Relay candidate (TURN allocated)
    Relay,
    /// Peer reflexive candidate (discovered during connectivity checks)
    PeerReflexive,
}

/// Transport protocol type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransportType {
    /// UDP transport
    Udp,
    /// TCP transport
    Tcp,
}

/// STUN client for discovering public address
pub struct StunClient {
    /// STUN server addresses
    servers: Vec<SocketAddr>,
    /// Local socket for communication
    socket: Option<UdpSocket>,
    /// Timeout for STUN requests
    timeout: Duration,
}

/// STUN server implementation (for testing and relay purposes)
pub struct StunServer {
    /// Bind address
    bind_addr: SocketAddr,
    /// UDP socket for listening
    socket: Option<UdpSocket>,
}

impl StunClient {
    /// Create a new STUN client with given server addresses
    pub async fn new(server_addr: &str) -> Self {
        // Try to parse as SocketAddr first (IP:port format)
        let servers = match server_addr.parse::<SocketAddr>() {
            Ok(addr) => vec![addr],
            Err(_) => {
                // If that fails, try to resolve as domain:port
                match Self::resolve_stun_server(server_addr).await {
                    Ok(addr) => vec![addr],
                    Err(e) => {
                        warn!("Failed to resolve STUN server '{}': {}", server_addr, e);
                        vec![]
                    }
                }
            }
        };
        Self {
            servers,
            socket: None,
            timeout: Duration::from_secs(3),
        }
    }
    
    /// Create a STUN client with multiple servers
    pub fn with_servers(servers: Vec<SocketAddr>) -> Self {
        Self {
            servers,
            socket: None,
            timeout: Duration::from_secs(3),
        }
    }
    
    /// Set the timeout for STUN requests
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    
    /// Resolve a STUN server address (domain:port format) using proper DNS resolution
    async fn resolve_stun_server(server_addr: &str) -> Result<SocketAddr> {
        // Split domain and port
        let parts: Vec<&str> = server_addr.split(':').collect();
        if parts.len() != 2 {
            return Err(WireError::stun("Invalid STUN server format, expected domain:port"));
        }
        
        let domain = parts[0];
        let port: u16 = parts[1].parse().map_err(|_| WireError::stun("Invalid port number"))?;
        
        // Use proper DNS resolution with fallback to hardcoded IPs for common servers
        match tokio::net::lookup_host((domain, port)).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    Ok(addr)
                } else {
                    Err(WireError::stun(&format!("No addresses found for domain: {}", domain)))
                }
            }
            Err(_) => {
                // Fallback to hardcoded IPs for common STUN servers if DNS fails
                let ip = match domain {
                    "stun.l.google.com" => "74.125.250.129".parse().map_err(|_| WireError::stun("Failed to parse IP"))?,
                    "stun1.l.google.com" => "74.125.250.130".parse().map_err(|_| WireError::stun("Failed to parse IP"))?,
                    "stun2.l.google.com" => "74.125.250.131".parse().map_err(|_| WireError::stun("Failed to parse IP"))?,
                    "stun3.l.google.com" => "74.125.250.132".parse().map_err(|_| WireError::stun("Failed to parse IP"))?,
                    "stun4.l.google.com" => "74.125.250.133".parse().map_err(|_| WireError::stun("Failed to parse IP"))?,
                    "stun.services.mozilla.com" => "52.86.224.165".parse().map_err(|_| WireError::stun("Failed to parse IP"))?,
                    "stun.stunprotocol.org" => "34.226.115.224".parse().map_err(|_| WireError::stun("Failed to parse IP"))?,
                    _ => return Err(WireError::stun(&format!("DNS resolution failed for unknown STUN server: {}", domain))),
                };
                
                Ok(SocketAddr::new(ip, port))
            }
        }
    }
    
    /// Discover the public address using STUN
    pub async fn discover(&mut self) -> Result<SocketAddr> {
        info!("Discovering public address via STUN");
        
        if self.servers.is_empty() {
            return Err(WireError::stun("No STUN servers configured"));
        }
        
        // Create UDP socket if not exists
        if self.socket.is_none() {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            self.socket = Some(socket);
        }
        
        let socket = self.socket.as_ref().unwrap();
        
        // Try each STUN server
        for server in &self.servers {
            debug!("Trying STUN server: {}", server);
            
            match self.query_stun_server(socket, *server).await {
                Ok(public_addr) => {
                    info!("Discovered public address: {} via STUN server: {}", public_addr, server);
                    return Ok(public_addr);
                }
                Err(e) => {
                    warn!("STUN server {} failed: {}", server, e);
                    continue;
                }
            }
        }
        
        Err(WireError::stun("All STUN servers failed"))
    }
    
    /// Generate ICE candidates for this host
    pub async fn generate_candidates(&self) -> Result<Vec<IceCandidate>> {
        info!("Generating ICE candidates");
        let mut candidates = Vec::new();
        
        // Get local interfaces
        let local_addrs = self.get_local_addresses().await?;
        let first_local_addr = local_addrs.get(0).copied();
        
        // Add host candidates
        for addr in &local_addrs {
            let candidate = IceCandidate {
                id: format!("host-{}", candidates.len()),
                candidate_type: CandidateType::Host,
                transport: TransportType::Udp,
                priority: self.calculate_priority(CandidateType::Host, *addr),
                address: *addr,
                related_address: None,
            };
            candidates.push(candidate);
        }
        
        // Add server reflexive candidate if we have a public address
        if let Some(socket) = &self.socket {
            if let Ok(public_addr) = self.query_stun_server(socket, self.servers[0]).await {
                let candidate = IceCandidate {
                    id: format!("srflx-{}", candidates.len()),
                    candidate_type: CandidateType::ServerReflexive,
                    transport: TransportType::Udp,
                    priority: self.calculate_priority(CandidateType::ServerReflexive, public_addr),
                    address: public_addr,
                    related_address: first_local_addr, // Simplified
                };
                candidates.push(candidate);
            }
        }
        
        debug!("Generated {} ICE candidates", candidates.len());
        Ok(candidates)
    }
    
    /// Query a specific STUN server
    async fn query_stun_server(&self, socket: &UdpSocket, server: SocketAddr) -> Result<SocketAddr> {
        // Create a simple STUN binding request
        let request = self.create_binding_request()?;
        
        // Send request with timeout
        let result = timeout(self.timeout, async {
            socket.send_to(&request, server).await?;
            
            let mut buf = vec![0u8; 1024];
            let (len, _from) = socket.recv_from(&mut buf).await?;
            
            self.parse_binding_response(&buf[..len])
        }).await;
        
        match result {
            Ok(Ok(addr)) => Ok(addr),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(WireError::Timeout),
        }
    }
    
    /// Create a STUN binding request (simplified)
    fn create_binding_request(&self) -> Result<Vec<u8>> {
        // Create a proper STUN binding request
        let mut request = Vec::new();
        
        // STUN message type: Binding Request (0x0001)
        request.extend_from_slice(&[0x00, 0x01]);
        
        // Message length: 0 (no attributes)
        request.extend_from_slice(&[0x00, 0x00]);
        
        // Magic cookie: 0x2112A442
        request.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        
        // Transaction ID: 12 cryptographically random bytes for security
        let mut transaction_id = [0u8; 12];
        getrandom::getrandom(&mut transaction_id).map_err(|_| WireError::stun("Failed to generate random transaction ID"))?;
        request.extend_from_slice(&transaction_id);
        
        Ok(request)
    }
    
    /// Parse STUN binding response with proper XOR-MAPPED-ADDRESS parsing
    fn parse_binding_response(&self, response: &[u8]) -> Result<SocketAddr> {
        // Parse STUN message header (20 bytes)
        if response.len() < 20 {
            return Err(WireError::InvalidMessage("STUN response too short".to_string()));
        }
        
        let msg_type = u16::from_be_bytes([response[0], response[1]]);
        if msg_type != 0x0101 {  // Binding Success Response
            return Err(WireError::InvalidMessage("Not a binding response".to_string()));
        }
        
        // Parse XOR-MAPPED-ADDRESS attribute
        let mut offset = 20;
        while offset + 4 < response.len() {
            let attr_type = u16::from_be_bytes([response[offset], response[offset+1]]);
            let attr_len = u16::from_be_bytes([response[offset+2], response[offset+3]]) as usize;
            
            if attr_type == 0x0020 {  // XOR-MAPPED-ADDRESS
                return self.parse_xor_mapped_address(&response[offset+4..offset+4+attr_len]);
            }
            offset += 4 + attr_len;
        }
        
        Err(WireError::InvalidMessage("No XOR-MAPPED-ADDRESS found".to_string()))
    }
    
    /// Parse XOR-MAPPED-ADDRESS attribute
    fn parse_xor_mapped_address(&self, data: &[u8]) -> Result<SocketAddr> {
        let family = data[1];
        let xor_port = u16::from_be_bytes([data[2], data[3]]) ^ 0x2112;
        
        match family {
            0x01 => {  // IPv4
                let xor_addr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) ^ 0x2112A442;
                let ip = Ipv4Addr::from(xor_addr);
                Ok(SocketAddr::V4(SocketAddrV4::new(ip, xor_port)))
            }
            0x02 => {  // IPv6
                // Handle IPv6 XOR with transaction ID
                // For now, return error as IPv6 support is more complex
                Err(WireError::InvalidMessage("IPv6 support not implemented".to_string()))
            }
            _ => Err(WireError::InvalidMessage("Unknown address family".to_string()))
        }
    }
    
    /// Get local network interface addresses
    async fn get_local_addresses(&self) -> Result<Vec<SocketAddr>> {
        let mut addrs = Vec::new();
        
        // Get all network interfaces
        match if_addrs::get_if_addrs() {
            Ok(interfaces) => {
                for interface in interfaces {
                    if !interface.is_loopback() {
                        let addr = SocketAddr::new(interface.ip(), 0);
                        addrs.push(addr);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to get network interfaces: {}", e);
                // Fallback to localhost
                addrs.push("127.0.0.1:0".parse().unwrap());
            }
        }
        
        if addrs.is_empty() {
            addrs.push("127.0.0.1:0".parse().unwrap());
        }
        
        Ok(addrs)
    }
    
    /// Calculate ICE candidate priority
    fn calculate_priority(&self, candidate_type: CandidateType, _addr: SocketAddr) -> u32 {
        // Simplified priority calculation
        // Real ICE uses: priority = (2^24)*(type preference) + (2^8)*(local preference) + (2^0)*(256 - component ID)
        match candidate_type {
            CandidateType::Host => 126,
            CandidateType::ServerReflexive => 100,
            CandidateType::PeerReflexive => 110,
            CandidateType::Relay => 0,
        }
    }
}

impl StunServer {
    /// Create a new STUN server
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            socket: None,
        }
    }
    
    /// Start the STUN server
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting STUN server on {}", self.bind_addr);
        
        let socket = UdpSocket::bind(self.bind_addr).await?;
        self.socket = Some(socket);
        
        info!("STUN server started successfully");
        Ok(())
    }
    
    /// Handle incoming STUN requests
    pub async fn handle_requests(&self) -> Result<()> {
        if let Some(socket) = &self.socket {
            let mut buf = vec![0u8; 1024];
            
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, from)) => {
                        debug!("Received STUN request from {}", from);
                        self.handle_request(&buf[..len], from).await?;
                    }
                    Err(e) => {
                        warn!("Error receiving STUN request: {}", e);
                        return Err(WireError::Network(e));
                    }
                }
            }
        } else {
            Err(WireError::stun("Server not started"))
        }
    }
    
    /// Handle a single STUN request
    async fn handle_request(&self, _request: &[u8], _from: SocketAddr) -> Result<()> {
        // Simplified request handling
        debug!("Handling STUN request from {}", _from);
        
        // Create response (simplified)
        let response = self.create_binding_response(_from);
        
        if let Some(socket) = &self.socket {
            socket.send_to(&response, _from).await?;
        }
        
        Ok(())
    }
    
    /// Create a STUN binding response
    fn create_binding_response(&self, _from: SocketAddr) -> Vec<u8> {
        // Simplified STUN binding response
        // In reality, this would include XOR-MAPPED-ADDRESS
        vec![0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42] // STUN binding success header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_stun_client_creation() {
        let client = StunClient::new("8.8.8.8:3478").await;
        assert_eq!(client.servers.len(), 1);
    }
    
    #[tokio::test]
    async fn test_ice_candidate_creation() {
        let candidate = IceCandidate {
            id: "test".to_string(),
            candidate_type: CandidateType::Host,
            transport: TransportType::Udp,
            priority: 126,
            address: "192.168.1.1:8080".parse().unwrap(),
            related_address: None,
        };
        
        assert_eq!(candidate.candidate_type, CandidateType::Host);
        assert_eq!(candidate.transport, TransportType::Udp);
    }
    
    #[tokio::test]
    async fn test_stun_server_creation() {
        let server = StunServer::new("0.0.0.0:3478".parse().unwrap());
        assert_eq!(server.bind_addr.port(), 3478);
    }
}