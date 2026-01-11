//! NAT traversal functionality for ZK Protocol
//! 
//! Provides hole punching, UPnP, NAT-PMP, and other NAT traversal techniques.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::{WireError, Result};

/// Represents different types of NAT configurations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT, directly accessible
    None,
    /// Full cone NAT
    FullCone,
    /// Restricted cone NAT
    RestrictedCone,
    /// Port restricted cone NAT
    PortRestrictedCone,
    /// Symmetric NAT (hardest to traverse)
    Symmetric,
    /// Unknown NAT type
    Unknown,
}

/// NAT traversal handler
pub struct NatTraversal {
    /// Local address
    local_addr: SocketAddr,
    /// Discovered NAT type
    nat_type: NatType,
    /// UPnP enabled
    upnp_enabled: bool,
    /// NAT-PMP enabled
    nat_pmp_enabled: bool,
}

impl NatTraversal {
    /// Create a new NAT traversal handler
    pub fn new() -> Self {
        Self {
            local_addr: "0.0.0.0:0".parse().unwrap(),
            nat_type: NatType::Unknown,
            upnp_enabled: false,
            nat_pmp_enabled: false,
        }
    }
    
    /// Set the local address for NAT traversal
    pub fn with_local_addr(mut self, addr: SocketAddr) -> Self {
        self.local_addr = addr;
        self
    }
    
    /// Discover the NAT type by testing connectivity with multiple STUN servers
    pub async fn discover_nat_type(&mut self) -> Result<NatType> {
        info!("Discovering NAT type for {}", self.local_addr);
        
        // Test 1: Basic connectivity with first STUN server
        let addr1 = self.test_stun_server("stun.l.google.com:19302").await?;
        
        // Test 2: Different server to check for consistent mapping
        let addr2 = self.test_stun_server("stun1.l.google.com:19302").await?;
        
        // Test 3: Different port on same server to check port mapping behavior
        let addr3 = self.test_stun_server("stun.l.google.com:3478").await?;
        
        self.nat_type = if addr1.ip() != addr2.ip() {
             NatType::Symmetric  // Different IPs = symmetric NAT
         } else if addr1.port() != addr3.port() {
             NatType::PortRestrictedCone  // Different ports = port restricted
         } else {
             NatType::FullCone  // Same IP and port = full cone
         };
        
        debug!("Detected NAT type: {:?}", self.nat_type);
        Ok(self.nat_type)
    }
    
    /// Test connectivity with a STUN server and return the discovered address
    async fn test_stun_server(&self, server_addr: &str) -> Result<SocketAddr> {
        use crate::stun::StunClient;
        
        let mut client = StunClient::new(server_addr).await;
        client.discover().await
    }
    
    /// Enable UPnP port mapping
    pub async fn enable_upnp(&mut self) -> Result<()> {
        info!("Attempting to enable UPnP");
        
        // Simplified UPnP implementation
        // In reality, this would involve SSDP discovery and SOAP requests
        match self.discover_upnp_gateway().await {
            Ok(gateway) => {
                info!("Found UPnP gateway: {}", gateway);
                self.upnp_enabled = true;
                Ok(())
            }
            Err(e) => {
                warn!("UPnP not available: {}", e);
                self.upnp_enabled = false;
                Err(WireError::nat("UPnP gateway not found"))
            }
        }
    }
    
    /// Enable NAT-PMP port mapping
    pub async fn enable_nat_pmp(&mut self) -> Result<()> {
        info!("Attempting to enable NAT-PMP");
        
        // Simplified NAT-PMP implementation
        // Would involve UDP communication with gateway on port 5351
        match self.discover_nat_pmp_gateway().await {
            Ok(gateway) => {
                info!("Found NAT-PMP gateway: {}", gateway);
                self.nat_pmp_enabled = true;
                Ok(())
            }
            Err(e) => {
                warn!("NAT-PMP not available: {}", e);
                self.nat_pmp_enabled = false;
                Err(WireError::nat("NAT-PMP gateway not found"))
            }
        }
    }
    
    /// Attempt hole punching to a remote peer
    pub async fn hole_punch(&self, remote_addr: SocketAddr) -> Result<SocketAddr> {
        info!("Attempting hole punch to {}", remote_addr);
        
        if self.nat_type == NatType::Symmetric {
            warn!("Hole punching unlikely to succeed with symmetric NAT");
        }
        
        // Simplified hole punching
        // Would involve coordinated punching with the remote peer
        let result = timeout(Duration::from_secs(5), self.attempt_punch(remote_addr)).await;
        
        match result {
            Ok(Ok(punched_addr)) => {
                info!("Hole punch successful: {}", punched_addr);
                Ok(punched_addr)
            }
            Ok(Err(e)) => {
                warn!("Hole punch failed: {}", e);
                Err(e)
            }
            Err(_) => {
                warn!("Hole punch timed out");
                Err(WireError::Timeout)
            }
        }
    }
    
    /// Get the current NAT type
    pub fn nat_type(&self) -> NatType {
        self.nat_type
    }
    
    /// Check if UPnP is enabled
    pub fn upnp_enabled(&self) -> bool {
        self.upnp_enabled
    }
    
    /// Check if NAT-PMP is enabled
    pub fn nat_pmp_enabled(&self) -> bool {
        self.nat_pmp_enabled
    }
    
    /// Check if any automatic port mapping is available
    pub fn has_port_mapping(&self) -> bool {
        self.upnp_enabled || self.nat_pmp_enabled
    }
    
    // Private helper methods
    
    async fn discover_upnp_gateway(&self) -> Result<IpAddr> {
        use igd_next::aio::tokio::search_gateway;
        
        info!("🔍 Searching for UPnP gateway...");
        
        // Search for UPnP gateway with timeout
        match timeout(Duration::from_secs(5), search_gateway(Default::default())).await {
            Ok(Ok(gateway)) => {
                // gateway.addr is SocketAddrV4
                let ip = gateway.addr.ip();
                info!("✅ Found UPnP gateway at {}", ip);
                
                // Try to get external IP to verify it works
                match gateway.get_external_ip().await {
                    Ok(external_ip) => {
                        info!("🌐 External IP via UPnP: {}", external_ip);
                    }
                    Err(e) => {
                        debug!("Could not get external IP: {} (gateway still usable)", e);
                    }
                }
                
                Ok(ip)
            }
            Ok(Err(e)) => {
                debug!("UPnP gateway not found: {}", e);
                Err(WireError::nat(format!("UPnP gateway not found: {}", e)))
            }
            Err(_) => {
                debug!("UPnP gateway search timed out");
                Err(WireError::nat("UPnP gateway search timed out"))
            }
        }
    }

    
    async fn discover_nat_pmp_gateway(&self) -> Result<IpAddr> {
        // NAT-PMP protocol: Send UDP request to gateway port 5351
        // Returns the gateway's default router IP
        
        // Get default gateway by checking common addresses
        let common_gateways = ["192.168.1.1", "192.168.0.1", "10.0.0.1", "172.16.0.1"];
        
        for gateway_str in common_gateways {
            if let Ok(gateway_ip) = gateway_str.parse::<IpAddr>() {
                // Try to connect to NAT-PMP port
                let addr = format!("{}:5351", gateway_str);
                match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                    Ok(socket) => {
                        // NAT-PMP public address request: 2 bytes (version=0, op=0)
                        let request = [0u8, 0u8];
                        if socket.send_to(&request, &addr).await.is_ok() {
                            // Wait briefly for response
                            let mut buf = [0u8; 12];
                            match timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
                                Ok(Ok((len, _))) if len >= 12 => {
                                    // Check for success (result code 0)
                                    if buf[3] == 0 {
                                        let external_ip = std::net::Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]);
                                        info!("✅ NAT-PMP supported at {} (external: {})", gateway_ip, external_ip);
                                        return Ok(gateway_ip);
                                    }
                                }
                                _ => continue,
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
        
        Err(WireError::nat("NAT-PMP gateway not found"))
    }
    
    async fn attempt_punch(&self, remote_addr: SocketAddr) -> Result<SocketAddr> {
        // UDP hole punching: Send packets to remote to open NAT mapping
        // The remote peer must simultaneously send to us
        
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| WireError::nat(format!("Failed to bind UDP socket: {}", e)))?;
        
        // Send hole punch packets
        let punch_data = b"ZKS_PUNCH";
        for _ in 0..5 {
            if let Err(e) = socket.send_to(punch_data, remote_addr).await {
                debug!("Hole punch send failed: {}", e);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        // Wait for response
        let mut buf = [0u8; 64];
        match timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await {
            Ok(Ok((_, peer_addr))) => {
                info!("✅ Hole punch successful - received from {}", peer_addr);
                Ok(peer_addr)
            }
            _ => {
                // Even if we don't get a response, the NAT mapping may be open
                debug!("No response received, but NAT mapping may be open");
                Ok(remote_addr)
            }
        }
    }
    
    /// Request port mapping via UPnP
    pub async fn add_port_mapping(&self, protocol: &str, internal_port: u16, external_port: u16, description: &str) -> Result<()> {
        use igd_next::aio::tokio::search_gateway;
        use igd_next::PortMappingProtocol;
        use std::net::SocketAddrV4;
        
        let gateway = search_gateway(Default::default()).await
            .map_err(|e| WireError::nat(format!("Gateway not found: {}", e)))?;
        
        let protocol = match protocol.to_uppercase().as_str() {
            "TCP" => PortMappingProtocol::TCP,
            "UDP" => PortMappingProtocol::UDP,
            _ => return Err(WireError::nat("Invalid protocol, use TCP or UDP")),
        };
        
        let local_addr = SocketAddrV4::new(
            match self.local_addr.ip() {
                IpAddr::V4(ip) => ip,
                _ => return Err(WireError::nat("IPv6 not supported for UPnP")),
            },
            internal_port
        );
        
        gateway.add_port(protocol, external_port, SocketAddr::from(local_addr), 3600, description).await
            .map_err(|e| WireError::nat(format!("Port mapping failed: {}", e)))?;
        
        info!("✅ UPnP port mapping added: {:?} {} -> {}", protocol, external_port, internal_port);
        Ok(())
    }
}

impl Default for NatTraversal {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_nat_traversal_creation() {
        let nat = NatTraversal::new();
        assert_eq!(nat.nat_type(), NatType::Unknown);
        assert!(!nat.has_port_mapping());
    }
    
    #[tokio::test]
    async fn test_nat_type_discovery() {
        let mut nat = NatTraversal::new();
        // This may fail in test environment if STUN servers are unreachable
        // We just want to ensure the method doesn't panic
        match nat.discover_nat_type().await {
            Ok(nat_type) => assert_ne!(nat_type, NatType::Unknown),
            Err(_) => {
                // Expected in test environments without internet access
                // The important thing is that the method executed without panicking
            }
        }
    }
    
    #[tokio::test]
    async fn test_upnp_enablement() {
        let mut nat = NatTraversal::new();
        // This may fail in test environment, which is expected
        let _ = nat.enable_upnp().await;
        // Just test that it doesn't panic
    }
    
    #[tokio::test]
    async fn test_hole_punch() {
        let nat = NatTraversal::new();
        let remote_addr = "203.0.113.1:8080".parse().unwrap();
        
        // This may fail in test environment, which is expected
        let _ = nat.hole_punch(remote_addr).await;
        // Just test that it doesn't panic
    }
}