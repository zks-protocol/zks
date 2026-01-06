//! URL parsing for ZK Protocol URLs
//! 
//! Supports two URL schemes:
//! - `zk://` - Direct peer-to-peer connections
//! - `zks://` - Swarm-based connections with peer discovery

use std::net::SocketAddr;
use url::Url;
use serde::{Serialize, Deserialize};

use crate::{ProtoError, Result};

/// URL scheme types for ZK Protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UrlScheme {
    /// Direct peer-to-peer connection (zk://)
    Direct,
    /// Swarm-based connection (zks://)
    Swarm,
}

/// Protocol mode for connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolMode {
    /// Direct peer-to-peer mode
    Direct,
    /// Swarm networking mode
    Swarm,
}

/// Parsed ZK Protocol URL
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkUrl {
    /// Original URL string
    pub original: String,
    /// Parsed URL scheme
    pub scheme: UrlScheme,
    /// Protocol mode
    pub mode: ProtocolMode,
    /// Host address
    pub host: String,
    /// Port number
    pub port: u16,
    /// Socket address (if resolvable)
    pub socket_addr: Option<SocketAddr>,
    /// Additional path components
    pub path: String,
    /// Query parameters
    pub query: Option<String>,
}

impl ZkUrl {
    /// Parse a ZK Protocol URL
    pub fn parse(url_str: &str) -> Result<Self> {
        let url = Url::parse(url_str).map_err(|e| ProtoError::invalid_url(format!("URL parse error: {}", e)))?;
        
        // Validate scheme
        let scheme = match url.scheme() {
            "zk" => UrlScheme::Direct,
            "zks" => UrlScheme::Swarm,
            other => return Err(ProtoError::unsupported_scheme(other.to_string())),
        };
        
        let mode = match scheme {
            UrlScheme::Direct => ProtocolMode::Direct,
            UrlScheme::Swarm => ProtocolMode::Swarm,
        };
        
        // Extract host and port
        let host = url.host_str()
            .ok_or_else(|| ProtoError::invalid_url("Missing host in URL"))?
            .to_string();
        
        // Validate hostname to prevent security issues
        Self::validate_hostname(&host)?;
        
        let port = url.port()
            .or_else(|| match scheme {
                UrlScheme::Direct => Some(8080),
                UrlScheme::Swarm => Some(8081),
            })
            .ok_or_else(|| ProtoError::invalid_url("Missing port in URL"))?;
        
        // Try to resolve socket address
        let socket_addr = format!("{}:{}", host, port).parse::<SocketAddr>().ok();
        
        let path = url.path().to_string();
        let query = url.query().map(|q| q.to_string());
        
        Ok(ZkUrl {
            original: url_str.to_string(),
            scheme,
            mode,
            host,
            port,
            socket_addr,
            path,
            query,
        })
    }
    
    /// Create a direct zk:// URL
    pub fn direct(host: &str, port: u16) -> Self {
        let url_str = format!("zk://{}:{}", host, port);
        Self {
            original: url_str.clone(),
            scheme: UrlScheme::Direct,
            mode: ProtocolMode::Direct,
            host: host.to_string(),
            port,
            socket_addr: format!("{}:{}", host, port).parse().ok(),
            path: String::new(),
            query: None,
        }
    }
    
    /// Create a swarm zks:// URL
    pub fn swarm(host: &str, port: u16) -> Self {
        let url_str = format!("zks://{}:{}", host, port);
        Self {
            original: url_str.clone(),
            scheme: UrlScheme::Swarm,
            mode: ProtocolMode::Swarm,
            host: host.to_string(),
            port,
            socket_addr: format!("{}:{}", host, port).parse().ok(),
            path: String::new(),
            query: None,
        }
    }
    
    /// Get the protocol mode
    pub fn mode(&self) -> ProtocolMode {
        self.mode
    }
    
    /// Get the URL scheme
    pub fn scheme(&self) -> UrlScheme {
        self.scheme
    }
    
    /// Get the socket address
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.socket_addr
    }
    
    /// Convert to a standard URL string
    pub fn to_url_string(&self) -> String {
        self.original.clone()
    }
    
    /// Check if this is a direct connection URL
    pub fn is_direct(&self) -> bool {
        matches!(self.scheme, UrlScheme::Direct)
    }
    
    /// Check if this is a swarm connection URL
    pub fn is_swarm(&self) -> bool {
        matches!(self.scheme, UrlScheme::Swarm)
    }
    
    /// Validate hostname to prevent security issues
    fn validate_hostname(hostname: &str) -> Result<()> {
        if hostname.is_empty() {
            return Err(ProtoError::invalid_url("Empty hostname"));
        }
        
        // Check for valid hostname length (RFC 1123: max 253 characters)
        if hostname.len() > 253 {
            return Err(ProtoError::invalid_url("Hostname too long (max 253 characters)"));
        }
        
        // Check if it's a valid IP address (IPv4 or IPv6)
        if Self::is_valid_ip_address(hostname) {
            return Ok(());
        }
        
        // Check for valid characters (alphanumeric, hyphens, dots)
        // This prevents injection attacks and malformed hostnames
        if !hostname.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '.') {
            return Err(ProtoError::invalid_url("Invalid hostname characters"));
        }
        
        // Check for valid hostname structure
        // - Cannot start or end with hyphen
        // - Cannot have consecutive dots
        // - Each label (between dots) cannot be empty or start/end with hyphen
        if hostname.starts_with('-') || hostname.ends_with('-') {
            return Err(ProtoError::invalid_url("Hostname cannot start or end with hyphen"));
        }
        
        if hostname.contains("..") {
            return Err(ProtoError::invalid_url("Hostname cannot contain consecutive dots"));
        }
        
        // Validate each label in the hostname
        for label in hostname.split('.') {
            if label.is_empty() {
                return Err(ProtoError::invalid_url("Empty label in hostname"));
            }
            
            if label.starts_with('-') || label.ends_with('-') {
                return Err(ProtoError::invalid_url("Hostname label cannot start or end with hyphen"));
            }
            
            // For domain names (not IP addresses), labels should not be all numeric
            if label.chars().all(|c| c.is_ascii_digit()) {
                return Err(ProtoError::invalid_url("Hostname label cannot be all numeric"));
            }
        }
        
        // Additional security checks
        // - Prevent localhost in certain contexts (could be added as a parameter if needed)
        // - Prevent private IP ranges if needed
        
        Ok(())
    }
    
    /// Check if the hostname is a valid IP address (IPv4 or IPv6)
    fn is_valid_ip_address(hostname: &str) -> bool {
        // Check for IPv4 address
        if hostname.split('.').count() == 4 {
            let parts: Vec<&str> = hostname.split('.').collect();
            if parts.iter().all(|part| {
                part.chars().all(|c| c.is_ascii_digit()) &&
                !part.is_empty() &&
                part.parse::<u8>().is_ok()
            }) {
                return true;
            }
        }
        
        // Check for IPv6 address (basic validation)
        if hostname.contains(':') && hostname.len() > 3 {
            // Basic IPv6 validation - contains colons and hex characters
            hostname.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '[' || c == ']')
        } else {
            false
        }
    }
}

impl std::fmt::Display for ZkUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.original)
    }
}

impl std::str::FromStr for ZkUrl {
    type Err = ProtoError;
    
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_direct_url_parsing() {
        let url = ZkUrl::parse("zk://192.168.1.1:8080").unwrap();
        assert_eq!(url.scheme, UrlScheme::Direct);
        assert_eq!(url.mode, ProtocolMode::Direct);
        assert_eq!(url.host, "192.168.1.1");
        assert_eq!(url.port, 8080);
        assert!(url.is_direct());
        assert!(!url.is_swarm());
    }
    
    #[test]
    fn test_swarm_url_parsing() {
        let url = ZkUrl::parse("zks://peer.example.com:8081").unwrap();
        assert_eq!(url.scheme, UrlScheme::Swarm);
        assert_eq!(url.mode, ProtocolMode::Swarm);
        assert_eq!(url.host, "peer.example.com");
        assert_eq!(url.port, 8081);
        assert!(!url.is_direct());
        assert!(url.is_swarm());
    }
    
    #[test]
    fn test_invalid_scheme() {
        let result = ZkUrl::parse("http://example.com:8080");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_url_creation() {
        let direct = ZkUrl::direct("localhost", 8080);
        assert_eq!(direct.scheme, UrlScheme::Direct);
        assert_eq!(direct.host, "localhost");
        assert_eq!(direct.port, 8080);
        
        let swarm = ZkUrl::swarm("peer.example.com", 8081);
        assert_eq!(swarm.scheme, UrlScheme::Swarm);
        assert_eq!(swarm.host, "peer.example.com");
        assert_eq!(swarm.port, 8081);
    }
    
    #[test]
    fn test_display() {
        let url = ZkUrl::parse("zk://192.168.1.1:8080").unwrap();
        assert_eq!(url.to_string(), "zk://192.168.1.1:8080");
    }
    
    #[test]
    fn test_invalid_hostnames() {
        // Empty hostname
        assert!(ZkUrl::parse("zk://:8080").is_err());
        
        // Invalid characters
        assert!(ZkUrl::parse("zk://host_name:8080").is_err());
        
        // Invalid structure
        assert!(ZkUrl::parse("zk://-hostname:8080").is_err());
        assert!(ZkUrl::parse("zk://hostname-:8080").is_err());
        assert!(ZkUrl::parse("zk://host..name:8080").is_err());
        assert!(ZkUrl::parse("zk://host.name-:8080").is_err());
        
        // Too long
        let long_hostname = "a".repeat(254);
        assert!(ZkUrl::parse(&format!("zk://{}:8080", long_hostname)).is_err());
    }
    
    #[test]
    fn test_valid_hostnames() {
        // Valid domain names
        assert!(ZkUrl::parse("zk://example.com:8080").is_ok());
        assert!(ZkUrl::parse("zk://sub.example.com:8080").is_ok());
        assert!(ZkUrl::parse("zk://my-host:8080").is_ok());
        assert!(ZkUrl::parse("zk://host-123:8080").is_ok());
        
        // Valid IP addresses
        assert!(ZkUrl::parse("zk://192.168.1.1:8080").is_ok());
        assert!(ZkUrl::parse("zk://10.0.0.1:8080").is_ok());
        assert!(ZkUrl::parse("zk://172.16.0.1:8080").is_ok());
        assert!(ZkUrl::parse("zk://127.0.0.1:8080").is_ok());
    }
}