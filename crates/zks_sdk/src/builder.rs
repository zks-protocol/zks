//! Connection builders for ZKS SDK

use std::time::Duration;
use url::Url;
use crate::{
    connection::{ZkConnection, ZksConnection},
    error::{Result, SdkError},
    config::{SecurityLevel, ConnectionConfig},
};

/// Builder for direct ZK connections (zk://)
pub struct ZkConnectionBuilder {
    url: Option<String>,
    security: Option<SecurityLevel>,
    timeout: Option<Duration>,
    buffer_size: Option<usize>,
}

impl ZkConnectionBuilder {
    /// Create a new ZK connection builder
    pub fn new() -> Self {
        Self {
            url: None,
            security: None,
            timeout: None,
            buffer_size: None,
        }
    }

    /// Set the connection URL (zk:// scheme)
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set the security level
    pub fn security(mut self, security: SecurityLevel) -> Self {
        self.security = Some(security);
        self
    }

    /// Set the connection timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the buffer size for data transfer
    pub fn buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = Some(size);
        self
    }

    /// Build the ZK connection
    pub async fn build(self) -> Result<ZkConnection> {
        let url = self.url.ok_or_else(|| SdkError::InvalidUrl("URL is required".to_string()))?;
        
        // Validate URL scheme
        let parsed_url = Url::parse(&url)
            .map_err(|e| SdkError::InvalidUrl(format!("Invalid URL: {}", e)))?;
        
        if parsed_url.scheme() != "zk" {
            return Err(SdkError::InvalidUrl("URL must use zk:// scheme".to_string()));
        }

        let config = ConnectionConfig {
            security: self.security.unwrap_or_default(),
            timeout: self.timeout.unwrap_or_else(|| Duration::from_secs(30)),
            buffer_size: self.buffer_size.unwrap_or(64 * 1024),
            ..Default::default()
        };

        ZkConnection::connect(url, config).await
    }
}

impl Default for ZkConnectionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for swarm-based ZKS connections (zks://)
pub struct ZksConnectionBuilder {
    url: Option<String>,
    security: Option<SecurityLevel>,
    timeout: Option<Duration>,
    buffer_size: Option<usize>,
    min_hops: Option<u8>,
    max_hops: Option<u8>,
    enable_scrambling: Option<bool>,
}

impl ZksConnectionBuilder {
    /// Create a new ZKS connection builder
    pub fn new() -> Self {
        Self {
            url: None,
            security: None,
            timeout: None,
            buffer_size: None,
            min_hops: None,
            max_hops: None,
            enable_scrambling: None,
        }
    }

    /// Set the connection URL (zks:// scheme)
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set the security level
    pub fn security(mut self, security: SecurityLevel) -> Self {
        self.security = Some(security);
        self
    }

    /// Set the connection timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the buffer size for data transfer
    pub fn buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = Some(size);
        self
    }

    /// Set minimum number of hops for onion routing
    pub fn min_hops(mut self, hops: u8) -> Self {
        self.min_hops = Some(hops);
        self
    }

    /// Set maximum number of hops for onion routing
    pub fn max_hops(mut self, hops: u8) -> Self {
        self.max_hops = Some(hops);
        self
    }

    /// Enable traffic scrambling for traffic analysis resistance
    pub fn enable_scrambling(mut self, enable: bool) -> Self {
        self.enable_scrambling = Some(enable);
        self
    }

    /// Build the ZKS connection
    pub async fn build(self) -> Result<ZksConnection> {
        let url = self.url.ok_or_else(|| SdkError::InvalidUrl("URL is required".to_string()))?;
        
        // Validate URL scheme
        let parsed_url = Url::parse(&url)
            .map_err(|e| SdkError::InvalidUrl(format!("Invalid URL: {}", e)))?;
        
        if parsed_url.scheme() != "zks" {
            return Err(SdkError::InvalidUrl("URL must use zks:// scheme".to_string()));
        }

        let config = ConnectionConfig {
            security: self.security.unwrap_or_default(),
            timeout: self.timeout.unwrap_or_else(|| Duration::from_secs(30)),
            buffer_size: self.buffer_size.unwrap_or(64 * 1024),
            enable_scrambling: self.enable_scrambling.unwrap_or(true),
            ..Default::default()
        };

        let min_hops = self.min_hops.unwrap_or(3);
        let max_hops = self.max_hops.unwrap_or(5);

        if min_hops > max_hops {
            return Err(SdkError::InvalidUrl("min_hops cannot be greater than max_hops".to_string()));
        }

        ZksConnection::connect(url, config, min_hops, max_hops).await
    }
}

impl Default for ZksConnectionBuilder {
    fn default() -> Self {
        Self::new()
    }
}