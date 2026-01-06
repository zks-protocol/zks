//! Prelude for ZKS SDK - import this for convenient access to all types

// Core SDK types
pub use crate::{
    ZkConnection,
    ZksConnection,
    SdkError,
    Result,
};

// Configuration types
pub use crate::config::{
    SecurityLevel,
    ConnectionConfig,
};

// Builder types
pub use crate::builder::{
    ZkConnectionBuilder,
    ZksConnectionBuilder,
};

// Prefabricated components
pub use crate::prefabs::{
    SecureMessenger,
    SecureFileTransfer,
    P2PConnection,
};

// Re-export commonly used external types
pub use std::time::Duration;
pub use url::Url;

/// Convenience macro for creating ZK connections
#[macro_export]
macro_rules! zk_connect {
    ($url:expr) => {
        $crate::ZkConnection::connect($url, $crate::ConnectionConfig::default()).await
    };
    ($url:expr, $security:expr) => {
        {
            let mut config = $crate::ConnectionConfig::default();
            config.security = $security;
            $crate::ZkConnection::connect($url, config).await
        }
    };
}

/// Convenience macro for creating ZKS connections
#[macro_export]
macro_rules! zks_connect {
    ($url:expr) => {
        $crate::ZksConnection::connect($url, $crate::ConnectionConfig::default(), 3, 5).await
    };
    ($url:expr, $min_hops:expr) => {
        $crate::ZksConnection::connect($url, $crate::ConnectionConfig::default(), $min_hops, 5).await
    };
}