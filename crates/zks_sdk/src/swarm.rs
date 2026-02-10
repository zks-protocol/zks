use crate::error::Result;
use crate::identity::ZksIdentity;
use crate::node::{NodeConfig, ZksNode};
use std::net::SocketAddr;
use tracing::info;

/// A local swarm of ZKS nodes for testing
pub struct ZksSwarm {
    nodes: Vec<ZksNode>,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl ZksSwarm {
    /// Create a new empty swarm
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            handles: Vec::new(),
        }
    }

    /// Spawn a local testnet with `count` relay nodes + 1 Authority + 1 Client
    pub async fn local_testnet(relay_count: usize) -> Result<Self> {
        let mut swarm = Self::new();

        let start_port = 9000;

        // 1. Directory Authority
        let auth_id = ZksIdentity::generate()?;
        let auth_config = NodeConfig::new()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], start_port)))
            .identity(auth_id)
            .network_name("local-testnet".into()); // TODO: set mode to Authority

        swarm.spawn_node(auth_config).await?;

        // 2. Relays
        for i in 0..relay_count {
            let relay_id = ZksIdentity::generate()?;
            let port = start_port + 1 + i as u16;
            let config = NodeConfig::new()
                .bind_addr(SocketAddr::from(([127, 0, 0, 1], port)))
                .identity(relay_id)
                .network_name("local-testnet".into());

            swarm.spawn_node(config).await?;
        }

        info!("🌟 Swarm started with {} nodes", swarm.nodes.len());
        Ok(swarm)
    }

    /// Add and start a node in the swarm
    pub async fn spawn_node(&mut self, config: NodeConfig) -> Result<()> {
        let node = ZksNode::new(config);
        let handle = node.start().await?;

        self.nodes.push(node);
        self.handles.push(handle);
        Ok(())
    }

    /// Stop all nodes
    pub fn shutdown(&mut self) {
        for node in &self.nodes {
            node.stop();
        }
    }
}
