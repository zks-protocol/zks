//! Faisal Swarm transport integration for cover traffic
//!
//! This module provides the integration layer between cover traffic generation
//! and actual network transmission through Faisal Swarm circuits.

use std::sync::Arc;

use zks_wire::faisal_swarm::{FaisalSwarmCell, FaisalSwarmCircuit};

use crate::error::{CoverError, Result};
use crate::types::CoverMessage;
use crate::generator::CoverGenerator;
use crate::config::CoverConfig;

/// Cover traffic transport that integrates with Faisal Swarm
/// 
/// This struct manages the connection between cover traffic generation
/// and actual network transmission through Faisal Swarm circuits.
#[derive(Debug)]
pub struct CoverTransport {
    config: CoverConfig,
    generator: Arc<CoverGenerator>,
}

impl CoverTransport {
    /// Create a new cover transport
    pub fn new(config: CoverConfig, generator: Arc<CoverGenerator>) -> Self {
        Self { config, generator }
    }
    
    /// Send cover traffic through a Faisal Swarm circuit
    /// 
    /// # Arguments
    /// * `circuit` - The Faisal Swarm circuit to send through
    /// * `circuit_id` - The circuit ID for cell construction
    /// 
    /// # Returns
    /// The onion-encrypted cell bytes ready for network transmission
    pub async fn send_cover(
        &self,
        circuit: &mut FaisalSwarmCircuit,
        circuit_id: u32,
    ) -> Result<Vec<u8>> {
        // Generate a cover message
        let cover_msg = self.generator.generate_cover(Some(circuit_id.to_string())).await?;
        
        // Convert to Faisal Swarm cell
        let cell = cover_msg.to_faisal_swarm_cell(circuit_id)
            .map_err(|e| CoverError::TransportError(e))?;
        
        // Serialize the cell
        let cell_bytes = cell.to_bytes();
        
        // Onion encrypt through the circuit
        let encrypted = circuit.encrypt_onion(&cell_bytes)
            .map_err(|e| CoverError::TransportError(format!("Onion encryption failed: {:?}", e)))?;
        
        Ok(encrypted)
    }
    
    /// Send multiple cover messages as burst traffic
    /// 
    /// # Arguments
    /// * `circuit` - The Faisal Swarm circuit to send through
    /// * `circuit_id` - The circuit ID for cell construction
    /// * `count` - Number of cover messages to send
    /// 
    /// # Returns
    /// Vector of onion-encrypted cell bytes
    pub async fn send_cover_burst(
        &self,
        circuit: &mut FaisalSwarmCircuit,
        circuit_id: u32,
        count: usize,
    ) -> Result<Vec<Vec<u8>>> {
        let mut encrypted_cells = Vec::with_capacity(count);
        
        for _ in 0..count {
            let encrypted = self.send_cover(circuit, circuit_id).await?;
            encrypted_cells.push(encrypted);
        }
        
        Ok(encrypted_cells)
    }
    
    /// Process incoming cells and identify cover traffic
    /// 
    /// # Arguments
    /// * `circuit` - The Faisal Swarm circuit for decryption
    /// * `encrypted_data` - The received encrypted data
    /// 
    /// # Returns
    /// Some(CoverMessage) if it's cover traffic, None otherwise
    pub fn receive_and_identify(
        &self,
        circuit: &mut FaisalSwarmCircuit,
        encrypted_data: &[u8],
    ) -> Result<Option<CoverMessage>> {
        // Decrypt the onion layers
        let decrypted = circuit.decrypt_onion(encrypted_data)
            .map_err(|e| CoverError::TransportError(format!("Onion decryption failed: {:?}", e)))?;
        
        // Parse as Faisal Swarm cell
        let cell = FaisalSwarmCell::from_bytes(&decrypted)
            .map_err(|e| CoverError::TransportError(format!("Cell parse failed: {:?}", e)))?;
        
        // Check if it's cover traffic
        Ok(CoverMessage::from_faisal_swarm_cell(&cell))
    }
    
    /// Create a padding cell directly for simple keepalive
    pub fn create_padding_cell(&self, circuit_id: u32) -> FaisalSwarmCell {
        FaisalSwarmCell::padding(circuit_id)
    }
}

/// Builder for CoverTransport
#[derive(Debug, Default)]
pub struct CoverTransportBuilder {
    config: Option<CoverConfig>,
    generator: Option<Arc<CoverGenerator>>,
}

impl CoverTransportBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set the configuration
    pub fn config(mut self, config: CoverConfig) -> Self {
        self.config = Some(config);
        self
    }
    
    /// Set the generator
    pub fn generator(mut self, generator: Arc<CoverGenerator>) -> Self {
        self.generator = Some(generator);
        self
    }
    
    /// Build the transport
    pub fn build(self) -> Result<CoverTransport> {
        let config = self.config.unwrap_or_default();
        let generator = self.generator.ok_or_else(|| {
            CoverError::InvalidConfig("Generator required".to_string())
        })?;
        
        Ok(CoverTransport::new(config, generator))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_transport_builder() {
        let config = CoverConfig::default();
        let generator = Arc::new(CoverGenerator::new(config.clone()).unwrap());
        
        let transport = CoverTransportBuilder::new()
            .config(config)
            .generator(generator)
            .build()
            .unwrap();
        
        // Should be able to create padding cell
        let padding = transport.create_padding_cell(1);
        assert_eq!(padding.header.command, CellCommand::Padding);
    }
}
