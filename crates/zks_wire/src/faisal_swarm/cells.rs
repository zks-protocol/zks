//! Faisal Swarm Cell Protocol
//! 
//! Defines the cell format used for communication between Faisal Swarm peers.
//! Each cell is encrypted with Wasif-Vernam and contains routing information.

use bytes::{Buf, BufMut};
use std::convert::TryInto;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use tracing::{debug, error, info, warn};

/// Faisal Swarm cell size (same as Tor: 512 bytes)
pub const CELL_SIZE: usize = 512;

/// Faisal Swarm cell header size (expanded to include delay field)
/// Format: circuit_id(4) + command(1) + payload_len(2) + flags(1) + delay_ms(2) = 10 bytes
pub const CELL_HEADER_SIZE: usize = 10;

/// Maximum payload size per cell
pub const CELL_PAYLOAD_SIZE: usize = CELL_SIZE - CELL_HEADER_SIZE;

/// Maximum delay in milliseconds (65 seconds)
pub const MAX_DELAY_MS: u16 = 65000;

/// Default delay for Loopix-style mixing (mean of exponential distribution)
pub const DEFAULT_MEAN_DELAY_MS: u16 = 100;

/// Faisal Swarm cell command types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CellCommand {
    /// Padding cell (keepalive)
    Padding = 0x00,
    
    /// Create circuit (initial handshake)
    Create = 0x01,
    
    /// Created circuit (handshake response)
    Created = 0x02,
    
    /// Relay cell (data transfer)
    Relay = 0x03,
    
    /// Destroy circuit
    Destroy = 0x04,
    
    /// Extend circuit to next hop
    Extend = 0x06,
    
    /// Extended circuit (extend response)
    Extended = 0x07,
    
    /// Post-quantum ML-KEM handshake
    MlKemHandshake = 0x80,
    
    /// Wasif-Vernam encrypted relay
    VernamRelay = 0x81,
}

impl CellCommand {
    /// Convert u8 to CellCommand
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(CellCommand::Padding),
            0x01 => Some(CellCommand::Create),
            0x02 => Some(CellCommand::Created),
            0x03 => Some(CellCommand::Relay),
            0x04 => Some(CellCommand::Destroy),
            0x06 => Some(CellCommand::Extend),
            0x07 => Some(CellCommand::Extended),
            0x80 => Some(CellCommand::MlKemHandshake),
            0x81 => Some(CellCommand::VernamRelay),
            _ => None,
        }
    }
}

/// Faisal Swarm cell header
/// 
/// Includes delay field for Loopix-style continuous-time mixing.
/// Each relay waits `delay_ms` before forwarding to resist timing attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellHeader {
    /// Circuit ID (4 bytes)
    pub circuit_id: u32,
    
    /// Command type (1 byte)
    pub command: CellCommand,
    
    /// Payload length (2 bytes)
    pub payload_len: u16,
    
    /// Reserved/flags (1 byte)
    pub flags: u8,
    
    /// Delay in milliseconds before forwarding (2 bytes)
    /// Used for Loopix-style continuous-time mixing to resist timing attacks.
    /// Set to 0 for no delay (immediate forwarding).
    pub delay_ms: u16,
}

impl CellHeader {
    /// Create a new cell header with no delay
    pub fn new(circuit_id: u32, command: CellCommand, payload_len: u16) -> Self {
        Self {
            circuit_id,
            command,
            payload_len,
            flags: 0,
            delay_ms: 0,
        }
    }
    
    /// Create a new cell header with Loopix-style exponential delay
    /// 
    /// Generates a random delay from exponential distribution with given mean.
    /// This provides timing attack resistance by making packet timing unpredictable.
    pub fn new_with_exponential_delay(
        circuit_id: u32,
        command: CellCommand,
        payload_len: u16,
        mean_delay_ms: u16,
    ) -> Self {
        // SECURITY: Use TrueEntropy for 256-bit post-quantum computational security in delay generation
        // Prevents timing correlation attacks that could break anonymity
        use zks_crypt::true_entropy::TrueEntropyRng;
        use rand::Rng;
        let mut rng = TrueEntropyRng;
        
        // Exponential distribution: delay = -ln(U) * mean
        let u: f64 = rng.gen_range(0.0001..1.0); // Avoid ln(0)
        let delay = (-f64::ln(u) * mean_delay_ms as f64) as u16;
        let delay_clamped = delay.min(MAX_DELAY_MS);
        
        Self {
            circuit_id,
            command,
            payload_len,
            flags: 0,
            delay_ms: delay_clamped,
        }
    }
    
    /// Create a new cell header with specific delay
    pub fn new_with_delay(
        circuit_id: u32,
        command: CellCommand,
        payload_len: u16,
        delay_ms: u16,
    ) -> Self {
        Self {
            circuit_id,
            command,
            payload_len,
            flags: 0,
            delay_ms: delay_ms.min(MAX_DELAY_MS),
        }
    }
    
    /// Serialize header to bytes (10 bytes)
    pub fn to_bytes(&self) -> [u8; CELL_HEADER_SIZE] {
        let mut bytes = [0u8; CELL_HEADER_SIZE];
        let mut buf = &mut bytes[..];
        
        buf.put_u32(self.circuit_id);
        buf.put_u8(self.command as u8);
        buf.put_u16(self.payload_len);
        buf.put_u8(self.flags);
        buf.put_u16(self.delay_ms);
        
        bytes
    }
    
    /// Deserialize header from bytes (10 bytes)
    pub fn from_bytes(bytes: &[u8; CELL_HEADER_SIZE]) -> Result<Self, CellError> {
        if bytes.len() < CELL_HEADER_SIZE {
            return Err(CellError::InvalidHeaderSize);
        }
        
        let mut buf = &bytes[..];
        
        let circuit_id = buf.get_u32();
        let command_byte = buf.get_u8();
        let payload_len = buf.get_u16();
        let flags = buf.get_u8();
        let delay_ms = buf.get_u16();
        
        let command = CellCommand::from_u8(command_byte)
            .ok_or(CellError::InvalidCommand(command_byte))?;
        
        if payload_len as usize > CELL_PAYLOAD_SIZE {
            return Err(CellError::PayloadTooLarge(payload_len));
        }
        
        Ok(Self {
            circuit_id,
            command,
            payload_len,
            flags,
            delay_ms: delay_ms.min(MAX_DELAY_MS),
        })
    }
    
    /// Get the delay duration for this cell
    pub fn delay_duration(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.delay_ms as u64)
    }
}

/// Faisal Swarm cell
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaisalSwarmCell {
    /// Cell header
    pub header: CellHeader,
    
    /// Cell payload (encrypted with Wasif-Vernam)
    pub payload: Vec<u8>,
}

impl FaisalSwarmCell {
    /// Create a new cell (no delay)
    pub fn new(circuit_id: u32, command: CellCommand, payload: Vec<u8>) -> Result<Self, CellError> {
        if payload.len() > CELL_PAYLOAD_SIZE {
            return Err(CellError::PayloadTooLarge(payload.len() as u16));
        }
        
        let header = CellHeader::new(circuit_id, command, payload.len() as u16);
        
        Ok(Self { header, payload })
    }
    
    /// Create a new cell with Loopix-style exponential delay
    /// 
    /// This provides timing attack resistance by adding random delays
    /// drawn from an exponential distribution with the given mean.
    /// 
    /// # Arguments
    /// * `circuit_id` - Circuit identifier
    /// * `command` - Cell command type
    /// * `payload` - Cell payload data
    /// * `mean_delay_ms` - Mean delay in milliseconds (e.g., 100ms)
    /// 
    /// # Example
    /// ```ignore
    /// // Create a relay cell with ~100ms mean delay
    /// let cell = FaisalSwarmCell::new_with_delay(
    ///     circuit_id,
    ///     CellCommand::Relay,
    ///     payload,
    ///     DEFAULT_MEAN_DELAY_MS,
    /// )?;
    /// ```
    pub fn new_with_delay(
        circuit_id: u32,
        command: CellCommand,
        payload: Vec<u8>,
        mean_delay_ms: u16,
    ) -> Result<Self, CellError> {
        if payload.len() > CELL_PAYLOAD_SIZE {
            return Err(CellError::PayloadTooLarge(payload.len() as u16));
        }
        
        let header = CellHeader::new_with_exponential_delay(
            circuit_id,
            command,
            payload.len() as u16,
            mean_delay_ms,
        );
        
        Ok(Self { header, payload })
    }
    
    /// Create a padding cell (keepalive)
    pub fn padding(circuit_id: u32) -> Self {
        let header = CellHeader::new(circuit_id, CellCommand::Padding, 0);
        Self {
            header,
            payload: Vec::new(),
        }
    }
    
    /// Create a destroy cell
    pub fn destroy(circuit_id: u32, reason: u8) -> Self {
        let header = CellHeader::new(circuit_id, CellCommand::Destroy, 1);
        Self {
            header,
            payload: vec![reason],
        }
    }
    
    /// Serialize cell to bytes (for network transmission)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CELL_SIZE);
        
        // Add header
        bytes.extend_from_slice(&self.header.to_bytes());
        
        // Add payload
        bytes.extend_from_slice(&self.payload);
        
        // Pad to CELL_SIZE
        let padding_len = CELL_SIZE - bytes.len();
        bytes.resize(CELL_SIZE, 0);
        
        debug!("Serialized cell: {} bytes ({} padding)", CELL_SIZE, padding_len);
        
        bytes
    }
    
    /// Deserialize cell from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CellError> {
        if bytes.len() != CELL_SIZE {
            return Err(CellError::InvalidCellSize(bytes.len()));
        }
        
        // Parse header
        let header_bytes: [u8; CELL_HEADER_SIZE] = bytes[0..CELL_HEADER_SIZE]
            .try_into()
            .map_err(|_| CellError::InvalidHeaderSize)?;
        
        let header = CellHeader::from_bytes(&header_bytes)?;
        
        // Parse payload
        let payload_start = CELL_HEADER_SIZE;
        let payload_end = payload_start + header.payload_len as usize;
        
        if payload_end > CELL_SIZE {
            return Err(CellError::InvalidPayloadBounds);
        }
        
        let payload = bytes[payload_start..payload_end].to_vec();
        
        Ok(Self { header, payload })
    }
    
    /// Check if this is a valid Faisal Swarm cell
    pub fn is_valid(&self) -> bool {
        self.header.payload_len as usize == self.payload.len() &&
        self.header.payload_len as usize <= CELL_PAYLOAD_SIZE
    }
}

/// Relay cell payload (for data transfer)
#[derive(Debug, Clone)]
pub struct RelayPayload {
    /// Relay command
    pub relay_command: RelayCommand,
    
    /// Stream ID (for multiplexing)
    pub stream_id: u16,
    
    /// Data payload
    pub data: Vec<u8>,
}

/// Relay commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCommand {
    /// Begin new stream
    Begin = 0x01,
    
    /// Data payload
    Data = 0x02,
    
    /// End stream
    End = 0x03,
    
    /// Connected acknowledgment
    Connected = 0x04,
    
    /// Resolve DNS
    Resolve = 0x05,
    
    /// Resolved DNS response
    Resolved = 0x06,
}

impl RelayPayload {
    /// Serialize relay payload
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.relay_command as u8);
        bytes.extend_from_slice(&self.stream_id.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }
    
    /// Deserialize relay payload
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CellError> {
        if bytes.len() < 3 {
            return Err(CellError::InvalidRelayPayload);
        }
        
        let relay_command = match bytes[0] {
            0x01 => RelayCommand::Begin,
            0x02 => RelayCommand::Data,
            0x03 => RelayCommand::End,
            0x04 => RelayCommand::Connected,
            0x05 => RelayCommand::Resolve,
            0x06 => RelayCommand::Resolved,
            _ => return Err(CellError::InvalidRelayCommand(bytes[0])),
        };
        
        let stream_id = u16::from_be_bytes([bytes[1], bytes[2]]);
        let data = bytes[3..].to_vec();
        
        Ok(Self {
            relay_command,
            stream_id,
            data,
        })
    }
}

/// Faisal Swarm cell processing
pub struct CellProcessor {
    /// Circuit manager reference
    circuit_manager: Arc<super::circuit_manager::FaisalSwarmManager>,
}

impl CellProcessor {
    /// Create a new cell processor
    pub fn new(circuit_manager: Arc<super::circuit_manager::FaisalSwarmManager>) -> Self {
        Self { circuit_manager }
    }
    
    /// Process incoming cell with Loopix-style timing delay
    /// 
    /// If the cell has a non-zero delay_ms, this function will wait before processing
    /// to provide timing attack resistance (continuous-time mixing).
    pub async fn process_cell(&self, cell: FaisalSwarmCell) -> Result<Vec<FaisalSwarmCell>, CellError> {
        // Apply Loopix-style delay before processing
        // This makes timing correlation exponentially harder
        if cell.header.delay_ms > 0 {
            let delay = cell.header.delay_duration();
            debug!(
                "⏱️ Applying Loopix delay: {}ms for circuit {} (timing attack resistance)",
                cell.header.delay_ms, cell.header.circuit_id
            );
            tokio::time::sleep(delay).await;
        }
        
        debug!("Processing cell: {:?} for circuit {}", cell.header.command, cell.header.circuit_id);
        
        match cell.header.command {
            CellCommand::Padding => {
                // Keepalive - no action needed
                Ok(vec![])
            },
            
            CellCommand::Relay => {
                // Handle relay cell
                self.process_relay_cell(cell).await
            },
            
            CellCommand::VernamRelay => {
                // Handle Wasif-Vernam encrypted relay
                self.process_vernam_relay_cell(cell).await
            },
            
            CellCommand::Destroy => {
                // Handle circuit destruction
                self.process_destroy_cell(cell).await
            },
            
            _ => {
                warn!("Unhandled cell command: {:?}", cell.header.command);
                Ok(vec![])
            }
        }
    }
    
    /// Process relay cell
    async fn process_relay_cell(&self, cell: FaisalSwarmCell) -> Result<Vec<FaisalSwarmCell>, CellError> {
        debug!("Processing relay cell for circuit {}", cell.header.circuit_id);
        
        // Deserialize the relay payload
        let relay_payload = RelayPayload::from_bytes(&cell.payload)
            .map_err(|_| CellError::InvalidRelayPayload)?;
        
        debug!("Relay command: {:?}, Stream ID: {}", relay_payload.relay_command, relay_payload.stream_id);
        
        // Process based on relay command
        match relay_payload.relay_command {
            RelayCommand::Data => {
                // Forward data through the circuit
                debug!("Forwarding data through circuit {}", cell.header.circuit_id);
                
                // For now, just echo the data back (in a real implementation, this would forward to the next hop)
                let response_payload = RelayPayload {
                    relay_command: RelayCommand::Data,
                    stream_id: relay_payload.stream_id,
                    data: relay_payload.data.clone(),
                };
                
                let response_cell = FaisalSwarmCell::new(
                    cell.header.circuit_id,
                    CellCommand::Relay,
                    response_payload.to_bytes()
                )?;
                
                Ok(vec![response_cell])
            },
            RelayCommand::Begin => {
                // Acknowledge stream creation
                debug!("Creating new stream {} on circuit {}", relay_payload.stream_id, cell.header.circuit_id);
                
                let response_payload = RelayPayload {
                    relay_command: RelayCommand::Connected,
                    stream_id: relay_payload.stream_id,
                    data: vec![],
                };
                
                let response_cell = FaisalSwarmCell::new(
                    cell.header.circuit_id,
                    CellCommand::Relay,
                    response_payload.to_bytes()
                )?;
                
                Ok(vec![response_cell])
            },
            RelayCommand::End => {
                // Acknowledge stream termination
                debug!("Terminating stream {} on circuit {}", relay_payload.stream_id, cell.header.circuit_id);
                Ok(vec![])
            },
            RelayCommand::Connected => {
                // Stream already connected, no action needed
                debug!("Stream {} already connected on circuit {}", relay_payload.stream_id, cell.header.circuit_id);
                Ok(vec![])
            },
            RelayCommand::Resolve | RelayCommand::Resolved => {
                // DNS resolution not implemented yet
                debug!("DNS resolution not implemented for circuit {}", cell.header.circuit_id);
                Err(CellError::NotImplemented("DNS resolution".into()))
            }
        }
    }
    
    /// Process Wasif-Vernam encrypted relay cell
    async fn process_vernam_relay_cell(&self, cell: FaisalSwarmCell) -> Result<Vec<FaisalSwarmCell>, CellError> {
        debug!("Processing Vernam relay cell for circuit {}", cell.header.circuit_id);
        
        // For Vernam relay cells, we need to decrypt the payload first
        // In a real implementation, this would use the circuit's Wasif-Vernam cipher
        // For now, we'll treat it as a regular relay cell (simulated)
        
        debug!("Decrypting Vernam relay payload (simulated)");
        
        // Simulate decryption - in reality this would use the circuit's backward cipher
        let decrypted_payload = cell.payload.clone();
        
        // Process as a regular relay cell after "decryption"
        let mut simulated_cell = cell;
        simulated_cell.payload = decrypted_payload;
        simulated_cell.header.command = CellCommand::Relay;
        
        self.process_relay_cell(simulated_cell).await
    }
    
    /// Process destroy cell
    async fn process_destroy_cell(&self, cell: FaisalSwarmCell) -> Result<Vec<FaisalSwarmCell>, CellError> {
        let circuit_id = cell.header.circuit_id;
        
        if let Some(reason) = cell.payload.first() {
            info!("Destroying circuit {} with reason: {}", circuit_id, reason);
            
            // Close the circuit
            if let Err(e) = self.circuit_manager.close_circuit(circuit_id).await {
                error!("Failed to close circuit {}: {}", circuit_id, e);
            }
        }
        
        Ok(vec![])
    }
}

/// Faisal Swarm cell errors
#[derive(Debug, thiserror::Error)]
pub enum CellError {
    /// Cell size is invalid (not exactly 512 bytes)
    #[error("Invalid cell size: expected {CELL_SIZE}, got {0}")]
    InvalidCellSize(usize),
    
    /// Header size is invalid
    #[error("Invalid header size")]
    InvalidHeaderSize,
    
    /// Command byte is invalid
    #[error("Invalid command: {0}")]
    InvalidCommand(u8),
    
    /// Payload exceeds maximum allowed size
    #[error("Payload too large: {0} bytes (max: {CELL_PAYLOAD_SIZE})")]
    PayloadTooLarge(u16),
    
    /// Payload bounds are invalid
    #[error("Invalid payload bounds")]
    InvalidPayloadBounds,
    
    /// Relay command is invalid
    #[error("Invalid relay command: {0}")]
    InvalidRelayCommand(u8),
    
    /// Relay payload is invalid
    #[error("Invalid relay payload")]
    InvalidRelayPayload,
    
    /// Cell validation failed
    #[error("Cell validation failed")]
    ValidationFailed,
    
    /// Feature is not implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

/// Create a padding cell for keepalive
pub fn create_padding_cell(circuit_id: u32) -> FaisalSwarmCell {
    FaisalSwarmCell::padding(circuit_id)
}

/// Create a destroy cell
pub fn create_destroy_cell(circuit_id: u32, reason: u8) -> FaisalSwarmCell {
    FaisalSwarmCell::destroy(circuit_id, reason)
}

/// Create a relay data cell
pub fn create_relay_cell(circuit_id: u32, stream_id: u16, data: Vec<u8>) -> Result<FaisalSwarmCell, CellError> {
    let relay_payload = RelayPayload {
        relay_command: RelayCommand::Data,
        stream_id,
        data,
    };
    
    let payload = relay_payload.to_bytes();
    FaisalSwarmCell::new(circuit_id, CellCommand::Relay, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cell_header_serialization() {
        let header = CellHeader::new(0x12345678, CellCommand::Relay, 100);
        let bytes = header.to_bytes();
        
        let deserialized = CellHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header.circuit_id, deserialized.circuit_id);
        assert_eq!(header.command, deserialized.command);
        assert_eq!(header.payload_len, deserialized.payload_len);
    }
    
    #[test]
    fn test_cell_creation() {
        let payload = vec![0x42; 50];
        let cell = FaisalSwarmCell::new(0x12345678, CellCommand::Relay, payload.clone()).unwrap();
        
        assert_eq!(cell.header.circuit_id, 0x12345678);
        assert_eq!(cell.header.command, CellCommand::Relay);
        assert_eq!(cell.payload, payload);
        assert!(cell.is_valid());
    }
    
    #[test]
    fn test_cell_serialization() {
        let payload = vec![0x42; 50];
        let cell = FaisalSwarmCell::new(0x12345678, CellCommand::Relay, payload).unwrap();
        
        let bytes = cell.to_bytes();
        assert_eq!(bytes.len(), CELL_SIZE);
        
        let deserialized = FaisalSwarmCell::from_bytes(&bytes).unwrap();
        assert_eq!(cell.header.circuit_id, deserialized.header.circuit_id);
        assert_eq!(cell.header.command, deserialized.header.command);
        assert_eq!(cell.payload, deserialized.payload);
    }
    
    #[test]
    fn test_relay_payload() {
        let data = vec![0x42; 20];
        let relay_payload = RelayPayload {
            relay_command: RelayCommand::Data,
            stream_id: 0x1234,
            data: data.clone(),
        };
        
        let bytes = relay_payload.to_bytes();
        let deserialized = RelayPayload::from_bytes(&bytes).unwrap();
        
        assert_eq!(relay_payload.relay_command, deserialized.relay_command);
        assert_eq!(relay_payload.stream_id, deserialized.stream_id);
        assert_eq!(relay_payload.data, deserialized.data);
    }
}