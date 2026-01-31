use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Types of cover messages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub enum CoverType {
    /// Regular cover traffic - indistinguishable from normal traffic
    Regular,
    /// Loop cover traffic - routes back to sender for additional anonymity
    Loop,
    /// Drop cover traffic - intentionally dropped to confuse traffic analysis
    Drop,
}

/// A cover message that is indistinguishable from real traffic
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CoverMessage {
    /// Type of cover message
    pub cover_type: CoverType,
    
    /// Encrypted payload - contains the actual cover data
    pub payload: Vec<u8>,
    
    /// Circuit ID for Faisal Swarm routing - optional for integration with existing circuits
    pub circuit_id: Option<String>,
    
    /// Timestamp when message was created (Unix timestamp in seconds)
    pub created_at: u64,
    
    /// Message size (should match ZKS fixed cell size of 512 bytes)
    pub size: usize,
}

impl CoverMessage {
    /// Create a new cover message with the specified type, payload, and optional circuit ID
    /// 
    /// # Arguments
    /// * `cover_type` - The type of cover traffic (Regular, Loop, or Drop)
    /// * `payload` - The encrypted payload data (should be 512 bytes for ZKS compatibility)
    /// * `circuit_id` - Optional circuit ID for Faisal Swarm integration
    /// 
    /// # Returns
    /// A new CoverMessage instance with the current timestamp and calculated size
    pub fn new(cover_type: CoverType, payload: Vec<u8>, circuit_id: Option<String>) -> Self {
        let size = payload.len();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            cover_type,
            payload,
            circuit_id,
            created_at,
            size,
        }
    }
    
    /// Create a regular cover message
    pub fn regular(payload: Vec<u8>, circuit_id: Option<String>) -> Self {
        Self::new(CoverType::Regular, payload, circuit_id)
    }
    
    /// Create a loop cover message
    pub fn loop_message(payload: Vec<u8>, circuit_id: Option<String>) -> Self {
        Self::new(CoverType::Loop, payload, circuit_id)
    }
    
    /// Create a drop cover message
    pub fn drop_message(payload: Vec<u8>, circuit_id: Option<String>) -> Self {
        Self::new(CoverType::Drop, payload, circuit_id)
    }
    
    /// Check if this is a loop message
    pub fn is_loop(&self) -> bool {
        self.cover_type == CoverType::Loop
    }
    
    /// Check if this is a drop message
    pub fn is_drop(&self) -> bool {
        self.cover_type == CoverType::Drop
    }
    
    /// Check if this is a regular cover message
    pub fn is_regular(&self) -> bool {
        self.cover_type == CoverType::Regular
    }
    
    /// Get the message age in seconds
    pub fn age(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now.saturating_sub(self.created_at)
    }
    
    /// Check if message is expired (older than max age)
    pub fn is_expired(&self, max_age: u64) -> bool {
        self.age() > max_age
    }
    
    /// Convert this cover message to a Faisal Swarm cell for network transmission
    /// 
    /// # Arguments
    /// * `circuit_id_u32` - The numeric circuit ID for the Faisal Swarm cell
    /// 
    /// # Returns
    /// A FaisalSwarmCell ready for transmission through the onion network
    pub fn to_faisal_swarm_cell(&self, circuit_id_u32: u32) -> Result<zks_wire::faisal_swarm::FaisalSwarmCell, String> {
        use zks_wire::faisal_swarm::{FaisalSwarmCell, CellCommand};
        
        // Cover traffic always uses Padding command to be indistinguishable
        FaisalSwarmCell::new(circuit_id_u32, CellCommand::Padding, self.payload.clone())
            .map_err(|e| format!("Failed to create Faisal Swarm cell: {:?}", e))
    }
    
    /// Create a cover message from a Faisal Swarm padding cell
    /// 
    /// This allows receiving and processing incoming cover traffic
    pub fn from_faisal_swarm_cell(cell: &zks_wire::faisal_swarm::FaisalSwarmCell) -> Option<Self> {
        use zks_wire::faisal_swarm::CellCommand;
        
        // Only process Padding cells as cover traffic
        if cell.header.command != CellCommand::Padding {
            return None;
        }
        
        Some(Self::new(
            CoverType::Regular,
            cell.payload.clone(),
            Some(cell.header.circuit_id.to_string())
        ))
    }
}

impl std::fmt::Display for CoverType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoverType::Regular => write!(f, "Regular"),
            CoverType::Loop => write!(f, "Loop"),
            CoverType::Drop => write!(f, "Drop"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cover_message_creation() {
        let payload = vec![0u8; 512];
        let message = CoverMessage::regular(payload.clone(), None);
        
        assert_eq!(message.cover_type, CoverType::Regular);
        assert_eq!(message.payload, payload);
        assert_eq!(message.size, 512);
        assert!(!message.is_loop());
        assert!(!message.is_drop());
        assert!(message.is_regular());
    }
    
    #[test]
    fn test_cover_message_types() {
        let payload = vec![0u8; 256];
        
        let regular = CoverMessage::regular(payload.clone(), None);
        assert!(regular.is_regular());
        
        let loop_msg = CoverMessage::loop_message(payload.clone(), None);
        assert!(loop_msg.is_loop());
        
        let drop_msg = CoverMessage::drop_message(payload, None);
        assert!(drop_msg.is_drop());
    }
    
    #[test]
    fn test_cover_message_age() {
        let payload = vec![0u8; 512];
        let message = CoverMessage::regular(payload, None);
        
        // Message should be very young (0 or 1 second old)
        assert!(message.age() <= 1);
        
        // Should not be expired with 60 second max age
        assert!(!message.is_expired(60));
    }
    
    #[test]
    fn test_cover_type_display() {
        assert_eq!(CoverType::Regular.to_string(), "Regular");
        assert_eq!(CoverType::Loop.to_string(), "Loop");
        assert_eq!(CoverType::Drop.to_string(), "Drop");
    }
    
    #[test]
    fn test_zeroize() {
        let payload = vec![0xFFu8; 512];
        let mut message = CoverMessage::regular(payload, None);
        
        // Zeroize the message
        message.zeroize();
        
        // Payload should be zeroed
        assert!(message.payload.iter().all(|&b| b == 0));
    }
}