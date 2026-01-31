//! Utility functions for SURB operations

use crate::{ZksSurb, SurbId, Result};

/// Generate multiple SURBs for a recipient
/// 
/// Returns a tuple of (public_surbs, private_data_vec) where private_data_vec contains the encryption keys
pub fn generate_surbs(count: usize, recipient_pk: &[u8]) -> Result<(Vec<ZksSurb>, Vec<crate::surb::PrivateSurbData>)> {
    let mut public_surbs = Vec::with_capacity(count);
    let mut private_data_vec = Vec::with_capacity(count);
    
    for _ in 0..count {
        let (surb, private_data) = ZksSurb::create(recipient_pk)?;
        public_surbs.push(surb);
        private_data_vec.push(private_data);
    }
    
    Ok((public_surbs, private_data_vec))
}

/// Generate multiple SURBs for a recipient with custom configuration
/// 
/// Returns a tuple of (public_surbs, private_data_vec) where private_data_vec contains the encryption keys
pub fn generate_surbs_with_config(count: usize, recipient_pk: &[u8], config: &crate::config::SurbConfig) -> Result<(Vec<ZksSurb>, Vec<crate::surb::PrivateSurbData>)> {
    let mut public_surbs = Vec::with_capacity(count);
    let mut private_data_vec = Vec::with_capacity(count);
    
    for _ in 0..count {
        let (surb, private_data) = ZksSurb::create_with_config(recipient_pk, config)?;
        public_surbs.push(surb);
        private_data_vec.push(private_data);
    }
    
    Ok((public_surbs, private_data_vec))
}

/// Validate a collection of SURBs
pub fn validate_surbs(surbs: &[ZksSurb]) -> Vec<bool> {
    surbs.iter().map(|surb| surb.is_valid()).collect()
}

/// Check if a SURB ID is unique within a collection
pub fn is_unique_surb_id(surb_id: &SurbId, surbs: &[ZksSurb]) -> bool {
    surbs.iter().filter(|surb| &surb.id == surb_id).count() == 1
}

/// Filter out expired SURBs
pub fn filter_expired(surbs: Vec<ZksSurb>) -> Vec<ZksSurb> {
    surbs.into_iter().filter(|surb| !surb.is_expired()).collect()
}

/// Filter out used SURBs
pub fn filter_used(surbs: Vec<ZksSurb>) -> Vec<ZksSurb> {
    surbs.into_iter().filter(|surb| !surb.is_used()).collect()
}