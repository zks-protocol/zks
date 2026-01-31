use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::surb::{SurbId, ZksSurb};
use crate::error::Result;

/// Trait for SURB storage backends
#[async_trait]
pub trait SurbStorage: Send + Sync {
    /// Store a SURB
    async fn store_surb(&self, surb: ZksSurb) -> Result<()>;
    
    /// Retrieve a SURB by ID
    async fn get_surb(&self, id: &SurbId) -> Result<Option<ZksSurb>>;
    
    /// Remove a SURB from storage
    async fn remove_surb(&self, id: &SurbId) -> Result<()>;
    
    /// Check if a SURB exists
    async fn has_surb(&self, id: &SurbId) -> Result<bool>;
    
    /// Get all SURB IDs
    async fn get_all_ids(&self) -> Result<Vec<SurbId>>;
    
    /// Get count of stored SURBs
    async fn count(&self) -> Result<usize>;
    
    /// Clear all SURBs
    async fn clear(&self) -> Result<()>;
}

/// In-memory SURB storage
#[derive(Debug, Default)]
pub struct MemorySurbStorage {
    surbs: Arc<RwLock<HashMap<SurbId, ZksSurb>>>,
}

impl MemorySurbStorage {
    /// Create a new memory storage
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SurbStorage for MemorySurbStorage {
    async fn store_surb(&self, surb: ZksSurb) -> Result<()> {
        let id = surb.id().clone();
        self.surbs.write().await.insert(id, surb);
        Ok(())
    }
    
    async fn get_surb(&self, id: &SurbId) -> Result<Option<ZksSurb>> {
        Ok(self.surbs.read().await.get(id).cloned())
    }
    
    async fn remove_surb(&self, id: &SurbId) -> Result<()> {
        self.surbs.write().await.remove(id);
        Ok(())
    }
    
    async fn has_surb(&self, id: &SurbId) -> Result<bool> {
        Ok(self.surbs.read().await.contains_key(id))
    }
    
    async fn get_all_ids(&self) -> Result<Vec<SurbId>> {
        Ok(self.surbs.read().await.keys().cloned().collect())
    }
    
    async fn count(&self) -> Result<usize> {
        Ok(self.surbs.read().await.len())
    }
    
    async fn clear(&self) -> Result<()> {
        self.surbs.write().await.clear();
        Ok(())
    }
}

/// File-based SURB storage (stub implementation)
#[derive(Debug)]
pub struct FileSurbStorage {
    path: String,
}

impl FileSurbStorage {
    /// Create a new file storage with the given path
    pub fn new(path: String) -> Self {
        Self { path }
    }
    
    /// Get the storage path
    pub fn path(&self) -> &str {
        &self.path
    }
}

#[async_trait]
impl SurbStorage for FileSurbStorage {
    async fn store_surb(&self, _surb: ZksSurb) -> Result<()> {
        // TODO: Implement file-based storage
        // For now, this is a stub that always succeeds
        Ok(())
    }
    
    async fn get_surb(&self, _id: &SurbId) -> Result<Option<ZksSurb>> {
        // TODO: Implement file-based storage
        // For now, this always returns None
        Ok(None)
    }
    
    async fn remove_surb(&self, _id: &SurbId) -> Result<()> {
        // TODO: Implement file-based storage
        Ok(())
    }
    
    async fn has_surb(&self, _id: &SurbId) -> Result<bool> {
        // TODO: Implement file-based storage
        Ok(false)
    }
    
    async fn get_all_ids(&self) -> Result<Vec<SurbId>> {
        // TODO: Implement file-based storage
        Ok(Vec::new())
    }
    
    async fn count(&self) -> Result<usize> {
        // TODO: Implement file-based storage
        Ok(0)
    }
    
    async fn clear(&self) -> Result<()> {
        // TODO: Implement file-based storage
        Ok(())
    }
}

/// Utility functions for SURB storage
pub mod storage_utils {
    use super::*;
    
    /// Create a memory storage with some test SURBs
    pub async fn create_test_storage() -> MemorySurbStorage {
        let storage = MemorySurbStorage::new();
        
        // Add some test SURBs (this would be done in tests)
        // For now, return empty storage
        storage
    }
    
    /// Validate SURB storage operations
    pub async fn validate_storage_ops(storage: &dyn SurbStorage) -> Result<bool> {
        // Test basic operations
        let count = storage.count().await?;
        
        // Get all IDs (should be empty for new storage)
        let ids = storage.get_all_ids().await?;
        
        // Validate consistency
        Ok(count == ids.len())
    }
    
    /// Export SURBs from storage
    pub async fn export_surbs(storage: &dyn SurbStorage) -> Result<Vec<ZksSurb>> {
        let ids = storage.get_all_ids().await?;
        let mut surbs = Vec::new();
        
        for id in ids {
            if let Some(surb) = storage.get_surb(&id).await? {
                surbs.push(surb);
            }
        }
        
        Ok(surbs)
    }
}