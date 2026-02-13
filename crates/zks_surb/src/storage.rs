use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::Result;
use crate::surb::{SurbId, ZksSurb};

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
    async fn store_surb(&self, surb: ZksSurb) -> Result<()> {
        let id_hex = surb.id().to_hex();
        let file_path = std::path::Path::new(&self.path).join(format!("{}.surb", id_hex));

        // Ensure directory exists
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                crate::error::SurbError::StorageError(format!("Failed to create directory: {}", e))
            })?;
        }

        let bytes = surb.to_bytes()?;
        tokio::fs::write(file_path, bytes).await.map_err(|e| {
            crate::error::SurbError::StorageError(format!("Failed to write SURB: {}", e))
        })?;

        Ok(())
    }

    async fn get_surb(&self, id: &SurbId) -> Result<Option<ZksSurb>> {
        let id_hex = id.to_hex();
        let file_path = std::path::Path::new(&self.path).join(format!("{}.surb", id_hex));

        if !file_path.exists() {
            return Ok(None);
        }

        let bytes = tokio::fs::read(file_path).await.map_err(|e| {
            crate::error::SurbError::StorageError(format!("Failed to read SURB: {}", e))
        })?;

        let surb = ZksSurb::from_bytes(&bytes)?;
        Ok(Some(surb))
    }

    async fn remove_surb(&self, id: &SurbId) -> Result<()> {
        let id_hex = id.to_hex();
        let file_path = std::path::Path::new(&self.path).join(format!("{}.surb", id_hex));

        if file_path.exists() {
            tokio::fs::remove_file(file_path).await.map_err(|e| {
                crate::error::SurbError::StorageError(format!("Failed to remove SURB: {}", e))
            })?;
        }

        Ok(())
    }

    async fn has_surb(&self, id: &SurbId) -> Result<bool> {
        let id_hex = id.to_hex();
        let file_path = std::path::Path::new(&self.path).join(format!("{}.surb", id_hex));
        Ok(file_path.exists())
    }

    async fn get_all_ids(&self) -> Result<Vec<SurbId>> {
        let mut ids = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.path).await.map_err(|e| {
            crate::error::SurbError::StorageError(format!("Failed to read directory: {}", e))
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            crate::error::SurbError::StorageError(format!("Failed to read entry: {}", e))
        })? {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("surb") {
                if let Some(file_stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(id_bytes) = hex::decode(file_stem) {
                        ids.push(SurbId::from_bytes(id_bytes));
                    }
                }
            }
        }

        Ok(ids)
    }

    async fn count(&self) -> Result<usize> {
        let ids = self.get_all_ids().await?;
        Ok(ids.len())
    }

    async fn clear(&self) -> Result<()> {
        let mut entries = tokio::fs::read_dir(&self.path).await.map_err(|e| {
            crate::error::SurbError::StorageError(format!("Failed to read directory: {}", e))
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            crate::error::SurbError::StorageError(format!("Failed to read entry: {}", e))
        })? {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("surb") {
                tokio::fs::remove_file(path).await.map_err(|e| {
                    crate::error::SurbError::StorageError(format!("Failed to remove file: {}", e))
                })?;
            }
        }

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
