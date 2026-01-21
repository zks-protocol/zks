//! Key file management for .zkskey files
//! 
//! This module handles the creation, reading, and management of key files
//! with offset tracking to prevent key reuse.

use crate::{OtpError, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

/// Header stored at the beginning of .zkskey files
#[derive(Debug, Clone)]
pub struct KeyFileHeader {
    /// Magic bytes: b"ZKSOTP01"
    pub magic: [u8; 8],
    /// File format version
    pub version: u16,
    /// Total bytes of key material available
    pub total_bytes: u64,
    /// Offset tracking (prevents reuse)
    pub used_bytes: u64,
    /// Unix timestamp of creation
    pub created_at: u64,
    /// SHA-256 checksum of entropy portion
    pub checksum: [u8; 32],
}

impl KeyFileHeader {
    /// Size of the header in bytes
    pub const SIZE: usize = 8 + 2 + 8 + 8 + 8 + 32; // 66 bytes

    /// Current version of the key file format
    pub const CURRENT_VERSION: u16 = 1;

    /// Create a new header with the given parameters
    pub fn new(total_bytes: u64, checksum: [u8; 32]) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            magic: *b"ZKSOTP01",
            version: Self::CURRENT_VERSION,
            total_bytes,
            used_bytes: 0,
            created_at,
            checksum,
        }
    }

    /// Serialize the header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);
        bytes.extend_from_slice(&self.magic);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.total_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.used_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.created_at.to_le_bytes());
        bytes.extend_from_slice(&self.checksum);
        bytes
    }

    /// Deserialize the header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(OtpError::corrupted("Header too short"));
        }

        let mut offset = 0;
        
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[offset..offset + 8]);
        offset += 8;

        if magic != *b"ZKSOTP01" {
            return Err(OtpError::corrupted("Invalid magic bytes"));
        }

        let mut version_bytes = [0u8; 2];
        version_bytes.copy_from_slice(&bytes[offset..offset + 2]);
        let version = u16::from_le_bytes(version_bytes);
        offset += 2;

        if version != Self::CURRENT_VERSION {
            return Err(OtpError::unsupported("Unsupported key file version"));
        }

        let mut total_bytes_bytes = [0u8; 8];
        total_bytes_bytes.copy_from_slice(&bytes[offset..offset + 8]);
        let total_bytes = u64::from_le_bytes(total_bytes_bytes);
        offset += 8;

        let mut used_bytes_bytes = [0u8; 8];
        used_bytes_bytes.copy_from_slice(&bytes[offset..offset + 8]);
        let used_bytes = u64::from_le_bytes(used_bytes_bytes);
        offset += 8;

        let mut created_at_bytes = [0u8; 8];
        created_at_bytes.copy_from_slice(&bytes[offset..offset + 8]);
        let created_at = u64::from_le_bytes(created_at_bytes);
        offset += 8;

        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&bytes[offset..offset + 32]);

        Ok(Self {
            magic,
            version,
            total_bytes,
            used_bytes,
            created_at,
            checksum,
        })
    }
}

/// Key file management structure
pub struct KeyFile {
    path: PathBuf,
    header: KeyFileHeader,
    file: File,
}

impl KeyFile {
    /// Create a new key file at the specified path
    pub fn create(path: &Path, size_bytes: u64) -> Result<Self> {
        // Validate size
        if size_bytes == 0 {
            return Err(OtpError::invalid("Key file size must be greater than 0"));
        }

        // Create the file
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| OtpError::io_error(format!("Failed to create key file: {}", e)))?;

        // Generate entropy for the key material
        let mut entropy = vec![0u8; size_bytes as usize];
        getrandom::fill(&mut entropy)
            .map_err(|e| OtpError::rng_error(format!("Failed to generate entropy: {}", e)))?;

        // Calculate checksum of the entropy
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&entropy);
        let checksum = hasher.finalize().into();

        // Create header
        let header = KeyFileHeader::new(size_bytes, checksum);

        // Write header to file
        let header_bytes = header.to_bytes();
        file.write_all(&header_bytes)
            .map_err(|e| OtpError::io_error(format!("Failed to write header: {}", e)))?;

        // Write entropy to file
        file.write_all(&entropy)
            .map_err(|e| OtpError::io_error(format!("Failed to write entropy: {}", e)))?;

        // Sync to disk for security
        file.sync_all()
            .map_err(|e| OtpError::io_error(format!("Failed to sync file: {}", e)))?;

        // Zeroize the entropy from memory
        entropy.zeroize();

        Ok(Self {
            path: path.to_path_buf(),
            header,
            file,
        })
    }

    /// Create a new key file with a custom RNG
    #[cfg(feature = "hardware-rng")]
    pub fn create_with_rng(
        path: &Path, 
        size_bytes: u64, 
        mut rng: Box<dyn crate::hardware_rng::HardwareRng>
    ) -> Result<Self> {
        // Validate size
        if size_bytes == 0 {
            return Err(OtpError::invalid("Key file size must be greater than 0"));
        }

        // Create the file
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| OtpError::io_error(format!("Failed to create key file: {}", e)))?;

        // Generate entropy using the provided RNG
        let mut entropy = vec![0u8; size_bytes as usize];
        rng.fill_bytes(&mut entropy)
            .map_err(|e| OtpError::rng_error(format!("Failed to generate entropy with hardware RNG: {}", e)))?;

        // Calculate checksum of the entropy
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&entropy);
        let checksum = hasher.finalize().into();

        // Create header
        let header = KeyFileHeader::new(size_bytes, checksum);

        // Write header to file
        let header_bytes = header.to_bytes();
        file.write_all(&header_bytes)
            .map_err(|e| OtpError::io_error(format!("Failed to write header: {}", e)))?;

        // Write entropy to file
        file.write_all(&entropy)
            .map_err(|e| OtpError::io_error(format!("Failed to write entropy: {}", e)))?;

        // Sync to disk for security
        file.sync_all()
            .map_err(|e| OtpError::io_error(format!("Failed to sync file: {}", e)))?;

        // Zeroize the entropy from memory
        entropy.zeroize();

        Ok(Self {
            path: path.to_path_buf(),
            header,
            file,
        })
    }

    /// Open an existing key file
    pub fn open(path: &Path) -> Result<Self> {
        // Open the file
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| OtpError::io_error(format!("Failed to open key file: {}", e)))?;

        // Read header
        let mut header_bytes = vec![0u8; KeyFileHeader::SIZE];
        file.read_exact(&mut header_bytes)
            .map_err(|e| OtpError::io_error(format!("Failed to read header: {}", e)))?;

        let header = KeyFileHeader::from_bytes(&header_bytes)?;

        // Verify file size matches header
        let metadata = file.metadata()
            .map_err(|e| OtpError::io_error(format!("Failed to get file metadata: {}", e)))?;
        
        let expected_size = KeyFileHeader::SIZE as u64 + header.total_bytes;
        if metadata.len() != expected_size {
            return Err(OtpError::corrupted(format!(
                "File size mismatch: expected {}, got {}",
                expected_size,
                metadata.len()
            )));
        }

        // Verify checksum of entropy portion
        let mut entropy = vec![0u8; header.total_bytes as usize];
        file.seek(SeekFrom::Start(KeyFileHeader::SIZE as u64))
            .map_err(|e| OtpError::io_error(format!("Failed to seek to entropy: {}", e)))?;
        file.read_exact(&mut entropy)
            .map_err(|e| OtpError::io_error(format!("Failed to read entropy: {}", e)))?;

        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&entropy);
        let calculated_checksum: [u8; 32] = hasher.finalize().into();

        if header.checksum != calculated_checksum {
            return Err(OtpError::corrupted("Entropy checksum mismatch"));
        }

        // Zeroize the entropy from memory
        entropy.zeroize();

        Ok(Self {
            path: path.to_path_buf(),
            header,
            file,
        })
    }

    /// Read entropy from the key file
    pub fn read_entropy(&mut self, len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Err(OtpError::invalid("Cannot read 0 bytes of entropy"));
        }

        let remaining = self.remaining();
        if len as u64 > remaining {
            return Err(OtpError::key_exhausted(format!(
                "Requested {} bytes, but only {} bytes remaining",
                len, remaining
            )));
        }

        // Seek to the current offset
        let offset = KeyFileHeader::SIZE as u64 + self.header.used_bytes;
        self.file.seek(SeekFrom::Start(offset))
            .map_err(|e| OtpError::io_error(format!("Failed to seek to entropy: {}", e)))?;

        // Read the entropy
        let mut entropy = vec![0u8; len];
        self.file.read_exact(&mut entropy)
            .map_err(|e| OtpError::io_error(format!("Failed to read entropy: {}", e)))?;

        Ok(entropy)
    }

    /// Mark a portion of the key as used
    pub fn mark_used(&mut self, len: usize) -> Result<()> {
        if len == 0 {
            return Err(OtpError::invalid("Cannot mark 0 bytes as used"));
        }

        let remaining = self.remaining();
        if len as u64 > remaining {
            return Err(OtpError::key_exhausted(format!(
                "Tried to use {} bytes, but only {} bytes remaining",
                len, remaining
            )));
        }

        // Update the header
        self.header.used_bytes += len as u64;

        // Seek to the header position
        self.file.seek(SeekFrom::Start(0))
            .map_err(|e| OtpError::io_error(format!("Failed to seek to header: {}", e)))?;

        // Write the updated header
        let header_bytes = self.header.to_bytes();
        self.file.write_all(&header_bytes)
            .map_err(|e| OtpError::io_error(format!("Failed to write updated header: {}", e)))?;

        // Sync to disk for security
        self.file.sync_all()
            .map_err(|e| OtpError::io_error(format!("Failed to sync file: {}", e)))?;

        Ok(())
    }

    /// Get remaining key material
    pub fn remaining(&self) -> u64 {
        self.header.total_bytes.saturating_sub(self.header.used_bytes)
    }

    /// Get the key file path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the key file header
    pub fn header(&self) -> &KeyFileHeader {
        &self.header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_key_file_creation_and_opening() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test_key.zkskey");

        // Create a key file
        let key_file = KeyFile::create(&path, 1024).unwrap();
        assert_eq!(key_file.header().total_bytes, 1024);
        assert_eq!(key_file.header().used_bytes, 0);
        assert_eq!(key_file.remaining(), 1024);

        // Open the key file
        let opened_key_file = KeyFile::open(&path).unwrap();
        assert_eq!(opened_key_file.header().total_bytes, 1024);
        assert_eq!(opened_key_file.header().used_bytes, 0);
        assert_eq!(opened_key_file.remaining(), 1024);
    }

    #[test]
    fn test_entropy_reading_and_usage_tracking() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test_entropy.zkskey");

        let mut key_file = KeyFile::create(&path, 1024).unwrap();

        // Read some entropy
        let entropy1 = key_file.read_entropy(100).unwrap();
        assert_eq!(entropy1.len(), 100);
        assert_eq!(key_file.remaining(), 1024);

        // Mark it as used
        key_file.mark_used(100).unwrap();
        assert_eq!(key_file.remaining(), 924);

        // Read more entropy
        let entropy2 = key_file.read_entropy(200).unwrap();
        assert_eq!(entropy2.len(), 200);
        key_file.mark_used(200).unwrap();
        assert_eq!(key_file.remaining(), 724);

        // Verify entropy is different
        assert_ne!(entropy1, entropy2);
    }

    #[test]
    fn test_key_exhaustion() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test_exhaustion.zkskey");

        let mut key_file = KeyFile::create(&path, 100).unwrap();

        // Use all the key material
        key_file.read_entropy(100).unwrap();
        key_file.mark_used(100).unwrap();
        assert_eq!(key_file.remaining(), 0);

        // Try to read more - should fail
        let result = key_file.read_entropy(1);
        assert!(matches!(result, Err(OtpError::InsufficientKeyMaterial { .. })));

        // Try to mark more as used - should fail
        let result = key_file.mark_used(1);
        assert!(matches!(result, Err(OtpError::InsufficientKeyMaterial { .. })));
    }

    #[test]
    fn test_checksum_validation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test_checksum.zkskey");

        // Create a key file
        KeyFile::create(&path, 1024).unwrap();

        // Corrupt the file by modifying some bytes
        let mut file = OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap();
        
        // Seek past the header and corrupt some entropy
        file.seek(SeekFrom::Start(KeyFileHeader::SIZE as u64 + 100)).unwrap();
        file.write_all(&[0xFF; 10]).unwrap();

        // Try to open the corrupted file - should fail
        let result = KeyFile::open(&path);
        assert!(matches!(result, Err(OtpError::KeyFileCorrupted(_))));
    }
}