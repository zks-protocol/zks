//! Secure key shredding functionality
//! 
//! This module provides secure deletion of key material to prevent recovery.
//! It implements multi-pass overwriting with filesystem synchronization.

use crate::Result;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
#[cfg(test)]
use std::io::Read;

/// Secure shredder for key material
pub struct SecureShredder;

impl SecureShredder {
    /// Overwrite a range of bytes in a file with zeros, then random, then zeros.
    /// Syncs to disk after each pass for maximum security.
    pub fn shred_range(file: &mut File, start: u64, len: u64) -> Result<()> {
        // Pass 1: Zeros
        Self::overwrite_with(file, start, len, 0x00)?;
        file.sync_all()?;
        
        // Pass 2: Random
        let random: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
        Self::overwrite_with_slice(file, start, &random)?;
        file.sync_all()?;
        
        // Pass 3: Zeros (final)
        Self::overwrite_with(file, start, len, 0x00)?;
        file.sync_all()?;
        
        Ok(())
    }

    /// Overwrite a range with a single byte value
    fn overwrite_with(file: &mut File, start: u64, len: u64, value: u8) -> Result<()> {
        let data = vec![value; len as usize];
        Self::overwrite_with_slice(file, start, &data)
    }

    /// Overwrite a range with specific data
    fn overwrite_with_slice(file: &mut File, start: u64, data: &[u8]) -> Result<()> {
        file.seek(SeekFrom::Start(start))?;
        file.write_all(data)?;
        Ok(())
    }

    /// Securely shred an entire file
    pub fn shred_file(path: &std::path::Path) -> Result<()> {
        let metadata = std::fs::metadata(path)?;
        let file_size = metadata.len();
        
        let mut file = File::options()
            .read(true)
            .write(true)
            .open(path)?;
        
        Self::shred_range(&mut file, 0, file_size)?;
        
        // Remove the file after shredding
        drop(file);
        std::fs::remove_file(path)?;
        
        Ok(())
    }

    /// Verify that a range has been properly shredded (for testing)
    #[cfg(test)]
    pub fn verify_shredded(file: &mut File, start: u64, len: u64) -> Result<bool> {
        let mut data = vec![0u8; len as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut data)?;
        
        // Check if all bytes are zero (assuming final pass was zeros)
        Ok(data.iter().all(|&b| b == 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_shred_range() {
        // Create a temporary file with some data
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = vec![0xABu8; 1024];
        temp_file.write_all(&test_data).unwrap();
        temp_file.flush().unwrap();
        
        // Shred the first 512 bytes
        let mut file = temp_file.as_file_mut();
        SecureShredder::shred_range(&mut file, 0, 512).unwrap();
        
        // Verify the shredded portion is zeros
        assert!(SecureShredder::verify_shredded(&mut file, 0, 512).unwrap());
    }
}