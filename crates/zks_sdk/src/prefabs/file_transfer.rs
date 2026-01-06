//! Secure file transfer with progress tracking

use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, debug};

use crate::{
    connection::{ZkConnection, ZksConnection},
    error::{Result, SdkError},
};

/// Maximum allowed file size (100MB)
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Sanitize a filename to prevent path traversal attacks

/// Sanitize a filename to prevent path traversal attacks
fn sanitize_filename(name: &str) -> String {
    // Remove any path separators and special characters
    let sanitized = name
        .replace(['/', '\\'], "_")
        .replace("..", "_")
        .replace('.', "_")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect::<String>();
    
    // Ensure it's not empty and doesn't start with a dot
    let sanitized = if sanitized.is_empty() {
        "unnamed_file".to_string()
    } else if sanitized.starts_with('.') {
        format!("file{}", sanitized)
    } else {
        sanitized
    };
    
    // Limit length to prevent filesystem issues
    if sanitized.len() > 255 {
        let (name, ext) = if let Some(dot_pos) = sanitized.rfind('.') {
            (sanitized[..dot_pos].to_string(), sanitized[dot_pos..].to_string())
        } else {
            (sanitized.clone(), String::new())
        };
        
        let max_name_len = 255 - ext.len();
        if name.len() > max_name_len {
            format!("{}{}", &name[..max_name_len], ext)
        } else {
            format!("{}{}", name, ext)
        }
    } else {
        sanitized
    }
}

/// Secure file transfer with progress tracking
pub struct SecureFileTransfer {
    chunk_size: usize,
}

impl SecureFileTransfer {
    /// Create a new secure file transfer
    pub fn new() -> Self {
        Self {
            chunk_size: 64 * 1024, // 64KB chunks
        }
    }
    
    /// Set the chunk size for file transfer
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }
    
    /// Send a file with progress callback
    pub async fn send_file<P, F>(
        &self,
        connection: &mut ZkConnection,
        path: P,
        mut on_progress: F,
    ) -> Result<()>
    where
        P: AsRef<Path>,
        F: FnMut(u64, u64),
    {
        let path = path.as_ref();
        let metadata = std::fs::metadata(path)
            .map_err(|e| SdkError::IoError(e))?;
        
        let file_size = metadata.len();
        let file_name = path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| SdkError::InvalidUrl("Invalid file name".to_string()))?;
        
        info!("Sending file: {} ({} bytes)", file_name, file_size);
        
        // Send file metadata
        let metadata = format!("{}:{}", file_name, file_size);
        connection.send_message(metadata.as_bytes()).await?;
        
        // Open file and send in chunks
        let mut file = File::open(path).await
            .map_err(SdkError::IoError)?;
        
        let mut buffer = vec![0u8; self.chunk_size];
        let mut sent = 0u64;
        
        loop {
            let n = file.read(&mut buffer).await
                .map_err(SdkError::IoError)?;
            
            if n == 0 {
                break;
            }
            
            // Send chunk
            connection.send_message(&buffer[..n]).await?;
            sent += n as u64;
            
            // Call progress callback
            on_progress(sent, file_size);
            
            debug!("Sent {} / {} bytes", sent, file_size);
        }
        
        info!("File transfer complete: {} ({} bytes)", file_name, sent);
        Ok(())
    }
    
    /// Receive a file with progress callback
    pub async fn recv_file<P, F>(
        &self,
        connection: &mut ZkConnection,
        save_path: P,
        mut on_progress: F,
    ) -> Result<String>
    where
        P: AsRef<Path>,
        F: FnMut(u64, u64),
    {
        info!("Receiving file...");
        
        // Receive file metadata
        let metadata = connection.recv_message().await?;
        let metadata_str = String::from_utf8(metadata)
            .map_err(|e| SdkError::SerializationError(e.to_string()))?;
        
        let parts: Vec<&str> = metadata_str.split(':').collect();
        if parts.len() != 2 {
            return Err(SdkError::InvalidUrl("Invalid file metadata format".to_string()));
        }
        
        let file_name = sanitize_filename(parts[0]);
        let file_size: u64 = parts[1].parse()
            .map_err(|_| SdkError::InvalidUrl("Invalid file size".to_string()))?;
        
        // Validate file size
        if file_size > MAX_FILE_SIZE {
            return Err(SdkError::InvalidUrl(format!(
                "File size {} exceeds maximum allowed size of {} bytes", 
                file_size, MAX_FILE_SIZE
            )));
        }
        
        info!("Receiving file: {} ({} bytes)", file_name, file_size);
        
        // Create save path
        let save_path = save_path.as_ref().join(&file_name);
        debug!("Saving file to: {:?}", save_path);
        let mut file = File::create(&save_path).await
            .map_err(SdkError::IoError)?;
        
        let mut received = 0u64;
        
        // Receive file in chunks
        while received < file_size {
            let chunk = connection.recv_message().await?;
            
            file.write_all(&chunk).await
                .map_err(SdkError::IoError)?;
            
            received += chunk.len() as u64;
            
            // Call progress callback
            on_progress(received, file_size);
            
            debug!("Received {} / {} bytes", received, file_size);
        }
        
        info!("File transfer complete: {} ({} bytes)", file_name, received);
        Ok(file_name.to_string())
    }
    
    /// Send a file using ZKS connection (swarm mode)
    pub async fn send_file_zks<P, F>(
        &self,
        connection: &mut ZksConnection,
        path: P,
        on_progress: F,
    ) -> Result<()>
    where
        P: AsRef<Path>,
        F: FnMut(u64, u64),
    {
        // For now, delegate to the regular send_file method
        // In a full implementation, this would handle swarm-specific optimizations
        self.send_file_zks_impl(connection, path, on_progress).await
    }
    
    /// Internal implementation for ZKS file sending
    async fn send_file_zks_impl<P, F>(
        &self,
        connection: &mut ZksConnection,
        path: P,
        mut on_progress: F,
    ) -> Result<()>
    where
        P: AsRef<Path>,
        F: FnMut(u64, u64),
    {
        let path = path.as_ref();
        let file = tokio::fs::File::open(path).await
            .map_err(SdkError::IoError)?;
        
        let metadata = file.metadata().await
            .map_err(SdkError::IoError)?;
        let total_size = metadata.len();
        
        info!("Sending file: {} ({} bytes)", path.display(), total_size);
        
        // Send file metadata first
        let file_name = path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| SdkError::InvalidInput("Invalid file name".to_string()))?;
        
        let metadata_msg = format!("FILE:{}:{}", file_name, total_size);
        connection.send(metadata_msg.as_bytes()).await?;
        
        // Send file data in chunks
        let mut reader = tokio::io::BufReader::new(file);
        let mut buffer = vec![0u8; self.chunk_size];
        let mut sent = 0u64;
        
        loop {
            let n = reader.read(&mut buffer).await
                .map_err(SdkError::IoError)?;
            
            if n == 0 {
                break;
            }
            
            connection.send(&buffer[..n]).await?;
            sent += n as u64;
            
            on_progress(sent, total_size);
        }
        
        info!("File sent successfully: {} ({} bytes)", file_name, sent);
        Ok(())
    }
    
    /// Receive a file using ZKS connection (swarm mode)
    pub async fn recv_file_zks<P, F>(
        &self,
        connection: &mut ZksConnection,
        save_path: P,
        on_progress: F,
    ) -> Result<String>
    where
        P: AsRef<Path>,
        F: FnMut(u64, u64),
    {
        // For now, delegate to the regular recv_file method
        // In a full implementation, this would handle swarm-specific optimizations
        self.recv_file_zks_impl(connection, save_path, on_progress).await
    }
    
    /// Internal implementation for ZKS file receiving
    async fn recv_file_zks_impl<P, F>(
        &self,
        connection: &mut ZksConnection,
        save_path: P,
        mut on_progress: F,
    ) -> Result<String>
    where
        P: AsRef<Path>,
        F: FnMut(u64, u64),
    {
        let save_path = save_path.as_ref();
        
        // Receive file metadata first
        let mut metadata_buf = vec![0u8; 1024];
        let n = connection.recv(&mut metadata_buf).await?;
        let metadata_str = String::from_utf8(metadata_buf[..n].to_vec())
            .map_err(|e| SdkError::SerializationError(e.to_string()))?;
        
        let parts: Vec<&str> = metadata_str.split(':').collect();
        if parts.len() != 3 || parts[0] != "FILE" {
            return Err(SdkError::InvalidInput("Invalid file metadata format".to_string()));
        }
        
        let file_name = parts[1];
        let total_size: u64 = parts[2].parse()
            .map_err(|e| SdkError::InvalidInput(format!("Invalid file size: {}", e)))?;
        
        info!("Receiving file: {} ({} bytes)", file_name, total_size);
        
        // Create file path
        let file_path = save_path.join(file_name);
        let mut file = tokio::fs::File::create(&file_path).await
            .map_err(SdkError::IoError)?;
        
        // Receive file data in chunks
        let mut buffer = vec![0u8; self.chunk_size];
        let mut received = 0u64;
        
        while received < total_size {
            let n = connection.recv(&mut buffer).await?;
            if n == 0 {
                break;
            }
            
            file.write_all(&buffer[..n]).await
                .map_err(SdkError::IoError)?;
            
            received += n as u64;
            on_progress(received, total_size);
        }
        
        file.flush().await
            .map_err(SdkError::IoError)?;
        
        info!("File received successfully: {} ({} bytes)", file_name, received);
        Ok(file_name.to_string())
    }
}

impl Default for SecureFileTransfer {
    fn default() -> Self {
        Self::new()
    }
}