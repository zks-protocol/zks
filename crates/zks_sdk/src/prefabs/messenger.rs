//! Secure messenger for encrypted text communication

use tokio::sync::mpsc;
use tracing::{info, debug, warn};

use crate::{
    connection::{ZkConnection, ZksConnection},
    error::{Result, SdkError},
};

/// A secure messenger for encrypted text communication
pub struct SecureMessenger {
    incoming_rx: mpsc::Receiver<String>,
    outgoing_tx: mpsc::Sender<String>,
}

/// Message types for the secure messenger
#[derive(Debug, Clone)]
pub enum Message {
    /// Regular text message
    Text(String),
    
    /// System notification
    System(String),
    
    /// File transfer notification
    FileTransfer { name: String, size: u64 },
}

impl SecureMessenger {
    /// Create a new secure messenger from a ZK connection
    pub fn from_zk(mut connection: ZkConnection) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel::<String>(100);
        let (outgoing_tx, outgoing_rx) = mpsc::channel::<String>(100);
        
        // Spawn task to handle both incoming and outgoing messages
        tokio::spawn(async move {
            let mut outgoing_rx = outgoing_rx;
            loop {
                tokio::select! {
                    // Handle incoming messages
                    result = connection.recv_message() => {
                        match result {
                            Ok(data) => {
                                match String::from_utf8(data) {
                                    Ok(text) => {
                                        if let Err(_) = incoming_tx.send(text).await {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Received invalid UTF-8 message: {}", e);
                                        // Optionally, you could send a notification about invalid messages
                                        // or implement a different encoding scheme
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to receive message: {}", e);
                                break;
                            }
                        }
                    }
                    // Handle outgoing messages
                    Some(message) = outgoing_rx.recv() => {
                        if let Err(e) = connection.send_message(message.as_bytes()).await {
                            warn!("Failed to send message: {}", e);
                            break;
                        }
                    }
                    else => break,
                }
            }
        });
        
        Self {
            incoming_rx,
            outgoing_tx,
        }
    }
    
    /// Create a new secure messenger from a ZKS connection
    pub fn from_zks(mut connection: ZksConnection) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel::<String>(100);
        let (outgoing_tx, outgoing_rx) = mpsc::channel::<String>(100);
        
        // Spawn task to handle both incoming and outgoing messages
        tokio::spawn(async move {
            let mut outgoing_rx = outgoing_rx;
            loop {
                tokio::select! {
                    // Handle incoming messages
                    result = connection.recv_message() => {
                        match result {
                            Ok(data) => {
                                if let Ok(text) = String::from_utf8(data) {
                                    if let Err(_) = incoming_tx.send(text).await {
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to receive message: {}", e);
                                break;
                            }
                        }
                    }
                    // Handle outgoing messages
                    Some(message) = outgoing_rx.recv() => {
                        if let Err(e) = connection.send_message(message.as_bytes()).await {
                            warn!("Failed to send message: {}", e);
                            break;
                        }
                    }
                    else => break,
                }
            }
        });
        
        Self {
            incoming_rx,
            outgoing_tx,
        }
    }
    
    /// Send a text message
    pub async fn send_text(&self, message: &str) -> Result<()> {
        self.outgoing_tx.send(message.to_string()).await
            .map_err(|_| SdkError::ConnectionFailed("Messenger closed".to_string()))?;
        
        debug!("Sent text message: {}", message);
        Ok(())
    }
    
    /// Receive a text message (blocking)
    pub async fn recv_text(&mut self) -> Result<String> {
        self.incoming_rx.recv().await
            .ok_or_else(|| SdkError::ConnectionFailed("Messenger closed".to_string()))
    }
    
    /// Try to receive a text message (non-blocking)
    pub fn try_recv_text(&mut self) -> Result<Option<String>> {
        match self.incoming_rx.try_recv() {
            Ok(message) => Ok(Some(message)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(SdkError::ConnectionFailed("Messenger closed".to_string()))
            }
        }
    }
    
    /// Send a system message
    pub async fn send_system(&self, message: &str) -> Result<()> {
        let system_msg = format!("SYSTEM: {}", message);
        self.send_text(&system_msg).await
    }
    
    /// Get the number of pending incoming messages
    pub fn pending_messages(&self) -> usize {
        self.incoming_rx.len()
    }
    
    /// Close the messenger
    pub async fn close(self) -> Result<()> {
        info!("Closing secure messenger");
        // The spawned tasks will exit when the channels are dropped
        Ok(())
    }
}

