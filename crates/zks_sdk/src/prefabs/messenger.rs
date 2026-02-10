//! # ZKS Secure Messenger
//!
//! High-level messaging abstraction over ZKS connections.

use crate::error::SdkError;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// High-level secure messenger for sending/receiving text messages
/// This is a simple wrapper that provides a channel-based interface
#[derive(Debug)]
pub struct SecureMessenger {
    incoming_rx: mpsc::Receiver<String>,
    outgoing_tx: mpsc::Sender<String>,
}

impl SecureMessenger {
    /// Create a new secure messenger from channel endpoints
    /// This approach allows the connection to remain on the same thread/task
    pub fn new(incoming_rx: mpsc::Receiver<String>, outgoing_tx: mpsc::Sender<String>) -> Self {
        Self {
            incoming_rx,
            outgoing_tx,
        }
    }

    /// Send a text message
    pub async fn send(&self, message: String) -> Result<(), SdkError> {
        debug!("Sending message: {}", message);
        self.outgoing_tx
            .send(message)
            .await
            .map_err(|_| SdkError::ConnectionFailed("Failed to send message".to_string()))?;
        Ok(())
    }

    /// Receive a text message (blocking)
    pub async fn recv(&mut self) -> Result<String, SdkError> {
        debug!("Waiting for message");
        self.incoming_rx
            .recv()
            .await
            .ok_or_else(|| SdkError::ConnectionFailed("Connection closed".to_string()))
    }

    /// Try to receive a text message (non-blocking)
    pub fn try_recv(&mut self) -> Result<String, SdkError> {
        self.incoming_rx.try_recv().map_err(|e| match e {
            mpsc::error::TryRecvError::Empty => SdkError::Timeout,
            mpsc::error::TryRecvError::Disconnected => {
                SdkError::ConnectionFailed("Connection closed".to_string())
            }
        })
    }

    /// Close the messenger
    pub fn close(&self) {
        info!("Closing messenger");
    }
}

/// Helper function to create a messenger from a ZKS connection
/// This function should be called from within the same task that owns the connection
/// and will return the messenger along with the channels needed for message processing
pub fn create_messenger_from_zks() -> (
    SecureMessenger,
    mpsc::Sender<String>,   // incoming_tx
    mpsc::Receiver<String>, // outgoing_rx
) {
    let (incoming_tx, incoming_rx) = mpsc::channel::<String>(100);
    let (outgoing_tx, outgoing_rx) = mpsc::channel::<String>(100);

    let messenger = SecureMessenger::new(incoming_rx, outgoing_tx);

    (messenger, incoming_tx, outgoing_rx)
}

impl Drop for SecureMessenger {
    fn drop(&mut self) {
        debug!("SecureMessenger dropped");
    }
}
