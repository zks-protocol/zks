//! OnionStream for Faisal Swarm
//!
//! Provides an AsyncRead/AsyncWrite interface for data transfer over a Faisal Swarm circuit.

use crate::faisal_swarm::circuit_manager::FaisalSwarmManager;
use crate::faisal_swarm::CircuitId;
use crate::signaling::SignalingClientTrait;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tracing::{error, warn};

/// A stream that routes data through a Faisal Swarm circuit
pub struct OnionStream<S: SignalingClientTrait + 'static> {
    circuit_id: CircuitId,
    stream_id: u16,
    manager: Arc<FaisalSwarmManager<S>>,
    receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    read_buf: Vec<u8>,
    is_closed: bool,
    /// Channel for write operations with bounded capacity (backpressure)
    write_sender: mpsc::Sender<WriteOp>,
    /// Pending write result for poll_write to check
    pending_result: Arc<TokioMutex<Option<std::io::Result<()>>>>,
    /// Flag indicating if a write is in progress
    write_in_progress: Arc<TokioMutex<bool>>,
}

/// Write operation data
struct WriteOp {
    data: Vec<u8>,
    result_tx: tokio::sync::oneshot::Sender<std::io::Result<()>>,
}

impl<S: SignalingClientTrait> OnionStream<S> {
    /// Create a new onion stream for the specified circuit
    pub async fn new(
        manager: Arc<FaisalSwarmManager<S>>,
        circuit_id: CircuitId,
        stream_id: u16,
    ) -> Self {
        Self::with_capacity(manager, circuit_id, stream_id, 64).await
    }

    /// Create a new onion stream with custom write capacity
    pub async fn with_capacity(
        manager: Arc<FaisalSwarmManager<S>>,
        circuit_id: CircuitId,
        stream_id: u16,
        write_capacity: usize,
    ) -> Self {
        let receiver = manager.register_stream(circuit_id, stream_id).await;
        let (write_sender, mut write_receiver) = mpsc::channel::<WriteOp>(write_capacity);

        // Spawn a task to handle write operations
        let manager_clone = manager.clone();
        let pending_result: Arc<TokioMutex<Option<std::io::Result<()>>>> = Arc::new(TokioMutex::new(None));
        let write_in_progress: Arc<TokioMutex<bool>> = Arc::new(TokioMutex::new(false));
        let pending_result_for_task = pending_result.clone();

        tokio::spawn(async move {
            while let Some(WriteOp { data, result_tx }) = write_receiver.recv().await {
                match manager_clone.send_stream_data(circuit_id, stream_id, &data).await {
                    Ok(_) => {
                        *pending_result_for_task.lock().await = Some(Ok(()));
                        let _ = result_tx.send(Ok(()));
                    }
                    Err(e) => {
                        error!("Failed to send stream data: {:?}", e);
                        let err = std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            format!("Send failed: {:?}", e),
                        );
                        *pending_result_for_task.lock().await = Some(Err(
                            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "Send failed")
                        ));
                        let _ = result_tx.send(Err(err));
                    }
                }
            }
        });

        Self {
            circuit_id,
            stream_id,
            manager,
            receiver,
            read_buf: Vec::new(),
            is_closed: false,
            write_sender,
            pending_result,
            write_in_progress,
        }
    }

    /// Get the circuit ID this stream is associated with
    pub fn circuit_id(&self) -> CircuitId {
        self.circuit_id
    }

    /// Get the stream ID
    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }
}

impl<S: SignalingClientTrait + 'static> Drop for OnionStream<S> {
    fn drop(&mut self) {
        // Unregister stream from manager when dropped
        let manager = self.manager.clone();
        let circuit_id = self.circuit_id;
        let stream_id = self.stream_id;

        tokio::spawn(async move {
            manager.unregister_stream(circuit_id, stream_id).await;
        });
    }
}

impl<S: SignalingClientTrait> AsyncRead for OnionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.is_closed {
            return Poll::Ready(Ok(()));
        }

        // 1. If we have data in the read_buf, use it
        if !self.read_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), self.read_buf.len());
            buf.put_slice(&self.read_buf[..n]);
            self.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        // 2. Otherwise, poll the receiver
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..n]);
                if data.len() > n {
                    self.read_buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.is_closed = true;
                Poll::Ready(Ok(())) // EOF
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: SignalingClientTrait + 'static> AsyncWrite for OnionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.is_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }

        // Check if we need to wait for space in the channel
        let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
        let data = buf.to_vec();

        // Try to send write request with bounded channel (backpressure)
        match self.write_sender.try_send(WriteOp {
            data,
            result_tx,
        }) {
            Ok(_) => {
                // Successfully queued write, we assume success for the AsyncWrite contract
                // The actual result is tracked for next poll or can be ignored
                Poll::Ready(Ok(buf.len()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel is full - implement backpressure
                // Register waker to be notified when space is available
                // We can't await in poll_write, so we return Pending
                // The write task will process items and free up space
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Channel is closed
                warn!("Write channel closed for circuit {}", self.circuit_id);
                Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // For bounded channel, flush means wait for all queued items to be processed
        // This is expensive, so we just return Ok for now
        // A proper implementation would track pending writes
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.is_closed = true;
        // Dropping the sender closes the channel, signaling the write task to stop
        // We can't drop self.write_sender here since we only have &mut self,
        // but marking is_closed ensures no new writes are accepted
        Poll::Ready(Ok(()))
    }
}
