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
use tokio::sync::mpsc;
use tracing::error;

/// A stream that routes data through a Faisal Swarm circuit
pub struct OnionStream<S: SignalingClientTrait + 'static> {
    circuit_id: CircuitId,
    stream_id: u16,
    manager: Arc<FaisalSwarmManager<S>>,
    receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    read_buf: Vec<u8>,
    is_closed: bool,
}

impl<S: SignalingClientTrait> OnionStream<S> {
    /// Create a new onion stream for the specified circuit
    pub async fn new(
        manager: Arc<FaisalSwarmManager<S>>,
        circuit_id: CircuitId,
        stream_id: u16,
    ) -> Self {
        let receiver = manager.register_stream(circuit_id, stream_id).await;
        Self {
            circuit_id,
            stream_id,
            manager,
            receiver,
            read_buf: Vec::new(),
            is_closed: false,
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
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.is_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }

        let manager = self.manager.clone();
        let circuit_id = self.circuit_id;
        let stream_id = self.stream_id;
        let data = buf.to_vec();

        // Since send_stream_data is async, we need a way to poll it or spawn it.
        // CRITICAL NOTE: This is a simplified implementation. Proper backpressure
        // should be implemented in Phase 3.
        tokio::spawn(async move {
            if let Err(e) = manager.send_stream_data(circuit_id, stream_id, &data).await {
                error!("Failed to send stream data: {:?}", e);
            }
        });

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.is_closed = true;
        Poll::Ready(Ok(()))
    }
}
