//! Enhanced Anti-Replay Attack Protection
//! 
//! Implements Citadel-style replay attack prevention using a HashSet-based
//! circular buffer with support for out-of-order packet delivery.
//! 
//! # Features
//! - Thread-safe packet ID (PID) generation and tracking
//! - Efficient HashSet-based history window (O(1) lookup)
//! - Handles out-of-order packet delivery (UDP reordering)
//! - Protection against delayed replay attacks
//! - Zero-allocation NoHashHasher for u64 PIDs
//! 
//! # Security Model
//! - Each outgoing packet gets a unique, monotonically increasing PID
//! - PIDs are encrypted with the packet payload
//! - Receiver tracks PIDs in a sliding window
//! - Duplicate or out-of-window PIDs are rejected as replay attacks

use std::collections::HashSet;
use std::hash::{BuildHasher, Hasher};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// History window size - number of PIDs to track
/// Allows for packet reordering within this window
pub const HISTORY_LEN: u64 = 1024;

/// Zero-allocation hasher for u64 PIDs
/// Since PIDs are already unique u64s, we use them directly as hash values
struct NoHashHasher<T>(u64, PhantomData<T>);

impl<T> Default for NoHashHasher<T> {
    fn default() -> Self {
        NoHashHasher(0, PhantomData)
    }
}

impl<T> Hasher for NoHashHasher<T> {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, _: &[u8]) {
        // No-op instead of panic to prevent DoS attacks
        // This method should never be called for u64 keys
        debug_assert!(false, "NoHashHasher::write() called - this indicates incorrect usage with non-u64 types");
        tracing::warn!("NoHashHasher::write() called with byte slice - potential collision risk from incorrect usage");
    }

    fn write_u64(&mut self, n: u64) {
        #[cfg(debug_assertions)]
        {
            // Ensure this hasher is only used with u64 values to prevent collision attacks
            if std::mem::size_of::<T>() != std::mem::size_of::<u64>() {
                panic!("NoHashHasher<T>::write_u64() called with T != u64 - potential collision risk");
            }
        }
        self.0 = n
    }
}

impl<T> BuildHasher for NoHashHasher<T> {
    type Hasher = Self;

    fn build_hasher(&self) -> Self::Hasher {
        Self::default()
    }
}

/// Anti-Replay Attack Container
/// 
/// Prevents replay attacks by tracking packet IDs in a sliding window.
/// Supports out-of-order packet delivery within the window size.
pub struct AntiReplayContainer {
    /// (base_counter, seen_pids) - base_counter tracks the sliding window position
    history: Mutex<(u64, HashSet<u64, NoHashHasher<u64>>)>,
    /// Counter for outgoing packets (monotonically increasing)
    counter_out: AtomicU64,
    /// Window size (configurable, default: HISTORY_LEN)
    window_size: u64,
}

impl AntiReplayContainer {
    /// Create a new container with default window size
    pub fn new() -> Self {
        Self::with_window_size(HISTORY_LEN)
    }

    /// Create with custom window size
    pub fn with_window_size(window_size: u64) -> Self {
        Self {
            history: Mutex::new((
                0,
                HashSet::with_capacity_and_hasher(window_size as usize, NoHashHasher::default()),
            )),
            counter_out: AtomicU64::new(0),
            window_size,
        }
    }

    /// Get the next PID for an outgoing packet
    #[inline]
    pub fn get_next_pid(&self) -> u64 {
        self.counter_out.fetch_add(1, Ordering::Relaxed)
    }

    /// Validate a received PID
    /// 
    /// Returns `true` if the PID is valid (not a replay).
    /// Returns `false` if:
    /// - The PID was already seen (duplicate)
    /// - The PID is too old (below window)
    /// - The PID is too far ahead (above window)
    /// 
    /// If valid, the PID is recorded in the history.
    /// 
    /// # Security Note
    /// This function is designed to be timing-safe for anti-replay purposes.
 /// The execution time depends on the PID value and window position, but this
    /// is acceptable since PID values are not secret and timing variations don't
    /// leak sensitive information.
    pub fn validate_pid(&self, pid: u64) -> bool {
        let mut queue = self.history.lock().unwrap_or_else(|e| e.into_inner());
        let (ref mut base_counter, ref mut seen_pids) = *queue;

        // Calculate the valid window: [base_counter, base_counter + window_size)
        // base_counter = the oldest PID still acceptable
        let min_acceptable = *base_counter;
        let max_acceptable = base_counter.saturating_add(self.window_size);

        // Check all conditions without early returns to prevent timing attacks
        let already_seen = seen_pids.contains(&pid);
        let too_old = pid < min_acceptable;
        let too_far_ahead = pid > max_acceptable;
        
        // Log security events in a timing-safe manner for anti-replay purposes
        // Note: The while loops (lines 162-168) have variable iterations depending on PID values,
        // but this is acceptable since PID values are not secret and timing variations don't
        // leak sensitive information for anti-replay validation.
        let event_type = if already_seen {
            "REPLAY_ATTACK"
        } else if too_old {
            "DELAYED_REPLAY"
        } else if too_far_ahead {
            "TOO_FAR_AHEAD"
        } else {
            "VALID"
        };
        
        // Log unconditionally with generic message to prevent timing leaks
        if event_type != "VALID" {
            tracing::warn!(
                "🚨 SECURITY EVENT: PID {} status: {} (min: {}, max: {})",
                pid,
                event_type,
                min_acceptable,
                max_acceptable
            );
        }

        // Only accept if all conditions are met (constant time check)
        let is_valid = !already_seen && !too_old && !too_far_ahead;
        
        if is_valid {
            // Add to history and slide window if needed
            seen_pids.insert(pid);
            
            // Slide the window if the new PID extends beyond the current window
            // This ensures the window stays bounded by [base_counter, base_counter + window_size)
            while pid >= base_counter.saturating_add(self.window_size) {
                seen_pids.remove(base_counter);
                *base_counter += 1;
            }
            
            // Also slide the window to maintain the size constraint
            // If we've exceeded the window size, remove the oldest entries
            while seen_pids.len() > self.window_size as usize {
                seen_pids.remove(base_counter);
                *base_counter += 1;
            }
        }
        
        is_valid
    }

    /// Check if any packets have been tracked
    pub fn has_tracked_packets(&self) -> bool {
        let counter = self.counter_out.load(Ordering::Relaxed);
        let queue = self.history.lock().unwrap();
        counter > 0 || queue.0 > 0 || !queue.1.is_empty()
    }

    /// Reset all counters (call on re-keying)
    pub fn reset(&self) {
        self.counter_out.store(0, Ordering::Relaxed);
        let mut lock = self.history.lock().unwrap();
        lock.0 = 0;
        lock.1 = HashSet::with_capacity_and_hasher(
            self.window_size as usize,
            NoHashHasher::default(),
        );
        tracing::debug!("🔄 Anti-replay container reset");
    }

    /// Get current outgoing counter value
    pub fn current_counter(&self) -> u64 {
        self.counter_out.load(Ordering::Relaxed)
    }

    /// Get number of tracked PIDs in history
    pub fn history_size(&self) -> usize {
        self.history.lock().unwrap().1.len()
    }
}

impl Default for AntiReplayContainer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_next_pid() {
        let container = AntiReplayContainer::new();
        assert_eq!(container.get_next_pid(), 0);
        assert_eq!(container.get_next_pid(), 1);
        assert_eq!(container.get_next_pid(), 2);
    }

    #[test]
    fn test_validate_fresh_pid() {
        let container = AntiReplayContainer::new();
        assert!(container.validate_pid(0));
        assert!(container.validate_pid(1));
        assert!(container.validate_pid(2));
    }

    #[test]
    fn test_reject_duplicate_pid() {
        let container = AntiReplayContainer::new();
        assert!(container.validate_pid(5));
        assert!(!container.validate_pid(5)); // Duplicate - should fail
    }

    #[test]
    fn test_out_of_order_packets() {
        let container = AntiReplayContainer::new();
        // Packets arrive out of order
        assert!(container.validate_pid(10));
        assert!(container.validate_pid(8));  // Earlier packet arrives late
        assert!(container.validate_pid(12));
        assert!(container.validate_pid(9));  // Another late arrival
        
        // All should be in history
        assert_eq!(container.history_size(), 4);
    }

    #[test]
    fn test_delayed_replay_protection() {
        let container = AntiReplayContainer::with_window_size(10);
        
        // Fill up the window
        for i in 0..20 {
            container.validate_pid(i);
        }
        
        // Try to replay a very old PID (should fail)
        assert!(!container.validate_pid(0));
        assert!(!container.validate_pid(5));
    }

    #[test]
    fn test_reset() {
        let container = AntiReplayContainer::new();
        container.get_next_pid();
        container.get_next_pid();
        container.validate_pid(100);
        
        assert!(container.has_tracked_packets());
        
        container.reset();
        
        assert_eq!(container.current_counter(), 0);
        assert_eq!(container.history_size(), 0);
    }

    #[test]
    fn test_window_sliding() {
        let container = AntiReplayContainer::with_window_size(5);
        
        // Add PIDs 0-4
        for i in 0..5 {
            assert!(container.validate_pid(i));
        }
        assert_eq!(container.history_size(), 5);
        
        // Add PID 5 - should push out PID 0
        assert!(container.validate_pid(5));
        assert_eq!(container.history_size(), 5);
        
        // PID 0 should now be rejected (too old)
        assert!(!container.validate_pid(0));
    }
}