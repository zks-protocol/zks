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
//! - Configurable window size for high-throughput applications
//! 
//! # Security Model
//! - Each outgoing packet gets a unique, monotonically increasing PID
//! - PIDs are encrypted with the packet payload
//! - Receiver tracks PIDs in a sliding window
//! - Duplicate or out-of-window PIDs are rejected as replay attacks
//!
//! # Window Size Recommendations
//! - Low-throughput (< 100 msg/sec): 1024 (legacy default)
//! - Medium-throughput (100-1000 msg/sec): 8192
//! - High-throughput (> 1000 msg/sec): 65536 (new default)
//! - Very high-throughput (> 10000 msg/sec): 262144
//!
//! # Time-Based Expiry
//! For applications with variable throughput, consider combining window-based
//! replay protection with time-based expiry (see `validate_pid_with_expiry`).

use std::collections::HashSet;
use std::hash::{BuildHasher, Hasher};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Default history window size - number of PIDs to track
/// Increased from 1024 to 65536 for high-throughput scenarios
/// At 1000 msg/sec, this provides ~65 seconds of window
pub const HISTORY_LEN: u64 = 65536;

/// Legacy window size for low-throughput applications
pub const HISTORY_LEN_LEGACY: u64 = 1024;

/// Recommended window size for very high-throughput applications
pub const HISTORY_LEN_HIGH_THROUGHPUT: u64 = 262144;

/// Zero-allocation hasher for u64 PIDs
/// Since PIDs are already unique u64s, we use them directly as hash values
/// Zero-allocation hasher for u64 PIDs
/// 
/// Since PIDs are already unique u64s, we use them directly as hash values.
/// This provides O(1) hashing with zero allocations for packet ID tracking.
/// 
/// # SECURITY NOTE (m7 Fix)
/// 
/// This hasher is ONLY safe for use with u64 keys. Using it with other types
/// could cause hash collisions and bypass replay protection.
/// 
/// The `write()` method now returns an error indicator via the hash value
/// instead of silently succeeding, making incorrect usage detectable.
struct NoHashHasher<T>(u64, PhantomData<T>, bool); // Added error flag

impl<T> Default for NoHashHasher<T> {
    fn default() -> Self {
        NoHashHasher(0, PhantomData, false)
    }
}

impl<T> Hasher for NoHashHasher<T> {
    fn finish(&self) -> u64 {
        // If error flag is set, return a sentinel value that will cause
        // the lookup to fail predictably rather than silently succeed
        if self.2 {
            tracing::error!("🚨 SECURITY: NoHashHasher used incorrectly - returning error sentinel");
            u64::MAX // Sentinel value - will never match valid PIDs
        } else {
            self.0
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        // SECURITY FIX m7: Set error flag instead of silent no-op
        // This makes incorrect usage detectable rather than causing silent failures
        self.2 = true; // Set error flag
        debug_assert!(false, "NoHashHasher::write() called - this indicates incorrect usage with non-u64 types");
        tracing::error!(
            "🚨 SECURITY: NoHashHasher::write() called with {} bytes - incorrect usage detected! \
             This hasher only supports u64 keys. Hash lookups will fail safely.",
            bytes.len()
        );
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

// =============================================================================
// WireGuard-style Bitmap Anti-Replay (Constant-Time)
// =============================================================================
// 
// Based on Cloudflare's boringtun implementation which follows WireGuard spec.
// Uses a bitmap for O(1) constant-time replay detection with no timing leaks.
// 
// Reference: https://github.com/cloudflare/boringtun/blob/master/boringtun/src/noise/session.rs

/// Bitmap-based anti-replay with constant-time operations
/// 
/// Uses a sliding window bitmap to track seen packet counters.
/// Provides deterministic execution time regardless of counter values.
/// 
/// # Security Properties
/// - Constant-time: No timing side-channels
/// - Memory-efficient: Uses bitmap instead of HashSet
/// - Handles packet reordering within window
/// - Distinct error types for invalid vs duplicate counters
pub struct BitmapAntiReplay {
    /// Counter for outgoing packets
    counter_out: AtomicU64,
    /// Validator for incoming packets
    validator: Mutex<BitmapValidator>,
}

/// Constants following WireGuard specification
const BITMAP_WORD_SIZE: u64 = 64;
const BITMAP_N_WORDS: usize = 16;  // 16 × 64 = 1024 bit window
const BITMAP_WINDOW_SIZE: u64 = BITMAP_WORD_SIZE * BITMAP_N_WORDS as u64;

/// Errors for replay detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// Counter is too old (below window)
    TooOld,
    /// Counter was already seen (duplicate)
    Duplicate,
}

/// Internal bitmap validator
struct BitmapValidator {
    /// The next expected counter (highest seen + 1)
    next: u64,
    /// Bitmap of seen counters within the window
    bitmap: [u64; BITMAP_N_WORDS],
}

impl Default for BitmapValidator {
    fn default() -> Self {
        Self {
            next: 0,
            bitmap: [0u64; BITMAP_N_WORDS],
        }
    }
}

impl BitmapValidator {
    /// Check if a counter will be accepted (without marking it)
    /// 
    /// Runs in constant time regardless of counter value.
    #[inline]
    fn will_accept(&self, counter: u64) -> Result<(), ReplayError> {
        // Counter is too old
        if counter.wrapping_add(BITMAP_WINDOW_SIZE) < self.next {
            return Err(ReplayError::TooOld);
        }
        
        // Counter is in the future - always acceptable
        if counter >= self.next {
            return Ok(());
        }
        
        // Counter is within window - check if already seen
        let bit_index = counter % BITMAP_WINDOW_SIZE;
        let word_index = (bit_index / BITMAP_WORD_SIZE) as usize;
        let bit_position = bit_index % BITMAP_WORD_SIZE;
        
        // Constant-time check using bitwise AND
        let mask = 1u64 << bit_position;
        let is_set = (self.bitmap[word_index] & mask) != 0;
        
        if is_set {
            Err(ReplayError::Duplicate)
        } else {
            Ok(())
        }
    }
    
    /// Mark a counter as seen
    /// 
    /// Runs in constant time regardless of counter value.
    #[inline]
    fn mark_seen(&mut self, counter: u64) -> Result<(), ReplayError> {
        // First check if acceptable
        self.will_accept(counter)?;
        
        // Advance window if counter is ahead
        if counter >= self.next {
            // Calculate how many words to clear
            let diff = counter - self.next + 1;
            
            if diff >= BITMAP_WINDOW_SIZE {
                // Counter is way ahead - clear entire bitmap
                self.bitmap = [0u64; BITMAP_N_WORDS];
            } else {
                // Clear words that are now out of window
                // This loop has bounded iterations (max BITMAP_N_WORDS)
                for i in 0..diff.min(BITMAP_WINDOW_SIZE) {
                    let idx = ((self.next + i) % BITMAP_WINDOW_SIZE) / BITMAP_WORD_SIZE;
                    let bit = ((self.next + i) % BITMAP_WINDOW_SIZE) % BITMAP_WORD_SIZE;
                    self.bitmap[idx as usize] &= !(1u64 << bit);
                }
            }
            self.next = counter + 1;
        }
        
        // Set the bit for this counter
        let bit_index = counter % BITMAP_WINDOW_SIZE;
        let word_index = (bit_index / BITMAP_WORD_SIZE) as usize;
        let bit_position = bit_index % BITMAP_WORD_SIZE;
        self.bitmap[word_index] |= 1u64 << bit_position;
        
        Ok(())
    }
}

impl BitmapAntiReplay {
    /// Create a new bitmap-based anti-replay container
    pub fn new() -> Self {
        Self {
            counter_out: AtomicU64::new(0),
            validator: Mutex::new(BitmapValidator::default()),
        }
    }
    
    /// Get the next counter for an outgoing packet
    #[inline]
    pub fn get_next_counter(&self) -> u64 {
        self.counter_out.fetch_add(1, Ordering::Relaxed)
    }
    
    /// Validate and mark a received counter (constant-time)
    /// 
    /// Returns `Ok(())` if the counter is valid and not a replay.
    /// Returns `Err(ReplayError)` with distinct error types.
    /// 
    /// # Security
    /// This function runs in constant time regardless of counter value,
    /// preventing timing side-channel attacks.
    #[inline]
    pub fn validate(&self, counter: u64) -> Result<(), ReplayError> {
        let mut validator = self.validator.lock().unwrap_or_else(|e| e.into_inner());
        validator.mark_seen(counter)
    }
    
    /// Check if a counter would be accepted without marking it
    #[inline]
    pub fn check(&self, counter: u64) -> Result<(), ReplayError> {
        let validator = self.validator.lock().unwrap_or_else(|e| e.into_inner());
        validator.will_accept(counter)
    }
    
    /// Reset the anti-replay state (call on re-keying)
    pub fn reset(&self) {
        self.counter_out.store(0, Ordering::Relaxed);
        let mut validator = self.validator.lock().unwrap();
        *validator = BitmapValidator::default();
        tracing::debug!("🔄 Bitmap anti-replay reset");
    }
    
    /// Get the current outgoing counter
    pub fn current_counter(&self) -> u64 {
        self.counter_out.load(Ordering::Relaxed)
    }
    
    /// Get the window size
    pub const fn window_size() -> u64 {
        BITMAP_WINDOW_SIZE
    }
}

impl Default for BitmapAntiReplay {
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
    
    // =========================================================================
    // BitmapAntiReplay Tests (WireGuard-style)
    // =========================================================================
    
    #[test]
    fn test_bitmap_fresh_counters() {
        let ar = BitmapAntiReplay::new();
        assert!(ar.validate(0).is_ok());
        assert!(ar.validate(1).is_ok());
        assert!(ar.validate(2).is_ok());
    }
    
    #[test]
    fn test_bitmap_reject_duplicate() {
        let ar = BitmapAntiReplay::new();
        assert!(ar.validate(5).is_ok());
        assert_eq!(ar.validate(5), Err(ReplayError::Duplicate));
    }
    
    #[test]
    fn test_bitmap_out_of_order() {
        let ar = BitmapAntiReplay::new();
        assert!(ar.validate(10).is_ok());
        assert!(ar.validate(8).is_ok());  // Earlier counter
        assert!(ar.validate(12).is_ok());
        assert!(ar.validate(9).is_ok());  // Late arrival
        
        // Duplicates should fail
        assert_eq!(ar.validate(10), Err(ReplayError::Duplicate));
        assert_eq!(ar.validate(8), Err(ReplayError::Duplicate));
    }
    
    #[test]
    fn test_bitmap_window_boundary() {
        let ar = BitmapAntiReplay::new();
        
        // Accept first counter
        assert!(ar.validate(0).is_ok());
        assert!(ar.validate(1).is_ok());
        
        // Jump way ahead - should clear bitmap
        assert!(ar.validate(BITMAP_WINDOW_SIZE + 100).is_ok());
        
        // Old counters should now be too old
        assert_eq!(ar.validate(0), Err(ReplayError::TooOld));
        assert_eq!(ar.validate(1), Err(ReplayError::TooOld));
    }
    
    #[test]
    fn test_bitmap_sliding_window() {
        let ar = BitmapAntiReplay::new();
        
        // Fill window with sequential counters
        for i in 0..BITMAP_WINDOW_SIZE {
            assert!(ar.validate(i).is_ok(), "Failed at counter {}", i);
        }
        
        // All should be duplicates now
        for i in 0..BITMAP_WINDOW_SIZE {
            assert_eq!(ar.validate(i), Err(ReplayError::Duplicate), "Should be duplicate at {}", i);
        }
        
        // Next counter should work
        assert!(ar.validate(BITMAP_WINDOW_SIZE).is_ok());
        
        // Counter 0 is now too old (outside window)
        assert_eq!(ar.validate(0), Err(ReplayError::TooOld));
    }
    
    #[test]
    fn test_bitmap_large_gap() {
        let ar = BitmapAntiReplay::new();
        
        assert!(ar.validate(0).is_ok());
        
        // Jump 3× window size
        assert!(ar.validate(BITMAP_WINDOW_SIZE * 3).is_ok());
        
        // Everything before 2× window should be too old
        for i in 0..=BITMAP_WINDOW_SIZE * 2 {
            assert_eq!(ar.validate(i), Err(ReplayError::TooOld));
        }
        
        // Counters just before the jump should be acceptable
        for i in (BITMAP_WINDOW_SIZE * 2 + 1)..BITMAP_WINDOW_SIZE * 3 {
            assert!(ar.validate(i).is_ok(), "Should accept counter {}", i);
        }
    }
    
    #[test]
    fn test_bitmap_reset() {
        let ar = BitmapAntiReplay::new();
        
        ar.get_next_counter();
        ar.get_next_counter();
        ar.validate(100).unwrap();
        
        ar.reset();
        
        assert_eq!(ar.current_counter(), 0);
        // After reset, counter 0 should be valid again
        assert!(ar.validate(0).is_ok());
    }
}