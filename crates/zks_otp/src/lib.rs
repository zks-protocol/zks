//! ZKS Offline One-Time Pad Encryption
//! 
//! This crate provides true information-theoretic security through physical key exchange.
//! It implements the classic one-time pad cipher with modern file management and security features.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::all)]

pub mod error;
pub mod key_file;
pub mod otp_cipher;
pub mod shredder;

#[cfg(feature = "hardware-rng")]
pub mod hardware_rng;

pub use error::{OtpError, Result};
pub use key_file::{KeyFile, KeyFileHeader};
pub use otp_cipher::{OfflineOtp, EncryptionResult, OtpMode};

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Magic bytes for .zkskey files
pub const KEY_FILE_MAGIC: &[u8; 8] = b"ZKSOTP01";

/// Default key file size (1GB)
pub const DEFAULT_KEY_SIZE: u64 = 1_073_741_824; // 1024 * 1024 * 1024