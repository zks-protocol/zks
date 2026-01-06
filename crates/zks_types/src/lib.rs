//! ZKS Protocol Core Types
//! 
//! This crate provides fundamental types used across the ZKS Protocol ecosystem.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
pub mod errors;

/// Convenience prelude that re-exports commonly used types
pub mod prelude {
    pub use crate::crypto::*;
    pub use crate::errors::*;
}