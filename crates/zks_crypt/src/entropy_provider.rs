//! Entropy Provider Trait - Abstraction for entropy sources
//!
//! This module defines the trait that allows TrueVernam to use different
//! entropy sources (including Entropy Grid) without creating cyclic dependencies.

use async_trait::async_trait;
use crate::entropy_block::DrandRound;
use crate::drand::DrandError;

/// Interface for entropy providers that can fetch drand rounds
#[async_trait]
pub trait EntropyProvider: Send + Sync {
    /// Fetch a specific drand round
    async fn fetch_round(&self, round_number: u64) -> Result<DrandRound, DrandError>;
    
    /// Fetch multiple consecutive rounds
    async fn fetch_range(&self, start_round: u64, count: u32) -> Result<Vec<DrandRound>, DrandError>;
}

/// Simple entropy provider that uses the drand client directly
pub struct DirectDrandProvider {
    client: std::sync::Arc<crate::drand::DrandEntropy>,
}

impl DirectDrandProvider {
    /// Create a new direct drand provider
    pub fn new(client: std::sync::Arc<crate::drand::DrandEntropy>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl EntropyProvider for DirectDrandProvider {
    async fn fetch_round(&self, round_number: u64) -> Result<DrandRound, DrandError> {
        let randomness = self.client.fetch_round(round_number).await?;
        Ok(DrandRound {
            round: round_number,
            randomness,
            signature: vec![0u8; 96], // We don't have signature in the current API
            previous_signature: vec![0u8; 96], // We don't have previous signature
        })
    }
    
    async fn fetch_range(&self, start_round: u64, count: u32) -> Result<Vec<DrandRound>, DrandError> {
        let mut rounds = Vec::new();
        for i in 0..count {
            let round_number = start_round + i as u64;
            rounds.push(self.fetch_round(round_number).await?);
        }
        Ok(rounds)
    }
}