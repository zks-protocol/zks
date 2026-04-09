//! Formal Anonymity Metrics for ZKS Protocol
//!
//! Implements formal anonymity metrics based on academic standards:
//! - Shannon entropy for information-theoretic anonymity
//! - Min-entropy for worst-case anonymity
//! - Scaled anonymity set size
//! - Path diversity metrics
//! - Timing attack resistance
//! - Correlation analysis

use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;

/// Error types for anonymity metrics
#[derive(Debug, Error)]
pub enum AnonymityError {
    /// Invalid probability distribution provided
    #[error("Invalid probability distribution: {0}")]
    InvalidProbability(String),
    /// Empty data set encountered during analysis
    #[error("Empty data set")]
    EmptyDataSet,
    /// Division by zero occurred during computation
    #[error("Division by zero")]
    DivisionByZero,
    /// Invalid circuit configuration specified
    #[error("Invalid circuit configuration: {0}")]
    InvalidCircuitConfig(String),
    /// Error during timing analysis
    #[error("Timing analysis error: {0}")]
    TimingAnalysisError(String),
}

/// Result type alias for anonymity operations
pub type Result<T> = std::result::Result<T, AnonymityError>;

/// Anonymity metrics for a circuit
#[derive(Debug, Clone)]
pub struct CircuitAnonymityMetrics {
    /// Circuit ID
    pub circuit_id: u32,
    /// Number of hops in the circuit
    pub hop_count: usize,
    /// Shannon entropy of the anonymity set (log2)
    pub shannon_entropy: f64,
    /// Min-entropy for worst-case anonymity (log2)
    pub min_entropy: f64,
    /// Scaled anonymity set size (normalized to [0, 1])
    pub scaled_anonymity_set: f64,
    /// Effective anonymity set size (2^shannon_entropy)
    pub effective_anonymity_set: f64,
    /// Path diversity score (0-1)
    pub path_diversity: f64,
    /// Timing correlation resistance (0-1)
    pub timing_resistance: f64,
    /// Size correlation vulnerability (0-1, lower is better)
    pub size_correlation_risk: f64,
    /// Overall anonymity score (0-1)
    pub overall_score: f64,
}

/// Traffic pattern analysis for anonymity
#[derive(Debug, Clone)]
pub struct TrafficPattern {
    /// Packet sizes in order
    pub packet_sizes: Vec<usize>,
    /// Packet timestamps (relative to start)
    pub timestamps: Vec<Duration>,
    /// Inter-packet delays
    pub delays: Vec<Duration>,
    /// Total bytes transferred
    pub total_bytes: usize,
}

/// Anonymity set configuration
#[derive(Debug, Clone)]
pub struct AnonymitySet {
    /// Known peers in the network
    pub known_peers: Vec<String>,
    /// Exit-capable peers
    pub exit_peers: Vec<String>,
    /// Guard-capable peers
    pub guard_peers: Vec<String>,
}

impl Default for AnonymitySet {
    fn default() -> Self {
        Self {
            known_peers: Vec::new(),
            exit_peers: Vec::new(),
            guard_peers: Vec::new(),
        }
    }
}

/// Calculate Shannon entropy of a distribution
pub fn calculate_shannon_entropy(probabilities: &[f64]) -> Result<f64> {
    if probabilities.is_empty() {
        return Err(AnonymityError::EmptyDataSet);
    }

    let total: f64 = probabilities.iter().sum();
    if total == 0.0 {
        return Err(AnonymityError::DivisionByZero);
    }

    // Validate probabilities
    for &p in probabilities {
        if p < 0.0 {
            return Err(AnonymityError::InvalidProbability(
                format!("Negative probability: {}", p)
            ));
        }
    }

    let mut entropy = 0.0;
    for &p in probabilities {
        if p > 0.0 {
            let normalized = p / total;
            entropy -= normalized * normalized.log2();
        }
    }

    Ok(entropy)
}

/// Calculate Shannon entropy of byte data
pub fn calculate_byte_entropy(data: &[u8]) -> Result<f64> {
    if data.is_empty() {
        return Err(AnonymityError::EmptyDataSet);
    }

    let mut frequency = HashMap::new();
    for &byte in data {
        *frequency.entry(byte).or_insert(0u64) += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in frequency.values() {
        let probability = count as f64 / len;
        if probability > 0.0 {
            entropy -= probability * probability.log2();
        }
    }

    Ok(entropy)
}

/// Calculate min-entropy (worst-case anonymity)
pub fn calculate_min_entropy(probabilities: &[f64]) -> Result<f64> {
    if probabilities.is_empty() {
        return Err(AnonymityError::EmptyDataSet);
    }

    let total: f64 = probabilities.iter().sum();
    if total == 0.0 {
        return Err(AnonymityError::DivisionByZero);
    }

    // Validate probabilities
    for &p in probabilities {
        if p < 0.0 {
            return Err(AnonymityError::InvalidProbability(
                format!("Negative probability: {}", p)
            ));
        }
    }

    let max_prob = probabilities.iter()
        .filter(|&&p| p > 0.0)
        .map(|&p| p / total)
        .fold(0.0_f64, f64::max);

    if max_prob == 0.0 {
        return Err(AnonymityError::DivisionByZero);
    }

    Ok(-max_prob.log2())
}

/// Calculate scaled anonymity set size
pub fn calculate_scaled_anonymity_set(entropy: f64, total_set_size: usize) -> Result<f64> {
    if total_set_size == 0 {
        return Err(AnonymityError::DivisionByZero);
    }

    let max_entropy = (total_set_size as f64).log2();
    if max_entropy == 0.0 {
        return Err(AnonymityError::DivisionByZero);
    }

    if entropy < 0.0 {
        return Err(AnonymityError::InvalidProbability(
            format!("Negative entropy: {}", entropy)
        ));
    }

    Ok((entropy / max_entropy).min(1.0).max(0.0))
}

/// Calculate effective anonymity set size (2^entropy)
pub fn calculate_effective_anonymity_set(entropy: f64) -> Result<f64> {
    if entropy < 0.0 {
        return Err(AnonymityError::InvalidProbability(
            format!("Negative entropy: {}", entropy)
        ));
    }
    Ok(2.0_f64.powf(entropy))
}

/// Calculate path diversity score based on hop uniqueness
pub fn calculate_path_diversity(
    hop_count: usize,
    total_peers: usize,
    selected_hops: &[String],
) -> Result<f64> {
    if total_peers == 0 {
        return Err(AnonymityError::DivisionByZero);
    }
    
    if selected_hops.is_empty() {
        return Err(AnonymityError::EmptyDataSet);
    }

    if hop_count == 0 {
        return Err(AnonymityError::InvalidCircuitConfig(
            "Hop count cannot be zero".to_string()
        ));
    }

    let unique_hops = selected_hops.iter().collect::<std::collections::HashSet<_>>().len();
    
    if unique_hops < selected_hops.len() {
        return Err(AnonymityError::InvalidCircuitConfig(
            "Duplicate hops detected in circuit".to_string()
        ));
    }

    if unique_hops > total_peers {
        return Err(AnonymityError::InvalidCircuitConfig(
            format!("More unique hops ({}) than total peers ({}) in anonymity set", unique_hops, total_peers)
        ));
    }

    let ideal_hops = hop_count.min(total_peers);
    Ok(unique_hops as f64 / ideal_hops as f64)
}

/// Analyze timing correlation between two traffic patterns
pub fn analyze_timing_correlation(pattern1: &TrafficPattern, pattern2: &TrafficPattern) -> Result<f64> {
    if pattern1.delays.is_empty() || pattern2.delays.is_empty() {
        return Err(AnonymityError::EmptyDataSet);
    }

    let len = pattern1.delays.len().min(pattern2.delays.len());
    if len < 2 {
        return Err(AnonymityError::TimingAnalysisError(
            "Insufficient timing data for correlation analysis".to_string()
        ));
    }

    let mut correlation = 0.0;
    for i in 0..len {
        let delay1 = pattern1.delays[i].as_secs_f64();
        let delay2 = pattern2.delays[i].as_secs_f64();
        
        if delay1 > 0.0 && delay2 > 0.0 {
            let ratio = delay1 / delay2;
            if ratio >= 0.9 && ratio <= 1.1 {
                correlation += 1.0;
            }
        }
    }

    Ok(correlation / len as f64)
}

/// Analyze size correlation between two traffic patterns
pub fn analyze_size_correlation(pattern1: &TrafficPattern, pattern2: &TrafficPattern) -> Result<f64> {
    if pattern1.packet_sizes.is_empty() || pattern2.packet_sizes.is_empty() {
        return Err(AnonymityError::EmptyDataSet);
    }

    let len = pattern1.packet_sizes.len().min(pattern2.packet_sizes.len());
    if len == 0 {
        return Err(AnonymityError::EmptyDataSet);
    }

    let mut correlated = 0;
    for i in 0..len {
        let size1 = pattern1.packet_sizes[i];
        let size2 = pattern2.packet_sizes[i];
        
        if (size1 as i32 - size2 as i32).abs() <= 3 {
            correlated += 1;
        }
    }

    Ok(correlated as f64 / len as f64)
}

/// Calculate timing resistance score (1 - correlation)
pub fn calculate_timing_resistance(correlation: f64) -> f64 {
    (1.0 - correlation).max(0.0).min(1.0)
}

/// Calculate size correlation risk
pub fn calculate_size_correlation_risk(correlation: f64) -> f64 {
    correlation.max(0.0).min(1.0)
}

/// Compute comprehensive anonymity metrics for a circuit
pub fn compute_circuit_anonymity_metrics(
    circuit_id: u32,
    hop_count: usize,
    anonymity_set: &AnonymitySet,
    selected_hops: &[String],
    traffic_patterns: &[TrafficPattern],
) -> Result<CircuitAnonymityMetrics> {
    let total_peers = anonymity_set.known_peers.len();
    
    if total_peers == 0 {
        return Err(AnonymityError::EmptyDataSet);
    }

    if hop_count == 0 {
        return Err(AnonymityError::InvalidCircuitConfig(
            "Hop count cannot be zero".to_string()
        ));
    }

    if selected_hops.is_empty() {
        return Err(AnonymityError::EmptyDataSet);
    }
    
    let uniform_prob = vec![1.0; total_peers];
    
    let shannon_entropy = calculate_shannon_entropy(&uniform_prob)?;
    let min_entropy = calculate_min_entropy(&uniform_prob)?;
    
    let scaled_anonymity_set = calculate_scaled_anonymity_set(shannon_entropy, total_peers)?;
    let effective_anonymity_set = calculate_effective_anonymity_set(shannon_entropy)?;
    
    let path_diversity = calculate_path_diversity(hop_count, total_peers, selected_hops)?;
    
    let timing_resistance = if traffic_patterns.len() >= 2 {
        let correlation = analyze_timing_correlation(&traffic_patterns[0], &traffic_patterns[1])?;
        calculate_timing_resistance(correlation)
    } else {
        1.0
    };
    
    let size_correlation_risk = if traffic_patterns.len() >= 2 {
        let correlation = analyze_size_correlation(&traffic_patterns[0], &traffic_patterns[1])?;
        calculate_size_correlation_risk(correlation)
    } else {
        0.5
    };
    
    let overall_score = (
        scaled_anonymity_set * 0.3 +
        path_diversity * 0.3 +
        timing_resistance * 0.2 +
        (1.0 - size_correlation_risk) * 0.2
    ).max(0.0).min(1.0);
    
    Ok(CircuitAnonymityMetrics {
        circuit_id,
        hop_count,
        shannon_entropy,
        min_entropy,
        scaled_anonymity_set,
        effective_anonymity_set,
        path_diversity,
        timing_resistance,
        size_correlation_risk,
        overall_score,
    })
}

/// Metrics aggregation across multiple circuits
#[derive(Debug, Clone)]
pub struct AggregateAnonymityMetrics {
    /// Number of circuits analyzed
    pub circuit_count: usize,
    /// Average Shannon entropy
    pub avg_shannon_entropy: f64,
    /// Average min-entropy
    pub avg_min_entropy: f64,
    /// Average scaled anonymity set
    pub avg_scaled_anonymity_set: f64,
    /// Minimum overall score
    pub min_overall_score: f64,
    /// Maximum overall score
    pub max_overall_score: f64,
    /// Average overall score
    pub avg_overall_score: f64,
    /// Circuits with poor anonymity (score < 0.5)
    pub poor_anonymity_count: usize,
}

/// Aggregate metrics from multiple circuits
pub fn aggregate_anonymity_metrics(metrics: &[CircuitAnonymityMetrics]) -> Result<AggregateAnonymityMetrics> {
    if metrics.is_empty() {
        return Err(AnonymityError::EmptyDataSet);
    }

    let count = metrics.len();
    let total_shannon: f64 = metrics.iter().map(|m| m.shannon_entropy).sum();
    let total_min: f64 = metrics.iter().map(|m| m.min_entropy).sum();
    let total_scaled: f64 = metrics.iter().map(|m| m.scaled_anonymity_set).sum();
    let total_overall: f64 = metrics.iter().map(|m| m.overall_score).sum();
    
    let min_overall = metrics.iter().map(|m| m.overall_score).fold(f64::INFINITY, f64::min);
    let max_overall = metrics.iter().map(|m| m.overall_score).fold(f64::NEG_INFINITY, f64::max);
    
    let poor_count = metrics.iter().filter(|m| m.overall_score < 0.5).count();

    Ok(AggregateAnonymityMetrics {
        circuit_count: count,
        avg_shannon_entropy: total_shannon / count as f64,
        avg_min_entropy: total_min / count as f64,
        avg_scaled_anonymity_set: total_scaled / count as f64,
        min_overall_score: min_overall,
        max_overall_score: max_overall,
        avg_overall_score: total_overall / count as f64,
        poor_anonymity_count: poor_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_uniform() {
        let uniform = vec![1.0, 1.0, 1.0, 1.0];
        let entropy = calculate_shannon_entropy(&uniform).unwrap();
        assert_eq!(entropy, 2.0);
    }

    #[test]
    fn test_shannon_entropy_empty() {
        let result = calculate_shannon_entropy(&[]);
        assert!(matches!(result, Err(AnonymityError::EmptyDataSet)));
    }

    #[test]
    fn test_shannon_entropy_negative_prob() {
        let result = calculate_shannon_entropy(&[1.0, -0.5, 1.0]);
        assert!(matches!(result, Err(AnonymityError::InvalidProbability(_))));
    }

    #[test]
    fn test_shannon_entropy_byte_data() {
        let data = vec![0u8; 256];
        let entropy = calculate_byte_entropy(&data).unwrap();
        assert_eq!(entropy, 0.0);
        
        let uniform_data: Vec<u8> = (0..=255).collect();
        let uniform_entropy = calculate_byte_entropy(&uniform_data).unwrap();
        assert_eq!(uniform_entropy, 8.0);
    }

    #[test]
    fn test_min_entropy() {
        let uniform = vec![1.0, 1.0, 1.0, 1.0];
        let min_entropy = calculate_min_entropy(&uniform).unwrap();
        assert_eq!(min_entropy, 2.0);
        
        let skewed = vec![10.0, 1.0, 1.0, 1.0];
        let skewed_min_entropy = calculate_min_entropy(&skewed).unwrap();
        assert!(skewed_min_entropy < min_entropy);
    }

    #[test]
    fn test_scaled_anonymity_set() {
        let entropy = 3.0;
        let total_set_size = 16;
        let scaled = calculate_scaled_anonymity_set(entropy, total_set_size).unwrap();
        assert_eq!(scaled, 0.75);
    }

    #[test]
    fn test_effective_anonymity_set() {
        let entropy = 5.0;
        let effective = calculate_effective_anonymity_set(entropy).unwrap();
        assert_eq!(effective, 32.0);
    }

    #[test]
    fn test_path_diversity() {
        let selected_hops = vec![
            "peer1".to_string(),
            "peer2".to_string(),
            "peer3".to_string(),
        ];
        
        let diversity = calculate_path_diversity(3, 10, &selected_hops).unwrap();
        assert_eq!(diversity, 1.0);
        
        let duplicate_hops = vec![
            "peer1".to_string(),
            "peer1".to_string(),
            "peer3".to_string(),
        ];
        let duplicate_result = calculate_path_diversity(3, 10, &duplicate_hops);
        assert!(matches!(duplicate_result, Err(AnonymityError::InvalidCircuitConfig(_))));
    }

    #[test]
    fn test_path_diversity_errors() {
        let result = calculate_path_diversity(0, 10, &["peer1".to_string()]);
        assert!(matches!(result, Err(AnonymityError::InvalidCircuitConfig(_))));
        
        let result = calculate_path_diversity(3, 0, &["peer1".to_string()]);
        assert!(matches!(result, Err(AnonymityError::DivisionByZero)));
        
        let result = calculate_path_diversity(3, 10, &[]);
        assert!(matches!(result, Err(AnonymityError::EmptyDataSet)));
    }

    #[test]
    fn test_timing_correlation() {
        let pattern1 = TrafficPattern {
            packet_sizes: vec![100, 200, 300],
            timestamps: vec![Duration::from_millis(0), Duration::from_millis(100), Duration::from_millis(250)],
            delays: vec![Duration::from_millis(100), Duration::from_millis(150)],
            total_bytes: 600,
        };
        
        let pattern2 = TrafficPattern {
            packet_sizes: vec![100, 200, 300],
            timestamps: vec![Duration::from_millis(0), Duration::from_millis(105), Duration::from_millis(260)],
            delays: vec![Duration::from_millis(105), Duration::from_millis(155)],
            total_bytes: 600,
        };
        
        let correlation = analyze_timing_correlation(&pattern1, &pattern2).unwrap();
        assert!(correlation > 0.5);
    }

    #[test]
    fn test_timing_correlation_errors() {
        let pattern1 = TrafficPattern {
            packet_sizes: vec![],
            timestamps: vec![],
            delays: vec![],
            total_bytes: 0,
        };
        
        let pattern2 = TrafficPattern {
            packet_sizes: vec![],
            timestamps: vec![],
            delays: vec![],
            total_bytes: 0,
        };
        
        let result = analyze_timing_correlation(&pattern1, &pattern2);
        assert!(matches!(result, Err(AnonymityError::EmptyDataSet)));
    }

    #[test]
    fn test_size_correlation() {
        let pattern1 = TrafficPattern {
            packet_sizes: vec![100, 200, 300],
            timestamps: vec![],
            delays: vec![],
            total_bytes: 600,
        };
        
        let pattern2 = TrafficPattern {
            packet_sizes: vec![102, 199, 301],
            timestamps: vec![],
            delays: vec![],
            total_bytes: 602,
        };
        
        let correlation = analyze_size_correlation(&pattern1, &pattern2).unwrap();
        assert_eq!(correlation, 1.0);
    }

    #[test]
    fn test_size_correlation_errors() {
        let pattern1 = TrafficPattern {
            packet_sizes: vec![],
            timestamps: vec![],
            delays: vec![],
            total_bytes: 0,
        };
        
        let pattern2 = TrafficPattern {
            packet_sizes: vec![],
            timestamps: vec![],
            delays: vec![],
            total_bytes: 0,
        };
        
        let result = analyze_size_correlation(&pattern1, &pattern2);
        assert!(matches!(result, Err(AnonymityError::EmptyDataSet)));
    }

    #[test]
    fn test_compute_circuit_anonymity_metrics() {
        let anonymity_set = AnonymitySet {
            known_peers: vec![
                "peer1".to_string(),
                "peer2".to_string(),
                "peer3".to_string(),
                "peer4".to_string(),
            ],
            exit_peers: vec![
                "peer2".to_string(),
                "peer4".to_string(),
            ],
            guard_peers: vec![
                "peer1".to_string(),
                "peer3".to_string(),
            ],
        };
        
        let selected_hops = vec![
            "peer1".to_string(),
            "peer2".to_string(),
            "peer3".to_string(),
        ];
        
        let metrics = compute_circuit_anonymity_metrics(
            1,
            3,
            &anonymity_set,
            &selected_hops,
            &[],
        ).unwrap();
        
        assert_eq!(metrics.circuit_id, 1);
        assert_eq!(metrics.hop_count, 3);
        assert_eq!(metrics.shannon_entropy, 2.0);
        assert_eq!(metrics.min_entropy, 2.0);
        assert!(metrics.overall_score > 0.0);
    }

    #[test]
    fn test_compute_circuit_anonymity_metrics_errors() {
        let anonymity_set = AnonymitySet {
            known_peers: vec![],
            exit_peers: vec![],
            guard_peers: vec![],
        };
        
        let result = compute_circuit_anonymity_metrics(
            1,
            3,
            &anonymity_set,
            &["peer1".to_string()],
            &[],
        );
        assert!(matches!(result, Err(AnonymityError::EmptyDataSet)));
    }

    #[test]
    fn test_aggregate_anonymity_metrics() {
        let metrics1 = CircuitAnonymityMetrics {
            circuit_id: 1,
            hop_count: 3,
            shannon_entropy: 3.0,
            min_entropy: 2.5,
            scaled_anonymity_set: 0.75,
            effective_anonymity_set: 8.0,
            path_diversity: 1.0,
            timing_resistance: 0.9,
            size_correlation_risk: 0.1,
            overall_score: 0.85,
        };
        
        let metrics2 = CircuitAnonymityMetrics {
            circuit_id: 2,
            hop_count: 3,
            shannon_entropy: 2.5,
            min_entropy: 2.0,
            scaled_anonymity_set: 0.6,
            effective_anonymity_set: 5.6,
            path_diversity: 0.8,
            timing_resistance: 0.7,
            size_correlation_risk: 0.3,
            overall_score: 0.6,
        };
        
        let aggregate = aggregate_anonymity_metrics(&[metrics1, metrics2]).unwrap();
        
        assert_eq!(aggregate.circuit_count, 2);
        assert_eq!(aggregate.avg_shannon_entropy, 2.75);
        assert_eq!(aggregate.avg_overall_score, 0.725);
        assert_eq!(aggregate.poor_anonymity_count, 0);
    }

    #[test]
    fn test_aggregate_anonymity_metrics_empty() {
        let result = aggregate_anonymity_metrics(&[]);
        assert!(matches!(result, Err(AnonymityError::EmptyDataSet)));
    }
}
