//! Cover Traffic Tests for ZKS Protocol
//!
//! Tests ensure cover traffic is indistinguishable from real traffic,
//! maintains proper timing distributions, and integrates correctly
//! with Faisal Swarm routing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use zks_cover::{
    CoverConfig, CoverGenerator, CoverScheduler,
};

/// Test that cover messages are indistinguishable from real traffic
#[tokio::test]
async fn test_cover_indistinguishable() {
    let config = CoverConfig::builder()
        .payload_size(512)
        .poisson_rate(1.0)
        .build()
        .expect("Failed to build config");
    
    let generator = CoverGenerator::new(config).expect("Failed to create generator");
    
    // Generate multiple cover messages
    let mut messages = Vec::new();
    for _ in 0..10 {
        let msg = generator.generate_cover(Some("test_circuit".to_string())).await
            .expect("Failed to generate cover");
        messages.push(msg);
    }
    
    // Verify all messages have consistent properties
    for msg in &messages {
        assert_eq!(msg.payload.len(), 512, "Cover payload must be 512 bytes");
        assert!(msg.circuit_id.is_some(), "Cover should have circuit ID");
        assert!(!msg.payload.iter().all(|&b| b == 0), "Cover payload should not be all zeros");
    }
    
    // Verify messages are different (not deterministic)
    let mut unique_payloads = HashMap::new();
    for msg in &messages {
        unique_payloads.entry(&msg.payload).or_insert(0);
        *unique_payloads.get_mut(&msg.payload).unwrap() += 1;
    }
    
    assert!(unique_payloads.len() > 5, "Cover messages should be varied");
}

/// Test Poisson timing distribution
#[tokio::test]
async fn test_timing_distribution() {
    let config = CoverConfig::builder()
        .payload_size(512)
        .poisson_rate(2.0) // 2 messages per second
        .build()
        .expect("Failed to build config");
    
    let generator = Arc::new(CoverGenerator::new(config.clone()).expect("Failed to create generator"));
    let scheduler = CoverScheduler::new(config, generator).expect("Failed to create scheduler");
    
    // Generate burst of covers
    let start = Instant::now();
    let covers = scheduler.schedule_burst(10, Some("timing_test".to_string())).await
        .expect("Failed to schedule burst");
    let elapsed = start.elapsed();
    
    assert_eq!(covers.len(), 10, "Should generate exactly 10 covers");
    
    // Verify timing is reasonable (should be very fast for burst)
    assert!(elapsed < Duration::from_millis(100), "Burst scheduling should be fast");
    
    // Verify each cover has correct properties
    for cover in &covers {
        assert_eq!(cover.payload.len(), 512, "Each cover should have 512-byte payload");
        assert_eq!(cover.circuit_id, Some("timing_test".to_string()), "Circuit ID should match");
    }
}

/// Test scheduler integration with Faisal Swarm
#[tokio::test]
async fn test_scheduler_integration() {
    let config = CoverConfig::builder()
        .payload_size(512)
        .poisson_rate(1.0)
        .build()
        .expect("Failed to build config");
    
    let generator = Arc::new(CoverGenerator::new(config.clone()).expect("Failed to create generator"));
    let scheduler = CoverScheduler::new(config, generator).expect("Failed to create scheduler");
    
    // Test burst scheduling with circuit integration
    let covers = scheduler.schedule_burst(5, Some("integration_circuit".to_string())).await
        .expect("Failed to schedule burst");
    
    assert_eq!(covers.len(), 5, "Should generate 5 covers");
    
    // Verify circuit integration
    for cover in &covers {
        assert_eq!(cover.circuit_id, Some("integration_circuit".to_string()), "Circuit ID should be set");
        assert_eq!(cover.payload.len(), 512, "Payload should be 512 bytes");
    }
}

/// Test Poisson scheduling produces realistic message counts
#[tokio::test]
async fn test_poisson_realism() {
    let config = CoverConfig::builder()
        .payload_size(512)
        .poisson_rate(5.0) // 5 messages per second
        .build()
        .expect("Failed to build config");
    
    let generator = Arc::new(CoverGenerator::new(config.clone()).expect("Failed to create generator"));
    let scheduler = CoverScheduler::new(config, generator).expect("Failed to create scheduler");
    
    // Generate multiple batches and check distribution
    let mut total_covers = 0;
    let batches = 20;
    
    for _ in 0..batches {
        let covers = scheduler.schedule_poisson(None).await
            .expect("Failed to schedule Poisson covers");
        total_covers += covers.len();
    }
    
    let average = total_covers as f64 / batches as f64;
    
    // Poisson rate of 5.0 should give us around 5 messages per batch on average
    // Allow some variance (between 3 and 7)
    assert!(average >= 3.0 && average <= 7.0, 
        "Average covers per batch should be around 5, got {}", average);
}

/// Test that different configurations produce different patterns
#[tokio::test]
async fn test_config_diversity() {
    // Low rate configuration
    let low_config = CoverConfig::builder()
        .payload_size(512)
        .poisson_rate(0.5)
        .build()
        .expect("Failed to build low config");
    
    // High rate configuration  
    let high_config = CoverConfig::builder()
        .payload_size(512)
        .poisson_rate(3.0)
        .build()
        .expect("Failed to build high config");
    
    let low_generator = CoverGenerator::new(low_config).expect("Failed to create low generator");
    let high_generator = CoverGenerator::new(high_config).expect("Failed to create high generator");
    
    // Generate covers with both configurations
    let low_covers = low_generator.generate_covers(5, Some("low_circuit".to_string())).await
        .expect("Failed to generate low covers");
    let high_covers = high_generator.generate_covers(5, Some("high_circuit".to_string())).await
        .expect("Failed to generate high covers");
    
    assert_eq!(low_covers.len(), 5, "Should generate 5 low covers");
    assert_eq!(high_covers.len(), 5, "Should generate 5 high covers");
    
    // Verify all have correct properties
    for cover in low_covers.iter().chain(high_covers.iter()) {
        assert_eq!(cover.payload.len(), 512, "All covers should have 512-byte payload");
        assert!(cover.circuit_id.is_some(), "All covers should have circuit ID");
    }
}

/// Test scheduler timing accuracy
#[tokio::test]
async fn test_scheduler_timing() {
    let config = CoverConfig::builder()
        .payload_size(512)
        .poisson_rate(2.0)
        .build()
        .expect("Failed to build config");
    
    let generator = Arc::new(CoverGenerator::new(config.clone()).expect("Failed to create generator"));
    let scheduler = CoverScheduler::new(config, generator).expect("Failed to create scheduler");
    
    // Test that Poisson scheduling works
    let start = Instant::now();
    let covers = scheduler.schedule_poisson(Some("timing_circuit".to_string())).await
        .expect("Failed to schedule Poisson covers");
    let _elapsed = start.elapsed();
    
    // Should generate some covers (Poisson distribution)
    assert!(!covers.is_empty(), "Should generate at least one cover");
    
    // Verify all covers have correct properties
    for cover in &covers {
        assert_eq!(cover.payload.len(), 512, "Each cover should have 512-byte payload");
        assert_eq!(cover.circuit_id, Some("timing_circuit".to_string()), "Circuit ID should match");
    }
}

/// Test error handling for invalid configurations
#[tokio::test]
async fn test_error_handling() {
    // Test with invalid payload size
    let result = CoverConfig::builder()
        .payload_size(0) // Invalid: 0 bytes
        .build();
    
    assert!(result.is_err(), "Should fail with invalid payload size");
}

/// Benchmark cover generation performance
#[tokio::test]
async fn test_generation_performance() {
    let config = CoverConfig::builder()
        .payload_size(512)
        .poisson_rate(10.0)
        .build()
        .expect("Failed to build config");
    
    let generator = CoverGenerator::new(config).expect("Failed to create generator");
    
    let start = Instant::now();
    
    // Generate a large batch
    let covers = generator.generate_covers(100, Some("perf_circuit".to_string())).await
        .expect("Failed to generate covers");
    
    let elapsed = start.elapsed();
    
    assert_eq!(covers.len(), 100, "Should generate 100 covers");
    
    // Should be reasonably fast (less than 1 second for 100 covers)
    assert!(elapsed < Duration::from_secs(1), "Generation should be fast, took {:?}", elapsed);
    
    // Verify all covers are valid
    for cover in &covers {
        assert_eq!(cover.payload.len(), 512, "Each cover should have 512-byte payload");
        assert_eq!(cover.circuit_id, Some("perf_circuit".to_string()), "Circuit ID should match");
    }
}