//! Performance benchmarks for Hybrid Ratchet (ML-KEM-1024 Asymmetric Ratchet)
//!
//! This benchmark measures the complete hybrid ratchet operations including:
//! - Ratchet creation with ML-KEM key generation
//! - Symmetric chain ratchet step (KDF only)
//! - Asymmetric ratchet step (ML-KEM encaps + KDF)
//! - Message key derivation
//!
//! Run with: cargo bench --package zks_crypt --bench hybrid_ratchet_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use zks_crypt::hybrid_ratchet::{HybridRatchet, HybridRatchetConfig};

/// Benchmark hybrid ratchet creation (includes ML-KEM-1024 keygen)
fn benchmark_ratchet_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("HybridRatchet-Create");
    
    let shared_secret = [0x42u8; 32];
    
    // Default config (interval=50)
    group.bench_function("default-config", |b| {
        b.iter(|| {
            let ratchet = HybridRatchet::new(
                black_box(&shared_secret),
                true,
                HybridRatchetConfig::default(),
            );
            black_box(ratchet)
        })
    });
    
    // Max security config (interval=1)
    group.bench_function("max-security-config", |b| {
        b.iter(|| {
            let ratchet = HybridRatchet::new(
                black_box(&shared_secret),
                true,
                HybridRatchetConfig::max_security(),
            );
            black_box(ratchet)
        })
    });
    
    // Balanced config (interval=10)
    group.bench_function("balanced-config", |b| {
        b.iter(|| {
            let ratchet = HybridRatchet::new(
                black_box(&shared_secret),
                true,
                HybridRatchetConfig::balanced(),
            );
            black_box(ratchet)
        })
    });
    
    group.finish();
}

/// Benchmark ratchet_encrypt (symmetric chain step, no asymmetric ratchet)
fn benchmark_symmetric_step(c: &mut Criterion) {
    let mut group = c.benchmark_group("HybridRatchet-SymmetricStep");
    
    let shared_secret = [0x42u8; 32];
    
    // Use high interval to avoid triggering asymmetric ratchet
    let config = HybridRatchetConfig {
        ratchet_interval: 10000,
        inline_messages: true,
        max_skip: 1000,
    };
    
    let mut ratchet = HybridRatchet::new(&shared_secret, true, config).unwrap();
    
    // Set peer public key to enable encryption
    let peer_ratchet = HybridRatchet::new(&shared_secret, false, HybridRatchetConfig::default()).unwrap();
    ratchet.set_peer_public_key(peer_ratchet.our_public_key().to_vec()).unwrap();
    
    group.bench_function("encrypt-symmetric-only", |b| {
        b.iter(|| {
            let output = ratchet.ratchet_encrypt();
            black_box(output)
        })
    });
    
    group.finish();
}

/// Benchmark full asymmetric ratchet step (ML-KEM encaps + new keypair)
fn benchmark_asymmetric_step(c: &mut Criterion) {
    let mut group = c.benchmark_group("HybridRatchet-AsymmetricStep");
    
    let shared_secret = [0x42u8; 32];
    
    // Use interval=1 to force asymmetric ratchet every message
    let config = HybridRatchetConfig::max_security();
    
    let mut alice = HybridRatchet::new(&shared_secret, true, config.clone()).unwrap();
    let bob = HybridRatchet::new(&shared_secret, false, config).unwrap();
    alice.set_peer_public_key(bob.our_public_key().to_vec()).unwrap();
    
    group.bench_function("encrypt-with-asymmetric-ratchet", |b| {
        b.iter(|| {
            let output = alice.ratchet_encrypt();
            black_box(output)
        })
    });
    
    group.finish();
}

/// Benchmark decryption with ratchet header processing
fn benchmark_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("HybridRatchet-Decrypt");
    
    let shared_secret = [0x42u8; 32];
    let config = HybridRatchetConfig::balanced();
    
    let mut alice = HybridRatchet::new(&shared_secret, true, config.clone()).unwrap();
    let mut bob = HybridRatchet::new(&shared_secret, false, config).unwrap();
    
    alice.set_peer_public_key(bob.our_public_key().to_vec()).unwrap();
    bob.set_peer_public_key(alice.our_public_key().to_vec()).unwrap();
    
    // Pre-generate headers for decryption benchmark
    let output = alice.ratchet_encrypt().unwrap();
    let header = output.header.clone();
    
    group.bench_function("decrypt-symmetric", |b| {
        // Reset bob for each iteration by cloning state
        b.iter(|| {
            // Just benchmark the header processing, not full decrypt
            let key = bob.ratchet_decrypt(black_box(&header));
            black_box(key)
        })
    });
    
    group.finish();
}

/// Benchmark message key derivation chain performance
fn benchmark_chain_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("HybridRatchet-Throughput");
    
    let shared_secret = [0x42u8; 32];
    
    // High interval for pure symmetric performance
    let config = HybridRatchetConfig {
        ratchet_interval: 100000,
        inline_messages: true,
        max_skip: 1000,
    };
    
    let mut ratchet = HybridRatchet::new(&shared_secret, true, config).unwrap();
    let peer = HybridRatchet::new(&shared_secret, false, HybridRatchetConfig::default()).unwrap();
    ratchet.set_peer_public_key(peer.our_public_key().to_vec()).unwrap();
    
    // Measure throughput in messages/second
    group.throughput(Throughput::Elements(100));
    group.bench_function("100-messages-symmetric", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let _ = ratchet.ratchet_encrypt();
            }
        })
    });
    
    group.finish();
}

/// Comparison benchmark: Full ratchet step timings for paper claims
fn benchmark_paper_claims(c: &mut Criterion) {
    let mut group = c.benchmark_group("Paper-Claims-Validation");
    
    let shared_secret = [0x42u8; 32];
    
    // Benchmark "5.8ms Hybrid Ratchet Step" claim
    let config = HybridRatchetConfig::max_security();
    let mut ratchet = HybridRatchet::new(&shared_secret, true, config).unwrap();
    let peer = HybridRatchet::new(&shared_secret, false, HybridRatchetConfig::default()).unwrap();
    ratchet.set_peer_public_key(peer.our_public_key().to_vec()).unwrap();
    
    group.bench_function("hybrid-ratchet-step", |b| {
        b.iter(|| {
            let output = ratchet.ratchet_encrypt();
            black_box(output)
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_ratchet_creation,
    benchmark_symmetric_step,
    benchmark_asymmetric_step,
    benchmark_decrypt,
    benchmark_chain_throughput,
    benchmark_paper_claims,
);
criterion_main!(benches);
