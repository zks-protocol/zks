//! Performance benchmarks for Reed-Solomon Erasure Coding
//!
//! Run with: cargo bench --package zks_crypt -- erasure

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use zks_crypt::erasure_ratchet::{ErasureConfig, ErasureCodec};

/// Generate random data for benchmarking
fn random_data(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut data = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

/// Benchmark Reed-Solomon encoding at different data sizes
fn benchmark_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("ReedSolomon-Encode");
    
    // Test different data sizes
    let sizes = [256, 1024, 4096, 16384, 65536];
    
    for size in sizes {
        let config = ErasureConfig::balanced(); // 4 original, 4 recovery
        let codec = ErasureCodec::new(config);
        let data = random_data(size);
        
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("balanced", size), &data, |b, data| {
            b.iter(|| {
                let shards = codec.encode(black_box(data), 0).unwrap();
                black_box(shards)
            })
        });
    }
    
    group.finish();
}

/// Benchmark encoding with different redundancy profiles
fn benchmark_encode_profiles(c: &mut Criterion) {
    let mut group = c.benchmark_group("ReedSolomon-Profiles");
    
    let data = random_data(4096);
    
    // Minimal: 4+1 (20% overhead, 20% loss tolerance)
    let minimal = ErasureCodec::new(ErasureConfig::minimal());
    group.bench_function("minimal-4k", |b| {
        b.iter(|| minimal.encode(black_box(&data), 0))
    });
    
    // Balanced: 4+4 (100% overhead, 50% loss tolerance)
    let balanced = ErasureCodec::new(ErasureConfig::balanced());
    group.bench_function("balanced-4k", |b| {
        b.iter(|| balanced.encode(black_box(&data), 0))
    });
    
    // Resilient: 4+8 (200% overhead, 66% loss tolerance)
    let resilient = ErasureCodec::new(ErasureConfig::resilient());
    group.bench_function("resilient-4k", |b| {
        b.iter(|| resilient.encode(black_box(&data), 0))
    });
    
    group.finish();
}

/// Benchmark Reed-Solomon decoding (no loss)
fn benchmark_decode_no_loss(c: &mut Criterion) {
    let mut group = c.benchmark_group("ReedSolomon-Decode-NoLoss");
    
    let sizes = [1024, 4096, 16384];
    
    for size in sizes {
        let config = ErasureConfig::balanced();
        let codec = ErasureCodec::new(config);
        let data = random_data(size);
        let shards = codec.encode(&data, 0).unwrap();
        let original_len = data.len();
        
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &shards, |b, shards| {
            b.iter(|| {
                let decoded = codec.decode(black_box(shards), original_len).unwrap();
                black_box(decoded)
            })
        });
    }
    
    group.finish();
}

/// Benchmark Reed-Solomon decoding with shard loss
fn benchmark_decode_with_loss(c: &mut Criterion) {
    let mut group = c.benchmark_group("ReedSolomon-Decode-WithLoss");
    
    let data = random_data(4096);
    let config = ErasureConfig::balanced(); // k=4, n=8
    let codec = ErasureCodec::new(config);
    let all_shards = codec.encode(&data, 0).unwrap();
    let original_len = data.len();
    
    // Test with 1 shard lost (12.5% loss)
    let mut shards_1_lost = all_shards.clone();
    shards_1_lost.remove(0);
    group.bench_function("1-shard-lost", |b| {
        b.iter(|| codec.decode(black_box(&shards_1_lost), original_len))
    });
    
    // Test with 2 shards lost (25% loss)
    let mut shards_2_lost = all_shards.clone();
    shards_2_lost.remove(0);
    shards_2_lost.remove(0);
    group.bench_function("2-shards-lost", |b| {
        b.iter(|| codec.decode(black_box(&shards_2_lost), original_len))
    });
    
    // Test with 4 shards lost (50% loss - maximum for balanced)
    let mut shards_4_lost = all_shards.clone();
    shards_4_lost.truncate(4); // Keep only 4 shards
    group.bench_function("4-shards-lost", |b| {
        b.iter(|| codec.decode(black_box(&shards_4_lost), original_len))
    });
    
    group.finish();
}

/// Benchmark complete encode-decode cycle
fn benchmark_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ReedSolomon-RoundTrip");
    
    let sizes = [1024, 4096, 16384];
    
    for size in sizes {
        let data = random_data(size);
        let config = ErasureConfig::balanced();
        let codec = ErasureCodec::new(config);
        
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let shards = codec.encode(black_box(data), 0).unwrap();
                let decoded = codec.decode(black_box(&shards), data.len()).unwrap();
                assert_eq!(data, &decoded);
                black_box(decoded)
            })
        });
    }
    
    group.finish();
}

/// Benchmark overhead calculation
fn benchmark_overhead(c: &mut Criterion) {
    c.bench_function("overhead-stats", |b| {
        b.iter(|| {
            let minimal = ErasureConfig::minimal();
            let balanced = ErasureConfig::balanced();
            let resilient = ErasureConfig::resilient();
            
            println!("\n=== Reed-Solomon Erasure Coding Stats ===");
            println!("Minimal:   k={}, n={} -> {:.0}% overhead, {:.0}% loss tolerance",
                minimal.original_count, minimal.total_shards(),
                minimal.overhead_factor() * 100.0,
                minimal.loss_tolerance() * 100.0
            );
            println!("Balanced:  k={}, n={} -> {:.0}% overhead, {:.0}% loss tolerance",
                balanced.original_count, balanced.total_shards(),
                balanced.overhead_factor() * 100.0,
                balanced.loss_tolerance() * 100.0
            );
            println!("Resilient: k={}, n={} -> {:.0}% overhead, {:.0}% loss tolerance",
                resilient.original_count, resilient.total_shards(),
                resilient.overhead_factor() * 100.0,
                resilient.loss_tolerance() * 100.0
            );
        })
    });
}

criterion_group!(
    benches,
    benchmark_encode,
    benchmark_encode_profiles,
    benchmark_decode_no_loss,
    benchmark_decode_with_loss,
    benchmark_round_trip,
    benchmark_overhead,
);

criterion_main!(benches);
