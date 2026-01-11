//! Performance benchmarks for ZKS cryptographic operations
//!
//! Run with: cargo bench --package zks_crypt

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput, BenchmarkId};
use zks_crypt::prelude::WasifVernam;

/// Generate random bytes for benchmarking
fn random_bytes(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Benchmark WasifVernam encryption throughput
fn benchmark_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("wasif_vernam_encrypt");
    
    // Test different message sizes
    let sizes = [32, 64, 256, 1024, 4096, 16384, 65536];
    
    for size in sizes {
        // Create cipher
        let key: [u8; 32] = random_bytes(32).try_into().unwrap();
        let mut cipher = WasifVernam::new(key).expect("Failed to create cipher");
        
        // Prepare data
        let data = random_bytes(size);
        
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let encrypted = cipher.encrypt(black_box(data)).unwrap();
                black_box(encrypted)
            })
        });
    }
    
    group.finish();
}

/// Benchmark TRUE Vernam (OTP) encryption for small messages
fn benchmark_true_vernam(c: &mut Criterion) {
    let mut group = c.benchmark_group("true_vernam_encrypt");
    
    // TRUE OTP is for small messages only
    let sizes = [16, 32, 48, 64];
    
    for size in sizes {
        let key: [u8; 32] = random_bytes(32).try_into().unwrap();
        let mut cipher = WasifVernam::new(key).expect("Failed to create cipher");
        
        // Enable synchronized Vernam mode
        let shared_seed: [u8; 32] = random_bytes(32).try_into().unwrap();
        cipher.enable_synchronized_vernam(shared_seed);
        
        let data = random_bytes(size);
        
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let encrypted = cipher.encrypt_true_vernam(black_box(data)).unwrap();
                black_box(encrypted)
            })
        });
    }
    
    group.finish();
}

/// Benchmark decryption
fn benchmark_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("wasif_vernam_decrypt");
    
    let sizes = [32, 256, 1024, 4096];
    
    for size in sizes {
        let key: [u8; 32] = random_bytes(32).try_into().unwrap();
        
        // Create cipher and encrypt data once
        let mut encrypt_cipher = WasifVernam::new(key).expect("Failed to create cipher");
        let data = random_bytes(size);
        let encrypted = encrypt_cipher.encrypt(&data).unwrap();
        
        // Clone key for decrypt cipher - use same cipher that encrypted
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &encrypted, |b, encrypted| {
            b.iter(|| {
                // Decrypt with same cipher state
                let decrypted = encrypt_cipher.decrypt(black_box(encrypted)).unwrap();
                black_box(decrypted)
            })
        });
    }
    
    group.finish();
}

/// Benchmark key generation and cipher setup
fn benchmark_setup(c: &mut Criterion) {
    c.bench_function("cipher_new", |b| {
        b.iter(|| {
            let key: [u8; 32] = random_bytes(32).try_into().unwrap();
            let cipher = WasifVernam::new(black_box(key)).unwrap();
            black_box(cipher)
        })
    });
    
    c.bench_function("create_shared_seed", |b| {
        let mlkem: [u8; 32] = random_bytes(32).try_into().unwrap();
        let drand: [u8; 32] = random_bytes(32).try_into().unwrap();
        let peer: [u8; 32] = random_bytes(32).try_into().unwrap();
        
        b.iter(|| {
            let seed = WasifVernam::create_shared_seed(
                black_box(mlkem),
                black_box(drand),
                black_box(peer),
            );
            black_box(seed)
        })
    });
}

criterion_group!(
    benches,
    benchmark_encrypt,
    benchmark_decrypt,
    benchmark_true_vernam,
    benchmark_setup,
);

criterion_main!(benches);

