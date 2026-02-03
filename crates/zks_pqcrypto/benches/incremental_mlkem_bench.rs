//! Performance benchmarks for Incremental ML-KEM-1024
//!
//! Run with: cargo bench --package zks_pqcrypto

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use zks_pqcrypto::incremental_mlkem::{
    self, generate, encaps1, encaps2, decaps,
    HEADER_SIZE, ENCAPSULATION_KEY_SIZE, CIPHERTEXT1_SIZE, CIPHERTEXT2_SIZE,
};
use zks_pqcrypto::ml_kem::MlKem;

/// Benchmark incremental keypair generation vs naive
fn benchmark_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-1024-Keygen");
    
    group.bench_function("incremental", |b| {
        b.iter(|| {
            let keys = generate();
            black_box(keys)
        })
    });
    
    group.bench_function("naive-768", |b| {
        b.iter(|| {
            let keypair = MlKem::generate_keypair();
            black_box(keypair)
        })
    });
    
    group.finish();
}

/// Benchmark incremental encapsulation phases
fn benchmark_encapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-1024-Encapsulate");
    
    let keys = generate();
    
    // Phase 1: Header only (can be cached)
    group.bench_function("encaps1-header-only", |b| {
        b.iter(|| {
            let result = encaps1(black_box(&keys.hdr));
            black_box(result)
        })
    });
    
    // Phase 2: Complete with EK
    group.bench_function("encaps2-with-ek", |b| {
        let (_, encaps_state, _) = encaps1(&keys.hdr).expect("encaps1");
        b.iter(|| {
            let ct2 = encaps2(black_box(&keys.ek), black_box(&encaps_state));
            black_box(ct2)
        })
    });
    
    // Full incremental encapsulation (both phases)
    group.bench_function("full-incremental", |b| {
        b.iter(|| {
            let (ct1, es, ss) = encaps1(black_box(&keys.hdr)).expect("encaps1");
            let ct2 = encaps2(black_box(&keys.ek), black_box(&es)).expect("encaps2");
            black_box((ct1, ct2, ss))
        })
    });
    
    // Naive ML-KEM-768 for comparison
    group.bench_function("naive-768-full", |b| {
        let keypair = MlKem::generate_keypair().unwrap();
        b.iter(|| {
            let encaps = MlKem::encapsulate(black_box(&keypair.public_key));
            black_box(encaps)
        })
    });
    
    group.finish();
}

/// Benchmark decapsulation
fn benchmark_decapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-1024-Decapsulate");
    
    let keys = generate();
    let (ct1, es, _) = encaps1(&keys.hdr).expect("encaps1");
    let ct2 = encaps2(&keys.ek, &es).expect("encaps2");
    
    group.bench_function("incremental-decaps", |b| {
        b.iter(|| {
            let ss = decaps(
                black_box(&keys.dk),
                black_box(&ct1),
                black_box(&ct2),
            );
            black_box(ss)
        })
    });
    
    // Naive ML-KEM-768 for comparison
    let keypair = MlKem::generate_keypair().unwrap();
    let encaps = MlKem::encapsulate(&keypair.public_key).unwrap();
    
    group.bench_function("naive-768-decaps", |b| {
        b.iter(|| {
            let ss = MlKem::decapsulate(
                black_box(&encaps.ciphertext),
                black_box(keypair.secret_key()),
            );
            black_box(ss)
        })
    });
    
    group.finish();
}

/// Benchmark complete round-trip
fn benchmark_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-1024-RoundTrip");
    
    group.bench_function("incremental-complete", |b| {
        b.iter(|| {
            // Keygen
            let keys = generate();
            // Encapsulate
            let (ct1, es, ss1) = encaps1(&keys.hdr).expect("encaps1");
            let ct2 = encaps2(&keys.ek, &es).expect("encaps2");
            // Decapsulate
            let ss2 = decaps(&keys.dk, &ct1, &ct2).expect("decaps");
            assert_eq!(ss1, ss2);
            black_box((ct1, ct2, ss2))
        })
    });
    
    group.bench_function("naive-768-complete", |b| {
        b.iter(|| {
            // Keygen
            let keypair = MlKem::generate_keypair().unwrap();
            // Encapsulate
            let encaps = MlKem::encapsulate(&keypair.public_key).unwrap();
            // Decapsulate
            let ss = MlKem::decapsulate(&encaps.ciphertext, keypair.secret_key()).unwrap();
            black_box(ss)
        })
    });
    
    group.finish();
}

/// Print size information for documentation
fn benchmark_sizes(c: &mut Criterion) {
    c.bench_function("print-sizes", |b| {
        b.iter(|| {
            println!("\n=== ML-KEM-1024 Incremental Sizes ===");
            println!("Header (pk1):        {} bytes", HEADER_SIZE);
            println!("EK (pk2):            {} bytes", ENCAPSULATION_KEY_SIZE);
            println!("Ciphertext1:         {} bytes", CIPHERTEXT1_SIZE);
            println!("Ciphertext2:         {} bytes", CIPHERTEXT2_SIZE);
            println!("Total incremental:   {} bytes", CIPHERTEXT1_SIZE + CIPHERTEXT2_SIZE);
            println!("Naive ML-KEM-1024:   3136 bytes (1568 + 1568)");
            println!("Bandwidth savings:   {:.1}%", incremental_mlkem::bandwidth_savings_percent());
        })
    });
}

criterion_group!(
    benches,
    benchmark_keygen,
    benchmark_encapsulate,
    benchmark_decapsulate,
    benchmark_round_trip,
    benchmark_sizes,
);

criterion_main!(benches);
