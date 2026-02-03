use criterion::{criterion_group, criterion_main, Criterion};
use zks_pqcrypto::ml_kem::MlKem;
use zks_pqcrypto::incremental_mlkem::{self, generate, encaps1, encaps2, decaps};

/// Benchmark ML-KEM-768 keypair generation
fn benchmark_mlkem768_keygen(c: &mut Criterion) {
    c.bench_function("ML-KEM-768-Keygen", |b| {
        b.iter(|| MlKem::generate_keypair())
    });
}

/// Benchmark ML-KEM-1024 keypair generation (via incremental API)
fn benchmark_mlkem1024_keygen(c: &mut Criterion) {
    c.bench_function("ML-KEM-1024-Keygen", |b| {
        b.iter(|| generate())
    });
}

/// Benchmark ML-KEM-768 encapsulation
fn benchmark_mlkem768_encapsulate(c: &mut Criterion) {
    let keypair = MlKem::generate_keypair().unwrap();
    
    c.bench_function("ML-KEM-768-Encapsulate", |b| {
        b.iter(|| MlKem::encapsulate(&keypair.public_key))
    });
}

/// Benchmark ML-KEM-1024 encapsulation (full incremental)
fn benchmark_mlkem1024_encapsulate(c: &mut Criterion) {
    let keys = generate();
    
    c.bench_function("ML-KEM-1024-Encapsulate", |b| {
        b.iter(|| {
            let (ct1, es, ss) = encaps1(&keys.hdr).expect("encaps1");
            let ct2 = encaps2(&keys.ek, &es).expect("encaps2");
            (ct1, ct2, ss)
        })
    });
}

/// Benchmark ML-KEM-768 decapsulation
fn benchmark_mlkem768_decapsulate(c: &mut Criterion) {
    let keypair = MlKem::generate_keypair().unwrap();
    let encaps = MlKem::encapsulate(&keypair.public_key).unwrap();
    
    c.bench_function("ML-KEM-768-Decapsulate", |b| {
        b.iter(|| MlKem::decapsulate(&encaps.ciphertext, keypair.secret_key()))
    });
}

/// Benchmark ML-KEM-1024 decapsulation
fn benchmark_mlkem1024_decapsulate(c: &mut Criterion) {
    let keys = generate();
    let (ct1, es, _) = encaps1(&keys.hdr).expect("encaps1");
    let ct2 = encaps2(&keys.ek, &es).expect("encaps2");
    
    c.bench_function("ML-KEM-1024-Decapsulate", |b| {
        b.iter(|| decaps(&keys.dk, &ct1, &ct2))
    });
}

criterion_group!(
    benches,
    benchmark_mlkem768_keygen,
    benchmark_mlkem1024_keygen,
    benchmark_mlkem768_encapsulate,
    benchmark_mlkem1024_encapsulate,
    benchmark_mlkem768_decapsulate,
    benchmark_mlkem1024_decapsulate,
);
criterion_main!(benches);
