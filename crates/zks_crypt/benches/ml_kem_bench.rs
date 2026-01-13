use criterion::{criterion_group, criterion_main, Criterion};
use zks_pqcrypto::ml_kem::MlKem;

fn benchmark_keygen(c: &mut Criterion) {
    c.bench_function("ML-KEM768-Keygen", |b| {
        b.iter(|| MlKem::generate_keypair())
    });
}

fn benchmark_encapsulate(c: &mut Criterion) {
    let keypair = MlKem::generate_keypair().unwrap();
    
    c.bench_function("ML-KEM768-Encapsulate", |b| {
        b.iter(|| MlKem::encapsulate(&keypair.public_key))
    });
}

fn benchmark_decapsulate(c: &mut Criterion) {
    let keypair = MlKem::generate_keypair().unwrap();
    let encaps = MlKem::encapsulate(&keypair.public_key).unwrap();
    
    c.bench_function("ML-KEM768-Decapsulate", |b| {
        b.iter(|| MlKem::decapsulate(&encaps.ciphertext, keypair.secret_key()))
    });
}

criterion_group!(benches, benchmark_keygen, benchmark_encapsulate, benchmark_decapsulate);
criterion_main!(benches);