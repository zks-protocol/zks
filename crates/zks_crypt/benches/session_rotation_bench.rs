//! Performance benchmarks for Session Rotation
//!
//! This benchmark measures session rotation operations:
//! - Session creation
//! - Session rotation (with new secret)
//! - Message key derivation
//! - Rotation check overhead
//!
//! Run with: cargo bench --package zks_crypt --bench session_rotation_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::time::Duration;
use zks_crypt::session_rotation::{RotatingSession, SessionRotationConfig};

/// Benchmark session creation
fn benchmark_session_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("SessionRotation-Create");
    
    let initial_secret = [0x42u8; 32];
    
    group.bench_function("default-config", |b| {
        b.iter(|| {
            let session = RotatingSession::new(
                black_box(initial_secret),
                black_box(1000000),
                SessionRotationConfig::default(),
            );
            black_box(session)
        })
    });
    
    group.bench_function("custom-interval-60s", |b| {
        b.iter(|| {
            let session = RotatingSession::new(
                black_box(initial_secret),
                black_box(1000000),
                SessionRotationConfig::with_interval(Duration::from_secs(60)),
            );
            black_box(session)
        })
    });
    
    group.bench_function("manual-only", |b| {
        b.iter(|| {
            let session = RotatingSession::new(
                black_box(initial_secret),
                black_box(1000000),
                SessionRotationConfig::manual_only(),
            );
            black_box(session)
        })
    });
    
    group.finish();
}

/// Benchmark session rotation (paper claim: 8.4ms)
fn benchmark_rotation(c: &mut Criterion) {
    let mut group = c.benchmark_group("SessionRotation-Rotate");
    
    let initial_secret = [0x42u8; 32];
    let mut session = RotatingSession::new(
        initial_secret,
        1000000,
        SessionRotationConfig::default(),
    );
    
    // Pre-generate new secrets for rotation
    let new_secrets: Vec<[u8; 32]> = (0..1000u64)
        .map(|i| {
            let mut s = [0u8; 32];
            s[0..8].copy_from_slice(&i.to_le_bytes());
            getrandom::getrandom(&mut s[8..]).ok();
            s
        })
        .collect();
    
    let mut idx = 0;
    
    group.bench_function("rotate-with-new-secret", |b| {
        b.iter(|| {
            let secret = new_secrets[idx % new_secrets.len()];
            session.rotate(black_box(secret), black_box(2000000 + idx as u64));
            idx += 1;
        })
    });
    
    group.finish();
}

/// Benchmark message key derivation
fn benchmark_message_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("SessionRotation-KeyDerivation");
    
    let session = RotatingSession::new(
        [0x42u8; 32],
        1000000,
        SessionRotationConfig::default(),
    );
    
    group.bench_function("derive-single-key", |b| {
        let mut msg_num = 0u64;
        b.iter(|| {
            let key = session.derive_message_key(black_box(msg_num));
            msg_num += 1;
            black_box(key)
        })
    });
    
    // Throughput: derive 1000 message keys
    group.throughput(Throughput::Elements(1000));
    group.bench_function("derive-1000-keys", |b| {
        b.iter(|| {
            for i in 0..1000u64 {
                let key = session.derive_message_key(black_box(i));
                black_box(key);
            }
        })
    });
    
    group.finish();
}

/// Benchmark rotation check overhead
fn benchmark_rotation_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("SessionRotation-CheckOverhead");
    
    let session = RotatingSession::new(
        [0x42u8; 32],
        1000000,
        SessionRotationConfig::default(),
    );
    
    group.bench_function("needs-rotation-check", |b| {
        b.iter(|| {
            let needs = session.needs_rotation();
            black_box(needs)
        })
    });
    
    group.bench_function("check-rotation", |b| {
        b.iter(|| {
            let rotated = session.check_rotation();
            black_box(rotated)
        })
    });
    
    group.finish();
}

/// Paper claims validation benchmark
fn benchmark_paper_claims(c: &mut Criterion) {
    let mut group = c.benchmark_group("Paper-Claims-SessionRotation");
    
    let initial_secret = [0x42u8; 32];
    let mut session = RotatingSession::new(
        initial_secret,
        1000000,
        SessionRotationConfig::default(),
    );
    
    // Paper claim: "8.4ms Session Rotation"
    // This should match the full rotation including zeroization and re-keying
    group.bench_function("session-rotation-full", |b| {
        let mut round = 2000000u64;
        b.iter(|| {
            let mut new_secret = [0u8; 32];
            getrandom::getrandom(&mut new_secret).ok();
            session.rotate(black_box(new_secret), black_box(round));
            round += 1;
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_session_creation,
    benchmark_rotation,
    benchmark_message_key_derivation,
    benchmark_rotation_check,
    benchmark_paper_claims,
);
criterion_main!(benches);
