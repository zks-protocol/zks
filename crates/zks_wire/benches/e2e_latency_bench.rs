//! End-to-End Latency Benchmarks for ZKS Protocol
//!
//! This benchmark measures simulated end-to-end latency for:
//! - Full handshake (3-message ML-KEM + ML-DSA)
//! - Swarm circuit construction (3-hop, 5-hop, 7-hop)
//! - Message encryption through circuit layers
//!
//! Note: These are local computation benchmarks. Network latency
//! would add additional overhead in real deployments.
//!
//! Run with: cargo bench --package zks_wire --bench e2e_latency_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use zks_pqcrypto::ml_kem::MlKem;
use zks_pqcrypto::ml_dsa::MlDsa;
use zks_crypt::wasif_vernam::WasifVernam;

/// Benchmark full handshake computation (excludes network RTT)
fn benchmark_handshake_compute(c: &mut Criterion) {
    let mut group = c.benchmark_group("E2E-Handshake-Compute");
    
    // Pre-generate identity keys (would be cached in real use)
    let alice_identity = MlDsa::generate_keypair().expect("keygen");
    let bob_identity = MlDsa::generate_keypair().expect("keygen");
    
    // Full 3-message handshake computation (client-side)
    group.bench_function("client-handshake-compute", |b| {
        b.iter(|| {
            // Message 1: Generate ephemeral ML-KEM keypair
            let ephemeral = MlKem::generate_keypair().expect("mlkem keygen");
            
            // Sign the ephemeral public key
            let sig = MlDsa::sign(
                &ephemeral.public_key,
                alice_identity.signing_key(),
            ).expect("sign");
            
            black_box((ephemeral, sig))
        })
    });
    
    // Full 3-message handshake computation (server-side)
    let alice_ephemeral = MlKem::generate_keypair().expect("keygen");
    
    group.bench_function("server-handshake-compute", |b| {
        b.iter(|| {
            // Message 2: Encapsulate to client's ephemeral key
            let encaps = MlKem::encapsulate(&alice_ephemeral.public_key).expect("encaps");
            
            // Generate our ephemeral keypair
            let our_ephemeral = MlKem::generate_keypair().expect("keygen");
            
            // Sign our response
            let response_data = [our_ephemeral.public_key.as_slice(), encaps.ciphertext.as_slice()].concat();
            let sig = MlDsa::sign(&response_data, bob_identity.signing_key()).expect("sign");
            
            black_box((encaps.shared_secret, our_ephemeral, sig))
        })
    });
    
    // Complete handshake (both sides, simulated)
    group.bench_function("full-handshake-both-sides", |b| {
        b.iter(|| {
            // Alice: Generate ephemeral
            let alice_eph = MlKem::generate_keypair().expect("keygen");
            let alice_sig = MlDsa::sign(&alice_eph.public_key, alice_identity.signing_key()).expect("sign");
            
            // Bob: Respond
            let bob_encaps = MlKem::encapsulate(&alice_eph.public_key).expect("encaps");
            let bob_eph = MlKem::generate_keypair().expect("keygen");
            let bob_response = [bob_eph.public_key.as_slice(), bob_encaps.ciphertext.as_slice()].concat();
            let bob_sig = MlDsa::sign(&bob_response, bob_identity.signing_key()).expect("sign");
            
            // Alice: Decapsulate and derive shared secret
            let alice_ss = MlKem::decapsulate(&bob_encaps.ciphertext, alice_eph.secret_key()).expect("decaps");
            
            // Alice: Encapsulate to Bob's ephemeral (for mutual auth)
            let alice_encaps = MlKem::encapsulate(&bob_eph.public_key).expect("encaps");
            
            // Bob: Decapsulate
            let bob_ss = MlKem::decapsulate(&alice_encaps.ciphertext, bob_eph.secret_key()).expect("decaps");
            
            black_box((alice_ss, bob_ss))
        })
    });
    
    group.finish();
}

/// Benchmark swarm circuit layer encryption (simulated multi-hop)
fn benchmark_circuit_layers(c: &mut Criterion) {
    let mut group = c.benchmark_group("E2E-Circuit-Layers");
    
    // Pre-generate layer keys
    let layer_keys: Vec<[u8; 32]> = (0..7)
        .map(|i| {
            let mut key = [0u8; 32];
            key[0] = i;
            getrandom::getrandom(&mut key[1..]).ok();
            key
        })
        .collect();
    
    let test_payload = vec![0u8; 512]; // Typical message size
    
    for hop_count in [3, 5, 7] {
        group.bench_with_input(
            BenchmarkId::new("encrypt-layers", hop_count),
            &hop_count,
            |b, &hops| {
                b.iter(|| {
                    let mut data = test_payload.clone();
                    
                    // Apply layers in reverse (onion routing)
                    for i in (0..hops).rev() {
                        let key = layer_keys[i as usize];
                        let mut cipher = WasifVernam::new(key).expect("cipher");
                        cipher.derive_base_iv(&key, true);
                        data = cipher.encrypt(&data).expect("encrypt");
                    }
                    
                    black_box(data)
                })
            },
        );
    }
    
    // Pre-encrypt for decrypt benchmarks
    let mut encrypted_3hop = test_payload.clone();
    for i in (0..3).rev() {
        let key = layer_keys[i];
        let mut cipher = WasifVernam::new(key).expect("cipher");
        cipher.derive_base_iv(&key, true);
        encrypted_3hop = cipher.encrypt(&encrypted_3hop).expect("encrypt");
    }
    
    group.bench_function("decrypt-3-layers", |b| {
        b.iter(|| {
            let mut data = encrypted_3hop.clone();
            
            for i in 0..3 {
                let key = layer_keys[i];
                let mut cipher = WasifVernam::new(key).expect("cipher");
                cipher.derive_base_iv(&key, true);
                data = cipher.decrypt(&data).expect("decrypt");
            }
            
            black_box(data)
        })
    });
    
    group.finish();
}

/// Paper claims validation: "18ms Swarm Circuit (3-hop)"
fn benchmark_paper_claims(c: &mut Criterion) {
    let mut group = c.benchmark_group("Paper-Claims-E2E");
    
    // Pre-generate all the keys needed for a 3-hop circuit
    let guard_key: [u8; 32] = {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).ok();
        k
    };
    let middle_key: [u8; 32] = {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).ok();
        k
    };
    let exit_key: [u8; 32] = {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).ok();
        k
    };
    
    let alice_identity = MlDsa::generate_keypair().expect("keygen");
    
    // Full simulated 3-hop circuit creation (computation only)
    // In reality, this also has network RTT, but we measure crypto overhead
    group.bench_function("3-hop-circuit-crypto-only", |b| {
        b.iter(|| {
            // Step 1: Establish with guard (ML-KEM handshake)
            let guard_eph = MlKem::generate_keypair().expect("keygen");
            let guard_encaps = MlKem::encapsulate(&guard_eph.public_key).expect("encaps");
            let _guard_ss = MlKem::decapsulate(&guard_encaps.ciphertext, guard_eph.secret_key()).expect("decaps");
            
            // Step 2: Extend to middle (through guard)
            let middle_eph = MlKem::generate_keypair().expect("keygen");
            let middle_encaps = MlKem::encapsulate(&middle_eph.public_key).expect("encaps");
            let _middle_ss = MlKem::decapsulate(&middle_encaps.ciphertext, middle_eph.secret_key()).expect("decaps");
            
            // Step 3: Extend to exit (through guard + middle)
            let exit_eph = MlKem::generate_keypair().expect("keygen");
            let exit_encaps = MlKem::encapsulate(&exit_eph.public_key).expect("encaps");
            let _exit_ss = MlKem::decapsulate(&exit_encaps.ciphertext, exit_eph.secret_key()).expect("decaps");
            
            // Apply onion layers to a test message
            let payload = vec![0u8; 256];
            let mut data = payload;
            
            // Encrypt with each layer key
            let mut exit_cipher = WasifVernam::new(exit_key).expect("cipher");
            exit_cipher.derive_base_iv(&exit_key, true);
            data = exit_cipher.encrypt(&data).expect("encrypt");
            
            let mut middle_cipher = WasifVernam::new(middle_key).expect("cipher");
            middle_cipher.derive_base_iv(&middle_key, true);
            data = middle_cipher.encrypt(&data).expect("encrypt");
            
            let mut guard_cipher = WasifVernam::new(guard_key).expect("cipher");
            guard_cipher.derive_base_iv(&guard_key, true);
            data = guard_cipher.encrypt(&data).expect("encrypt");
            
            black_box(data)
        })
    });
    
    group.finish();
}

/// Comparative baseline: measure just ML-KEM vs claimed NIST reference times
fn benchmark_comparative_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("Comparative-Baseline");
    
    // Our ML-KEM-768 (for comparison)
    group.bench_function("ZKS-ML-KEM-768-keygen", |b| {
        b.iter(|| {
            let kp = MlKem::generate_keypair();
            black_box(kp)
        })
    });
    
    let kp768 = MlKem::generate_keypair().expect("keygen");
    group.bench_function("ZKS-ML-KEM-768-encaps", |b| {
        b.iter(|| {
            let enc = MlKem::encapsulate(&kp768.public_key);
            black_box(enc)
        })
    });
    
    let enc768 = MlKem::encapsulate(&kp768.public_key).expect("encaps");
    group.bench_function("ZKS-ML-KEM-768-decaps", |b| {
        b.iter(|| {
            let ss = MlKem::decapsulate(&enc768.ciphertext, kp768.secret_key());
            black_box(ss)
        })
    });
    
    // ML-DSA-87 (our signature algorithm)
    group.bench_function("ZKS-ML-DSA-87-keygen", |b| {
        b.iter(|| {
            let kp = MlDsa::generate_keypair();
            black_box(kp)
        })
    });
    
    let dsa_kp = MlDsa::generate_keypair().expect("keygen");
    let msg = b"benchmark test message for signing";
    group.bench_function("ZKS-ML-DSA-87-sign", |b| {
        b.iter(|| {
            let sig = MlDsa::sign(black_box(msg), dsa_kp.signing_key());
            black_box(sig)
        })
    });
    
    let sig = MlDsa::sign(msg, dsa_kp.signing_key()).expect("sign");
    group.bench_function("ZKS-ML-DSA-87-verify", |b| {
        b.iter(|| {
            let result = MlDsa::verify(black_box(msg), &sig, dsa_kp.verifying_key());
            black_box(result)
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_handshake_compute,
    benchmark_circuit_layers,
    benchmark_paper_claims,
    benchmark_comparative_baseline,
);
criterion_main!(benches);
