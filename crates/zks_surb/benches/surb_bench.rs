use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;
use zks_surb::{ZksSurb, SurbConfig, SurbEncryption, MemorySurbStorage, SurbStorage};

/// Benchmark SURB creation
fn bench_surb_creation(c: &mut Criterion) {
    let runtime = Runtime::new().expect("Failed to create runtime");
    
    // Generate test ML-KEM public key
    let pk = generate_test_ml_kem_public_key();
    
    c.bench_function("surb_create", |b| {
        b.iter(|| {
            runtime.block_on(async {
                ZksSurb::create(black_box(&pk))
            })
        });
    });
    
    let config = SurbConfig::builder()
        .lifetime(3600)
        .build()
        .expect("Failed to build config");
    
    c.bench_function("surb_create_with_config", |b| {
        b.iter(|| {
            runtime.block_on(async {
                ZksSurb::create_with_config(black_box(&pk), black_box(&config))
            })
        });
    });
}

/// Benchmark SURB encryption
fn bench_surb_encryption(c: &mut Criterion) {
    let runtime = Runtime::new().expect("Failed to create runtime");
    
    let pk = generate_test_ml_kem_public_key();
    let surb = runtime.block_on(async {
        ZksSurb::create(&pk).expect("Failed to create SURB")
    });
    
    let encryption = SurbEncryption::from_surb(&surb)
        .expect("Failed to create encryption");
    
    let test_payloads = vec![
        vec![0u8; 32],     // Small payload
        vec![0u8; 256],    // Medium payload
        vec![0u8; 1024],   // Large payload
        vec![0u8; 4096],   // Very large payload
    ];
    
    for (i, payload) in test_payloads.iter().enumerate() {
        let size = payload.len();
        c.bench_function(&format!("surb_encrypt_{}b", size), |b| {
            b.iter(|| {
                encryption.encrypt(black_box(payload))
            })
        });
    }
}

/// Benchmark SURB decryption
fn bench_surb_decryption(c: &mut Criterion) {
    let runtime = Runtime::new().expect("Failed to create runtime");
    
    let pk = generate_test_ml_kem_public_key();
    let surb = runtime.block_on(async {
        ZksSurb::create(&pk).expect("Failed to create SURB")
    });
    
    let encryption = SurbEncryption::from_surb(&surb)
        .expect("Failed to create encryption");
    
    // Pre-encrypt test payloads
    let test_payloads = vec![
        vec![0u8; 32],
        vec![0u8; 256],
        vec![0u8; 1024],
    ];
    
    let encrypted_payloads: Vec<_> = test_payloads.iter()
        .map(|payload| encryption.encrypt(payload).expect("Failed to encrypt"))
        .collect();
    
    for (i, encrypted) in encrypted_payloads.iter().enumerate() {
        let size = test_payloads[i].len();
        c.bench_function(&format!("surb_decrypt_{}b", size), |b| {
            b.iter(|| {
                encryption.decrypt(black_box(encrypted))
            })
        });
    }
}

/// Benchmark SURB storage operations
fn bench_surb_storage(c: &mut Criterion) {
    let runtime = Runtime::new().expect("Failed to create runtime");
    
    let storage = MemorySurbStorage::new();
    let pk = generate_test_ml_kem_public_key();
    
    // Pre-create some SURBs for testing
    let surbs: Vec<_> = (0..10)
        .map(|_| runtime.block_on(async {
            ZksSurb::create(&pk).expect("Failed to create SURB")
        }))
        .collect();
    
    c.bench_function("surb_storage_store", |b| {
        b.iter(|| {
            let surb = surbs[0].clone();
            runtime.block_on(async {
                storage.store_surb(black_box(surb))
            })
        });
    });
    
    c.bench_function("surb_storage_get", |b| {
        runtime.block_on(async {
            storage.store_surb(surbs[1].clone()).await
                .expect("Failed to store SURB");
        });
        
        b.iter(|| {
            runtime.block_on(async {
                storage.get_surb(black_box(surbs[1].id()))
            })
        });
    });
    
    c.bench_function("surb_storage_has", |b| {
        runtime.block_on(async {
            storage.store_surb(surbs[2].clone()).await
                .expect("Failed to store SURB");
        });
        
        b.iter(|| {
            runtime.block_on(async {
                storage.has_surb(black_box(surbs[2].id()))
            })
        });
    });
    
    c.bench_function("surb_storage_count", |b| {
        b.iter(|| {
            runtime.block_on(async {
                storage.count()
            })
        });
    });
}

/// Benchmark SURB serialization
fn bench_surb_serialization(c: &mut Criterion) {
    let runtime = Runtime::new().expect("Failed to create runtime");
    
    let pk = generate_test_ml_kem_public_key();
    let surb = runtime.block_on(async {
        ZksSurb::create(&pk).expect("Failed to create SURB")
    });
    
    c.bench_function("surb_serialize_json", |b| {
        b.iter(|| {
            serde_json::to_string(black_box(&surb))
        });
    });
    
    c.bench_function("surb_deserialize_json", |b| {
        let serialized = serde_json::to_string(&surb).expect("Failed to serialize");
        b.iter(|| {
            serde_json::from_str::<ZksSurb>(black_box(&serialized))
        });
    });
    
    c.bench_function("surb_serialize_bincode", |b| {
        b.iter(|| {
            bincode::serialize(black_box(&surb))
        });
    });
}

/// Benchmark complete SURB workflow
fn bench_surb_workflow(c: &mut Criterion) {
    let runtime = Runtime::new().expect("Failed to create runtime");
    
    c.bench_function("surb_complete_workflow", |b| {
        b.iter(|| {
            runtime.block_on(async {
                // 1. Create SURB
                let pk = generate_test_ml_kem_public_key();
                let surb = ZksSurb::create(&pk).expect("Failed to create SURB");
                
                // 2. Create encryption
                let encryption = SurbEncryption::from_surb(&surb)
                    .expect("Failed to create encryption");
                
                // 3. Encrypt message
                let message = b"Anonymous reply message";
                let encrypted = encryption.encrypt(message)
                    .expect("Failed to encrypt");
                
                // 4. Decrypt message
                let decrypted = encryption.decrypt(&encrypted)
                    .expect("Failed to decrypt");
                
                assert_eq!(decrypted, message.to_vec());
            })
        });
    });
}

/// Helper function to generate test ML-KEM public key
fn generate_test_ml_kem_public_key() -> Vec<u8> {
    // In a real implementation, this would use the actual ML-KEM crate
    // For benchmarking, we return a deterministic test key
    let mut pk = vec![0u8; 1184]; // ML-KEM-768 public key size
    for (i, byte) in pk.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    pk
}

criterion_group!(
    benches,
    bench_surb_creation,
    bench_surb_encryption,
    bench_surb_decryption,
    bench_surb_storage,
    bench_surb_serialization,
    bench_surb_workflow
);

criterion_main!(benches);