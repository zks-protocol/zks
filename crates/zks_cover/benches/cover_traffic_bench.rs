use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;
use zks_cover::{CoverConfig, CoverGenerator, CoverScheduler};

/// Benchmark cover message generation
fn bench_cover_generation(c: &mut Criterion) {
    let runtime = Runtime::new().expect("Failed to create runtime");
    
    let config = CoverConfig::builder()
        .payload_size(512)
        .build()
        .expect("Failed to build config");
    
    let generator = runtime.block_on(async {
        CoverGenerator::new(config).expect("Failed to create generator")
    });
    
    c.bench_function("cover_generation_single", |b| {
        b.iter(|| {
            runtime.block_on(async {
                generator.generate_cover(black_box(Some("bench_circuit".to_string()))).await
            })
        });
    });
    
    c.bench_function("cover_generation_no_circuit", |b| {
        b.iter(|| {
            runtime.block_on(async {
                generator.generate_cover(black_box(None)).await
            })
        });
    });
}

/// Benchmark batch cover generation
fn bench_cover_batch_generation(c: &mut Criterion) {
    let runtime = Runtime::new().expect("Failed to create runtime");
    
    let config = CoverConfig::builder()
        .payload_size(512)
        .build()
        .expect("Failed to build config");
    
    let generator = runtime.block_on(async {
        CoverGenerator::new(config).expect("Failed to create generator")
    });
    
    c.bench_function("cover_batch_5", |b| {
        b.iter(|| {
            runtime.block_on(async {
                generator.generate_batch_cover(black_box(5), black_box(Some("bench_circuit".to_string()))).await
            })
        });
    });
    
    c.bench_function("cover_batch_10", |b| {
        b.iter(|| {
            runtime.block_on(async {
                generator.generate_batch_cover(black_box(10), black_box(Some("bench_circuit".to_string()))).await
            })
        });
    });
    
    c.bench_function("cover_batch_20", |b| {
        b.iter(|| {
            runtime.block_on(async {
                generator.generate_batch_cover(black_box(20), black_box(Some("bench_circuit".to_string()))).await
            })       });
    });
}

/// Benchmark adaptive cover generation
fn bench_adaptive_cover_generation(c: &mut Criterion) {
    let runtime = Runtime::new().expect("Failed to create runtime");
    
    let config = CoverConfig::builder()
        .payload_size(512)
        .build()
        .expect("Failed to build config");
    
    let generator = runtime.block_on(async {
        CoverGenerator::new(config).expect("Failed to create generator")
    });
    
    c.bench_function("adaptive_cover_low_load", |b| {
        b.iter(|| {
            runtime.block_on(async {
                generator.generate_cover_with_load(black_box(Some("bench_circuit".to_string())), black_box(0.1)).await
            })
        });
    });
    
    c.bench_function("adaptive_cover_high_load", |b| {
        b.iter(|| {
            runtime.block_on(async {
                generator.generate_cover_with_load(black_box(Some("bench_circuit".to_string())), black_box(0.9)).await
            })
        });
    });
}

/// Benchmark cover scheduler operations
fn bench_cover_scheduler(c: &mut Criterion) {
    let config = CoverConfig::builder()
        .poisson_rate(1.0)
        .build()
        .expect("Failed to build config");
    
    let scheduler = CoverScheduler::new(config);
    
    c.bench_function("scheduler_next_time", |b| {
        b.iter(|| {
            scheduler.next_cover_time()
        });
    });
    
    c.bench_function("scheduler_rate_calculation", |b| {
        b.iter(|| {
            let _rate = scheduler.rate();
        });
    });
}

/// Benchmark cover config creation
fn bench_cover_config(c: &mut Criterion) {
    c.bench_function("config_builder", |b| {
        b.iter(|| {
            CoverConfig::builder()
                .payload_size(black_box(512))
                .poisson_rate(black_box(1.0))
                .build()
        });
    });
    
    c.bench_function("config_builder_with_scenario", |b| {
        b.iter(|| {
            CoverConfig::builder()
                .payload_size(black_box(512))
                .poisson_rate(black_box(1.0))
                .scenario(black_box(zks_cover::CoverScenario::Adaptive))
                .build()
        });
    });
}

/// Benchmark memory usage patterns
fn bench_memory_patterns(c: &mut Criterion) {
    let runtime = Runtime::new().expect("Failed to create runtime");
    
    c.bench_function("memory_allocation_512b", |b| {
        b.iter(|| {
            let _payload = vec![0u8; 512];
        });
    });
    
    c.bench_function("memory_allocation_1024b", |b| {
        b.iter(|| {
            let _payload = vec![0u8; 1024];
        });
    });
    
    let config = CoverConfig::builder()
        .payload_size(512)
        .build()
        .expect("Failed to build config");
    
    let generator = runtime.block_on(async {
        CoverGenerator::new(config).expect("Failed to create generator")
    });
    
    c.bench_function("cover_with_zeroize", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let msg = generator.generate_cover(Some("bench_circuit".to_string())).await
                    .expect("Failed to generate cover");
                // Zeroize happens automatically on drop
                drop(msg);
            })
        });
    });
}

criterion_group!(
    benches,
    bench_cover_generation,
    bench_cover_batch_generation,
    bench_adaptive_cover_generation,
    bench_cover_scheduler,
    bench_cover_config,
    bench_memory_patterns
);

criterion_main!(benches);