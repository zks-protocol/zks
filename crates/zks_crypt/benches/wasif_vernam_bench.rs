use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput, black_box};
use zks_crypt::true_vernam::SynchronizedVernamBuffer;

fn benchmark_synchronized_vernam(c: &mut Criterion) {
    let mut group = c.benchmark_group("SynchronizedVernam");
    
    let seed = [0x42u8; 32];
    
    for size in [32, 64, 128, 512, 1024].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &s| {
            b.iter_batched(
                || SynchronizedVernamBuffer::new(seed),
                |buffer| black_box(buffer.consume_sync(s)),
                criterion::BatchSize::SmallInput
            )
        });
    }
    group.finish();
}

criterion_group!(benches, benchmark_synchronized_vernam);
criterion_main!(benches);