use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput, black_box};
use zks_crypt::wasif_vernam::WasifVernam;
use std::sync::{Arc, RwLock};

// Mock circuit layer for benchmarking
struct MockCircuitLayer {
    cipher: Arc<RwLock<WasifVernam>>,
}

impl MockCircuitLayer {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: Arc::new(RwLock::new(WasifVernam::new(key).unwrap())),
        }
    }
    
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        self.cipher.write().unwrap().encrypt(data).unwrap()
    }
}

fn benchmark_onion_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("FaisalSwarm-OnionEncrypt");
    
    for hops in [1, 3, 5, 7].iter() {
        let layers: Vec<_> = (0..*hops)
            .map(|i| MockCircuitLayer::new([i as u8; 32]))
            .collect();
        
        let payload = vec![0xAB; 512]; // Fixed cell size
        
        group.bench_with_input(BenchmarkId::from_parameter(hops), hops, |b, _| {
            b.iter(|| {
                let mut data = payload.clone();
                for layer in layers.iter().rev() {
                    data = layer.encrypt(&data);
                }
                black_box(data)
            })
        });
    }
    group.finish();
}

fn benchmark_cell_padding(c: &mut Criterion) {
    let mut group = c.benchmark_group("FaisalSwarm-CellPadding");
    
    for payload_size in [64, 128, 256, 400].iter() {
        let target_size = 512usize;
        let data = vec![0xAB; *payload_size];
        
        group.throughput(Throughput::Bytes(*payload_size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(payload_size), payload_size, |b, _| {
            b.iter(|| {
                let mut padded = data.clone();
                padded.resize(target_size, 0);
                black_box(padded)
            })
        });
    }
    group.finish();
}

criterion_group!(benches, benchmark_onion_encrypt, benchmark_cell_padding);
criterion_main!(benches);