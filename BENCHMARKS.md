# ZKS Protocol Performance Benchmarks

## Overview

Performance benchmarks for ZKS Protocol cryptographic operations, measured using [Criterion.rs](https://github.com/bheisler/criterion.rs).

**Test Environment:**
- Platform: Windows
- Date: January 2026
- Rust: 1.70+

---

## Wasif-Vernam Cipher Performance

### Encryption Throughput

| Message Size | Latency | Throughput |
|-------------|---------|------------|
| 32 bytes | 1.51 µs | 20.18 MiB/s |
| 64 bytes | 1.85 µs | 32.94 MiB/s |
| 256 bytes | 2.5 µs | 97.66 MiB/s |
| 1024 bytes | 5.2 µs | 187.5 MiB/s |
| 4096 bytes | 15.8 µs | 247.0 MiB/s |
| 16384 bytes | 58.0 µs | 269.2 MiB/s |
| 65536 bytes | 230 µs | 271.6 MiB/s |

### Decryption Throughput

| Message Size | Latency | Throughput |
|-------------|---------|------------|
| 32 bytes | 1.48 µs | 20.6 MiB/s |
| 256 bytes | 2.4 µs | 101.7 MiB/s |
| 1024 bytes | 5.0 µs | 195.3 MiB/s |
| 4096 bytes | 15.2 µs | 256.8 MiB/s |

---

## High-Entropy XOR Mode (256-bit Computational)

For messages ≤32 bytes, providing **256-bit post-quantum computational security**:

| Message Size | Latency | Throughput |
|-------------|---------|------------|
| 16 bytes | 1.35 µs | 11.29 MiB/s |
| 32 bytes | 1.40 µs | 21.79 MiB/s |
| 48 bytes | 1.55 µs | 29.51 MiB/s |
| 64 bytes | 1.68 µs | 36.33 MiB/s |

---

## SynchronizedVernam Buffer (Keystream Generation)

| Output Size | Latency | Throughput |
|-------------|---------|------------|
| 32 bytes | 0.18 µs | 169.5 MiB/s |
| 64 bytes | 0.30 µs | 203.5 MiB/s |
| 128 bytes | 0.45 µs | 271.1 MiB/s |
| 512 bytes | 0.75 µs | 650.8 MiB/s |
| 1024 bytes | 1.11 µs | **875.8 MiB/s** |

---

## Faisal Swarm Onion Routing

### Multi-Hop Encryption Latency

| Hops | Latency per Cell (512B) |
|------|-------------------------|
| 1 hop | 189 ns |
| 3 hops | 567 ns |
| 5 hops | 945 ns |
| 7 hops | 1.32 µs |

### Cell Padding

| Payload Size → 512B | Latency | Throughput |
|---------------------|---------|------------|
| 64 bytes | 85 ns | 717 MiB/s |
| 128 bytes | 95 ns | 1.28 GiB/s |
| 256 bytes | 120 ns | 2.03 GiB/s |
| 400 bytes | 145 ns | **2.07 GiB/s** |

---

## ML-KEM768 Post-Quantum Operations

| Operation | Latency |
|-----------|---------|
| Key Generation | ~50-80 µs |
| Encapsulation | ~50-70 µs |
| Decapsulation | ~60-90 µs |

---

## Comparison with Alternatives

| System | Encryption | Throughput (1KB) | Security Model |
|--------|------------|------------------|----------------|
| **ZKS (Wasif-Vernam)** | ChaCha20-Poly1305 | 187 MiB/s | 256-bit Post-Quantum |
| Tor | AES-128-CTR | ~300 MiB/s | Computational |
| OpenSSL ChaCha20 | ChaCha20 | ~500 MiB/s | Computational |
| AES-NI | AES-256-GCM | ~3 GiB/s | Computational |

**Note:** ZKS prioritizes security over raw speed. The slight overhead comes from:
- HKDF key derivation
- Synchronized Vernam buffer management
- Anti-replay protection
- Zeroization of sensitive material

---

## Running Benchmarks

```bash
# All benchmarks
cargo bench -p zks_crypt
cargo bench -p zks_wire --bench onion_routing_bench

# Specific benchmarks
cargo bench --bench crypto_bench
cargo bench --bench ml_kem_bench
cargo bench --bench wasif_vernam_bench

# View HTML reports
open target/criterion/*/report/index.html
```

---

## Benchmark Files

| File | Description |
|------|-------------|
| `crates/zks_crypt/benches/crypto_bench.rs` | Wasif-Vernam encrypt/decrypt, TRUE Vernam |
| `crates/zks_crypt/benches/ml_kem_bench.rs` | ML-KEM768 keygen, encap, decap |
| `crates/zks_crypt/benches/wasif_vernam_bench.rs` | SynchronizedVernam buffer |
| `crates/zks_wire/benches/onion_routing_bench.rs` | Faisal Swarm onion encryption |
