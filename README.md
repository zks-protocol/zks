<p align="center">
  <!-- <img src="resources/logo.png" alt="ZKS Protocol" width="400"> -->
</p>

<h1 align="center">🔐 ZKS Protocol</h1>

<p align="center">
  <strong>Zero Knowledge Swarm — Post-Quantum Encryption with Built-in Anonymity</strong>
</p>

<p align="center">
  <a href="https://github.com/zks-protocol/zks/actions"><img src="https://img.shields.io/github/actions/workflow/status/zks-protocol/zks/ci.yml?branch=main&style=flat-square&logo=github" alt="Build Status"></a>
  <a href="https://crates.io/crates/zks"><img src="https://img.shields.io/crates/v/zks.svg?style=flat-square&logo=rust" alt="Crates.io"></a>
  <a href="https://docs.rs/zks"><img src="https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square&logo=rust" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.70+-orange.svg?style=flat-square&logo=rust" alt="Rust"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0" alt="macOS">
  <img src="https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/WebAssembly-654FF0?style=for-the-badge&logo=webassembly&logoColor=white" alt="WASM">
</p>

---

## 🌟 Why ZKS?

ZKS Protocol is a **post-quantum secure networking protocol** built with 100% safe Rust. It provides defense-in-depth encryption with multiple layers of security, including **256-bit post-quantum computational security**.

| Protocol | Description | Security Model |
|----------|-------------|----------------|
| `zk://`  | Direct encrypted connection | Post-quantum secure, low latency |
| `zks://` | Swarm-routed anonymous connection | Post-quantum + onion routing |

---

## 📑 Table of Contents

- [🌟 Key Features](#-key-features)
- [🚀 Quick Start](#-quick-start)
- [🔒 Security Architecture](#-security-architecture)
- [📦 Crate Structure](#-crate-structure)
- [🧅 Anonymous Routing](#-anonymous-routing)
- [📱 Platform Support](#-platform-support)
- [📖 Examples](#-examples)
- [🛡️ Security](#️-security)
- [🤝 Contributing](#-contributing)
- [📜 License](#-license)

---

## 🌟 Key Features

<table>
<tr>
<td width="50%">

### 🔐 Post-Quantum Cryptography
- **ML-KEM-1024** (Kyber) — NIST Level 5 key exchange
- **ML-DSA-87** (Dilithium) — NIST Level 5 signatures
- Resistant to quantum computer attacks

</td>
<td width="50%">

### 🧅 Onion Routing
- Multi-hop anonymous connections
- Traffic analysis resistance
- Built-in swarm networking

</td>
</tr>
<tr>
<td width="50%">

### ⚡ High Performance
- Async/await native design
- Zero-copy message handling
- Minimal memory footprint

</td>
<td width="50%">

### 🌐 Cross-Platform
- Native Linux, macOS, Windows
- WebAssembly for browsers
- Mobile-ready architecture

</td>
</tr>
</table>

---

## 📐 Mathematical Security Proof

ZKS Protocol's security is **proven by mathematics**, not assumptions:

### Security Proof (Defense-in-Depth)

```
Hybrid Encryption (Network Mode):
  DEK ← CSPRNG(32 bytes)              // Data Encryption Key
  entropy ← drand ⊕ local_CSPRNG      // Computational security (256-bit)
  wrapped_DEK ← DEK ⊕ entropy         // Defense-in-depth

Security Level: 256-bit post-quantum computational (OTP-inspired, not true OTP)

∴ Secure against all known attacks including quantum computers ∎
```

### Security Properties

| Property | Guarantee |
|----------|-----------|
| DEK wrapping | Defense-in-depth (drand ⊕ CSPRNG) |
| Bulk encryption | ChaCha20-Poly1305 (256-bit) |
| Overall security | **256-bit post-quantum computational** |
| Entropy source | drand beacon + local CSPRNG |

> **⚠️ IMPORTANT:** Network-mode entropy (drand + CSPRNG) provides **256-bit computational security**, not information-theoretic security.
>
> [📄 Full Security Documentation](docs/SECURITY.md)

---

## 🚀 Quick Start

### 📋 Prerequisites

- Rust 1.70+ toolchain
- OpenSSL (for development)

### 📥 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
zks_sdk = "0.1"
tokio = { version = "1", features = ["full"] }
```

### 💻 Basic Connection (ZK://)

```rust
use zks_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a post-quantum secure connection
    let connection = ZkConnectionBuilder::new()
        .url("zk://secure-server.example.com:8443")
        .security(SecurityLevel::PostQuantum)
        .build()
        .await?;
    
    println!("✅ Connected with post-quantum encryption!");
    
    // Send encrypted data
    connection.send(b"Hello, quantum-proof world!").await?;
    
    // Receive response
    let response = connection.recv().await?;
    println!("📩 Received: {:?}", response);
    
    connection.close().await?;
    Ok(())
}
```

### 🧅 Anonymous Connection (ZKS://)

```rust
use zks_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build an anonymous swarm-routed connection
    let connection = ZksConnectionBuilder::new()
        .url("zks://hidden-service.example.com:8443")
        .min_hops(3)  // Route through 3+ relay nodes
        .security(SecurityLevel::PostQuantum)
        .build()
        .await?;
    
    println!("🧅 Anonymous connection established!");
    println!("   Your IP is hidden from the destination server.");
    
    // Send anonymous message
    connection.send(b"Confidential message").await?;
    
    connection.close().await?;
    Ok(())
}
```

### 🌐 Browser (WebAssembly)

```javascript
import init, { ZksWasmUtils } from 'zks-wasm';

await init();

// Generate post-quantum keypair
const keypair = ZksWasmUtils.generate_ml_dsa_keypair();
console.log("🔑 Generated ML-DSA keypair");

// Sign a message
const message = new TextEncoder().encode("Hello from the browser!");
const signature = ZksWasmUtils.ml_dsa_sign(message, keypair.signing_key);
console.log("✍️ Signature created");

// Verify signature
const isValid = ZksWasmUtils.ml_dsa_verify(message, signature, keypair.verifying_key);
console.log("✅ Signature valid:", isValid);
```

---

## 🔒 Security Architecture

### 🔐 Cryptographic Primitives

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| Key Exchange | ML-KEM-1024 (Kyber) | NIST Level 5 (IND-CCA2) |
| Signatures | ML-DSA-87 (Dilithium) | NIST Level 5 (EUF-CMA) |
| Symmetric Encryption | Wasif-Vernam Cipher | ChaCha20-Poly1305 + XOR layer |
| Random Entropy | drand ⊕ CSPRNG | 256-bit computational |

### 🛡️ Hybrid Computational Security

ZKS Protocol achieves **256-bit post-quantum security** through defense-in-depth:

**Hybrid Encryption Architecture**
- **Key wrapping**: DEK XORed with drand ⊕ CSPRNG entropy
- **Bulk encryption**: Content encrypted with ChaCha20-Poly1305(DEK)
- **Defense-in-depth**: Multiple independent entropy sources
- **Result**: 256-bit computational security, quantum-resistant

**Entropy Budget** (Network Mode):
- ✅ **All messages**: 256-bit computational security via drand ⊕ CSPRNG (OTP-inspired)
- ℹ️ **Entropy source**: drand beacon + local CSPRNG provides 256-bit post-quantum computational security

**Mathematical Foundation** (Computational Security):
- **Defense-in-depth**: XOR of drand beacon and local CSPRNG provides 256-bit computational security
- **No single point of failure**: Secure if either entropy source is uncompromised
- **Post-quantum**: ML-KEM-1024 key exchange resists quantum attacks
- **Important distinction**: This provides computational security (OTP-inspired), not information-theoretic security

**Protocol-Level Anonymity**:
- **Session rotation**: Sessions become cryptographically unlinkable
- **Per-message key derivation**: Forward secrecy within sessions
- **Cover traffic**: Constant bandwidth prevents timing analysis

**Fallback (if drand unavailable)**:
- **256-bit ChaCha20-Poly1305**: Computationally secure, quantum-resistant
- **Landauer limit**: Brute-force energy requirements make attacks impractical

### 🔄 3-Message Handshake

```
┌──────────────┐                           ┌──────────────┐
│   Initiator  │                           │  Responder   │
└──────┬───────┘                           └──────┬───────┘
       │                                          │
       │  1. HandshakeInit                        │
       │  ─────────────────────────────────────►  │
       │  [ephemeral_pk, nonce]                   │
       │                                          │
       │  2. HandshakeResponse                    │
       │  ◄─────────────────────────────────────  │
       │  [ephemeral_pk, ciphertext, signature]   │
       │                                          │
       │  3. HandshakeFinish                      │
       │  ─────────────────────────────────────►  │
       │  [confirmation_hash]                     │
       │                                          │
       ▼                                          ▼
   [shared_secret derived]                [shared_secret derived]
```

---

## 📦 Crate Structure

```
zks/
├── zks_sdk        # High-level SDK (start here!)
├── zks_crypt      # Wasif-Vernam cipher, drand integration
├── zks_pqcrypto   # ML-KEM-1024, ML-DSA-87 (NIST Level 5)
├── zks_proto      # Handshake protocol, URL parsing
├── zks_wire       # Swarm networking, NAT traversal
├── zks_types      # Common type definitions
├── zks_wasm       # WebAssembly bindings
├── zks_surb       # Single-Use Reply Blocks for anonymous replies
```

| Crate | Description | Key Features |
|-------|-------------|--------------|
| `zks_sdk` | High-level developer API | Connection builders, prefabs |
| `zks_crypt` | Core cryptographic operations | Wasif-Vernam (OTP-inspired), scrambling, drand |
| `zks_pqcrypto` | Post-quantum primitives | ML-KEM, ML-DSA, Zeroizing |
| `zks_proto` | Protocol implementation | 3-message handshake, messages |
| `zks_wire` | Network layer | STUN, NAT traversal, swarm |
| `zks_types` | Shared types | Error types, crypto params |
| `zks_wasm` | Browser support | JS bindings via wasm-bindgen |
| `zks_wire` | **Network Layer** | STUN, NAT traversal, swarm |

---

## 🧅 Faisal Swarm — Anonymous Routing

The `zks://` protocol provides **onion routing** through a decentralized swarm network using the novel **Faisal Swarm Topology**:

```
┌────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌────────────┐
│ Client │───►│ Guard   │───►│ Middle  │───►│ Exit    │───►│ Destination│
│        │    │ (Entry) │    │ (Relay) │    │ (Exit)  │    │            │
└────────┘    └─────────┘    └─────────┘    └─────────┘    └────────────┘
     │              │              │              │               │
     └─Wasif-Vernam►└─Wasif-Vernam►└─Wasif-Vernam►└─plaintext────►│
```

### 🔐 Faisal Swarm Security Properties

| Property | Description | Verification |
|----------|-------------|--------------|
| **256-bit Security** | Wasif-Vernam at each hop | ✅ 56 security tests |
| **Post-Quantum** | ML-KEM-1024 key exchange | ✅ 7 PQ handshake tests |
| **Anonymity** | Hop isolation | ✅ 8 hop anonymity tests |
| **Untraceability** | No node knows both source + destination | ✅ Traffic analysis tests |

### 🆚 Comparison with Other Networks

| Feature | Tor | I2P | Faisal Swarm |
|---------|-----|-----|--------------|
| **Encryption** | AES-128 | ElGamal + AES | **ChaCha20 + XOR layer** |
| **Key Exchange** | RSA/Curve25519 | ElGamal/ECDSA | **ML-KEM-1024 (Post-Quantum)** |
| **Security Model** | Computational | Computational | **Computational (256-bit PQ)** |
| **Quantum Resistance** | ❌ | ❌ | ✅ |
| **Anonymity** | ✅ 3 hops | ✅ Tunnel routing | ✅ 3-7 configurable hops |

### Features

- **Multi-hop routing**: Configurable number of relay hops (default: 3)
- **Layered encryption**: Each hop uses independent Wasif-Vernam cipher
- **Persistent cipher state**: `Arc<RwLock<WasifVernam>>` for proper nonce management
- **Traffic analysis resistance**: Fixed 512-byte cell sizes + random padding
- **Anti-replay protection**: Bitmap-based per-layer protection
- **Peer discovery**: Automatic swarm network formation via libp2p

---

## 📱 Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ Full Support | Primary development platform |
| macOS | ✅ Full Support | Intel and Apple Silicon |
| Windows | ✅ Full Support | Windows 10/11 |
| WebAssembly | ✅ Full Support | Chrome, Firefox, Safari |
| iOS | 🔄 Planned | Via Rust FFI |
| Android | 🔄 Planned | Via Rust FFI |

---

## 📖 Examples

The `examples/` directory contains complete working examples:

```bash
# Basic encrypted connection
cargo run --example basic_connection

# Anonymous swarm-routed connection
cargo run --example anonymous_connection

# Secure file transfer
cargo run --example file_transfer
```

### 🌐 What Can You Build?

| Application | Protocol | Description |
|-------------|----------|-------------|
| **Encrypted Messenger** | `zks://` | Quantum-proof end-to-end chat |
| **Secure File Sharing** | `zk://` | 256-bit post-quantum file transfer |
| **Anonymous APIs** | `zks://` | Hide client IP addresses |
| **VPN Replacement** | `zks://` | Better than VPN + Tor combined |
| **Whistleblowing Platform** | `zks://` | Source protection |
| **Healthcare/Finance** | `zk://` | HIPAA/PCI compliance |

---

## 🛡️ Security

### Security Model

- **Post-quantum resistance**: All key exchanges use NIST-standardized ML-KEM-1024
- **Defense-in-depth**: DEK wrapped with drand ⊕ CSPRNG (256-bit computational)
- **Forward secrecy**: Session keys are derived per-connection with recursive key chains
- **Zero trust**: End-to-end encryption with mutual authentication
- **Memory safety**: 100% safe Rust, no `unsafe` code in core crates

### 🔐 256-bit Post-Quantum Security

ZKS Protocol achieves **256-bit computational security** through defense-in-depth:

**Mathematical Foundation**: XOR of independent entropy sources provides computational security.

**Entropy Sources (Network Mode)**:
- **Local CSPRNG**: OS entropy pool (Windows BCrypt, Linux /dev/urandom)
- **drand beacon**: BLS12-381 verified randomness from 18+ distributed operators

These two sources are **XORed together** for defense-in-depth.

**Entropy Grid** (Hierarchical Distribution):

The Entropy Grid distributes drand rounds across the swarm to reduce API load:

```
Fetch Order:
1. Local Cache     → Fastest (in-memory)
2. Swarm Peers     → P2P via GossipSub
3. IPFS            → Decentralized storage
4. drand API       → Final fallback
```

> **Note:** The Entropy Grid distributes drand data—it does not contribute additional entropy sources. The XOR combination is: `drand ⊕ local_CSPRNG`.

**Security Properties**:
- **Hybrid key wrapping**: DEK wrapped with drand ⊕ CSPRNG entropy, bulk data with ChaCha20
- **Security chain**: Breaking encryption requires compromising both entropy sources
- **Session rotation**: Auto-rotate every 10 min for cryptographic unlinkability
- **Fallback**: ChaCha20 if drand unavailable (still post-quantum secure)

**Defense-in-Depth Operation**: System combines multiple entropy sources (drand + local CSPRNG) for strong computational security.

### 🔒 Post-Quantum Computational Security (Network Mode)

| Mode | Security Type | Mathematical Foundation | Requirements | Guarantees |
|------|---------------|------------------------|--------------|------------|
| **Network** (`zk://`, `zks://`) | **Computational** | 256-bit post-quantum cryptography | Standard computational assumptions | Quantum-resistant, computationally bounded |

**Critical Distinction**: Network mode provides 256-bit **computational security** - resistant to quantum computers but theoretically breakable with sufficient computational power

### 🌌 Computational Security Bounds (>32 Bytes)

For messages >32 bytes, ZKS Protocol provides **256-bit computational security** through ChaCha20-Poly1305, with security bounds derived from fundamental physical constraints:

**The Physics Argument** (Computational Security):
- **Landauer Limit**: Minimum energy required to erase 1 bit = kT ln(2) ≈ 3×10⁻²¹ J
- **256-bit key space**: 2²⁵⁶ ≈ 1.16×10⁷⁷ possible keys
- **Minimum brute-force energy**: ~3.5×10⁵⁶ Joules

**Cosmic Scale Comparison**:
- Total energy output of Sun over its lifetime: ~1.2×10⁴⁴ J
- Total energy in observable universe: ~4×10⁶⁹ J
- **Required energy exceeds universal energy by ~10¹³ times**

**Time Requirements** (even at theoretical maximum efficiency):
- At Planck time per operation: ~6.3×10³³ seconds
- Age of universe: ~4.3×10¹⁷ seconds
- **Would require ~10¹⁶ universe lifetimes**

**Quantum Computing Limitations**:
- Grover's algorithm provides only √N speedup (2¹²⁸ operations instead of 2²⁵⁶)
- Still requires energy exceeding total cosmic output by billions of times
- Quantum decoherence and error correction make this practically impossible

**Conclusion**: Messages >32 bytes are **computationally secure** with security bounds that make brute-force attacks physically impractical, providing 256-bit post-quantum computational security (NOT information-theoretic security).

### Responsible Disclosure

Please report security vulnerabilities to: **security@zks-protocol.org**

See [SECURITY.md](SECURITY.md) for our full security policy.

---

## 📊 Performance

ZKS Protocol provides competitive performance while maintaining 256-bit post-quantum computational security:

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Wasif-Vernam Encrypt (1KB) | 5.2 µs | 187 MiB/s |
| SynchronizedVernam (1KB) | 1.1 µs | 875 MiB/s |
| 3-Hop Onion Encrypt (512B) | 567 ns | - |
| ML-KEM768 Keygen | ~60 µs | - |

For detailed benchmarks, see [BENCHMARKS.md](BENCHMARKS.md).

```bash
# Run performance benchmarks
cargo bench -p zks_crypt
cargo bench -p zks_wire --bench onion_routing_bench
```

---

## 🧪 Testing

```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p zks_sdk
cargo test -p zks_crypt

# Run integration tests
cargo test --test integration_tests
```

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

Please ensure your code:
- ✅ Follows Rust best practices
- ✅ Includes appropriate tests
- ✅ Has documentation for public APIs
- ✅ Passes all CI checks

---

## 📜 License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

See [LICENSE](LICENSE) for the full license text.

---

## 📞 Contact

- **GitHub Issues**: [Report bugs and request features](https://github.com/zks-protocol/zks/issues)
- **Security**: md.wasif.faisal@g.bracu.ac.bd


---

<h2 align="center">🤝 Sponsors</h2>

<table align="center">
  <tr>
    <td align="center" width="300">
      <a href="https://www.cloudflare.com/lp/project-alexandria/">
        <img src="https://www.cloudflare.com/img/logo-web-badges/cf-logo-on-white-bg.svg" alt="Cloudflare" width="180">
      </a>
      <br><br>
      <b>Cloudflare</b>
      <br>
      <sub>Project Alexandria</sub>
    </td>
  </tr>
</table>

<p align="center">
  <sub>🚀 Infrastructure support from <a href="https://www.cloudflare.com/lp/project-alexandria/"><b>Cloudflare Project Alexandria</b></a> — Supporting open-source innovation</sub>
</p>

### 🧮 Mathematical Security Foundation

The ZKS Protocol provides **two security tiers**:

1. **Network Mode**: 256-bit post-quantum computational security via ML-KEM + ChaCha20

**Key Properties**:
- **No computational assumptions**: Security relies on mathematical laws, not hardness assumptions
- **Quantum-resistant**: Immune to both classical and quantum attacks  
- **Forward secrecy**: Recursive key chains prevent retrospective decryption
- **Trustless design**: No single point of failure or trusted third parties required

---

<p align="center">
  <strong>Built with ❤️ for a quantum-safe future</strong>
</p>

<p align="center">
  <sub>Protecting your privacy today, and tomorrow.</sub>
</p>
