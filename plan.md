<p align="center">
  <img src="resources/logo.png" alt="ZKS Protocol" width="400">
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

ZKS Protocol is the **first post-quantum secure networking SDK** with built-in **anonymity through onion routing**. Built with 100% safe Rust, it provides unbreakable encryption for the quantum computing era.

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
- **ML-KEM-768** (Kyber) — NIST Level 3 key exchange
- **ML-DSA-65** (Dilithium) — Post-quantum signatures
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
        .security(SecurityLevel::TrueVernam)
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
| Key Exchange | ML-KEM-768 (Kyber) | NIST Level 3 (IND-CCA2) |
| Signatures | ML-DSA-65 (Dilithium) | NIST Level 3 (EUF-CMA) |
| Symmetric Encryption | Wasif-Vernam Cipher | ChaCha20-Poly1305 + XOR |
| Random Entropy | drand beacon + local | TRUE random (not pseudo) |

### 🛡️ Security Levels

```rust
pub enum SecurityLevel {
    /// Classical cryptography (for testing only)
    Classical,
    
    /// Post-quantum secure (recommended for production)
    PostQuantum,
    
    /// Maximum security with TRUE random entropy
    TrueVernam,
}
```

| Level | Key Exchange | Encryption | Use Case |
|-------|--------------|------------|----------|
| `Classical` | Random | ChaCha20 | Testing/Development |
| `PostQuantum` | ML-KEM | Wasif-Vernam | Production |
| `TrueVernam` | ML-KEM + drand | OTP-style | Maximum Security |

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
├── zks_pqcrypto   # ML-KEM-768, ML-DSA-65
├── zks_proto      # Handshake protocol, URL parsing
├── zks_wire       # Swarm networking, NAT traversal
├── zks_types      # Common type definitions
└── zks_wasm       # WebAssembly bindings
```

| Crate | Description | Key Features |
|-------|-------------|--------------|
| `zks_sdk` | High-level developer API | Connection builders, prefabs |
| `zks_crypt` | Core cryptographic operations | Wasif-Vernam, scrambling, drand |
| `zks_pqcrypto` | Post-quantum primitives | ML-KEM, ML-DSA, Zeroizing |
| `zks_proto` | Protocol implementation | 3-message handshake, messages |
| `zks_wire` | Network layer | STUN, NAT traversal, swarm |
| `zks_types` | Shared types | Error types, crypto params |
| `zks_wasm` | Browser support | JS bindings via wasm-bindgen |

---

## 🧅 Anonymous Routing

The `zks://` protocol provides **onion routing** through a decentralized swarm network:

```
┌────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌────────────┐
│ Client │───►│ Entry   │───►│ Middle  │───►│ Exit    │───►│ Destination│
│        │    │ Relay   │    │ Relay   │    │ Relay   │    │            │
└────────┘    └─────────┘    └─────────┘    └─────────┘    └────────────┘
     │              │              │              │               │
     └──encrypted──►└──encrypted──►└──encrypted──►└──plaintext───►│
```

### Features

- **Multi-hop routing**: Configurable number of relay hops (default: 3)
- **Layered encryption**: Each hop can only decrypt its layer
- **Traffic analysis resistance**: Optional scrambling mode
- **Peer discovery**: Automatic swarm network formation

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
| **Secure File Sharing** | `zk://` | Unbreakable file transfer |
| **Anonymous APIs** | `zks://` | Hide client IP addresses |
| **VPN Replacement** | `zks://` | Better than VPN + Tor combined |
| **Whistleblowing Platform** | `zks://` | Source protection |
| **Healthcare/Finance** | `zk://` | HIPAA/PCI compliance |

---

## 🛡️ Security

### Security Model

- **Post-quantum resistance**: All key exchanges use NIST-standardized algorithms
- **Forward secrecy**: Session keys are derived per-connection
- **Zero trust**: End-to-end encryption with mutual authentication
- **Memory safety**: 100% safe Rust, no `unsafe` code in core crates

### Responsible Disclosure

Please report security vulnerabilities to: **security@zks-protocol.org**

See [SECURITY.md](SECURITY.md) for our full security policy.

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
- **Security**: security@zks-protocol.org

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
  <sub>🚀 Infrastructure powered by <a href="https://www.cloudflare.com/lp/project-alexandria/"><b>Cloudflare Project Alexandria</b></a> — Supporting open-source innovation</sub>
</p>

---

<p align="center">
  <strong>Built with ❤️ for a quantum-safe future</strong>
</p>

<p align="center">
  <sub>Protecting your privacy today, and tomorrow.</sub>
</p>
