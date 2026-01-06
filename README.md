# ZKS Protocol SDK

> **Zero Knowledge Swarm** — The first post-quantum encryption SDK with built-in anonymity

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](https://opensource.org/licenses/AGPL-3.0)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)

---

## 🔐 What is ZKS?

ZKS (Zero Knowledge Swarm) provides **unbreakable encryption** for the quantum age with two protocols:

| Protocol | Description | Use Case |
|----------|-------------|----------|
| `zk://` | Encrypted connection (fast) | Secure browsing, APIs |
| `zks://` | Encrypted + Anonymous (swarm-routed) | Maximum privacy |

---

## ✨ Features

- **Post-Quantum Security**: ML-KEM-768 key exchange (NIST Level 3)
- **TRUE Random Entropy**: drand beacon integration
- **Wasif-Vernam Cipher**: ChaCha20-Poly1305 + XOR layer
- **Onion Routing**: Multi-hop anonymous connections
- **WASM Support**: Works in browsers
- **Simple API**: Builder pattern, async/await

---

## 🚀 Quick Start

### Add to Cargo.toml

```toml
[dependencies]
zks_sdk = "0.1"
```

### Basic Usage (ZK://)

```rust
use zks_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Direct encrypted connection
    let conn = ZkConnection::builder()
        .url("zk://example.com")
        .security(SecurityLevel::PostQuantum)
        .build()
        .await?;
    
    // Send encrypted data
    conn.send(b"Hello, quantum-proof world!").await?;
    
    // Receive response
    let response = conn.recv().await?;
    println!("Received: {:?}", response);
    
    Ok(())
}
```

### Anonymous Connection (ZKS://)

```rust
use zks_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Anonymous swarm-routed connection
    let conn = ZksConnection::builder()
        .url("zks://example.com")
        .min_hops(3)  // Route through 3+ peers
        .security(SecurityLevel::TrueVernam)
        .build()
        .await?;
    
    // Your IP is hidden from the server!
    conn.send(b"Anonymous message").await?;
    
    Ok(())
}
```

### Browser (WASM)

```javascript
import init, { ZksWasmUtils } from 'zks-wasm';

await init();

// Generate post-quantum keypair
const keypair = ZksWasmUtils.generate_ml_dsa_keypair();

// Sign a message
const message = new TextEncoder().encode("Hello ZKS!");
const signature = ZksWasmUtils.ml_dsa_sign(message, keypair.signing_key);

// Verify signature
ZksWasmUtils.ml_dsa_verify(message, signature, keypair.verifying_key);
```

---

## 📦 Crates

| Crate | Description |
|-------|-------------|
| `zks_sdk` | High-level SDK (start here) |
| `zks_crypt` | Wasif-Vernam cipher, drand |
| `zks_pqcrypto` | ML-KEM, ML-DSA |
| `zks_proto` | Handshake, URL parsing |
| `zks_wire` | Swarm, NAT traversal |
| `zks_wasm` | Browser support |

---

## 🔒 Security Levels

| Level | Key Exchange | Encryption | Use Case |
|-------|--------------|------------|----------|
| `Classical` | Random | ChaCha20 | Testing |
| `PostQuantum` | ML-KEM | ChaCha20 + XOR | Production |
| `TrueVernam` | ML-KEM + drand | OTP | Maximum security |

---

## 🌐 What Can You Build?

- **Encrypted Messengers** — Quantum-proof chat
- **Secure File Transfer** — Unbreakable file sharing
- **Anonymous APIs** — Hide client IPs
- **Healthcare/Finance** — HIPAA/PCI compliant
- **Whistleblowing Platforms** — Source protection
- **VPN Replacement** — zks:// = VPN + Tor

---

## 📖 Examples

See the [`examples/`](examples/) folder:

```bash
# Run basic connection example
cargo run --example basic_connection

# Run file transfer example
cargo run --example file_transfer

# Run anonymous connection example
cargo run --example anonymous_connection
```

---

## 🛡️ Security

See [SECURITY.md](SECURITY.md) for:
- Security model
- Threat analysis
- Responsible disclosure

---

## 📜 License

This project is licensed under **AGPL-3.0**. See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines first.

---

**Built with ❤️ for a quantum-safe future**