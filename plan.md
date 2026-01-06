# ZK Protocol SDK - Public Release Plan

## Vision

Transform ZK from a VPN application into a **universal quantum-proof security protocol** that anyone can use to build secure applications. Like HTTP/HTTPS, but unbreakable.

| Protocol | Description |
|----------|-------------|
| `zk://` | Encrypted connection (fast, IP visible) |
| `zks://` | Encrypted + Anonymous (swarm-routed, IP hidden) |

---

## Protocol Comparison

| Feature | HTTP | HTTPS | ZK:// | ZKS:// |
|---------|------|-------|-------|--------|
| Encrypted | ❌ | ✅ | ✅ | ✅ |
| Post-Quantum | ❌ | ❌ | ✅ | ✅ |
| TRUE Random | ❌ | ❌ | ✅ (drand) | ✅ (drand) |
| IP Hidden | ❌ | ❌ | ❌ | ✅ (swarm) |
| Untraceable | ❌ | ❌ | ❌ | ✅ |

---

## Core Architecture

### Entropy System (drand + Wasif-Vernam)

```
drand beacon (32 bytes, free, cached every 30 sec)
    +
User OS random (unique per connection)
    +
ML-KEM key exchange (post-quantum)
    ↓
HKDF mixing → Unlimited keystream
    ↓
ChaCha20-Poly1305 encryption
```

| Component | Purpose |
|-----------|---------|
| **drand** | TRUE random seed (free, decentralized) |
| **ML-KEM** | Post-quantum key exchange |
| **ChaCha20-Poly1305** | AEAD stream cipher |
| **HKDF** | Key derivation (unlimited size) |

### Two Modes

| Mode | Security Level | Use Case |
|------|----------------|----------|
| **Wasif-Vernam Standard** | Computationally unbreakable | Large files, streaming |
| **Wasif-Vernam TRUE** | Information-theoretic | Small files, messages (via swarm entropy) |

---

## Crate Structure

```
zk-protocol/
├── Cargo.toml
├── README.md
├── SECURITY.md
│
├── crates/
│   ├── zks_types/          # Core types
│   │   ├── crypto/         # CryptoParameters, SecBuffer
│   │   └── errors/         # ZksError, Result<T>
│   │
│   ├── zks_crypt/          # Cryptographic primitives
│   │   ├── drand.rs        # drand beacon integration ⭐
│   │   ├── wasif_vernam.rs # Main cipher
│   │   ├── anti_replay.rs  # Replay protection
│   │   ├── scramble.rs     # Ciphertext scrambling
│   │   ├── recursive_chain.rs # Key ratchet
│   │   └── true_vernam.rs  # TRUE Vernam mode
│   │
│   ├── zks_pqcrypto/       # Post-quantum crypto
│   │   ├── ml_kem.rs       # ML-KEM (Kyber)
│   │   └── ml_dsa.rs       # ML-DSA signatures
│   │
│   ├── zks_wire/           # Network layer
│   │   ├── swarm.rs        # Swarm routing (for zks://) ⭐
│   │   ├── nat_traversal.rs
│   │   ├── stun.rs
│   │   └── relay.rs
│   │
│   ├── zks_proto/          # Protocol layer
│   │   ├── handshake.rs    # ZK/ZKS handshake
│   │   ├── url_scheme.rs   # zk:// and zks:// parsing ⭐
│   │   └── messages.rs
│   │
│   └── zks_sdk/            # High-level SDK ⭐
│       ├── prelude.rs      # Convenience re-exports
│       ├── builder.rs      # Connection builders
│       ├── prefabs/        # Pre-built patterns
│       └── fs.rs           # File transfer
```

---

## URL Scheme Design

### zk:// (Direct Mode)

```
zk://example.com/page
    ↓
DNS → TCP → ZK Handshake → Encrypted connection
    ↓
Server sees: Your IP + encrypted content
```

### zks:// (Swarm Mode)

```
zks://example.com/page
    ↓
Build circuit: You → Peer A → Peer B → Peer C
    ↓
Onion encryption: [[[request]]]
    ↓
Route through swarm
    ↓
Server sees: Peer C's IP (not yours!)
```

---

## Phase 1: Core Crates ✅ (In Progress)

| Crate | Status | Features |
|-------|--------|----------|
| `zks_types` | ✅ Done | `CryptoParameters`, `SecBuffer`, `ZksError` |
| `zks_crypt` | ✅ Done | Wasif-Vernam, anti-replay, scramble, drand |
| `zks_pqcrypto` | 🔄 Build issue | ML-KEM, ML-DSA (rand_core conflict) |

---

## Phase 2: SDK Layer

### Connection Builder API

```rust
use zks_sdk::prelude::*;

// Direct encrypted connection
let conn = ZkConnection::builder()
    .url("zk://example.com")
    .build()
    .await?;

// Anonymous swarm connection
let conn = ZksConnection::builder()
    .url("zks://example.com")
    .min_hops(3)
    .build()
    .await?;
```

### Prefabs

| Prefab | Description |
|--------|-------------|
| `SecureMessenger` | E2E encrypted messaging |
| `SecureFileTransfer` | Quantum-proof file sharing with sharding |
| `P2PConnection` | Direct peer connection |
| `AnonymousConnection` | Swarm-routed zks:// |

---

## Phase 3: Swarm Routing (ZKS)

### Multi-Hop Architecture

```
Entry Node → Middle Nodes → Exit Node → Destination
     ↑              ↑            ↑
Sees your IP   Sees nothing   Sees destination
```

### Implementation

```rust
pub enum ConnectionMode {
    /// zk:// - Direct, encrypted
    Direct,
    
    /// zks:// - Swarm-routed, anonymous
    Swarm { min_hops: u8 },
}

pub struct SwarmCircuit {
    entry_peer: PeerId,
    middle_peers: Vec<PeerId>,
    exit_peer: PeerId,
    layer_keys: Vec<[u8; 32]>,
}
```

---

## Phase 4: drand Integration ✅

### DrandEntropy Module

```rust
// Fetch TRUE random from drand (cached)
let entropy = get_drand_entropy().await?;

// Get unique entropy per connection
let unique = get_unique_entropy(session_id).await?;
```

### Endpoints

| Region | URL |
|--------|-----|
| US | `https://api.drand.sh/` |
| EU | `https://api2.drand.sh/` |
| Asia | `https://api3.drand.sh/` |
| Global | `https://drand.cloudflare.com/` |

---

## Phase 5: Browser/WASM Support

### JavaScript SDK

```javascript
import { ZkClient, ZksClient } from 'zk-protocol';

// Direct encrypted
const zk = new ZkClient();
await zk.connect('zk://example.com');

// Anonymous
const zks = new ZksClient();
await zks.connect('zks://example.com');
```

---

## Phase 6: URI Scheme Registration

### IANA Registration

| Scheme | Status | Description |
|--------|--------|-------------|
| `zk://` | Pending | Direct encrypted connection |
| `zks://` | Pending | Swarm-routed anonymous connection |

### Registration Process

1. Email `iana@iana.org` with scheme specification
2. Request provisional registration
3. Wait for review (~weeks)

---

## Security Summary

| Attack | ZK:// | ZKS:// |
|--------|-------|--------|
| Brute force | ✅ Protected | ✅ Protected |
| Quantum | ✅ Protected (ML-KEM) | ✅ Protected |
| Traffic analysis | ❌ | ✅ Protected |
| IP tracking | ❌ | ✅ Protected |

---

## Timeline

| Week | Phase | Deliverables |
|------|-------|--------------|
| 1-2 | Core Crates | zks_types, zks_crypt, zks_pqcrypto |
| 3-4 | SDK Layer | zks_sdk with builders, prefabs |
| 5-6 | Swarm Routing | zks_wire with swarm support |
| 7-8 | Browser/WASM | zks-sdk-wasm package |
| 9 | Documentation | Whitepaper, examples |
| 10 | Release | crates.io, IANA registration |

---

## Marketing Taglines

| Protocol | Tagline |
|----------|---------|
| **ZK** | "Unbreakable encryption for the quantum age" |
| **ZKS** | "Unbreakable AND untraceable - true digital freedom" |
