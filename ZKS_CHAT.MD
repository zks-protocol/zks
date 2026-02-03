# ZKS Protocol: Post-Quantum Secure Anonymous Chat

> ⚠️ **IMPORTANT SECURITY CLARIFICATION**: This document previously made incorrect claims about "information-theoretic security" and "TRUE OTP". The ZKS Protocol provides **256-bit post-quantum computational security**, NOT information-theoretic security. True OTP requires physical key exchange - network-based systems cannot achieve Shannon secrecy.

## 🔐 256-Bit Post-Quantum Computational Security

**ZKS Protocol provides 256-bit post-quantum computational security** using NIST-standardized algorithms (ML-KEM-1024, ML-DSA-87) combined with defense-in-depth entropy mixing.

---

## What Makes ZKS Secure?

### Security Model

| Aspect | ZKS Protocol |
|--------|--------------|
| **Security basis** | 256-bit computational (MLWE assumption) |
| **Quantum resistant** | ✅ NIST Level 5 post-quantum |
| **Defense-in-depth** | ✅ Multi-layer encryption |
| **Forward secrecy** | ✅ Session rotation every 10 min |

### The Wasif-Vernam Cipher

A four-layer computational encryption scheme providing:

```
Layer 1: ChaCha20-Poly1305 (authenticated encryption)
Layer 2: High-entropy XOR (defense-in-depth)
Layer 3: Ciphertext scrambling (traffic analysis resistance)
Layer 4: Recursive key chains (forward secrecy)
```

**Entropy sources combined via XOR:**
- 🌍 **drand** — Distributed randomness beacon (18+ operators)
- 💻 **Local CSPRNG** — System entropy

If **EITHER** source remains uncompromised, the encryption maintains **256-bit computational security**.

---

## How It Works

### Entropy Grid Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                 Hierarchical Entropy System                     │
├────────────────────────────────────────────────────────────────┤
│  Level 1: Local cache (fastest)                                 │
│  Level 2: Swarm peers (P2P distribution)                        │
│  Level 3: IPFS storage (decentralized)                          │
│  Level 4: Direct drand API (fallback)                           │
└────────────────────────────────────────────────────────────────┘
```

### Per-Session Security

Each anonymous chat session:

1. **ML-KEM-1024 handshake** → Post-quantum shared secret (NIST Level 5)
2. **Entropy mixing** → drand ⊕ CSPRNG for defense-in-depth
3. **Session rotation** → Automatic every 10 minutes

---

## Security Level

### Per Message
| Message Size | Security |
|--------------|----------|
| **ANY size** | 🔐 **256-bit post-quantum computational** |
| Fallback (entropy unavailable) | 🔒 ChaCha20-Poly1305 (256-bit) |

### Session Management
| Metric | Value |
|--------|-------|
| Key exchange | ML-KEM-1024 (NIST Level 5) |
| Signatures | ML-DSA-87 (post-quantum) |
| Session rotation | **Automatic** every 10 min |
| Forward secrecy | ✅ Per-session key derivation |

---

## Why This Is Free

### No Token Required
Unlike some privacy networks that require tokens/fees:
- ✅ drand is **free public infrastructure**
- ✅ CURBy is **free academic service**
- ✅ ZKS Protocol is **open source (AGPL-3.0)**

### Decentralized Verification
- drand: BLS threshold signatures from League of Entropy (Cloudflare, Protocol Labs, etc.)
- CURBy: Quantum Bell test verification from University of Colorado/NIST

---

## Comparison with Other Systems

| Feature | Signal | Telegram | ZKS Chat |
|---------|--------|----------|----------|
| E2E Encryption | ✅ | ⚠️ Optional | ✅ |
| Post-Quantum | ❌ | ❌ | ✅ ML-KEM-1024 |
| Defense-in-depth | ❌ | ❌ | ✅ 4-layer |
| Anonymous routing | ❌ | ❌ | ✅ Faisal Swarm |
| Metadata protection | ❌ | ❌ | ✅ |
| Forward secrecy | ✅ | ❌ | ✅ |

---

## Technical Implementation

### Entropy Sources

```rust
// Defense-in-depth: XOR combination ensures security if either source is uncompromised
mixed_entropy = drand_beacon(32) ⊕ local_CSPRNG(32)
```

### Wasif-Vernam Cipher

```rust
// Four-layer encryption
Layer 1: ChaCha20-Poly1305 authenticated encryption
Layer 2: High-entropy XOR with mixed entropy
Layer 3: Optional ciphertext scrambling
Layer 4: Recursive key chains for forward secrecy
```

### Large File Handling

```rust
// Hybrid Computational Encryption for files of any size
DEK = CSPRNG(32 bytes)
wrapped_DEK = DEK ⊕ mixed_entropy
ciphertext = ChaCha20_Poly1305(DEK, plaintext)
// 256-bit post-quantum computational security
```

---

## Security Properties

### Computational Security (256-bit)
- ✅ **Post-quantum**: Resistant to Shor's algorithm attacks
- ✅ **Defense-in-depth**: Multiple entropy sources via XOR
- ✅ **Forward secrecy**: Session rotation with new key derivation

### 🌪️ Entropy Swarm (P2P Randomness)
For large files (GBs), ZKS uses a **torrent-like swarm** to fetch historical drand rounds:
- **Distributed Load**: Peers share cached entropy rounds
- **Max Speed**: Parallel downloads from swarm peers
- **Trustless**: BLS signatures verify every drand round
- **Result**: Fast entropy distribution for high-throughput encryption

### Anonymity
- ✅ **Faisal Swarm topology**: No single point of traffic analysis
- ✅ **Cover traffic**: Constant bandwidth to prevent timing attacks
- ✅ **SURB-based replies**: Sender remains anonymous even to recipient

---

## Use Cases

### Perfect for:
- 🔒 Whistleblower communications
- 🏥 Healthcare data (HIPAA)
- 💼 Legal privilege communications
- 🏛️ Government classified messaging
- 🔐 Financial transactions
- 👤 Human rights activists

### Why Post-Quantum Security Matters
> "256-bit computational security resistant to both classical and quantum attacks, built on NIST-standardized algorithms with defense-in-depth entropy mixing."

---

## Getting Started

```rust
use zks_sdk::prelude::*;

// Create post-quantum encrypted channel
let cipher = WasifVernam::new(shared_key)?;
cipher.derive_base_iv(&shared_key, true); // Required for encryption

// Encrypt message (256-bit post-quantum computational security)
let ciphertext = cipher.encrypt(b"Hello, secure world!")?;

// Decrypt
let plaintext = cipher.decrypt(&ciphertext)?;
```

---

## License

ZKS Protocol is open source under **AGPL-3.0**.

256-bit post-quantum security for everyone. 🛡️

---

*Wasif-Vernam Cipher: Because privacy is a human right, not a premium feature.*
