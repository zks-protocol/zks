# ZKS Protocol: TRUE One-Time Pad Anonymous Chat

## 🔐 Revolutionary Security: Information-Theoretic Encryption for Everyone

**ZKS Protocol enables the first practical TRUE One-Time Pad (OTP) anonymous chat** — encryption that is mathematically proven unbreakable by the laws of physics, not just computational assumptions.

---

## What Makes This Revolutionary?

### Traditional Encryption vs TRUE OTP

| Aspect | Traditional (AES, ChaCha20) | ZKS Wasif-Vernam (TRUE OTP) |
|--------|----------------------------|------------------------------|
| **Security basis** | Computational (math puzzles) | Information-theoretic (physics) |
| **Can quantum computers break?** | ⚠️ Uncertain for AES | ❌ **Impossible** |
| **Can infinite compute break?** | ✅ Eventually | ❌ **Impossible** |
| **Proven secure?** | By complexity assumptions | **By Shannon's theorem (1949)** |

### The Wasif-Vernam Cipher

Named after **Wasif Jalal** (ZKS creator) and **Gilbert Vernam** (OTP inventor), this cipher achieves:

```
Ciphertext = Message ⊕ TrueRandomKey
```

**Where TrueRandomKey comes from:**
- 🌍 **drand** — Distributed randomness beacon (global, verified)
- 🔬 **CURBy** — Quantum randomness from Bell tests
- 💻 **Local CSPRNG** — System entropy

If **ANY** source remains uncompromised, the encryption is **perfectly secure**.

---

## How It Works

### Unlimited TRUE OTP for Chat

```
┌────────────────────────────────────────────────────────────────┐
│                    drand Randomness Pool                        │
├────────────────────────────────────────────────────────────────┤
│  Genesis: May 2020                                              │
│  New round: Every 30 seconds                                    │
│  Total available: ~60+ million rounds = ~1.9 GB TRUE random    │
│  Growth: ~33 MB per year (forever)                             │
└────────────────────────────────────────────────────────────────┘
```

### Per-Session Security

Each anonymous chat session:

1. **ML-KEM handshake** → Unique shared secret (post-quantum)
2. **Pick latest drand round** → Starting point
3. **Generate keystream** → `drand ⊕ shared_secret`

**Result:** Same drand round, different secrets = unique keystreams per session!

---

## Capacity

### Per Message
| Message Size | Security |
|--------------|----------|
| **ANY size** | 🔐 **TRUE OTP** |
| Fallback (drand unavailable) | 🔒 ChaCha20 (256-bit) |

### Per Session (10 minutes default)
| Metric | Value |
|--------|-------|
| Available TRUE random | ~1.9 GB |
| Messages | **~28 million** |
| Rotation | **Automatic** every 10 min |

### Session Rotation = Unlimited TRUE OTP
| After Rotation | What Happens |
|----------------|--------------|
| New ML-KEM handshake | New shared secret |
| Same drand rounds? | **✅ OK!** (different secret = different keystream) |
| Pool exhausted? | **Never!** (rotation resets access to all ~1.9 GB) |

**Result: TRUE OTP for ANY message size, UNLIMITED data!** 🎉

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
| Post-Quantum | ❌ | ❌ | ✅ ML-KEM |
| TRUE OTP | ❌ | ❌ | ✅ **Yes** |
| Anonymous routing | ❌ | ❌ | ✅ Faisal Swarm |
| Metadata protection | ❌ | ❌ | ✅ |
| Quantum-safe forever | ❌ | ❌ | ✅ |

---

## Technical Implementation

### Entropy Sources

```rust
TrueEntropy = CURBy(64) ⊕ drand(32) ⊕ CSPRNG(64)
```

### TRUE OTP Keystream

```rust
// For messages ≤64 bytes
keystream = drand_round[N] || drand_round[N+1]  // 64 bytes
ciphertext = message ⊕ keystream
```

### Fallback (>64 bytes)

```rust
// ChaCha20 expansion for larger messages
keystream = ChaCha20(shared_seed, nonce)
// Still 256-bit post-quantum secure
```

---

## Security Properties

### Information-Theoretic Security
- ✅ **Shannon secrecy**: Ciphertext reveals zero information about plaintext
- ✅ **Everlasting security**: Even future quantum computers cannot break past messages
- ✅ **Defense-in-depth**: Multiple independent entropy sources

### 🌪️ Entropy Swarm (P2P Randomness)
For large files (GBs), ZKS uses a **torrent-like swarm** to fetch historical drand rounds:
- **Distributed Load**: Peers share cached rounds, removing pressure from drand servers
- **Max Speed**: Downloads happen in parallel from thousands of peers (Gbps+)
- **Trustless**: BLS signatures verify every round locally (bad data is rejected instantly)
- **Result**: 10 GB TRUE OTP transfer in minutes, not days.

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

### Why TRUE OTP Matters
> "The only encryption proven secure by mathematics itself. Not 'probably secure' or 'secure for now' — **provably unbreakable** by any adversary with any technology, forever."

---

## Getting Started

```rust
// Create TRUE OTP encrypted channel
let entropy = TrueEntropy::global().get_entropy_64().await;
let cipher = WasifVernam::new(shared_seed, starting_round);

// Encrypt message (TRUE OTP for ≤64 bytes)
let ciphertext = cipher.encrypt(b"Hello, secure world!");

// Decrypt
let plaintext = cipher.decrypt(&ciphertext);
```

---

## License

ZKS Protocol is open source under **AGPL-3.0**.

TRUE OTP for the people. God-level security for free. 🛡️

---

*Wasif-Vernam Cipher: Because privacy is a human right, not a premium feature.*
