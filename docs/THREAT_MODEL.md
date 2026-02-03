# ZKS Protocol Threat Model

## 1. Executive Summary

This document formally defines the threat model for the ZKS Protocol, including adversary capabilities, trust assumptions, and security guarantees. This is required for academic peer review and NIST compliance.

---

## 2. Adversary Model

### 2.1 Network Adversary (Dolev-Yao)

The protocol assumes a **Dolev-Yao network adversary** with the following capabilities:

| Capability | Description |
|------------|-------------|
| **Eavesdropping** | Can observe all network traffic |
| **Interception** | Can intercept, delay, or drop messages |
| **Injection** | Can inject arbitrary messages into the network |
| **Modification** | Can modify messages in transit |
| **Replay** | Can replay previously observed messages |

### 2.2 Computational Assumptions

The adversary is **computationally bounded** (probabilistic polynomial-time):

| Assumption | Primitive | Hardness Level |
|------------|-----------|----------------|
| **Module-LWE** | ML-KEM-1024 | NIST Level 5 (256-bit PQ) |
| **Module-SIS** | ML-DSA-87 | NIST Level 5 (256-bit PQ) |
| **PRF Security** | HKDF-SHA256 | 256-bit classical |
| **AEAD Security** | ChaCha20-Poly1305 | 256-bit classical |

### 2.3 Quantum Adversary

The protocol provides **post-quantum security** against:

- Shor's algorithm attacks on key exchange (ML-KEM replaces ECDH)
- Grover's algorithm (mitigated by 256-bit symmetric keys)

The protocol does **NOT** protect against:
- Harvest-now-decrypt-later attacks on data encrypted before deployment
- Quantum side-channel attacks (theoretical)

---

## 3. Trust Assumptions

### 3.1 Endpoint Security

| Assumption | Justification |
|------------|---------------|
| **Trusted execution environment** | Shared secrets are zeroized after use |
| **Secure memory** | Uses `Zeroizing<>` wrapper for sensitive data |
| **Authentic public keys** | Bob's signing key distributed via trusted channel |

### 3.2 Entropy Sources

| Source | Trust Level | Validation |
|--------|-------------|------------|
| **OS CSPRNG** | High | getrandom syscall |
| **ring::SystemRandom** | High | Hardware RNG when available |
| **drand beacon** | Medium | BLS signature verification |

**XOR Composition Security**: If ANY source provides full entropy, the combined output has full entropy. Compromise of one source does not compromise the output.

### 3.3 Time Synchronization

- Timestamps validated within ±5 minutes
- Clock skew tolerance of 60 seconds for future timestamps
- Replay protection via timestamp + nonce combination

---

## 4. Security Properties

### 4.1 Handshake Protocol

| Property | Guarantee | Verification |
|----------|-----------|--------------|
| **Session Key Secrecy** | Attacker cannot learn session key | ProVerif ✅, CryptoVerif ✅ |
| **Responder Authentication** | Alice confirms Bob's identity | ProVerif ✅ (injective) |
| **Forward Secrecy** | Past sessions protected if long-term key compromised | ProVerif ✅ |
| **Replay Protection** | Old messages cannot be replayed | ProVerif ✅ |

### 4.2 Ratcheting Protocol

| Property | RecursiveChain | HybridRatchet | KatanaRkem |
|----------|----------------|---------------|------------|
| **Forward Secrecy** | ✅ | ✅ | ✅ |
| **Break-in Recovery** | ❌ | ✅ | ✅ |
| **Post-Quantum** | ✅ | ✅ | ✅ |
| **Bandwidth Optimized** | N/A | ❌ | ✅ (37% savings) |

### 4.3 Swarm Routing (Onion)

| Property | Guarantee | Verification |
|----------|-----------|--------------|
| **Sender Anonymity** | Relays cannot identify message origin | ProVerif ✅ |
| **Receiver Anonymity** | Relays cannot identify destination | ProVerif ✅ |
| **Message Confidentiality** | Only recipient can decrypt | ProVerif ✅ |

---

## 5. Known Limitations

### 5.1 Dolev-Yao Model Limitations

The following properties **cannot** be proven in the symbolic model:

| Property | Reason | Mitigation |
|----------|--------|------------|
| Alice-to-Bob Auth | Attacker can inject fake public key | Key confirmation via hash(session_key) |
| Message Injection | Attacker controls network | End-to-end encryption |

These are inherent limitations of server-only authentication (like TLS 1.3) and do not represent vulnerabilities.

### 5.2 Statistical Entropy Testing

Per NIST SP 800-90B Section 5:
> "Statistical tests can indicate that a source is clearly broken, but cannot prove that a source is random."

Our entropy validation is **defense-in-depth only**. Primary entropy assurance comes from:
1. Cryptographic verification of drand BLS signatures
2. XOR composition with local CSPRNG
3. Hardware RNG when available

### 5.3 Side-Channel Attacks

| Attack Vector | Mitigation | Status |
|---------------|------------|--------|
| **Timing attacks** | `subtle::ConstantTimeEq`, `constant_time.rs` module | ✅ Mitigated |
| **Cache timing** | Relies on underlying crypto library mitigations | ⚠️ Partial |
| **Power analysis** | Out of scope for software implementation | ❌ Not addressed |

---

## 6. Security Boundaries

### 6.1 In Scope

- Network-level attacks (eavesdropping, MITM, replay)
- Cryptographic attacks on primitives
- Protocol-level attacks (unknown key share, key confirmation)
- Quantum computer attacks (Shor, Grover)

### 6.2 Out of Scope

- Endpoint compromise (malware, physical access)
- Social engineering
- Implementation bugs in dependencies
- Hardware-level attacks (cold boot, DPA)
- Denial of service (availability)

---

## 7. Formal Verification Coverage

### 7.1 ProVerif (Symbolic Model)

| Model | Properties Verified | Result |
|-------|---------------------|--------|
| `zks_protocol.pv` | Auth, Secrecy | ✅ All pass |
| `anti_replay.pv` | Replay protection | ✅ All pass |
| `forward_secrecy.pv` | Forward secrecy | ✅ All pass |
| `swarm_routing.pv` | Anonymity, Secrecy | ✅ All pass |

### 7.2 CryptoVerif (Computational Model)

| Model | Properties Verified | Probability Bound |
|-------|---------------------|-------------------|
| `zks_handshake.cv` | Secrecy, Auth | O(N²/|nonce| + Psign + Pprf) |
| `zks_handshake_kem.ocv` | KEM Secrecy | O(N²/|nonce| + Pprf + Psign) |

---

## 8. Compliance References

- **NIST FIPS 203**: ML-KEM (Kyber) key encapsulation
- **NIST FIPS 204**: ML-DSA (Dilithium) digital signatures
- **NIST SP 800-90B**: Entropy source recommendations
- **RFC 5869**: HKDF key derivation
- **RFC 8439**: ChaCha20-Poly1305 AEAD

---

## 9. Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-03 | Initial threat model for peer review |

