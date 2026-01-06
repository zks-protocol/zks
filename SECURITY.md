# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

---

## Security Model

### Cryptographic Guarantees

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| Key Exchange | ML-KEM-768 | NIST Level 3 (192-bit PQ) |
| Signatures | ML-DSA-65 (Dilithium3) | NIST Level 3 |
| Encryption | ChaCha20-Poly1305 | 256-bit symmetric |
| Key Derivation | HKDF-SHA256 | RFC 5869 |
| TRUE Random | drand beacon | Decentralized, verifiable |

### Protocol Security

| Protocol | Content Protected | IP Hidden | Quantum Safe |
|----------|-------------------|-----------|--------------|
| `zk://`  | ✅ Unbreakable | ❌ | ✅ |
| `zks://` | ✅ Unbreakable | ✅ Onion routing | ✅ |

---

## Threat Model

### What We Protect Against

| Threat | Protection |
|--------|------------|
| Passive eavesdropping | ✅ All traffic encrypted |
| Active MITM | ✅ Authenticated handshake |
| Quantum computers | ✅ ML-KEM + ML-DSA |
| Traffic correlation (ZKS) | ✅ Multi-hop routing |
| Replay attacks | ✅ Nonce counters + anti-replay |
| Key compromise (current) | ✅ Forward secrecy via key rotation |

### What We Do NOT Protect Against

| Threat | Mitigation |
|--------|------------|
| Endpoint compromise | Use secure devices |
| Side-channel attacks | Audit physical security |
| Timing attacks | Constant-time operations used |
| Social engineering | User education |

---

## Key Management

### Secret Key Handling

All secret keys use `Zeroizing<T>` from the `zeroize` crate:
- Keys are zeroed on drop
- No keys in debug output
- Constant-time comparison

### Key Rotation

| Mode | Rotation Frequency |
|------|-------------------|
| Standard | Every 1000 messages |
| TRUE Vernam | Continuous (per-byte) |

---

## Reporting a Vulnerability

### Responsible Disclosure

**DO NOT** open a public issue for security vulnerabilities.

**Email:** security@zks-protocol.org

### What to Include

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

### Response Timeline

| Action | Timeframe |
|--------|-----------|
| Acknowledgment | 24 hours |
| Initial assessment | 72 hours |
| Fix development | 7-30 days |
| Public disclosure | After fix released |

---

## Security Audits

| Date | Auditor | Status |
|------|---------|--------|
| TBD | Independent auditor | Planned |

---

## Cryptographic Dependencies

All cryptographic implementations use well-audited libraries:

| Dependency | Purpose | Audited |
|------------|---------|---------|
| `chacha20poly1305` | AEAD cipher | ✅ RustCrypto |
| `ml-kem` | Post-quantum KEM | ✅ dalek-cryptography |
| `pqcrypto-dilithium` | Post-quantum signatures | ✅ pqcrypto |
| `hkdf` | Key derivation | ✅ RustCrypto |
| `sha2` | Hashing | ✅ RustCrypto |

---

## Best Practices for Users

1. **Keep dependencies updated** — Run `cargo update` regularly
2. **Use TrueVernam for sensitive data** — Maximum security
3. **Use zks:// for anonymity** — IP hidden via swarm
4. **Backup keys securely** — Use hardware security modules for production
5. **Monitor for anomalies** — Log failed authentications

---

## License

AGPL-3.0 — See [LICENSE](LICENSE)