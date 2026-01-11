# Critical Issues - ZKS Protocol

## Status: Security Hardening Complete (January 2026)

### ✅ Fixed Issues

| ID | Severity | File | Issue | Status |
|----|----------|------|-------|--------|
| 1 | 🔴 Critical | anti_replay.rs | Timing attack via conditional logging | ✅ Fixed (unconditional logging) |
| 2 | 🔴 Critical | true_vernam.rs | Silent fallback to zero entropy | ✅ Fixed (error propagation) |
| 6 | 🟠 Security | anti_replay.rs | Mutex poison handling | ✅ Fixed (unwrap_or_else) |
| 7 | 🟠 Security | drand.rs | drand signature not verified | ✅ Fixed (BLS12-381 via blst) |
| 8 | 🟠 Security | wasif_vernam.rs | Nonce counter overflow | ✅ Fixed (u64::MAX check) |
| 9 | 🟠 Security | wasif_vernam.rs | Nonce not reset on key rotation | ✅ Fixed (counter reset) |

### ✅ Additional Fixes (January 2026)

| Fix | File | Description |
|-----|------|-------------|
| ML-KEM RNG | ml_kem.rs | Removed predictable fallback - panics on RNG failure |
| Circuit RNG | circuit.rs | OsRng instead of thread_rng() for cryptographic path selection |
| Circuit ID | circuit.rs | Result type instead of expect() for error handling |
| Relay Port | relay.rs | Cryptographic random port selection |
| Scramble Bias | scramble.rs | ChaCha20Rng + gen_range for unbiased Fisher-Yates |
| Handshake Timestamp | handshake.rs | Added timestamp validation in process_init() |

---

## Known Limitations (Acceptable for Paper Publication)

### 5. Chi-square Bounds (true_vernam.rs)
**Status:** Documented limitation  
**Notes:** Bounds 100-500 are reasonable for typical use cases. May reject edge cases.

### 10. XOR Key Not Transmitted (wasif_vernam.rs)
**Status:** Architectural decision  
**Notes:** True Vernam mode relies on synchronized entropy (drand beacon). This is documented in the paper.

### 15. ChainState Clone (recursive_chain.rs)
**Status:** Low priority  
**Notes:** Zeroizing wrapper handles cleanup. Clone needed for state export.

---

## Test Results
```
cargo test -p zks_crypt --lib
test result: ok. 43 passed; 0 failed
```

All cryptographic tests pass including:
- Anti-replay validation
- Constant-time operations
- Drand BLS verification
- Scramble/unscramble identity
- Recursive chain synchronization
- True Vernam entropy