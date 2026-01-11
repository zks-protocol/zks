# ZKS Protocol Formal Verification

This directory contains ProVerif models for formally verifying the security properties of the ZKS Protocol.

## Files

| File | Description |
|:-----|:------------|
| `zks_protocol.pv` | Full 3-message handshake protocol model |

## Security Properties Verified

### 1. Secrecy of Session Key
```proverif
query attacker(shared_session_key).
```
Verifies that an attacker observing the network cannot learn the shared session key.

### 2. Responder Authentication
```proverif
query pk_bob: pkey; event(endAliceAccepts(pk_bob)) ==> event(beginBobResponse(pk_bob)).
```
Verifies that if Alice accepts a handshake, Bob actually participated.

### 3. Initiator Authentication  
```proverif
query pk_alice: pkey; event(endBobAccepts(pk_alice)) ==> event(beginAliceInit(pk_alice)).
```
Verifies that if Bob accepts a handshake, Alice actually initiated it.

### 4. Key Agreement
```proverif
query k: bitstring; event(aliceDerivedKey(k)) && event(bobDerivedKey(k)).
```
Verifies that both parties derive the same session key.

## Protocol Overview

```
Alice (Initiator)                          Bob (Responder)
      |                                          |
      |  1. Init(pk_A, nonce_A, timestamp)       |
      |----------------------------------------->|
      |                                          |
      |  2. Response(pk_B, ciphertext, sig,      |
      |              nonce_B, timestamp, vk_B)   |
      |<-----------------------------------------|
      |                                          |
      |  3. Finish(confirmation = H(session_key))|
      |----------------------------------------->|
      |                                          |
    [session_key established]          [session_key established]
```

## Cryptographic Primitives Modeled

- **ML-KEM-768**: Post-quantum key encapsulation (NIST FIPS 203)
- **ML-DSA-65**: Post-quantum digital signatures (NIST FIPS 204)  
- **HKDF-SHA256**: Key derivation function
- **SHA-256**: Hash for key confirmation

## Running Verification

### Prerequisites
- ProVerif 2.05 or later

### Commands
```bash
# Verify all properties
proverif zks_protocol.pv

# Expected output for a secure protocol:
# RESULT not attacker(shared_session_key[]) is true.
# RESULT event(endAliceAccepts(pk_bob)) ==> event(beginBobResponse(pk_bob)) is true.
# RESULT event(endBobAccepts(pk_alice)) ==> event(beginAliceInit(pk_alice)) is true.
```

## Security Model Assumptions

1. **Trusted Public Key**: Alice has Bob's ML-DSA verification key through a trusted channel (PKI, TOFU, etc.)
2. **Fresh Randomness**: All nonces and ephemeral keys are generated from cryptographically secure RNG
3. **Timestamp Validation**: Timestamps are validated to prevent replay attacks (±5 minutes)
4. **Honest Parties**: The model verifies security against network attackers, not compromised endpoints

## References

- [ZKS Protocol Specification](../README.md)
- [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
- [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final)
- [ProVerif Manual](https://bblanche.gitlabpages.inria.fr/proverif/)
