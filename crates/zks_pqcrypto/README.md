# zks_pqcrypto

Post-quantum cryptographic implementations for the ZKS Protocol.

## Overview

This crate provides NIST-standardized post-quantum cryptographic primitives:

- **ML-KEM-768** (Kyber) - Key encapsulation mechanism (NIST Level 3)
- **ML-DSA-65** (Dilithium) - Digital signatures (NIST Level 3)

## Security Properties

| Algorithm | Security Level | Property |
|-----------|----------------|----------|
| ML-KEM-768 | NIST Level 3 | IND-CCA2 |
| ML-DSA-65 | NIST Level 3 | EUF-CMA |

## Features

- Pure Rust implementation for WASM compatibility
- Memory-safe with Zeroizing wrappers
- No unsafe code

## Usage

```rust
use zks_pqcrypto::prelude::*;

// Generate ML-KEM keypair
let keypair = MlKem::generate_keypair()?;

// Encapsulate shared secret
let (ciphertext, shared_secret) = keypair.encapsulate()?;

// Decapsulate shared secret
let decapsulated = keypair.decapsulate(&ciphertext)?;
```

## License

AGPL-3.0-only
