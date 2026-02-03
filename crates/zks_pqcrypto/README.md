# zks_pqcrypto

Post-quantum cryptographic implementations for the ZKS Protocol.

## Overview

This crate provides NIST-standardized post-quantum cryptographic primitives:

- **ML-KEM-1024** (Kyber) - Key encapsulation mechanism (NIST Level 5)
- **ML-DSA-87** (Dilithium) - Digital signatures (NIST Level 5)

## Security Properties

| Algorithm | Security Level | Property |
|-----------|----------------|----------|
| ML-KEM-1024 | NIST Level 5 | IND-CCA2 |
| ML-DSA-87 | NIST Level 5 | EUF-CMA |

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
