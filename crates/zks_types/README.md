# zks_types

Core types and data structures for the ZKS Protocol.

## Overview

This crate provides foundational types used across the ZKS Protocol ecosystem:

- **SecBuffer** - Security buffer for encrypted data
- **CryptoParameters** - Cryptographic parameter configurations
- **KemAlgorithm** - Key encapsulation mechanism selection
- **SecurityLevel** - Security level definitions
- **ZksError** - Unified error types

## Usage

```rust
use zks_types::prelude::*;

let params = CryptoParameters::default();
println!("KEM: {}", params.kem_algorithm);
println!("Security: {}", params.security_level);
```

## License

AGPL-3.0-only
