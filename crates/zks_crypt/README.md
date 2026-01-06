# zks_crypt

Cryptographic primitives for the ZKS Protocol - post-quantum secure encryption.

## Overview

This crate provides the core cryptographic operations for ZKS Protocol:

- **Wasif-Vernam Cipher** - ChaCha20-Poly1305 with XOR layer
- **TRUE Random Entropy** - drand beacon integration
- **Recursive Chain** - Key derivation with forward secrecy
- **Scrambling Mode** - Traffic analysis resistance

## Features

- Post-quantum resistant symmetric encryption
- TRUE random entropy from drand network
- Memory-safe with automatic zeroization
- No unsafe code

## Usage

```rust
use zks_crypt::wasif_vernam::WasifVernam;

let key = [0u8; 32]; // Use proper random key in production
let mut cipher = WasifVernam::new(&key)?;

let encrypted = cipher.encrypt(b"Hello, World!")?;
let decrypted = cipher.decrypt(&encrypted)?;
```

## License

AGPL-3.0-only
