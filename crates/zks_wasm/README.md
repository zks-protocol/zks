# zks_wasm

WebAssembly bindings for the ZKS Protocol.

## Overview

This crate provides JavaScript/TypeScript bindings for browser usage:

- **ML-DSA Signatures** - Post-quantum digital signatures
- **ML-KEM Key Exchange** - Post-quantum key encapsulation
- **Utility Functions** - Encoding, hashing, random generation

## Installation

```bash
npm install zks-wasm
```

## Usage

```javascript
import init, { ZksWasmUtils } from 'zks-wasm';

await init();

// Generate post-quantum keypair
const keypair = ZksWasmUtils.generate_ml_dsa_keypair();

// Sign a message
const message = new TextEncoder().encode("Hello ZKS!");
const signature = ZksWasmUtils.ml_dsa_sign(message, keypair.signing_key);

// Verify signature
const isValid = ZksWasmUtils.ml_dsa_verify(message, signature, keypair.verifying_key);
console.log("Valid:", isValid);
```

## Building

```bash
wasm-pack build --target web
```

## License

AGPL-3.0-only
