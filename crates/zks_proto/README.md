# zks_proto

Protocol layer for the ZKS Protocol - handshake and URL parsing.

## Overview

This crate implements the ZKS Protocol message layer:

- **3-Message Handshake** - Post-quantum secure key exchange
- **URL Parsing** - `zk://` and `zks://` protocol handlers
- **Message Types** - Structured protocol messages
- **Error Handling** - Protocol-specific errors

## Handshake Flow

```
Initiator                              Responder
    │                                       │
    │  1. HandshakeInit                     │
    │  ────────────────────────────────►    │
    │  [ephemeral_pk, nonce]                │
    │                                       │
    │  2. HandshakeResponse                 │
    │  ◄────────────────────────────────    │
    │  [ephemeral_pk, ciphertext, sig]      │
    │                                       │
    │  3. HandshakeFinish                   │
    │  ────────────────────────────────►    │
    │  [confirmation_hash]                  │
    │                                       │
```

## Usage

```rust
use zks_proto::url::ZksUrl;

let url = ZksUrl::parse("zks://example.com:8443/room123")?;
println!("Protocol: {}", url.protocol());
println!("Host: {}", url.host());
```

## License

AGPL-3.0-only
