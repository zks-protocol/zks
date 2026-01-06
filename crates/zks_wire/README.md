# zks_wire

Network primitives for the ZKS Protocol - NAT traversal, STUN, and swarm networking.

## Overview

This crate provides low-level networking primitives:

- **NAT Traversal** - Hole punching and UPnP/NAT-PMP support
- **STUN/ICE** - Connection establishment
- **Swarm Networking** - Peer discovery and mesh formation
- **Wire Protocol** - Binary message framing
- **Onion Routing** - Multi-hop anonymous circuits

## Features

- Built-in NAT traversal
- Decentralized peer discovery
- Circuit-based onion routing
- Traffic analysis resistance

## Usage

```rust
use zks_wire::{Swarm, StunClient, NatTraversal};

// Discover public address
let mut stun = StunClient::new("stun.l.google.com:19302");
let public_addr = stun.discover().await?;

// Create swarm network
let swarm = Swarm::new("my-network".to_string());
```

## License

AGPL-3.0-only
