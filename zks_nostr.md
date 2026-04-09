# ZKS Protocol + Nostr Integration Plan

## 1. Executive Summary
This document outlines the architectural plan to replace the existing centralized Cloudflare Workers signaling layer of the ZKS Protocol with a decentralized, permissionless signaling layer using the Nostr network. This transition transforms ZKS from a private VPN-like infrastructure into a global, community-driven onion routing network (similar to Tor) while maintaining its 256-bit post-quantum security properties.

## 2. Core Objectives
- **Eliminate VPS Costs**: Replace the centralized `zks-protocol-signaling.faisal-swarm.workers.dev` hub with free public Nostr relays (e.g., Damus, Snort).
- **True Decentralization**: Remove the single point of failure in peer discovery.
- **Maintain Anonymity**: Ensure Nostr's pseudonymous metadata model does not leak ZKS routing information or user IP associations.

## 3. Architectural Changes

### 3.1 Swappable Signaling Implementations
Currently, `circuit_manager.rs` relies on the `SignalingClientTrait`. The architecture is already beautifully abstracted. The step forward is to:
1. Deprecate `cloudflare_signaling.rs`.
2. Create a new file: `nostr_signaling.rs`.
3. Add a dependency on a Rust Nostr SDK (e.g., `nostr-sdk` or `nostr-rust`) in `zks_wire/Cargo.toml`.

### 3.2 Peer Discovery via Nostr Events
Instead of sending a JSON `Join` packet to the Cloudflare worker, ZKS Nodes will announce themselves on the Nostr network.

**Publishing Presence (For Relay Nodes):**
- A ZKS Relay Node generates an ephemeral `secp256k1` key upon startup.
- It publishes a **Parameterized Replaceable Event (Kind 30000)** to a list of default Nostr relays.
- The event's `content` contains the JSON representation of `PeerInfo` (including `multiaddrs` for libp2p and capabilities).
- The event is tagged with `["t", "{room_id}"]` so the ZKS swarm can find it.

**Discovering Peers (For Client Nodes):**
- A ZKS Client connects to the Nostr relay via WebSocket.
- It sends a Nostr `REQ` (Subscription) filter:
  `[{"kinds": [30000], "#t": ["{room_id}"]}]`
- The relay responds with the active ZKS Guard/Middle/Exit nodes available in the community.
- The `FaisalSwarmManager` then uses `TrueEntropyRng` to select 3 nodes and builds the ML-KEM-1024 libp2p circuit.

## 4. Solving the Anonymity Problem
**The Problem:** Nostr events broadcast public keys and relays log IP addresses.
**The ZKS Solution:** "Burner" Identities.

To preserve the ZKS anonymity guarantees:
- **Clients**: A ZKS Client will generate a *brand new, randomly generated* Nostr keypair every single time it builds a circuit. It will use this burner ID to fetch the peer list and then discard the key immediately. This breaks all identity correlation on the Nostr application layer.
- **Relays**: A Relay Node will maintain a persistent session key for the duration of its uptime to build its "Health Score" reliability over time, but will frequently rotate its IP/Key associations if censorship resistance is heavily required.

## 5. Solving the Entropy Problem
**The Problem:** `cloudflare_signaling.rs` currently provides certified 32-byte cryptographic entropy via `get_swarm_entropy()`. Nostr relays cannot dynamically generate and sign cryptographic entropy payloads.
**The ZKS Solution:** 
- ZKS Nodes must rely directly on the distributed `api.drand.sh` network natively to fetch the BLS-signed round randomness.
- The local `TrueEntropyRng` must act as the primary fallback securely integrated into the `Wasif-Vernam` setup.

## 6. Implementation Timeline

### Phase 1: Nostr Client Integration
- Implement `nostr_signaling.rs` utilizing the `nostr-sdk` crate.
- Map the functions `discover_peers` and `join_room` to Nostr `REQ` streams and `EVENT` broadcasts.

### Phase 2: Local Randomness Transition
- Refactor `circuit_manager.rs` to fetch drand independently of the signaling trait.
- Ensure `TrueEntropyRng` handles local OS randomness without requiring a server oracle.

### Phase 3: Anonymity Polish
- Introduce ephemeral key generation inside the `SignalingClientTrait` constructor.
- Add event expiry tags (`["expiration", "<timestamp>"]`) to the Kind 30000 events so Nostr relays automatically delete dead ZKS nodes from their database.

## 7. Conclusion
By utilizing Nostr as a decentralized peer discovery directory, ZKS Protocol eliminates centralized points of failure and creator hosting costs. It turns ZKS into a self-sustaining, community-driven network layer that can scale infinitely on top of the world's largest permissionless message broker.
