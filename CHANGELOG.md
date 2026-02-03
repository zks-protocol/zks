# Changelog

All notable changes to ZKS Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Faisal Swarm P2P onion routing topology
- NAT traversal with UPnP and hole punching
- Bitmap-based anti-replay protection (WireGuard-style)
- Global HTTP client singleton for connection pooling

### Changed
- Improved DrandEntropy performance with connection reuse

### Security
- No known vulnerabilities

## [0.1.0] - 2026-01-12

### Added
- **Wasif-Vernam Cipher**: Multi-layer post-quantum encryption
  - HKDF mode for computational security
  - High-entropy XOR mode with drand beacon
- **Post-Quantum Cryptography**
  - ML-KEM-768 key encapsulation
  - ML-DSA-65 digital signatures
- **Core Protocol**
  - libp2p-based P2P networking
  - Signaling server for peer discovery
  - QUIC transport with TLS 1.3
- **Security Features**
  - Anti-replay protection
  - Ciphertext scrambling
  - Recursive key chaining
- **Entropy Sources**
  - drand beacon integration
  - Cloudflare randomness API

### Security
- Formal verification with ProVerif
- No known vulnerabilities
