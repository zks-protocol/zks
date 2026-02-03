# zks_cover

Post-quantum secure cover traffic for ZKS Protocol.

## Overview

Cover traffic provides traffic analysis resistance by generating indistinguishable dummy packets that blend with real traffic. This makes it harder for adversaries to correlate network activity.

## Features

- **Post-quantum secure**: ML-KEM-1024 key encapsulation (NIST Level 5)
- **Wasif-Vernam encryption**: Each cover packet uniquely encrypted
- **Poisson timing**: Realistic traffic patterns
- **Faisal Swarm integration**: Ready for onion routing

## Quick Start

```rust
use zks_cover::{CoverConfig, CoverGenerator};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure with 2 messages/second average
    let config = CoverConfig::builder()
        .poisson_rate(2.0)
        .payload_size(512)
        .build()?;
    
    let generator = CoverGenerator::new(config)?;
    
    // Generate cover message
    let cover = generator.generate_cover(None).await?;
    println!("Generated {} bytes", cover.payload.len());
    
    Ok(())
}
```

## API Overview

| Type | Purpose |
|------|---------|
| `CoverGenerator` | Generate cover messages |
| `CoverScheduler` | Poisson-timed scheduling |
| `CoverTransport` | Faisal Swarm integration |
| `CoverMessage` | Cover packet with metadata |

## Faisal Swarm Integration

```rust
use zks_cover::{CoverTransport, CoverGenerator, CoverConfig};
use std::sync::Arc;

// Create transport
let config = CoverConfig::default();
let generator = Arc::new(CoverGenerator::new(config.clone())?);
let transport = CoverTransport::new(config, generator);

// Send through circuit
let encrypted = transport.send_cover(&mut circuit, circuit_id).await?;
```

## Run Example

```bash
cargo run --example cover_traffic -p zks_cover
```

## License

AGPLv3 - See LICENSE file
