# zks_surb

Single-Use Reply Blocks (SURBs) for ZKS Protocol - post-quantum anonymous replies.

## Overview

SURBs enable anonymous bidirectional communication. A sender creates a SURB and shares it with a recipient, who can then send an anonymous reply without knowing the sender's identity.

## Features

- **Post-quantum secure**: ML-KEM-1024 key encapsulation (NIST Level 5)
- **Anonymous replies**: Recipient can't identify sender
- **Single-use**: Each SURB works exactly once
- **Time-limited**: Configurable expiry
- **Faisal Swarm ready**: Integrates with onion routing

## Quick Start

```rust
use zks_surb::{ZksSurb, SurbEncryption};
use zks_pqcrypto::ml_kem::MlKem;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Alice creates SURB
    let alice_keypair = MlKem::generate_keypair()?;
    let (surb, private_data) = ZksSurb::create(alice_keypair.public_key())?;
    
    // Alice sends surb to Bob (keep private_data secret!)
    let surb_bytes = surb.to_bytes()?;
    
    // Bob receives and uses SURB
    let received_surb = ZksSurb::from_bytes(&surb_bytes)?;
    
    // Alice decrypts reply using private_data.encryption_key
    let decryptor = SurbEncryption::new(private_data.encryption_key);
    
    Ok(())
}
```

## API Overview

| Type | Purpose |
|------|---------|
| `ZksSurb` | Public SURB (shared with recipient) |
| `PrivateSurbData` | Secret data (kept by sender) |
| `SurbEncryption` | Encrypt/decrypt replies |
| `ReplyRequest` | Structure for sending replies |

## SURB Workflow

```
1. Alice generates ML-KEM keypair
2. Alice creates SURB → (public_surb, private_data)
3. Alice sends public_surb to Bob
4. Bob encrypts reply using SURB
5. Bob sends encrypted reply through SURB route
6. Alice decrypts using private_data.encryption_key
```

## Run Example

```bash
cargo run --example anonymous_reply -p zks_surb
```

## Security Notes

- **Never share `private_data`** - it contains the decryption key
- **Each SURB is single-use** - for replay attack prevention
- **SURBs expire** - default 1 hour lifetime

## License

AGPLv3 - See LICENSE file
