# ZKS Offline OTP

> **Zero Knowledge Swarm - Offline One-Time Pad Encryption**

A Rust implementation of information-theoretically secure file encryption using the One-Time Pad (OTP) cipher with physical key exchange.

## Security Levels

| Mode | Security Level | Key Usage | Use Case |
|------|----------------|-----------|----------|
| **Strict** | Information-Theoretic (Unbreakable) | 1 byte per data byte | Small critical files |
| **Efficient** | 256-bit Computational | 32 bytes per file | Large files |

> ⚠️ **IMPORTANT SECURITY CLAIMS**
> 
> - **Strict Mode** provides *information-theoretic security* (ITS) when using truly random keys from a hardware RNG.
> - **Efficient Mode** provides *computational security* (ChaCha20-Poly1305), which is NOT information-theoretically secure.
> - System RNG (`getrandom`) provides *cryptographically secure* randomness, but not *true* randomness for ITS.
> - Intel RDSEED provides hardware entropy that is *probably* true random, but cannot be independently verified.

## Installation

```bash
# Build the CLI tool
cargo build -p zks_otp --features cli --release

# The binary will be at target/release/zks-otp
```

## Usage

### Generate a Key File

```bash
# Generate 1GB key file
zks-otp generate --output mykey.zkskey --size 1GB

# Generate with hardware RNG (Intel RDSEED if available)
zks-otp generate --output mykey.zkskey --size 100MB --hardware
```

### Encrypt a File (Strict Mode - ITS)

```bash
# Strict OTP: Consumes key_size == file_size
zks-otp encrypt --input secret.txt --key mykey.zkskey --output secret.enc
```

### Decrypt a File

```bash
zks-otp decrypt --input secret.enc --key mykey.zkskey --output secret_recovered.txt
```

### Check Key Status

```bash
zks-otp status --key mykey.zkskey
# Output:
# Total bytes: 1073741824
# Used bytes: 1024
# Remaining bytes: 1073740800
# Usage: 0.0%
```

## Key File Format (.zkskey)

```
┌──────────────────────────────────────┐
│ Header (66 bytes)                    │
├──────────────────────────────────────┤
│ Magic: "ZKSOTP01" (8 bytes)          │
│ Version: u16 (2 bytes)               │
│ Total Bytes: u64 (8 bytes)           │
│ Used Bytes: u64 (8 bytes)            │
│ Created At: u64 (8 bytes)            │
│ SHA-256 Checksum: [u8; 32]           │
├──────────────────────────────────────┤
│ Entropy (variable length)            │
│ Raw random bytes from RNG            │
└──────────────────────────────────────┘
```

## Encryption Modes

### Strict Mode (Information-Theoretic Security)

```
Plaintext:  [AAAABBBBCCCC...]
Key:        [XXXXYYYYZZZZ...] (same length)
Ciphertext: Plaintext ⊕ Key
```

- **Security:** Unbreakable by any computational power (Shannon's proof)
- **Requirement:** Key length ≥ Data length
- **Key consumption:** 1:1 (100% efficient)

### Efficient Mode (256-bit Computational Security)

```
Output Format:
┌─────────────────┬────────────┬───────────────────┐
│ Wrapped DEK     │ Nonce      │ ChaCha20 Ciphertext│
│ (32 bytes)      │ (12 bytes) │ (variable)         │
└─────────────────┴────────────┴───────────────────┘

Where:
  DEK = Random 32-byte key
  Wrapped DEK = DEK ⊕ OTP_Key (32 bytes from key file)
  Ciphertext = ChaCha20-Poly1305(DEK, Nonce, Plaintext)
```

- **Security:** 256-bit computational (unbreakable until quantum computers with millions of qubits)
- **Requirement:** 32 bytes of key material per file
- **Key consumption:** 32 bytes per file regardless of size

## Hardware RNG Support

| Source | Type | Speed | Trust Level |
|--------|------|-------|-------------|
| Intel RDSEED | CPU instruction | ~500 MB/s | Medium (black box) |
| SerialPort RNG | USB device (OneRNG, TrueRNG) | ~10 KB/s | High (open hardware) |
| System RNG | OS CSPRNG | ~1 GB/s | High for computational security |

## Security Considerations

### What This Provides

✅ Perfect secrecy in Strict Mode (with true random keys)
✅ Authentication via Poly1305 in Efficient Mode
✅ Key reuse prevention (offset tracking)
✅ File integrity verification (SHA-256 checksum)
✅ Secure key shredding (3-pass overwrite)

### What This Does NOT Provide

❌ Key exchange (you must physically transfer keys)
❌ Authentication of sender (no signatures)
❌ Protection against physical access to key files
❌ True randomness verification (you trust the RNG)

### SSD Warning

⚠️ SSDs may not honor in-place overwrites due to wear leveling. For maximum security:
- Generate keys on encrypted volumes
- Use hardware-encrypted USB drives
- Use HDDs for key storage if possible

## Library Usage

```rust
use zks_otp::{KeyFile, OfflineOtp, OtpMode};
use std::path::Path;

fn main() -> zks_otp::Result<()> {
    // Create a new key file
    let mut key = KeyFile::create(Path::new("key.zkskey"), 1024)?;
    
    // Encrypt with strict OTP (ITS)
    let result = OfflineOtp::encrypt_strict(
        Path::new("secret.txt"),
        &mut key,
        Path::new("secret.enc"),
    )?;
    
    println!("Encrypted {} bytes", result.bytes_encrypted);
    println!("Key bytes used: {}", result.key_bytes_consumed);
    
    Ok(())
}
```

## Testing

```bash
# Run all tests
cargo test -p zks_otp

# Run tests with verbose output
cargo test -p zks_otp -- --nocapture
```

## License

MIT OR Apache-2.0
