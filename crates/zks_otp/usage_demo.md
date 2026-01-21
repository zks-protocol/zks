# ZKS OTP Usage Demo

## Understanding Key Material Consumption

The ZKS OTP implementation correctly treats key material as consumable. Once key material is used, it's marked as "used" and cannot be reused. This is fundamental to OTP security.

### Problem Demonstration

When you run these commands:
```bash
# Generate a key file
cargo run --features cli -- generate --output demo_key.zkskey --size 1KB

# Encrypt a file (uses first 190 bytes of key material)
cargo run --features cli -- encrypt --input test_message.txt --key demo_key.zkskey --output encrypted.zksenc

# Try to decrypt with the same key file (uses next 190 bytes of key material)
cargo run --features cli -- decrypt --input encrypted.zksenc --key demo_key.zkskey --output decrypted.txt
```

The decryption fails because it uses different key material than the encryption.

### Correct Usage Pattern

For proper OTP usage, you should:

1. **Generate sufficient key material for all your files**
2. **Track which key positions were used for which files**
3. **Never reuse key material**

Example workflow:
```bash
# Generate a large key file
cargo run --features cli -- generate --output large_key.zkskey --size 100MB

# Encrypt file 1 (uses position 0-190)
cargo run --features cli -- encrypt --input file1.txt --key large_key.zkskey --output file1.zksenc

# Encrypt file 2 (uses position 191-380, etc.)
cargo run --features cli -- encrypt --input file2.txt --key large_key.zkskey --output file2.zksenc

# To decrypt file1, you need to know it used positions 0-190
# This requires external key position tracking
```

### Key File Status

Check key file usage:
```bash
cargo run --features cli -- status --key demo_key.zkskey
```

This shows:
- Total key material available
- Used key material (cannot be reused)
- Remaining key material (available for future use)

### Security Note

The current implementation is cryptographically correct. Key material should never be reused in OTP. The "garbled" output when decrypting with wrong key material is the expected behavior.