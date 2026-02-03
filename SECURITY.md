# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

### How to Report

1. **Email** (preferred): security@zks.wasif.app
2. **GitHub Private Advisory**: [Create a private security advisory](https://github.com/zks-protocol/zks/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

### Disclosure Policy

We follow responsible disclosure:
1. We will acknowledge your report within 48 hours
2. We will work with you to understand and validate the issue
3. We will develop and test a fix
4. We will coordinate public disclosure timing with you
5. We will credit you in security advisories (unless you prefer anonymity)

## Security Measures

ZKS Protocol implements multiple layers of security:

- **Post-Quantum Cryptography**: ML-KEM-768 for key exchange
- **256-bit Post-Quantum Computational Security**: Wasif-Vernam cipher
- **Memory Safety**: Written in Rust
- **Anti-Replay Protection**: Bitmap-based nonce tracking
- **Formal Verification**: Critical components verified with ProVerif

## Bug Bounty

We do not currently have a formal bug bounty program, but we deeply appreciate security researchers who responsibly disclose vulnerabilities and will acknowledge your contribution publicly.
