# Contributing to ZKS Protocol

Thank you for your interest in contributing to ZKS Protocol! This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/zks.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`

## Development Setup

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build the project
cargo build

# Run tests
cargo test

# Run lints
cargo clippy
```

## Code Standards

Before submitting a pull request:

1. **Format your code**: `cargo fmt`
2. **Run lints**: `cargo clippy -- -D warnings`
3. **Run tests**: `cargo test`
4. **Add tests** for new functionality

## Pull Request Process

1. Ensure all tests pass
2. Update documentation if needed
3. Add a clear description of what your PR does
4. Reference any related issues

## Commit Messages

Use clear, descriptive commit messages:
- `feat: add post-quantum key exchange`
- `fix: resolve anti-replay window edge case`
- `docs: update security documentation`
- `test: add unit tests for Wasif-Vernam cipher`

## Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for reporting instructions.

## Code of Conduct

Be respectful and constructive in all interactions. We welcome contributors from all backgrounds.

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
