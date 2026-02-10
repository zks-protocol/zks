# Builder stage
FROM rust:1.75-slim-bookworm as builder

WORKDIR /usr/src/zks
COPY . .

# Install dependencies for compilation
RUN apt-get update && apt-get install -y pkg-config libssl-dev protobuf-compiler

# Build the admin tool in release mode
RUN cargo build --release --example zks_admin --bin zks-admin

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies (OpenSSL)
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from builder
COPY --from=builder /usr/src/zks/target/release/examples/zks_admin /usr/local/bin/zks-node

# Expose port (Render sets PORT env var automatically)
ENV PORT=10000 
EXPOSE ${PORT}

# Entrypoint script to handle dynamic port binding
COPY <<EOF /entrypoint.sh
#!/bin/sh
echo "🚀 Starting ZKS Node on port \${PORT}..."
exec zks-node start --role \${ROLE:-relay} --bind 0.0.0.0:\${PORT} --network \${NETWORK_NAME:-zks-testnet}
EOF

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
