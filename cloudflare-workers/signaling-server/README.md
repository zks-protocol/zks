# ZKS Protocol Cloudflare Workers Signaling Server

Production-grade signaling infrastructure for ZKS Protocol using Cloudflare Workers for global distribution and high availability.

## Architecture

### Dual-Network Design
- **WebSocket Signaling**: Peer discovery and coordination via Cloudflare Workers
- **libp2p Data Transmission**: Encrypted data transfer using post-quantum ML-KEM

### Key Features
- **Global Edge Distribution**: Deployed to 300+ Cloudflare edge locations
- **Rate Limiting**: Per-IP and per-room message limits
- **Authentication**: JWT-based peer authentication
- **High Availability**: Automatic failover with fallback endpoints
- **Real-time Metrics**: Built-in analytics and monitoring

## Deployment

### Prerequisites
```bash
npm install -g wrangler
wrangler login
```

### Environment Setup
```bash
# Create KV namespaces
wrangler kv:namespace create "SIGNALING_KV"
wrangler kv:namespace create "SIGNALING_KV" --preview

# Set secrets
wrangler secret put JWT_SIGNING_KEY
wrangler secret put API_SECRET
wrangler secret put ANALYTICS_API_KEY
```

### Deploy to Staging
```bash
wrangler deploy --env staging
```

### Deploy to Production
```bash
wrangler deploy --env production
```

## Configuration

### Environment Variables
- `ENVIRONMENT`: "staging" or "production"
- `MAX_PEERS_PER_ROOM`: Maximum peers per signaling room (default: 100)
- `MESSAGE_RATE_LIMIT`: Messages per minute per peer (default: 200)
- `ROOM_EXPIRY_HOURS`: Room cleanup interval (default: 48)
- `ENABLE_METRICS`: Enable analytics collection (default: true)

### Client Configuration
```rust
use zks_wire::cloudflare_signaling::{CloudflareSignalingClient, CloudflareSignalingConfig};

let config = CloudflareSignalingConfig {
    primary_endpoint: "wss://signal.zks-protocol.com/ws".to_string(),
    fallback_endpoints: vec![
        "wss://signal-backup.zks-protocol.com/ws".to_string(),
    ],
    auth_token: Some("your-jwt-token".to_string()),
    max_reconnect_attempts: 5,
    connection_timeout: Duration::from_secs(30),
};

let client = CloudflareSignalingClient::connect(config, "my-peer-id".to_string()).await?;
```

## API Endpoints

### WebSocket Connection
```
wss://signal.zks-protocol.com/ws
```

### Message Types
- `join`: Join a signaling room
- `leave`: Leave a signaling room  
- `discover`: Discover peers in room
- `entropy_request`: Request swarm entropy

### Response Types
- `JoinSuccess`: Room join confirmation
- `PeerJoined`: New peer notification
- `PeerLeft`: Peer departure notification
- `DiscoverResponse`: Peer discovery results
- `EntropyResponse`: Swarm entropy data

## Monitoring

### Health Check
```bash
curl https://signal.zks-protocol.com/health
```

### Metrics
```bash
curl https://signal.zks-protocol.com/metrics
```

## Security

### Authentication
- JWT tokens for peer authentication
- API keys for administrative access
- Rate limiting per IP address

### Encryption
- TLS 1.3 for WebSocket connections
- Post-quantum ML-KEM for libp2p handshakes
- End-to-end encryption for data transmission

## Troubleshooting

### Common Issues
1. **Connection Timeouts**: Check firewall settings and Cloudflare Workers status
2. **Rate Limiting**: Verify `MESSAGE_RATE_LIMIT` configuration
3. **Authentication Failures**: Validate JWT tokens and signing keys

### Logs
```bash
wrangler tail --env production
```

## Production Checklist

- [ ] KV namespaces created and configured
- [ ] Secrets set (JWT_SIGNING_KEY, API_SECRET, ANALYTICS_API_KEY)
- [ ] Custom domain configured
- [ ] Rate limits tuned for your use case
- [ ] Monitoring and alerting set up
- [ ] Backup signaling endpoints deployed
- [ ] Authentication system integrated
- [ ] Load testing completed