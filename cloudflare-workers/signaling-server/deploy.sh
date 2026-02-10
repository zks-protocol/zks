#!/bin/bash

# ZKS Protocol Signaling Server Deployment Script
# Deploys the signaling server to Cloudflare Workers

set -e

echo "🚀 Deploying ZKS Protocol Signaling Server..."

# Check if wrangler is installed
if ! command -v wrangler &> /dev/null; then
    echo "❌ Wrangler CLI not found. Installing..."
    npm install -g wrangler
fi

# Login to Cloudflare if not authenticated
if ! wrangler whoami &> /dev/null; then
    echo "🔐 Please authenticate with Cloudflare..."
    wrangler login
fi

# Navigate to the signaling server directory
cd "$(dirname "$0")"

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Deploy based on environment
ENVIRONMENT=${1:-staging}

case $ENVIRONMENT in
    production)
        echo "🌐 Deploying to PRODUCTION..."
        wrangler deploy --env production
        echo "✅ Production deployment complete!"
        echo "🔗 Production endpoint: https://zks-protocol-signaling-prod.your-subdomain.workers.dev"
        ;;
    staging)
        echo "🔧 Deploying to STAGING..."
        wrangler deploy --env staging
        echo "✅ Staging deployment complete!"
        echo "🔗 Staging endpoint: https://zks-protocol-signaling-staging.your-subdomain.workers.dev"
        ;;
    *)
        echo "❌ Unknown environment: $ENVIRONMENT"
        echo "Usage: $0 [staging|production]"
        exit 1
        ;;
esac

echo "📝 Next steps:"
echo "1. Update your KV namespace IDs in wrangler.toml"
echo "2. Configure your custom domain in Cloudflare dashboard"
echo "3. Update the SignalingClient in your Rust code with the new endpoint"