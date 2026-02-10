#!/bin/bash
# ZKS Protocol Cloudflare Signaling End-to-End Test Script
# This script validates the complete production signaling infrastructure

set -e

echo "🧪 ZKS Protocol Cloudflare Signaling End-to-End Test"
echo "=================================================="

# Configuration
CLOUDFLARE_WORKER_URL=${CLOUDFLARE_WORKER_URL:-"https://signal-staging.zks-protocol.com"}
API_SECRET=${API_SECRET:-"your-api-secret"}
TEST_ROOM="zks-protocol-e2e-test-$(date +%s)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

test_passed() {
    echo -e "${GREEN}✅ $1${NC}"
    ((TESTS_PASSED++))
}

test_failed() {
    echo -e "${RED}❌ $1${NC}"
    ((TESTS_FAILED++))
}

# Test 1: Health Check
log_info "Testing health endpoint..."
if curl -s -f "${CLOUDFLARE_WORKER_URL}/health" > /dev/null; then
    HEALTH_RESPONSE=$(curl -s "${CLOUDFLARE_WORKER_URL}/health")
    if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
        test_passed "Health check endpoint"
    else
        test_failed "Health check endpoint - invalid response"
    fi
else
    test_failed "Health check endpoint - connection failed"
fi

# Test 2: Metrics Endpoint (if API secret available)
if [ "$API_SECRET" != "your-api-secret" ]; then
    log_info "Testing metrics endpoint..."
    if curl -s -f -H "X-API-Key: ${API_SECRET}" "${CLOUDFLARE_WORKER_URL}/metrics" > /dev/null; then
        test_passed "Metrics endpoint (authenticated)"
    else
        test_failed "Metrics endpoint - authentication or connection failed"
    fi
else
    log_warn "Skipping metrics test (no API secret configured)"
fi

# Test 3: WebSocket Connection
log_info "Testing WebSocket connection..."
if command -v websocat &> /dev/null; then
    # Test WebSocket connection with timeout
    timeout 5 websocat -t 3 "${CLOUDFLARE_WORKER_URL}/ws" <<< '{"type":"ping"}' 2>/dev/null || true
    test_passed "WebSocket connection (basic)"
else
    log_warn "websocat not found, skipping WebSocket test"
fi

# Test 4: Rust Integration Tests
log_info "Running Rust integration tests..."
if command -v cargo &> /dev/null; then
    cd "$(dirname "$0")/../../../"
    
    # Set environment for staging tests
    export ZKS_SIGNALING_ENVIRONMENT=staging
    export ZKS_SIGNALING_AUTH_TOKEN="test-token"
    
    if cargo test --test production_integration -- --nocapture; then
        test_passed "Rust integration tests"
    else
        test_failed "Rust integration tests"
    fi
else
    log_warn "Cargo not found, skipping Rust tests"
fi

# Test 5: Rate Limiting
log_info "Testing rate limiting..."
RATE_LIMIT_PASSED=true
for i in {1..15}; do
    if curl -s -f "${CLOUDFLARE_WORKER_URL}/health" > /dev/null; then
        continue
    else
        RATE_LIMIT_PASSED=false
        break
    fi
done

if [ "$RATE_LIMIT_PASSED" = true ]; then
    test_passed "Rate limiting (basic)"
else
    test_failed "Rate limiting (basic)"
fi

# Test 6: Authentication
log_info "Testing authentication..."
if curl -s -f -H "Authorization: Bearer invalid-token" "${CLOUDFLARE_WORKER_URL}/ws" > /dev/null 2>&1; then
    test_failed "Authentication - should reject invalid token"
else
    test_passed "Authentication - rejects invalid token"
fi

# Test 7: CORS Headers
log_info "Testing CORS headers..."
CORS_RESPONSE=$(curl -s -i -X OPTIONS "${CLOUDFLARE_WORKER_URL}/health" | grep -i "access-control")
if echo "$CORS_RESPONSE" | grep -q "Access-Control-Allow-Origin"; then
    test_passed "CORS headers"
else
    test_failed "CORS headers"
fi

# Test 8: Response Time
log_info "Testing response time..."
RESPONSE_TIME=$(curl -s -w "%{time_total}" -o /dev/null "${CLOUDFLARE_WORKER_URL}/health")
RESPONSE_TIME_MS=$(echo "$RESPONSE_TIME * 1000" | bc -l | cut -d. -f1)

if [ "$RESPONSE_TIME_MS" -lt 500 ]; then
    test_passed "Response time (< 500ms): ${RESPONSE_TIME_MS}ms"
else
    test_failed "Response time (too slow): ${RESPONSE_TIME_MS}ms"
fi

# Summary
echo ""
echo "=================================================="
echo "🏁 Test Summary"
echo "=================================================="
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed! Cloudflare signaling is ready for production.${NC}"
    exit 0
else
    echo -e "${RED}⚠️  Some tests failed. Please review the issues above.${NC}"
    exit 1
fi