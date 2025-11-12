#!/usr/bin/env bash

# Quick API test script
BASE_URL="http://localhost:3000"

echo "Quick JWT Auth Service Test"
echo "=============================="

# Test 1: Health check
echo ""
echo "1. Health Check:"
curl -s "$BASE_URL/health" | jq . || echo "jq not available, raw response above"

# Test 2: Login
echo ""
echo "2. Login:"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}')

echo "$LOGIN_RESPONSE" | jq . || echo "$LOGIN_RESPONSE"

# Extract token
TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token' 2>/dev/null || echo "")

if [ "$TOKEN" != "" ] && [ "$TOKEN" != "null" ]; then
    echo ""
    echo "3. Protected /me endpoint:"
    curl -s "$BASE_URL/me" \
      -H "Authorization: Bearer $TOKEN" | jq . || echo "jq not available, raw response above"
    
    echo ""
    echo "4. JWKS endpoint:"
    curl -s "$BASE_URL/.well-known/jwks.json" | jq . || echo "jq not available, raw response above"
else
    echo "Failed to get token, skipping protected endpoint test"
fi

echo ""
echo "Quick test complete!"