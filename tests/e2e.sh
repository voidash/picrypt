#!/usr/bin/env bash
set -euo pipefail

# End-to-end test for picrypt server and client binaries.
# Starts a real server process, exercises the HTTP API with curl, and validates
# the full lifecycle: heartbeat, unseal, register, get key, lock, re-unseal.

# Build
cargo build --workspace --release

SERVER=./target/release/picrypt-server
CLIENT=./target/release/picrypt-client

# Create temp dirs for server and client configs
SERVER_DIR=$(mktemp -d)
CLIENT_DIR=$(mktemp -d)
trap 'kill $SERVER_PID 2>/dev/null; rm -rf $SERVER_DIR $CLIENT_DIR' EXIT

# Generate admin token
ADMIN_TOKEN=$(openssl rand -base64 32)
PORT=$(shuf -i 10000-60000 -n 1)  # Random port

# Write server config
cat > "$SERVER_DIR/server.toml" <<EOF
listen_addr = "127.0.0.1:$PORT"
data_dir = "$SERVER_DIR/data"
dead_man_timeout_secs = 0
admin_token = "$ADMIN_TOKEN"
EOF
mkdir -p "$SERVER_DIR/data/devices"

# Start server
HOME="$SERVER_DIR" $SERVER &
SERVER_PID=$!
sleep 1

BASE="http://127.0.0.1:$PORT"

# Test 1: Heartbeat returns sealed
echo "Test 1: Heartbeat..."
STATE=$(curl -s "$BASE/heartbeat" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
[ "$STATE" = "sealed" ] && echo "  PASS: sealed" || { echo "  FAIL: expected sealed, got $STATE"; exit 1; }

# Test 2: Unseal
echo "Test 2: Unseal..."
RESP=$(curl -s -X POST "$BASE/unseal" -H 'Content-Type: application/json' -d '{"password":"test123"}')
STATE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
[ "$STATE" = "active" ] && echo "  PASS: active" || { echo "  FAIL: $RESP"; exit 1; }

# Test 3: Register device
echo "Test 3: Register..."
RESP=$(curl -s -X POST "$BASE/devices/register" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"device_name":"test-device","platform":"linux"}')
DEVICE_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['device_id'])")
AUTH_TOKEN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_token'])")
KEYFILE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['keyfile'])")
echo "  PASS: device=$DEVICE_ID"

# Test 4: Get key
echo "Test 4: Get key..."
RESP=$(curl -s "$BASE/key/$DEVICE_ID" -H "Authorization: Bearer $AUTH_TOKEN")
KEY2=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['keyfile'])")
[ "$KEY2" = "$KEYFILE" ] && echo "  PASS: keyfile matches" || { echo "  FAIL: keyfile mismatch"; exit 1; }

# Test 5: Lock
echo "Test 5: Lock..."
RESP=$(curl -s -X POST "$BASE/lock" -H 'Content-Type: application/json' -d '{}')
STATE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
[ "$STATE" = "sealed" ] && echo "  PASS: sealed after lock" || { echo "  FAIL: $RESP"; exit 1; }

# Test 6: Key fails when sealed
echo "Test 6: Key when sealed..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/key/$DEVICE_ID" -H "Authorization: Bearer $AUTH_TOKEN")
[ "$HTTP_CODE" = "401" -o "$HTTP_CODE" = "503" ] && echo "  PASS: rejected ($HTTP_CODE)" || { echo "  FAIL: expected 401/503, got $HTTP_CODE"; exit 1; }

# Test 7: Re-unseal
echo "Test 7: Re-unseal..."
RESP=$(curl -s -X POST "$BASE/unseal" -H 'Content-Type: application/json' -d '{"password":"test123"}')
STATE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
[ "$STATE" = "active" ] && echo "  PASS: active again" || { echo "  FAIL: $RESP"; exit 1; }

# Test 8: Key still works after re-unseal
echo "Test 8: Key after re-unseal..."
RESP=$(curl -s "$BASE/key/$DEVICE_ID" -H "Authorization: Bearer $AUTH_TOKEN")
KEY3=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['keyfile'])")
[ "$KEY3" = "$KEYFILE" ] && echo "  PASS: keyfile preserved across lock/unseal" || { echo "  FAIL: keyfile changed"; exit 1; }

# Test 9: Wrong password
echo "Test 9: Wrong password..."
kill $SERVER_PID; wait $SERVER_PID 2>/dev/null || true
HOME="$SERVER_DIR" $SERVER &
SERVER_PID=$!
sleep 1
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/unseal" -H 'Content-Type: application/json' -d '{"password":"wrong"}')
[ "$HTTP_CODE" = "401" ] && echo "  PASS: wrong password rejected" || { echo "  FAIL: expected 401, got $HTTP_CODE"; exit 1; }

# Test 10: Unauthenticated register fails
echo "Test 10: Unauthed register..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/unseal" -H 'Content-Type: application/json' -d '{"password":"test123"}')
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/devices/register" -H 'Content-Type: application/json' -d '{"device_name":"rogue","platform":"linux"}')
[ "$HTTP_CODE" = "401" ] && echo "  PASS: unauthed register rejected" || { echo "  FAIL: expected 401, got $HTTP_CODE"; exit 1; }

echo ""
echo "All E2E tests passed."
