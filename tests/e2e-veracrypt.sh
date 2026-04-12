#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# picrypt E2E VeraCrypt volume lifecycle test
#
# Tests the FULL flow: server unseal → register → get keyfile →
# create VeraCrypt container → mount → write file → dismount →
# remount → verify file survives → lock → re-unseal → re-mount → verify
#
# Requirements:
#   - VeraCrypt installed (macOS: brew install --cask veracrypt, Linux: apt install veracrypt)
#   - macOS: macFUSE installed and loaded (requires reboot after first install)
#   - sudo (VeraCrypt mount/dismount requires root)
#   - cargo (to build the server binary)
#
# Usage:
#   sudo ./tests/e2e-veracrypt.sh
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}PASS${NC}: $*"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $*" >&2; FAIL_COUNT=$((FAIL_COUNT+1)); cleanup; exit 1; }
skip() { echo -e "  ${YELLOW}SKIP${NC}: $*"; }
info() { echo -e "${BLUE}[*]${NC} $*"; }

PASS_COUNT=0
FAIL_COUNT=0

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
CONTAINER_FILE=""
MOUNT_POINT=""
KEYFILE_TMP=""
SERVER_PID=""
TMPDIR_ROOT=""

cleanup() {
    set +e
    if [[ -n "$MOUNT_POINT" ]] && mount | grep -q "$MOUNT_POINT"; then
        "$VERACRYPT_BIN" --text --dismount --force "$MOUNT_POINT" 2>/dev/null
    fi
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
    [[ -n "$TMPDIR_ROOT" ]] && rm -rf "$TMPDIR_ROOT"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Detect VeraCrypt
# ---------------------------------------------------------------------------
OS="$(uname -s)"
VERACRYPT_BIN=""

if [[ "$OS" == "Darwin" ]]; then
    # Check macFUSE
    if [[ ! -d "/Library/Filesystems/macfuse.fs" ]] && \
       [[ ! -d "/Library/Frameworks/macFUSE.framework" ]]; then
        skip "macFUSE not installed. Required for VeraCrypt on macOS."
        skip "Install: brew install --cask macfuse (requires reboot)"
        exit 0
    fi
    VERACRYPT_BIN="/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"
else
    VERACRYPT_BIN="$(command -v veracrypt 2>/dev/null || true)"
fi

if [[ -z "$VERACRYPT_BIN" ]] || [[ ! -x "$VERACRYPT_BIN" ]]; then
    skip "VeraCrypt not installed."
    [[ "$OS" == "Darwin" ]] && skip "Install: brew install --cask veracrypt"
    [[ "$OS" != "Darwin" ]] && skip "Install: sudo apt install veracrypt"
    exit 0
fi

info "VeraCrypt: $VERACRYPT_BIN"

# Check root/sudo
if [[ "$(id -u)" -ne 0 ]]; then
    echo "VeraCrypt mount requires root. Run: sudo $0"
    exit 1
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
info "Building picrypt-server (release)..."
(cd "$REPO_DIR" && cargo build --release -p picrypt-server 2>&1 | tail -1)
SERVER="$REPO_DIR/target/release/picrypt-server"

# ---------------------------------------------------------------------------
# Setup temp environment
# ---------------------------------------------------------------------------
TMPDIR_ROOT=$(mktemp -d)
SERVER_DIR="$TMPDIR_ROOT/server"
CONTAINER_FILE="$TMPDIR_ROOT/test.hc"
MOUNT_POINT="$TMPDIR_ROOT/mnt"
KEYFILE_TMP="$TMPDIR_ROOT/keyfile.bin"

mkdir -p "$SERVER_DIR/data/devices" "$MOUNT_POINT"

ADMIN_TOKEN=$(openssl rand -base64 32)

# Find a free port
if command -v python3 &>/dev/null; then
    PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
else
    PORT=$((10000 + RANDOM % 50000))
fi

cat > "$SERVER_DIR/server.toml" <<EOF
listen_addr = "127.0.0.1:$PORT"
data_dir = "$SERVER_DIR/data"
dead_man_timeout_secs = 0
admin_token = "$ADMIN_TOKEN"
EOF

# Start server (as the original user if running under sudo)
HOME="$SERVER_DIR" "$SERVER" &
SERVER_PID=$!
sleep 1

BASE="http://127.0.0.1:$PORT"

# Verify server is up
if ! curl -sf "$BASE/heartbeat" > /dev/null 2>&1; then
    fail "Server did not start"
fi

# ---------------------------------------------------------------------------
# Phase 1: Server API
# ---------------------------------------------------------------------------
echo ""
info "Phase 1: Server API"

# Unseal
RESP=$(curl -sf -X POST "$BASE/unseal" \
    -H 'Content-Type: application/json' \
    -d '{"password":"e2e-veracrypt-test"}')
STATE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
[[ "$STATE" == "active" ]] && pass "Unseal → active" || fail "Unseal: got $STATE"

# Register
RESP=$(curl -sf -X POST "$BASE/devices/register" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{"device_name":"e2e-vc","platform":"linux"}')
DEVICE_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['device_id'])")
AUTH_TOKEN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_token'])")
KEYFILE_B64=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['keyfile'])")
pass "Registered device=$DEVICE_ID"

# Decode keyfile
echo "$KEYFILE_B64" | base64 --decode > "$KEYFILE_TMP"
chmod 600 "$KEYFILE_TMP"
pass "Keyfile decoded ($(wc -c < "$KEYFILE_TMP" | tr -d ' ') bytes)"

# ---------------------------------------------------------------------------
# Phase 2: VeraCrypt container lifecycle
# ---------------------------------------------------------------------------
echo ""
info "Phase 2: VeraCrypt container lifecycle"

# Create container (10MB, FAT, AES — fast for testing)
info "Creating 10MB VeraCrypt container..."
if "$VERACRYPT_BIN" --text --create "$CONTAINER_FILE" \
    --size=10M \
    --encryption=AES \
    --hash=SHA-512 \
    --filesystem=FAT \
    --keyfiles="$KEYFILE_TMP" \
    --random-source=/dev/urandom \
    --password= \
    --pim=0 \
    --volume-type=normal \
    --non-interactive 2>&1; then
    pass "Container created: $(du -h "$CONTAINER_FILE" | cut -f1)"
else
    fail "veracrypt --create failed"
fi

# Mount
info "Mounting..."
if "$VERACRYPT_BIN" --text --mount \
    --keyfiles="$KEYFILE_TMP" \
    --protect-hidden=no \
    --pim=0 \
    --password= \
    "$CONTAINER_FILE" \
    "$MOUNT_POINT" 2>&1; then
    pass "Mounted at $MOUNT_POINT"
else
    fail "veracrypt --mount failed"
fi

# Write canary
CANARY="picrypt-e2e-$(date +%s)-$$"
echo "$CANARY" > "$MOUNT_POINT/canary.txt"
[[ -f "$MOUNT_POINT/canary.txt" ]] && pass "Canary written" || fail "Write failed"

CONTENT=$(cat "$MOUNT_POINT/canary.txt")
[[ "$CONTENT" == "$CANARY" ]] && pass "Canary verified" || fail "Content mismatch: $CONTENT"

# Dismount
"$VERACRYPT_BIN" --text --dismount --force "$MOUNT_POINT"
sleep 1
if mount | grep -q "$MOUNT_POINT"; then
    fail "Still mounted after dismount"
fi
pass "Dismounted"

# Verify empty
if [[ -f "$MOUNT_POINT/canary.txt" ]]; then
    fail "Canary visible after dismount"
fi
pass "Mount point empty"

# Remount
"$VERACRYPT_BIN" --text --mount \
    --keyfiles="$KEYFILE_TMP" \
    --protect-hidden=no \
    --pim=0 \
    --password= \
    "$CONTAINER_FILE" \
    "$MOUNT_POINT"
pass "Remounted"

# Verify canary survived
CONTENT2=$(cat "$MOUNT_POINT/canary.txt")
[[ "$CONTENT2" == "$CANARY" ]] \
    && pass "Canary survived dismount/remount" \
    || fail "Canary lost: $CONTENT2"

# ---------------------------------------------------------------------------
# Phase 3: Lock/unseal cycle with mounted volume
# ---------------------------------------------------------------------------
echo ""
info "Phase 3: Lock/unseal key preservation"

# Dismount before lock
"$VERACRYPT_BIN" --text --dismount --force "$MOUNT_POINT"
sleep 1

# Lock server
RESP=$(curl -sf -X POST "$BASE/lock" -H 'Content-Type: application/json' -d '{}')
STATE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
[[ "$STATE" == "sealed" ]] && pass "Server locked" || fail "Lock: $STATE"

# Key should fail when sealed
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/key/$DEVICE_ID" \
    -H "Authorization: Bearer $AUTH_TOKEN")
[[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "503" ]] \
    && pass "Key rejected when sealed ($HTTP_CODE)" \
    || fail "Expected 401/503, got $HTTP_CODE"

# Re-unseal
RESP=$(curl -sf -X POST "$BASE/unseal" \
    -H 'Content-Type: application/json' \
    -d '{"password":"e2e-veracrypt-test"}')
STATE=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['state'])")
[[ "$STATE" == "active" ]] && pass "Re-unsealed" || fail "Re-unseal: $STATE"

# Key should be the same
RESP=$(curl -sf "$BASE/key/$DEVICE_ID" -H "Authorization: Bearer $AUTH_TOKEN")
KEYFILE_B64_AFTER=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['keyfile'])")
[[ "$KEYFILE_B64_AFTER" == "$KEYFILE_B64" ]] \
    && pass "Keyfile survived lock/unseal" \
    || fail "Keyfile changed after lock/unseal"

# Re-mount with the re-fetched key and verify canary
echo "$KEYFILE_B64_AFTER" | base64 --decode > "$KEYFILE_TMP"
"$VERACRYPT_BIN" --text --mount \
    --keyfiles="$KEYFILE_TMP" \
    --protect-hidden=no \
    --pim=0 \
    --password= \
    "$CONTAINER_FILE" \
    "$MOUNT_POINT"

CONTENT3=$(cat "$MOUNT_POINT/canary.txt")
[[ "$CONTENT3" == "$CANARY" ]] \
    && pass "Canary survived full lock/unseal/remount cycle" \
    || fail "Canary lost after lock/unseal: $CONTENT3"

# Final dismount
"$VERACRYPT_BIN" --text --dismount --force "$MOUNT_POINT"
pass "Final dismount"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}All $PASS_COUNT E2E VeraCrypt tests passed.${NC}"
