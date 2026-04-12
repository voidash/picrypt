#!/usr/bin/env bash
# install-server.sh — Install picrypt-server on a Raspberry Pi.
#
# Idempotent: safe to run multiple times. Re-running will:
#   - Update the binary (if a new one is provided)
#   - Reinstall the systemd unit file
#   - NOT overwrite an existing server.toml (preserves tokens/config)
#
# Usage:
#   sudo ./install-server.sh [--binary /path/to/picrypt-server]
#
# If --binary is not provided, falls back to building from source with cargo.

set -euo pipefail

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

log_info()  { printf "[INFO]  %s\n" "$*"; }
log_warn()  { printf "[WARN]  %s\n" "$*" >&2; }
log_error() { printf "[ERROR] %s\n" "$*" >&2; }
log_ok()    { printf "[OK]    %s\n" "$*"; }

die() {
    log_error "$@"
    exit 1
}

# --------------------------------------------------------------------------- #
# Parse arguments
# --------------------------------------------------------------------------- #

BINARY_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)
            if [[ -z "${2:-}" ]]; then
                die "--binary requires a path argument"
            fi
            BINARY_PATH="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: sudo $0 [--binary /path/to/picrypt-server]"
            echo ""
            echo "Options:"
            echo "  --binary PATH   Use a pre-built binary instead of building from source"
            exit 0
            ;;
        *)
            die "Unknown argument: $1"
            ;;
    esac
done

# --------------------------------------------------------------------------- #
# Pre-checks
# --------------------------------------------------------------------------- #

if [[ "$(id -u)" -ne 0 ]]; then
    die "This script must be run as root. Use: sudo $0"
fi

# --------------------------------------------------------------------------- #
# Check Tailscale
# --------------------------------------------------------------------------- #

log_info "Checking Tailscale status..."

if ! command -v tailscale &>/dev/null; then
    die "tailscale command not found. Install Tailscale first: https://tailscale.com/download"
fi

if ! systemctl is-active --quiet tailscaled; then
    die "tailscaled is not running. Start it with: sudo systemctl start tailscaled"
fi

TAILSCALE_IP="$(tailscale ip -4 2>/dev/null || true)"
if [[ -z "${TAILSCALE_IP}" ]]; then
    die "Could not determine Tailscale IPv4 address. Is this node logged in?"
fi

log_ok "Tailscale is running. IP: ${TAILSCALE_IP}"

# --------------------------------------------------------------------------- #
# Create system user
# --------------------------------------------------------------------------- #

log_info "Ensuring 'picrypt' system user exists..."

if id picrypt &>/dev/null; then
    log_ok "User 'picrypt' already exists"
else
    # Use /var/lib/picrypt as the home dir so it lines up with the
    # systemd unit's StateDirectory= and HOME= environment override.
    # /home/picrypt is intentionally NOT used: the unit hardens with
    # ProtectHome=yes, which makes /home invisible to the service.
    useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/picrypt picrypt
    log_ok "Created system user 'picrypt'"
fi

# Ensure the state dir exists with correct ownership. systemd's
# StateDirectory= will (re-)create this on each start, but we need it
# now so we can drop server.toml in before the service is enabled.
mkdir -p /var/lib/picrypt/.picrypt/data
chown -R picrypt:picrypt /var/lib/picrypt
chmod 700 /var/lib/picrypt /var/lib/picrypt/.picrypt

# --------------------------------------------------------------------------- #
# Install binary
# --------------------------------------------------------------------------- #

INSTALL_DIR="/usr/local/bin"

if [[ -n "${BINARY_PATH}" ]]; then
    if [[ ! -f "${BINARY_PATH}" ]]; then
        die "Binary not found at: ${BINARY_PATH}"
    fi
    if ! file "${BINARY_PATH}" | grep -q "executable\|ELF"; then
        log_warn "File at ${BINARY_PATH} may not be a valid executable"
    fi
    log_info "Installing pre-built binary from ${BINARY_PATH}..."
    install -o root -g root -m 0755 "${BINARY_PATH}" "${INSTALL_DIR}/picrypt-server"
    log_ok "Binary installed to ${INSTALL_DIR}/picrypt-server"
else
    log_info "No --binary provided, building from source with cargo..."

    if ! command -v cargo &>/dev/null; then
        die "cargo not found. Either provide --binary or install Rust: https://rustup.rs"
    fi

    # Build as the picrypt user to avoid permission issues with cargo cache
    REPO_DIR=""
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "${SCRIPT_DIR}/../Cargo.toml" ]]; then
        REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
    elif [[ -f "/home/picrypt/picrypt/Cargo.toml" ]]; then
        REPO_DIR="/home/picrypt/picrypt"
    else
        die "Cannot find project source. Provide --binary or clone the repo to /home/picrypt/picrypt"
    fi

    log_info "Building from ${REPO_DIR}..."
    (cd "${REPO_DIR}" && cargo build --release -p picrypt-server)

    install -o root -g root -m 0755 "${REPO_DIR}/target/release/picrypt-server" "${INSTALL_DIR}/picrypt-server"
    log_ok "Binary built and installed to ${INSTALL_DIR}/picrypt-server"
fi

# --------------------------------------------------------------------------- #
# Install systemd service
# --------------------------------------------------------------------------- #

log_info "Installing systemd service..."

SERVICE_SRC=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/picrypt-server.service" ]]; then
    SERVICE_SRC="${SCRIPT_DIR}/picrypt-server.service"
elif [[ -f "/tmp/picrypt-server.service" ]]; then
    SERVICE_SRC="/tmp/picrypt-server.service"
else
    die "Cannot find picrypt-server.service. Expected at ${SCRIPT_DIR}/picrypt-server.service"
fi

install -o root -g root -m 0644 "${SERVICE_SRC}" /etc/systemd/system/picrypt-server.service
systemctl daemon-reload
log_ok "Service file installed"

# --------------------------------------------------------------------------- #
# Generate server.toml (only if it doesn't exist)
# --------------------------------------------------------------------------- #

CONFIG_DIR="/var/lib/picrypt/.picrypt"
CONFIG_FILE="${CONFIG_DIR}/server.toml"

# Migrate from the old /home/picrypt location if a previous install left
# config there. We move (not copy) so the post-install service has only
# one source of truth, and we don't accidentally read stale state later.
if [[ -f "/home/picrypt/.picrypt/server.toml" && ! -f "${CONFIG_FILE}" ]]; then
    log_info "Migrating existing server.toml from /home/picrypt → /var/lib/picrypt"
    cp -a /home/picrypt/.picrypt/. "${CONFIG_DIR}/"
    chown -R picrypt:picrypt /var/lib/picrypt
    chmod 700 /var/lib/picrypt "${CONFIG_DIR}"
    # Rewrite data_dir if it points at the old location.
    sed -i 's|"/home/picrypt/\.picrypt/data"|"/var/lib/picrypt/.picrypt/data"|' "${CONFIG_FILE}" || true
    log_ok "Migrated config to ${CONFIG_FILE}"
fi
GENERATED_TOKEN=""
GENERATED_PIN=""

if [[ -f "${CONFIG_FILE}" ]]; then
    log_warn "server.toml already exists at ${CONFIG_FILE} — not overwriting"
    log_info "To regenerate, remove it and re-run this script"
else
    log_info "Generating server.toml..."

    GENERATED_TOKEN="$(openssl rand -base64 32)"
    GENERATED_PIN="$(printf "%06d" "$(( RANDOM * RANDOM % 1000000 ))")"
    LISTEN_ADDR="${TAILSCALE_IP}:7123"

    cat > "${CONFIG_FILE}" <<TOML
# picrypt server configuration
# Generated on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Listen only on the Tailscale interface
listen_addr = "${LISTEN_ADDR}"

# Persistent data directory
data_dir = "${CONFIG_DIR}/data"

# Dead man's switch timeout (seconds). 0 = disabled.
# Default: 86400 (24 hours)
dead_man_timeout_secs = 86400

# Admin token for device management (register, revoke, list).
# Keep this secret — it grants full control over device enrollment.
admin_token = "${GENERATED_TOKEN}"

# Lock PIN. Required when calling POST /lock.
# Share only with trusted users who should be able to trigger a panic lock.
lock_pin = "${GENERATED_PIN}"
TOML

    chown picrypt:picrypt "${CONFIG_FILE}"
    chmod 600 "${CONFIG_FILE}"
    log_ok "Generated ${CONFIG_FILE}"
fi

# --------------------------------------------------------------------------- #
# Run hardening script if present
# --------------------------------------------------------------------------- #

HARDEN_SCRIPT=""
if [[ -f "${SCRIPT_DIR}/../scripts/harden-linux.sh" ]]; then
    HARDEN_SCRIPT="$(cd "${SCRIPT_DIR}/../scripts" && pwd)/harden-linux.sh"
elif [[ -f "${SCRIPT_DIR}/harden-linux.sh" ]]; then
    HARDEN_SCRIPT="${SCRIPT_DIR}/harden-linux.sh"
fi

if [[ -n "${HARDEN_SCRIPT}" ]]; then
    log_info "Found hardening script at ${HARDEN_SCRIPT}"
    log_info "Running hardening script with --yes flag..."
    bash "${HARDEN_SCRIPT}" --yes || log_warn "Hardening script reported errors (non-fatal)"
else
    log_warn "No harden-linux.sh found — skipping OS-level hardening"
    log_info "You can run it manually later from the scripts/ directory"
fi

# --------------------------------------------------------------------------- #
# Enable and start service
# --------------------------------------------------------------------------- #

log_info "Enabling and starting picrypt-server..."

systemctl enable picrypt-server.service
systemctl restart picrypt-server.service

# Give it a moment to start
sleep 1

if systemctl is-active --quiet picrypt-server.service; then
    log_ok "picrypt-server is running"
else
    log_warn "Service may not have started cleanly. Check: journalctl -u picrypt-server -n 50"
fi

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

echo ""
echo "=============================================="
echo "  picrypt server installation complete"
echo "=============================================="
echo ""
echo "  Server URL:   http://${TAILSCALE_IP}:7123"
echo "  Config:       ${CONFIG_FILE}"
echo "  Data dir:     ${CONFIG_DIR}/data"
echo ""

if [[ -n "${GENERATED_TOKEN}" ]]; then
    echo "  Admin Token:  ${GENERATED_TOKEN}"
    echo "  Lock PIN:     ${GENERATED_PIN}"
    echo ""
    echo "  SAVE THESE VALUES — they are not stored anywhere else in plaintext"
    echo "  except in ${CONFIG_FILE} (readable only by the picrypt user)."
else
    echo "  Existing config preserved. Admin token and lock PIN unchanged."
    echo "  To view: sudo cat ${CONFIG_FILE}"
fi

echo ""
echo "  Status:       sudo systemctl status picrypt-server"
echo "  Logs:         sudo journalctl -u picrypt-server -f"
echo ""
echo "  Next step on clients:"
echo "    picrypt init --server-url http://${TAILSCALE_IP}:7123"
echo "    picrypt register --name \$(hostname)"
echo ""
