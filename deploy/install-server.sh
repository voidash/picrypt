#!/usr/bin/env bash
# install-server.sh — Install picrypt-server + picrypt-panic-listener on a
# Raspberry Pi (or any Linux box on your tailnet).
#
# Idempotent: safe to run multiple times. Re-running will:
#   - Update the binaries (if new ones are provided)
#   - Reinstall the systemd unit files
#   - NOT overwrite existing server.toml or panic.toml (preserves tokens/config)
#
# Usage:
#   sudo ./install-server.sh [--binary /path/to/picrypt-server]
#   sudo ./install-server.sh [--release v0.1.12]
#
# If neither --binary nor --release is provided, falls back to building from
# source with cargo.
#
# With --binary, the script also looks for picrypt-panic-listener in the same
# directory. With --release, both binaries are downloaded from the CI tarball.
# With source builds, both crates are compiled.

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
# Release download helpers
# --------------------------------------------------------------------------- #

GITHUB_REPO="voidash/picrypt"

detect_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "${os}" in
        Linux)
            case "${arch}" in
                x86_64)  echo "x86_64-unknown-linux-musl" ;;
                aarch64) echo "aarch64-unknown-linux-musl" ;;
                *)       die "Unsupported architecture: ${arch}" ;;
            esac
            ;;
        *)
            die "install-server.sh is only supported on Linux (got: ${os})"
            ;;
    esac
}

# download_release TAG TARGET
# Downloads, verifies, and extracts a release tarball.
# Sets RELEASE_DIR to the extracted directory path.
download_release() {
    local tag="$1"
    local target="$2"
    local base="picrypt-${tag}-${target}"
    local archive="${base}.tar.gz"
    local url_base="https://github.com/${GITHUB_REPO}/releases/download/${tag}"

    RELEASE_TMPDIR="$(mktemp -d)"

    log_info "Downloading ${archive}..."
    curl -fSL -o "${RELEASE_TMPDIR}/${archive}" "${url_base}/${archive}" \
        || die "Failed to download ${archive}. Check that tag '${tag}' exists and has a build for '${target}'."

    log_info "Downloading verification files..."
    curl -fSL -o "${RELEASE_TMPDIR}/${archive}.sha256" "${url_base}/${archive}.sha256" \
        || die "Failed to download SHA256 checksum"
    curl -fSL -o "${RELEASE_TMPDIR}/${archive}.sig" "${url_base}/${archive}.sig" \
        || die "Failed to download cosign signature"
    curl -fSL -o "${RELEASE_TMPDIR}/${archive}.crt" "${url_base}/${archive}.crt" \
        || die "Failed to download cosign certificate"

    log_info "Verifying SHA256 checksum..."
    (cd "${RELEASE_TMPDIR}" && shasum -a 256 -c "${archive}.sha256") \
        || die "SHA256 verification FAILED — do not use this binary"
    log_ok "SHA256 checksum verified"

    if command -v cosign &>/dev/null; then
        log_info "Verifying cosign signature..."
        cosign verify-blob \
            --certificate "${RELEASE_TMPDIR}/${archive}.crt" \
            --signature "${RELEASE_TMPDIR}/${archive}.sig" \
            --certificate-identity-regexp "^https://github\\.com/${GITHUB_REPO}/\\.github/workflows/release\\.yml@refs/tags/v.*\$" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            "${RELEASE_TMPDIR}/${archive}" \
            || die "Cosign signature verification FAILED — do not use this binary"
        log_ok "Cosign signature verified"
    else
        log_warn "================================================================"
        log_warn "cosign is not installed — skipping signature verification."
        log_warn "The SHA256 checksum passed, but without cosign you cannot verify"
        log_warn "that the binary was built by the official CI pipeline."
        log_warn "Install cosign: https://docs.sigstore.dev/cosign/installation/"
        log_warn "================================================================"
    fi

    log_info "Extracting ${archive}..."
    tar -xzf "${RELEASE_TMPDIR}/${archive}" -C "${RELEASE_TMPDIR}"

    RELEASE_DIR="${RELEASE_TMPDIR}/${base}"
    if [[ ! -d "${RELEASE_DIR}" ]]; then
        die "Expected directory ${base} not found after extraction"
    fi
    log_ok "Release ${tag} extracted"
}

cleanup_release_tmpdir() {
    if [[ -n "${RELEASE_TMPDIR:-}" && -d "${RELEASE_TMPDIR}" ]]; then
        rm -rf "${RELEASE_TMPDIR}"
    fi
}

# --------------------------------------------------------------------------- #
# Parse arguments
# --------------------------------------------------------------------------- #

BINARY_PATH=""
RELEASE_TAG=""
RELEASE_TMPDIR=""
RELEASE_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)
            if [[ -z "${2:-}" ]]; then
                die "--binary requires a path argument"
            fi
            BINARY_PATH="$2"
            shift 2
            ;;
        --release)
            if [[ -z "${2:-}" ]]; then
                die "--release requires a tag argument (e.g. v0.1.12)"
            fi
            RELEASE_TAG="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: sudo $0 [--binary /path/to/picrypt-server] [--release vX.Y.Z]"
            echo ""
            echo "Options:"
            echo "  --binary PATH    Use a pre-built server binary (also picks up"
            echo "                   picrypt-panic-listener from the same directory)"
            echo "  --release TAG    Download a verified release from GitHub"
            echo "                   (e.g. --release v0.1.12)"
            echo ""
            echo "If neither is provided, builds from source with cargo."
            exit 0
            ;;
        *)
            die "Unknown argument: $1"
            ;;
    esac
done

if [[ -n "${BINARY_PATH}" && -n "${RELEASE_TAG}" ]]; then
    die "--binary and --release are mutually exclusive"
fi

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
# Handle --release: download and verify
# --------------------------------------------------------------------------- #

PANIC_BINARY_PATH=""

if [[ -n "${RELEASE_TAG}" ]]; then
    TARGET="$(detect_target)"
    download_release "${RELEASE_TAG}" "${TARGET}"
    trap cleanup_release_tmpdir EXIT

    BINARY_PATH="${RELEASE_DIR}/picrypt-server"
    if [[ ! -f "${BINARY_PATH}" ]]; then
        die "picrypt-server binary not found in release archive"
    fi
    PANIC_BINARY_PATH="${RELEASE_DIR}/picrypt-panic-listener"
    if [[ ! -f "${PANIC_BINARY_PATH}" ]]; then
        die "picrypt-panic-listener binary not found in release archive"
    fi
fi

# --------------------------------------------------------------------------- #
# Create system users
# --------------------------------------------------------------------------- #

log_info "Ensuring 'picrypt' system user exists..."

if id picrypt &>/dev/null; then
    log_ok "User 'picrypt' already exists"
else
    useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/picrypt picrypt
    log_ok "Created system user 'picrypt'"
fi

log_info "Ensuring 'picrypt-panic' system user exists..."

if id picrypt-panic &>/dev/null; then
    log_ok "User 'picrypt-panic' already exists"
else
    useradd --system --shell /usr/sbin/nologin --no-create-home picrypt-panic
    log_ok "Created system user 'picrypt-panic'"
fi

# Ensure the state dir exists with correct ownership
mkdir -p /var/lib/picrypt/.picrypt/data
chown -R picrypt:picrypt /var/lib/picrypt
chmod 700 /var/lib/picrypt /var/lib/picrypt/.picrypt

# --------------------------------------------------------------------------- #
# Install binaries
# --------------------------------------------------------------------------- #

INSTALL_DIR="/usr/local/bin"
PANIC_LISTENER_INSTALLED=false

if [[ -n "${BINARY_PATH}" ]]; then
    # --binary or --release path: server binary is at BINARY_PATH
    if [[ ! -f "${BINARY_PATH}" ]]; then
        die "Server binary not found at: ${BINARY_PATH}"
    fi
    if ! file "${BINARY_PATH}" | grep -q "executable\|ELF"; then
        log_warn "File at ${BINARY_PATH} may not be a valid executable"
    fi
    log_info "Installing picrypt-server from ${BINARY_PATH}..."
    install -o root -g root -m 0755 "${BINARY_PATH}" "${INSTALL_DIR}/picrypt-server"
    log_ok "picrypt-server installed to ${INSTALL_DIR}/picrypt-server"

    # Panic-listener: auto-pickup from same directory if not already set
    if [[ -z "${PANIC_BINARY_PATH}" ]]; then
        BINARY_DIR="$(dirname "${BINARY_PATH}")"
        if [[ -f "${BINARY_DIR}/picrypt-panic-listener" ]]; then
            PANIC_BINARY_PATH="${BINARY_DIR}/picrypt-panic-listener"
            log_info "Found picrypt-panic-listener next to server binary"
        fi
    fi

    if [[ -n "${PANIC_BINARY_PATH}" && -f "${PANIC_BINARY_PATH}" ]]; then
        log_info "Installing picrypt-panic-listener from ${PANIC_BINARY_PATH}..."
        install -o root -g root -m 0755 "${PANIC_BINARY_PATH}" "${INSTALL_DIR}/picrypt-panic-listener"
        log_ok "picrypt-panic-listener installed to ${INSTALL_DIR}/picrypt-panic-listener"
        PANIC_LISTENER_INSTALLED=true
    else
        log_warn "picrypt-panic-listener binary not found — skipping"
        log_info "To install later, place it next to picrypt-server and re-run, or use --release"
    fi
else
    log_info "No --binary or --release provided, building from source with cargo..."

    if ! command -v cargo &>/dev/null; then
        die "cargo not found. Provide --binary, use --release, or install Rust: https://rustup.rs"
    fi

    # Build as the picrypt user to avoid permission issues with cargo cache
    REPO_DIR=""
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "${SCRIPT_DIR}/../Cargo.toml" ]]; then
        REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
    elif [[ -f "/home/picrypt/picrypt/Cargo.toml" ]]; then
        REPO_DIR="/home/picrypt/picrypt"
    else
        die "Cannot find project source. Provide --binary, use --release, or clone the repo."
    fi

    log_info "Building from ${REPO_DIR}..."
    (cd "${REPO_DIR}" && cargo build --release -p picrypt-server -p picrypt-panic-listener)

    install -o root -g root -m 0755 "${REPO_DIR}/target/release/picrypt-server" "${INSTALL_DIR}/picrypt-server"
    log_ok "picrypt-server built and installed to ${INSTALL_DIR}/picrypt-server"

    install -o root -g root -m 0755 "${REPO_DIR}/target/release/picrypt-panic-listener" "${INSTALL_DIR}/picrypt-panic-listener"
    log_ok "picrypt-panic-listener built and installed to ${INSTALL_DIR}/picrypt-panic-listener"
    PANIC_LISTENER_INSTALLED=true
fi

# --------------------------------------------------------------------------- #
# Install systemd services
# --------------------------------------------------------------------------- #

log_info "Installing systemd services..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- picrypt-server.service ---

SERVER_SERVICE_SRC=""
if [[ -f "${SCRIPT_DIR}/picrypt-server.service" ]]; then
    SERVER_SERVICE_SRC="${SCRIPT_DIR}/picrypt-server.service"
elif [[ -n "${RELEASE_DIR:-}" && -f "${RELEASE_DIR}/deploy/picrypt-server.service" ]]; then
    SERVER_SERVICE_SRC="${RELEASE_DIR}/deploy/picrypt-server.service"
elif [[ -f "/tmp/picrypt-server.service" ]]; then
    SERVER_SERVICE_SRC="/tmp/picrypt-server.service"
else
    die "Cannot find picrypt-server.service. Expected at ${SCRIPT_DIR}/picrypt-server.service"
fi

install -o root -g root -m 0644 "${SERVER_SERVICE_SRC}" /etc/systemd/system/picrypt-server.service
log_ok "picrypt-server.service installed"

# --- picrypt-panic-listener.service ---

PANIC_SERVICE_INSTALLED=false

if [[ "${PANIC_LISTENER_INSTALLED}" == "true" ]]; then
    PANIC_SERVICE_SRC=""
    if [[ -f "${SCRIPT_DIR}/picrypt-panic-listener.service" ]]; then
        PANIC_SERVICE_SRC="${SCRIPT_DIR}/picrypt-panic-listener.service"
    elif [[ -n "${RELEASE_DIR:-}" && -f "${RELEASE_DIR}/deploy/picrypt-panic-listener.service" ]]; then
        PANIC_SERVICE_SRC="${RELEASE_DIR}/deploy/picrypt-panic-listener.service"
    fi

    if [[ -n "${PANIC_SERVICE_SRC}" ]]; then
        install -o root -g root -m 0644 "${PANIC_SERVICE_SRC}" /etc/systemd/system/picrypt-panic-listener.service
        log_ok "picrypt-panic-listener.service installed"
        PANIC_SERVICE_INSTALLED=true
    else
        log_warn "picrypt-panic-listener.service file not found — skipping service install"
    fi
fi

systemctl daemon-reload

# --------------------------------------------------------------------------- #
# Generate server.toml (only if it doesn't exist)
# --------------------------------------------------------------------------- #

CONFIG_DIR="/var/lib/picrypt/.picrypt"
CONFIG_FILE="${CONFIG_DIR}/server.toml"

# Migrate from the old /home/picrypt location if a previous install left
# config there.
if [[ -f "/home/picrypt/.picrypt/server.toml" && ! -f "${CONFIG_FILE}" ]]; then
    log_info "Migrating existing server.toml from /home/picrypt → /var/lib/picrypt"
    cp -a /home/picrypt/.picrypt/. "${CONFIG_DIR}/"
    chown -R picrypt:picrypt /var/lib/picrypt
    chmod 700 /var/lib/picrypt "${CONFIG_DIR}"
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
# Generate panic.toml (only if it doesn't exist)
# --------------------------------------------------------------------------- #

PANIC_CONFIG_DIR="/etc/picrypt"
PANIC_CONFIG_FILE="${PANIC_CONFIG_DIR}/panic.toml"

GENERATED_CONTACT_TOKEN=""

if [[ -f "${PANIC_CONFIG_FILE}" ]]; then
    log_warn "panic.toml already exists at ${PANIC_CONFIG_FILE} — not overwriting"
    log_info "To regenerate, remove it and re-run this script"
elif [[ "${PANIC_LISTENER_INSTALLED}" == "true" ]]; then
    log_info "Generating panic.toml..."
    mkdir -p "${PANIC_CONFIG_DIR}"

    # Reuse the lock_pin: prefer the one we just generated, fall back to
    # parsing the existing server.toml.
    PANIC_LOCK_PIN="${GENERATED_PIN}"
    if [[ -z "${PANIC_LOCK_PIN}" ]]; then
        PANIC_LOCK_PIN="$(sed -n 's/^lock_pin *= *"\([^"]*\)".*/\1/p' "${CONFIG_FILE}" 2>/dev/null || true)"
    fi
    if [[ -z "${PANIC_LOCK_PIN}" ]]; then
        die "Cannot determine lock_pin for panic.toml — set it manually in ${PANIC_CONFIG_FILE}"
    fi

    GENERATED_CONTACT_TOKEN="$(openssl rand -base64 32)"

    cat > "${PANIC_CONFIG_FILE}" <<TOML
# picrypt panic-listener configuration
# Generated on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
#
# The panic-listener accepts authenticated POST /panic requests (typically
# via Tailscale Funnel) and forwards them to the main picrypt-server's
# POST /lock endpoint.

# Must match the lock_pin in server.toml.
lock_pin = "${PANIC_LOCK_PIN}"

# URL of the local picrypt-server. Uses the Tailscale IP because the server
# binds only to its Tailscale interface, not localhost.
picrypt_server_url = "http://${TAILSCALE_IP}:7123"

# Origins allowed to POST /panic via CORS (for browser-based PWA clients).
# Empty = no browser origins allowed; curl and native apps still work.
# Example: ["https://lock.example.com"]
allowed_origins = []

# Each contact gets a unique token. Generate more with: openssl rand -base64 32
# The label is logged on every panic event for auditability.
[[contact]]
label = "default"
token = "${GENERATED_CONTACT_TOKEN}"
TOML

    chown root:picrypt-panic "${PANIC_CONFIG_FILE}"
    chmod 0640 "${PANIC_CONFIG_FILE}"
    log_ok "Generated ${PANIC_CONFIG_FILE}"
fi

# --------------------------------------------------------------------------- #
# Run hardening script if present
# --------------------------------------------------------------------------- #

HARDEN_SCRIPT=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/../scripts/harden-linux.sh" ]]; then
    HARDEN_SCRIPT="$(cd "${SCRIPT_DIR}/../scripts" && pwd)/harden-linux.sh"
elif [[ -f "${SCRIPT_DIR}/harden-linux.sh" ]]; then
    HARDEN_SCRIPT="${SCRIPT_DIR}/harden-linux.sh"
elif [[ -n "${RELEASE_DIR:-}" && -f "${RELEASE_DIR}/scripts/harden-linux.sh" ]]; then
    HARDEN_SCRIPT="${RELEASE_DIR}/scripts/harden-linux.sh"
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
# Enable and start services
# --------------------------------------------------------------------------- #

log_info "Enabling and starting picrypt-server..."

systemctl enable picrypt-server.service
systemctl restart picrypt-server.service

# Give it a moment to start
sleep 1

if systemctl is-active --quiet picrypt-server.service; then
    log_ok "picrypt-server is running"
else
    log_warn "picrypt-server may not have started cleanly. Check: journalctl -u picrypt-server -n 50"
fi

if [[ "${PANIC_SERVICE_INSTALLED}" == "true" ]]; then
    log_info "Enabling and starting picrypt-panic-listener..."
    systemctl enable picrypt-panic-listener.service
    systemctl restart picrypt-panic-listener.service

    sleep 1

    if systemctl is-active --quiet picrypt-panic-listener.service; then
        log_ok "picrypt-panic-listener is running"
    else
        log_warn "picrypt-panic-listener may not have started cleanly. Check: journalctl -u picrypt-panic-listener -n 50"
    fi
fi

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

echo ""
echo "=============================================="
echo "  picrypt server installation complete"
echo "=============================================="
echo ""
echo "  Server URL:         http://${TAILSCALE_IP}:7123"
echo "  Server config:      ${CONFIG_FILE}"
echo "  Server data dir:    ${CONFIG_DIR}/data"
echo ""

if [[ -n "${GENERATED_TOKEN}" ]]; then
    echo "  Admin Token:        ${GENERATED_TOKEN}"
    echo "  Lock PIN:           ${GENERATED_PIN}"
    echo ""
    echo "  SAVE THESE VALUES — they are not stored anywhere else in plaintext"
    echo "  except in ${CONFIG_FILE} (readable only by the picrypt user)."
else
    echo "  Existing server config preserved. Admin token and lock PIN unchanged."
    echo "  To view: sudo cat ${CONFIG_FILE}"
fi

echo ""

if [[ "${PANIC_SERVICE_INSTALLED}" == "true" ]]; then
    echo "  Panic listener:     http://127.0.0.1:7124"
    echo "  Panic config:       ${PANIC_CONFIG_FILE}"
    echo ""
    if [[ -n "${GENERATED_CONTACT_TOKEN}" ]]; then
        echo "  Contact token:      ${GENERATED_CONTACT_TOKEN}"
        echo "  Contact label:      default"
        echo ""
        echo "  SAVE THE CONTACT TOKEN — this is what your panic clients (PWA, Android,"
        echo "  curl) send in POST /panic requests to trigger a lock."
        echo "  Add more contacts by editing ${PANIC_CONFIG_FILE}."
    else
        echo "  Existing panic config preserved."
        echo "  To view: sudo cat ${PANIC_CONFIG_FILE}"
    fi
    echo ""
fi

echo "  Status:"
echo "    sudo systemctl status picrypt-server"
if [[ "${PANIC_SERVICE_INSTALLED}" == "true" ]]; then
    echo "    sudo systemctl status picrypt-panic-listener"
fi
echo ""
echo "  Logs:"
echo "    sudo journalctl -u picrypt-server -u picrypt-panic-listener -f"
echo ""
echo "  Next steps:"
if [[ "${PANIC_SERVICE_INSTALLED}" == "true" ]]; then
    echo "    1. Expose the panic-listener via Tailscale Funnel:"
    echo "       sudo tailscale funnel --bg 7124"
    echo "    2. On each client machine:"
else
    echo "    1. On each client machine:"
fi
echo "       picrypt init --server-url http://${TAILSCALE_IP}:7123"
echo "       picrypt register --name \$(hostname)"
echo ""
