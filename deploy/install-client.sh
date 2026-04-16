#!/usr/bin/env bash
# install-client.sh — Install picrypt-client on macOS or Linux.
#
# Idempotent: safe to run multiple times. Re-running will:
#   - Update the binary (if a new one is provided or rebuilt)
#   - NOT overwrite existing client.toml or re-register the device
#
# Usage:
#   ./install-client.sh [--binary /path/to/picrypt-client]
#   ./install-client.sh [--release v0.1.12]
#
# If neither --binary nor --release is provided, builds from source with cargo.

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

prompt_value() {
    local var_name="$1"
    local prompt_text="$2"
    local default_value="${3:-}"
    local value=""

    if [[ -n "${default_value}" ]]; then
        printf "%s [%s]: " "${prompt_text}" "${default_value}"
    else
        printf "%s: " "${prompt_text}"
    fi
    read -r value
    value="${value:-${default_value}}"

    if [[ -z "${value}" ]]; then
        die "${var_name} is required"
    fi

    printf -v "${var_name}" '%s' "${value}"
}

confirm() {
    local prompt="$1"
    printf "%s [y/N] " "${prompt}"
    read -r answer
    [[ "${answer}" =~ ^[Yy]$ ]]
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
        Darwin)
            case "${arch}" in
                x86_64)  echo "x86_64-apple-darwin" ;;
                arm64)   echo "aarch64-apple-darwin" ;;
                *)       die "Unsupported architecture: ${arch}" ;;
            esac
            ;;
        *)
            die "Unsupported OS: ${os}"
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
            echo "Usage: $0 [--binary /path/to/picrypt-client] [--release vX.Y.Z]"
            echo ""
            echo "Options:"
            echo "  --binary PATH    Use a pre-built binary instead of building from source"
            echo "  --release TAG    Download a verified release from GitHub (e.g. --release v0.1.12)"
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
# Detect OS
# --------------------------------------------------------------------------- #

OS="$(uname -s)"
case "${OS}" in
    Darwin)
        OS_TYPE="macos"
        ;;
    Linux)
        OS_TYPE="linux"
        ;;
    *)
        die "Unsupported OS: ${OS}. This script supports macOS and Linux only."
        ;;
esac

log_info "Detected OS: ${OS_TYPE}"

# --------------------------------------------------------------------------- #
# Handle --release: download and verify
# --------------------------------------------------------------------------- #

if [[ -n "${RELEASE_TAG}" ]]; then
    TARGET="$(detect_target)"
    download_release "${RELEASE_TAG}" "${TARGET}"
    trap cleanup_release_tmpdir EXIT
    BINARY_PATH="${RELEASE_DIR}/picrypt-client"
    if [[ ! -f "${BINARY_PATH}" ]]; then
        die "picrypt-client binary not found in release archive at ${BINARY_PATH}"
    fi
fi

# --------------------------------------------------------------------------- #
# Determine install directory
# --------------------------------------------------------------------------- #

if [[ "${OS_TYPE}" == "macos" ]]; then
    # macOS: prefer ~/.local/bin (no sudo needed)
    INSTALL_DIR="${HOME}/.local/bin"
else
    # Linux: use ~/.local/bin if not root, /usr/local/bin if root
    if [[ "$(id -u)" -eq 0 ]]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="${HOME}/.local/bin"
    fi
fi

mkdir -p "${INSTALL_DIR}"

# Warn if the install dir is not on PATH
if ! echo "${PATH}" | tr ':' '\n' | grep -qx "${INSTALL_DIR}"; then
    log_warn "${INSTALL_DIR} is not in your PATH"
    log_info "Add it with: export PATH=\"${INSTALL_DIR}:\${PATH}\""
    log_info "Or add that line to your shell profile (~/.bashrc, ~/.zshrc, etc.)"
fi

# --------------------------------------------------------------------------- #
# Install binary
# --------------------------------------------------------------------------- #

if [[ -n "${BINARY_PATH}" ]]; then
    if [[ ! -f "${BINARY_PATH}" ]]; then
        die "Binary not found at: ${BINARY_PATH}"
    fi
    log_info "Installing pre-built binary from ${BINARY_PATH}..."
    install -m 0755 "${BINARY_PATH}" "${INSTALL_DIR}/picrypt"
    log_ok "Binary installed to ${INSTALL_DIR}/picrypt"
else
    log_info "No --binary or --release provided, building from source with cargo..."

    if ! command -v cargo &>/dev/null; then
        die "cargo not found. Provide --binary, use --release, or install Rust: https://rustup.rs"
    fi

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_DIR=""
    if [[ -f "${SCRIPT_DIR}/../Cargo.toml" ]]; then
        REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
    else
        die "Cannot find project source. Provide --binary, use --release, or run from the repo's deploy/ directory."
    fi

    log_info "Building from ${REPO_DIR}..."
    (cd "${REPO_DIR}" && cargo build --release -p picrypt-client)

    install -m 0755 "${REPO_DIR}/target/release/picrypt-client" "${INSTALL_DIR}/picrypt"
    log_ok "Binary built and installed to ${INSTALL_DIR}/picrypt"
fi

PICRYPT="${INSTALL_DIR}/picrypt"

# --------------------------------------------------------------------------- #
# Configure client (skip if already configured)
# --------------------------------------------------------------------------- #

CONFIG_DIR="${HOME}/.picrypt"
CONFIG_FILE="${CONFIG_DIR}/client.toml"

if [[ -f "${CONFIG_FILE}" ]]; then
    log_ok "Client config already exists at ${CONFIG_FILE}"
    log_info "Skipping init and register (to reconfigure, remove ${CONFIG_FILE} and re-run)"
else
    echo ""
    echo "--- Client Configuration ---"
    echo ""

    prompt_value SERVER_URL "Server URL (e.g. http://100.x.y.z:7123)" ""

    echo ""
    log_info "You will need the admin token from the server install."
    log_info "The admin token is only needed for registration and can be discarded after."
    echo ""
    prompt_value ADMIN_TOKEN "Admin token" ""

    # Initialize config
    log_info "Initializing client config..."
    "${PICRYPT}" init --server-url "${SERVER_URL}"

    # Register this device
    DEVICE_NAME="$(hostname)"
    prompt_value DEVICE_NAME "Device name" "${DEVICE_NAME}"

    log_info "Registering device '${DEVICE_NAME}' with server..."
    PICRYPT_ADMIN_TOKEN="${ADMIN_TOKEN}" "${PICRYPT}" register --name "${DEVICE_NAME}"

    log_ok "Device registered"
fi

# --------------------------------------------------------------------------- #
# Optional: auto-unlock daemon
# --------------------------------------------------------------------------- #

echo ""
if confirm "Set up persistent unlock daemon at login?"; then

    if [[ "${OS_TYPE}" == "macos" ]]; then
        # macOS: LaunchAgent
        AGENT_DIR="${HOME}/Library/LaunchAgents"
        AGENT_PLIST="${AGENT_DIR}/com.picrypt.unlock.plist"

        mkdir -p "${AGENT_DIR}"

        if [[ -f "${AGENT_PLIST}" ]]; then
            log_ok "LaunchAgent already exists at ${AGENT_PLIST}"
        else
            cat > "${AGENT_PLIST}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.picrypt.unlock</string>
    <key>ProgramArguments</key>
    <array>
        <string>${PICRYPT}</string>
        <string>unlock</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${HOME}/.picrypt/unlock.log</string>
    <key>StandardErrorPath</key>
    <string>${HOME}/.picrypt/unlock.err.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:${INSTALL_DIR}</string>
    </dict>
</dict>
</plist>
PLIST
            log_ok "Created LaunchAgent at ${AGENT_PLIST}"
            log_info "Loading agent..."
            launchctl load "${AGENT_PLIST}" 2>/dev/null || true
            log_info "picrypt unlock daemon will run at login and restart on crash"
        fi

    elif [[ "${OS_TYPE}" == "linux" ]]; then
        # Linux: user systemd service (persistent daemon, not oneshot)
        SERVICE_DIR="${HOME}/.config/systemd/user"
        SERVICE_FILE="${SERVICE_DIR}/picrypt-unlock.service"

        mkdir -p "${SERVICE_DIR}"

        if [[ -f "${SERVICE_FILE}" ]]; then
            log_ok "User service already exists at ${SERVICE_FILE}"
        else
            cat > "${SERVICE_FILE}" <<UNIT
[Unit]
Description=picrypt persistent unlock daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${PICRYPT} unlock
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
UNIT
            systemctl --user daemon-reload
            systemctl --user enable picrypt-unlock.service
            log_ok "Created and enabled user service at ${SERVICE_FILE}"
            log_info "picrypt unlock daemon will run at login and restart on crash"
            log_info "To start now: systemctl --user start picrypt-unlock"
        fi
    fi
else
    log_info "Skipping daemon setup. You can run 'picrypt unlock' manually."
fi

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

echo ""
echo "=============================================="
echo "  picrypt client installation complete"
echo "=============================================="
echo ""
echo "  Binary:   ${PICRYPT}"
echo "  Config:   ${CONFIG_FILE}"
echo ""
echo "  Useful commands:"
echo "    picrypt status            — check server and volume status"
echo "    picrypt unlock            — start persistent daemon (mount + heartbeat)"
echo "    picrypt lock              — dismount all volumes"
echo "    picrypt panic             — emergency lock all devices"
echo "    picrypt create-container  — create a new VeraCrypt container"
echo ""
echo "  To create your first encrypted container:"
echo "    picrypt create-container --path ~/vault.hc --size 10G --mount-point ~/Vault"
echo ""
echo "  Then start the daemon:"
echo "    picrypt unlock"
echo ""
