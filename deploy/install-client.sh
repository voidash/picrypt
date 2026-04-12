#!/usr/bin/env bash
# install-client.sh — Install picrypt-client on macOS or Linux.
#
# Idempotent: safe to run multiple times. Re-running will:
#   - Update the binary (if a new one is provided or rebuilt)
#   - NOT overwrite existing client.toml or re-register the device
#
# Usage:
#   ./install-client.sh [--binary /path/to/picrypt-client]
#
# If --binary is not provided, builds from source with cargo.

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

    eval "${var_name}=\"${value}\""
}

confirm() {
    local prompt="$1"
    printf "%s [y/N] " "${prompt}"
    read -r answer
    [[ "${answer}" =~ ^[Yy]$ ]]
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
            echo "Usage: $0 [--binary /path/to/picrypt-client]"
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
    log_info "No --binary provided, building from source with cargo..."

    if ! command -v cargo &>/dev/null; then
        die "cargo not found. Either provide --binary or install Rust: https://rustup.rs"
    fi

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_DIR=""
    if [[ -f "${SCRIPT_DIR}/../Cargo.toml" ]]; then
        REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
    else
        die "Cannot find project source. Provide --binary or run from the repo's deploy/ directory."
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
# Optional: auto-unlock service
# --------------------------------------------------------------------------- #

echo ""
if confirm "Set up auto-unlock at login?"; then

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
    <false/>
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
            log_info "picrypt unlock will run automatically at next login"
        fi

    elif [[ "${OS_TYPE}" == "linux" ]]; then
        # Linux: user systemd service
        SERVICE_DIR="${HOME}/.config/systemd/user"
        SERVICE_FILE="${SERVICE_DIR}/picrypt-unlock.service"

        mkdir -p "${SERVICE_DIR}"

        if [[ -f "${SERVICE_FILE}" ]]; then
            log_ok "User service already exists at ${SERVICE_FILE}"
        else
            cat > "${SERVICE_FILE}" <<UNIT
[Unit]
Description=picrypt auto-unlock
After=network-online.target

[Service]
Type=oneshot
ExecStart=${PICRYPT} unlock
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
UNIT
            systemctl --user daemon-reload
            systemctl --user enable picrypt-unlock.service
            log_ok "Created and enabled user service at ${SERVICE_FILE}"
            log_info "picrypt unlock will run automatically at next login"
            log_info "To run now: systemctl --user start picrypt-unlock"
        fi
    fi
else
    log_info "Skipping auto-unlock setup. You can run 'picrypt unlock' manually."
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
echo "    picrypt unlock            — mount encrypted volumes"
echo "    picrypt lock              — dismount all volumes"
echo "    picrypt panic             — emergency lock all devices"
echo "    picrypt create-container  — create a new VeraCrypt container"
echo ""
echo "  To create your first encrypted container:"
echo "    picrypt create-container --path ~/vault.hc --size 10G --mount-point ~/Vault"
echo ""
echo "  Then unlock:"
echo "    picrypt unlock"
echo ""
