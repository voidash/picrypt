#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# picrypt unified installer
#
# Interactive setup for both server (Raspberry Pi) and client (macOS/Linux).
# Run: curl -sSL <url>/install.sh | bash
#   or: ./install.sh
# ============================================================================

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PICRYPT_VERSION="0.1.0"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[!]${NC} $*" >&2; }
fatal() { err "$@"; exit 1; }

prompt() {
    local var_name="$1" prompt_text="$2" default="${3:-}"
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${BOLD}${prompt_text}${NC} [${default}]: ")" value
        eval "$var_name=\"${value:-$default}\""
    else
        read -rp "$(echo -e "${BOLD}${prompt_text}${NC}: ")" value
        eval "$var_name=\"$value\""
    fi
}

prompt_yn() {
    local prompt_text="$1" default="${2:-y}"
    local yn
    read -rp "$(echo -e "${BOLD}${prompt_text}${NC} [${default}]: ")" yn
    yn="${yn:-$default}"
    [[ "$yn" =~ ^[Yy] ]]
}

# ---------------------------------------------------------------------------
# Detect environment
# ---------------------------------------------------------------------------
detect_os() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux)
            if grep -qi "raspberry\|aarch64" /proc/cpuinfo 2>/dev/null || \
               [[ "$(uname -m)" == "aarch64" ]]; then
                echo "linux-arm"
            else
                echo "linux-x86"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) echo "unknown" ;;
    esac
}

check_command() {
    command -v "$1" &>/dev/null
}

ensure_command() {
    if ! check_command "$1"; then
        fatal "$1 is required but not installed. $2"
    fi
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
build_binary() {
    local crate="$1" target_name="$2"
    if [[ -f "${REPO_DIR}/target/release/${target_name}" ]]; then
        if prompt_yn "Found existing release binary. Rebuild?"; then
            cargo build --release -p "$crate"
        fi
    else
        info "Building ${crate} (release)..."
        cargo build --release -p "$crate"
    fi
    echo "${REPO_DIR}/target/release/${target_name}"
}

install_binary() {
    local src="$1" name="$2" dest
    if [[ "$(id -u)" == "0" ]]; then
        dest="/usr/local/bin/${name}"
    else
        dest="${HOME}/.local/bin/${name}"
        mkdir -p "$(dirname "$dest")"
        # Ensure ~/.local/bin is in PATH
        if ! echo "$PATH" | tr ':' '\n' | grep -q "${HOME}/.local/bin"; then
            warn "~/.local/bin is not in PATH. Add to your shell profile:"
            warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
        fi
    fi
    cp "$src" "$dest"
    chmod +x "$dest"
    ok "Installed ${name} to ${dest}"
    echo "$dest"
}

# ---------------------------------------------------------------------------
# Server install
# ---------------------------------------------------------------------------
install_server() {
    echo ""
    echo -e "${BOLD}=== picrypt SERVER installation ===${NC}"
    echo ""

    # Check Tailscale
    if check_command tailscale; then
        local ts_ip
        ts_ip="$(tailscale ip -4 2>/dev/null || true)"
        if [[ -n "$ts_ip" ]]; then
            ok "Tailscale detected: ${ts_ip}"
        else
            warn "Tailscale installed but no IPv4 — is it running?"
            ts_ip="127.0.0.1"
        fi
    else
        warn "Tailscale not found. Server will bind to 127.0.0.1 only."
        ts_ip="127.0.0.1"
    fi

    prompt LISTEN_ADDR "Listen address" "${ts_ip}:7123"

    # Build
    ensure_command cargo "Install Rust: https://rustup.rs"
    local binary
    binary="$(build_binary picrypt-server picrypt-server)"

    # Install binary
    local installed_path
    installed_path="$(install_binary "$binary" picrypt-server)"

    # Generate config
    local config_dir="${HOME}/.picrypt"
    local config_file="${config_dir}/server.toml"
    mkdir -p "${config_dir}/data/devices"

    if [[ -f "$config_file" ]]; then
        warn "Config already exists at ${config_file}"
        if ! prompt_yn "Overwrite?"; then
            info "Keeping existing config."
            ADMIN_TOKEN="(existing — check ${config_file})"
            LOCK_PIN="(existing — check ${config_file})"
        else
            generate_server_config "$config_file" "$LISTEN_ADDR"
        fi
    else
        generate_server_config "$config_file" "$LISTEN_ADDR"
    fi

    # Set permissions
    chmod 700 "${config_dir}"
    chmod 600 "${config_file}" 2>/dev/null || true

    # Hardening
    echo ""
    if prompt_yn "Run system hardening (disable hibernation, etc.)?"; then
        local os
        os="$(detect_os)"
        case "$os" in
            macos)
                if [[ -f "${REPO_DIR}/scripts/harden-macos.sh" ]]; then
                    info "Running macOS hardening..."
                    sudo bash "${REPO_DIR}/scripts/harden-macos.sh" || warn "Hardening had errors"
                fi
                ;;
            linux*)
                if [[ -f "${REPO_DIR}/scripts/harden-linux.sh" ]]; then
                    info "Running Linux hardening..."
                    sudo bash "${REPO_DIR}/scripts/harden-linux.sh" --yes || warn "Hardening had errors"
                fi
                ;;
        esac
    fi

    # Systemd service (Linux only)
    if [[ "$(detect_os)" == linux* ]] && check_command systemctl; then
        echo ""
        if prompt_yn "Install systemd service?"; then
            install_systemd_service "$installed_path"
        fi
    fi

    # Summary
    echo ""
    echo -e "${BOLD}=== Server installation complete ===${NC}"
    echo ""
    echo "  Config:      ${config_file}"
    echo "  Binary:      ${installed_path}"
    echo "  Listen:      ${LISTEN_ADDR}"
    echo ""
    echo -e "  ${BOLD}Admin token:${NC} ${ADMIN_TOKEN}"
    echo -e "  ${BOLD}Lock PIN:${NC}    ${LOCK_PIN}"
    echo ""
    echo -e "${YELLOW}SAVE THESE VALUES — you need the admin token to register devices.${NC}"
    echo ""
    echo "To start the server:"
    if check_command systemctl && [[ "$(detect_os)" == linux* ]]; then
        echo "  sudo systemctl start picrypt-server"
    else
        echo "  picrypt-server"
    fi
    echo ""
    echo "First unseal (creates the master key):"
    echo "  curl -X POST http://${LISTEN_ADDR}/unseal \\"
    echo "    -H 'Content-Type: application/json' \\"
    echo "    -d '{\"password\": \"YOUR-MASTER-PASSWORD\"}'"
    echo ""
}

generate_server_config() {
    local config_file="$1" listen_addr="$2"
    ADMIN_TOKEN="$(openssl rand -base64 32)"
    LOCK_PIN="$(printf '%06d' $((RANDOM % 1000000)))"

    cat > "$config_file" <<EOF
listen_addr = "${listen_addr}"
data_dir = "${HOME}/.picrypt/data"
dead_man_timeout_secs = 86400
admin_token = "${ADMIN_TOKEN}"
lock_pin = "${LOCK_PIN}"
EOF
    ok "Config written to ${config_file}"
}

install_systemd_service() {
    local binary_path="$1"
    local service_src="${REPO_DIR}/deploy/picrypt-server.service"
    local service_dest="/etc/systemd/system/picrypt-server.service"

    if [[ -f "$service_src" ]]; then
        sudo cp "$service_src" "$service_dest"
    else
        # Generate minimal service file
        sudo tee "$service_dest" > /dev/null <<EOF
[Unit]
Description=Picrypt Key Server
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
ExecStart=${binary_path}
Restart=on-failure
RestartSec=5
LimitMEMLOCK=infinity
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF
    fi

    sudo systemctl daemon-reload
    sudo systemctl enable picrypt-server
    ok "Systemd service installed and enabled"
}

# ---------------------------------------------------------------------------
# Client install
# ---------------------------------------------------------------------------
install_veracrypt_deps() {
    local os
    os="$(detect_os)"
    NEEDS_REBOOT=false

    info "Checking VeraCrypt dependencies..."

    case "$os" in
        macos)
            # macFUSE
            if [[ ! -d "/Library/Filesystems/macfuse.fs" ]] && \
               [[ ! -d "/Library/Frameworks/macFUSE.framework" ]]; then
                warn "macFUSE is not installed (required by VeraCrypt on macOS)."
                if prompt_yn "Install macFUSE via Homebrew?"; then
                    ensure_command brew "Install Homebrew: https://brew.sh"
                    brew install --cask macfuse
                    NEEDS_REBOOT=true
                    warn ""
                    warn "=== REBOOT REQUIRED ==="
                    warn "macFUSE needs a reboot to load its kernel extension."
                    warn "After rebooting:"
                    warn "  1. System Settings > Privacy & Security — allow macFUSE"
                    warn "  2. Re-run this installer"
                    warn ""
                else
                    warn "Skipping macFUSE. VeraCrypt will not work without it."
                fi
            else
                ok "macFUSE detected"
            fi

            # VeraCrypt
            if [[ ! -x "/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt" ]]; then
                if [[ "$NEEDS_REBOOT" == "true" ]]; then
                    warn "Install VeraCrypt after rebooting for macFUSE."
                elif prompt_yn "Install VeraCrypt via Homebrew?"; then
                    ensure_command brew "Install Homebrew: https://brew.sh"
                    brew install --cask veracrypt
                    ok "VeraCrypt installed"
                else
                    warn "Skipping VeraCrypt. Install: https://veracrypt.fr/en/Downloads.html"
                fi
            else
                ok "VeraCrypt detected"
            fi
            ;;
        linux*)
            if ! check_command veracrypt; then
                warn "VeraCrypt not found."
                if prompt_yn "Attempt to install VeraCrypt?"; then
                    if check_command apt-get; then
                        # Try the unit193 PPA first (has VeraCrypt)
                        if sudo add-apt-repository -y ppa:unit193/encryption 2>/dev/null; then
                            sudo apt-get update -qq
                            sudo apt-get install -y veracrypt && ok "VeraCrypt installed" \
                                || warn "apt install failed. Download from: https://veracrypt.fr/en/Downloads.html"
                        else
                            warn "PPA not available. Download .deb from: https://veracrypt.fr/en/Downloads.html"
                            warn "Then: sudo dpkg -i veracrypt-*.deb && sudo apt-get install -f"
                        fi
                    elif check_command dnf; then
                        sudo dnf install -y veracrypt 2>/dev/null \
                            || warn "Not in repos. Download from: https://veracrypt.fr/en/Downloads.html"
                    elif check_command pacman; then
                        sudo pacman -S --noconfirm veracrypt 2>/dev/null \
                            || warn "Not found. Try: yay -S veracrypt"
                    else
                        warn "Unknown package manager. Download from: https://veracrypt.fr/en/Downloads.html"
                    fi
                fi
            else
                ok "VeraCrypt detected: $(command -v veracrypt)"
            fi
            ;;
    esac
}

install_client() {
    echo ""
    echo -e "${BOLD}=== picrypt CLIENT installation ===${NC}"
    echo ""

    # Install VeraCrypt and dependencies
    install_veracrypt_deps
    echo ""

    # Build
    ensure_command cargo "Install Rust: https://rustup.rs"
    local binary
    binary="$(build_binary picrypt-client picrypt-client)"

    # Install binary
    local installed_path
    installed_path="$(install_binary "$binary" picrypt)"

    # Check if already initialized
    if [[ -f "${HOME}/.picrypt/client.toml" ]]; then
        warn "Client already configured at ~/.picrypt/client.toml"
        if ! prompt_yn "Reconfigure?"; then
            info "Keeping existing config."
            run_client_post_install "$installed_path"
            return
        fi
    fi

    # Get server URL
    echo ""
    prompt SERVER_URL "Pi server URL (e.g. http://100.64.0.5:7123)" ""
    if [[ -z "$SERVER_URL" ]]; then
        fatal "Server URL is required"
    fi

    # Init
    info "Initializing client..."
    "$installed_path" init --server-url "$SERVER_URL"
    ok "Client config created"

    # Register
    echo ""
    if prompt_yn "Register this device now?"; then
        local device_name
        device_name="$(hostname | tr '[:upper:]' '[:lower:]' | tr ' ' '-')"
        prompt DEVICE_NAME "Device name" "$device_name"

        prompt ADMIN_TOKEN "Admin token (from server install)" ""
        if [[ -n "$ADMIN_TOKEN" ]]; then
            info "Registering device..."
            "$installed_path" register --name "$DEVICE_NAME" --admin-token "$ADMIN_TOKEN"
            ok "Device registered"
        else
            info "Registering without admin token (server must allow unauthenticated registration)..."
            "$installed_path" register --name "$DEVICE_NAME"
        fi

        # Create container
        echo ""
        if prompt_yn "Create a VeraCrypt container now?"; then
            if ! check_command veracrypt; then
                warn "VeraCrypt not found in PATH."
                case "$(detect_os)" in
                    macos)
                        echo "  Install: brew install --cask veracrypt macfuse"
                        echo "  Or download from: https://veracrypt.fr/en/Downloads.html"
                        ;;
                    linux*)
                        echo "  Install: sudo apt install veracrypt  # or your distro's package"
                        ;;
                esac
                echo ""
                if ! prompt_yn "Continue anyway (if veracrypt is installed elsewhere)?"; then
                    info "Skipping container creation. Run later:"
                    echo "  picrypt create-container --path ~/vault.hc --size 10G --mount-point ~/Vault"
                    run_client_post_install "$installed_path"
                    return
                fi
            fi

            local container_path mount_point container_size
            prompt container_path "Container path" "${HOME}/vault.hc"
            prompt mount_point "Mount point" "${HOME}/Vault"
            prompt container_size "Size" "10G"

            info "Creating container (this may take a moment)..."
            "$installed_path" create-container \
                --path "$container_path" \
                --size "$container_size" \
                --mount-point "$mount_point" \
                || warn "Container creation failed — you can retry later"
        fi
    fi

    run_client_post_install "$installed_path"
}

run_client_post_install() {
    local installed_path="$1"
    echo ""

    # Hardening
    if prompt_yn "Run system hardening (disable hibernation, encrypted swap)?"; then
        local os
        os="$(detect_os)"
        case "$os" in
            macos)
                if [[ -f "${REPO_DIR}/scripts/harden-macos.sh" ]]; then
                    sudo bash "${REPO_DIR}/scripts/harden-macos.sh" || warn "Hardening had errors"
                fi
                ;;
            linux*)
                if [[ -f "${REPO_DIR}/scripts/harden-linux.sh" ]]; then
                    sudo bash "${REPO_DIR}/scripts/harden-linux.sh" --yes || warn "Hardening had errors"
                fi
                ;;
        esac
    fi

    # Hotkey
    echo ""
    if prompt_yn "Set up panic hotkey (Ctrl+Shift+L)?"; then
        local os
        os="$(detect_os)"
        case "$os" in
            macos)
                [[ -f "${REPO_DIR}/scripts/setup-hotkey-macos.sh" ]] && \
                    bash "${REPO_DIR}/scripts/setup-hotkey-macos.sh" || warn "Hotkey setup had errors"
                ;;
            linux*)
                [[ -f "${REPO_DIR}/scripts/setup-hotkey-linux.sh" ]] && \
                    bash "${REPO_DIR}/scripts/setup-hotkey-linux.sh" || warn "Hotkey setup had errors"
                ;;
        esac
    fi

    # Summary
    echo ""
    echo -e "${BOLD}=== Client installation complete ===${NC}"
    echo ""
    echo "  Config:  ~/.picrypt/client.toml"
    echo "  Binary:  ${installed_path}"
    echo ""
    echo "Commands:"
    echo "  picrypt unlock              — mount volumes (starts heartbeat daemon)"
    echo "  picrypt lock                — dismount local volumes"
    echo "  picrypt panic               — emergency lock ALL devices"
    echo "  picrypt panic --pin 123456  — emergency lock with PIN"
    echo "  picrypt status              — check server & volume status"
    echo "  picrypt create-container    — create a new VeraCrypt container"
    echo "  picrypt backup --keyfile .. — create YubiKey recovery backup"
    echo "  picrypt recover             — mount via YubiKey (when Pi is dead)"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║         picrypt installer            ║${NC}"
    echo -e "${BOLD}║   VeraCrypt remote key management    ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════╝${NC}"
    echo ""
    echo "Detected OS: $(detect_os)"
    echo ""

    local os
    os="$(detect_os)"
    if [[ "$os" == "windows" ]]; then
        warn "Native Windows is not directly supported."
        echo "Options:"
        echo "  1. Use WSL2 (recommended): install Ubuntu in WSL, then re-run this script"
        echo "  2. Build manually: cargo build --release -p picrypt-client"
        echo ""
        fatal "Re-run from WSL2 or build manually."
    fi

    echo "What would you like to install?"
    echo ""
    echo "  [s] Server  — runs on Raspberry Pi, holds encryption keys"
    echo "  [c] Client  — runs on your workstation, mounts encrypted volumes"
    echo "  [b] Both    — server + client on the same machine (development/testing)"
    echo ""

    local choice
    prompt choice "Choice" "c"

    case "$choice" in
        [sS]) install_server ;;
        [cC]) install_client ;;
        [bB])
            install_server
            echo ""
            echo "---"
            install_client
            ;;
        *) fatal "Invalid choice: $choice" ;;
    esac

    echo ""
    ok "Done."
}

main "$@"
