#!/usr/bin/env bash
# setup-hotkey-linux.sh — Set up a keyboard shortcut for `picrypt panic` on Linux.
#
# Detects the desktop environment and configures a keyboard shortcut accordingly.
# Supports GNOME, KDE Plasma, i3, sway, Hyprland, and a generic xbindkeys fallback.
#
# Does NOT require sudo. Safe to run multiple times (idempotent).
#
# Flags:
#   --shortcut KEY   Override the default shortcut (default: Ctrl+Shift+L)
#   --de ENV         Force a specific desktop environment instead of auto-detect.
#                    Values: gnome, kde, i3, sway, hyprland, xbindkeys

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly DEFAULT_SHORTCUT="<Ctrl><Shift>l"
readonly DEFAULT_SHORTCUT_HUMAN="Ctrl+Shift+L"

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

SHORTCUT="${DEFAULT_SHORTCUT}"
SHORTCUT_HUMAN="${DEFAULT_SHORTCUT_HUMAN}"
FORCE_DE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --shortcut)
            [[ -z "${2:-}" ]] && die "--shortcut requires a value"
            SHORTCUT="$2"
            SHORTCUT_HUMAN="$2"
            shift 2
            ;;
        --de)
            [[ -z "${2:-}" ]] && die "--de requires a value"
            FORCE_DE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: ./${SCRIPT_NAME} [--shortcut KEY] [--de ENV]"
            echo ""
            echo "Options:"
            echo "  --shortcut KEY   Keyboard shortcut (default: ${DEFAULT_SHORTCUT_HUMAN})"
            echo "  --de ENV         Force desktop environment: gnome, kde, i3, sway, hyprland, xbindkeys"
            exit 0
            ;;
        *)
            die "Unknown argument: $1. Use --help for usage."
            ;;
    esac
done

# --------------------------------------------------------------------------- #
# Pre-flight checks
# --------------------------------------------------------------------------- #

if [[ "$(uname -s)" != "Linux" ]]; then
    die "This script is for Linux only. Detected: $(uname -s)"
fi

# --------------------------------------------------------------------------- #
# 1. Locate the picrypt binary
# --------------------------------------------------------------------------- #

log_info "Locating picrypt binary..."

PICRYPT_BIN=""

if command -v picrypt &>/dev/null; then
    PICRYPT_BIN="$(command -v picrypt)"
elif [[ -x "${HOME}/.cargo/bin/picrypt" ]]; then
    PICRYPT_BIN="${HOME}/.cargo/bin/picrypt"
elif [[ -x "/usr/local/bin/picrypt" ]]; then
    PICRYPT_BIN="/usr/local/bin/picrypt"
fi

if [[ -z "${PICRYPT_BIN}" ]]; then
    log_warn "picrypt binary not found in PATH or common locations."
    log_warn "Using 'picrypt' as command — ensure it's in PATH when the shortcut triggers."
    PICRYPT_BIN="picrypt"
else
    PICRYPT_BIN="$(readlink -f "${PICRYPT_BIN}" 2>/dev/null || echo "${PICRYPT_BIN}")"
    log_ok "Found picrypt at: ${PICRYPT_BIN}"
fi

readonly PANIC_CMD="${PICRYPT_BIN} panic"

# --------------------------------------------------------------------------- #
# 2. Detect desktop environment
# --------------------------------------------------------------------------- #

detect_de() {
    if [[ -n "${FORCE_DE}" ]]; then
        echo "${FORCE_DE}"
        return
    fi

    local de="${XDG_CURRENT_DESKTOP:-${DESKTOP_SESSION:-unknown}}"
    de="$(echo "${de}" | tr '[:upper:]' '[:lower:]')"

    case "${de}" in
        *gnome*|*unity*|*ubuntu*|*pop*|*cinnamon*|*budgie*)
            echo "gnome"
            ;;
        *kde*|*plasma*)
            echo "kde"
            ;;
        *i3*)
            echo "i3"
            ;;
        *sway*)
            echo "sway"
            ;;
        *hyprland*)
            echo "hyprland"
            ;;
        *)
            # Second-pass detection: check running processes.
            if pgrep -x "gnome-shell" &>/dev/null; then
                echo "gnome"
            elif pgrep -x "plasmashell" &>/dev/null; then
                echo "kde"
            elif pgrep -x "i3" &>/dev/null; then
                echo "i3"
            elif pgrep -x "sway" &>/dev/null; then
                echo "sway"
            elif pgrep -x "Hyprland" &>/dev/null; then
                echo "hyprland"
            else
                echo "unknown"
            fi
            ;;
    esac
}

DETECTED_DE="$(detect_de)"
log_info "Detected desktop environment: ${DETECTED_DE}"

# --------------------------------------------------------------------------- #
# 3. Configure shortcut based on DE
# --------------------------------------------------------------------------- #

setup_gnome() {
    log_info "Configuring GNOME keyboard shortcut..."

    if ! command -v gsettings &>/dev/null; then
        die "gsettings not found. Cannot configure GNOME shortcut."
    fi

    # GNOME custom keybindings are stored as an array of dconf paths.
    local schema="org.gnome.settings-daemon.plugins.media-keys"
    local custom_schema="org.gnome.settings-daemon.plugins.media-keys.custom-keybinding"
    local base_path="/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings"
    local keybinding_path="${base_path}/picrypt-panic/"

    # Check if our keybinding already exists.
    local existing_bindings
    existing_bindings="$(gsettings get ${schema} custom-keybindings 2>/dev/null || echo "@as []")"

    local already_exists="false"
    if echo "${existing_bindings}" | grep -q "picrypt-panic"; then
        already_exists="true"
        log_info "Keybinding path already registered. Updating..."
    fi

    # Set the custom keybinding properties.
    gsettings set "${custom_schema}:${keybinding_path}" name "Picrypt Panic Lock"
    gsettings set "${custom_schema}:${keybinding_path}" command "${PANIC_CMD}"
    gsettings set "${custom_schema}:${keybinding_path}" binding "${SHORTCUT}"

    # Add our path to the list of custom keybindings if not already present.
    if [[ "${already_exists}" == "false" ]]; then
        if [[ "${existing_bindings}" == "@as []" || "${existing_bindings}" == "[]" ]]; then
            gsettings set ${schema} custom-keybindings "['${keybinding_path}']"
        else
            # Append our path to the existing array.
            local new_bindings
            new_bindings="${existing_bindings/]/, \'${keybinding_path}\']}"
            gsettings set ${schema} custom-keybindings "${new_bindings}"
        fi
    fi

    log_ok "GNOME shortcut configured: ${SHORTCUT_HUMAN} -> ${PANIC_CMD}"
    log_info "Verify: gsettings get ${custom_schema}:${keybinding_path} binding"
}

setup_kde() {
    log_info "Configuring KDE Plasma keyboard shortcut..."

    # KDE uses .desktop files in ~/.local/share/kglobalaccel/ or khotkeys.
    # The modern approach (Plasma 5.21+) uses custom commands via kwriteconfig5/6.
    local desktop_dir="${HOME}/.local/share/applications"
    local desktop_file="${desktop_dir}/picrypt-panic.desktop"

    mkdir -p "${desktop_dir}"

    cat > "${desktop_file}" << EOF
[Desktop Entry]
Type=Application
Name=Picrypt Panic Lock
Comment=Send emergency lock signal to all picrypt devices
Exec=${PANIC_CMD}
Icon=system-lock-screen
Terminal=false
Categories=Utility;Security;
EOF

    log_ok "Created desktop entry: ${desktop_file}"

    # Configure the global shortcut via kwriteconfig.
    local kwriteconfig=""
    if command -v kwriteconfig6 &>/dev/null; then
        kwriteconfig="kwriteconfig6"
    elif command -v kwriteconfig5 &>/dev/null; then
        kwriteconfig="kwriteconfig5"
    fi

    local shortcut_dir="${HOME}/.config"
    local shortcuts_file="${shortcut_dir}/kglobalshortcutsrc"

    if [[ -n "${kwriteconfig}" ]]; then
        ${kwriteconfig} --file "${shortcuts_file}" \
            --group "picrypt-panic.desktop" \
            --key "_k_friendly_name" "Picrypt Panic Lock"
        ${kwriteconfig} --file "${shortcuts_file}" \
            --group "picrypt-panic.desktop" \
            --key "_launch" "Ctrl+Shift+L,none,Picrypt Panic Lock"
        log_ok "KDE global shortcut configured via ${kwriteconfig}."
    else
        log_warn "kwriteconfig5/6 not found."
    fi

    # Also create a khotkeys entry for older Plasma.
    local khotkeys_dir="${shortcut_dir}"
    local khotkeys_file="${khotkeys_dir}/khotkeysrc"
    if [[ -f "${khotkeys_file}" ]]; then
        if ! grep -q "picrypt-panic" "${khotkeys_file}" 2>/dev/null; then
            log_info "Adding entry to khotkeysrc..."
            cat >> "${khotkeys_file}" << EOF

[Data_picrypt]
Comment=Picrypt Panic Lock
Enabled=true
Name=Picrypt Panic Lock
Type=SIMPLE_ACTION_DATA

[Data_picrypt/Actions]
ActionsCount=1

[Data_picrypt/Actions/Action0]
CommandURL=${PANIC_CMD}
Type=COMMAND_URL

[Data_picrypt/Triggers]
Comment=Simple_action
TriggersCount=1

[Data_picrypt/Triggers/Trigger0]
Key=Ctrl+Shift+L
Type=SHORTCUT
EOF
            log_ok "Added khotkeys entry."
        else
            log_info "khotkeys entry for picrypt-panic already exists."
        fi
    fi

    echo ""
    log_info "KDE shortcut may require a session restart or:"
    log_info "  kquitapp5 kglobalaccel && kglobalaccel5 &"
    log_info "Or set it manually via System Settings > Shortcuts > Custom Shortcuts."
}

setup_i3() {
    log_info "Configuring i3 keyboard shortcut..."

    local i3_config="${HOME}/.config/i3/config"
    if [[ ! -f "${i3_config}" ]]; then
        i3_config="${HOME}/.i3/config"
    fi

    local bind_line="bindsym \$mod+Shift+l exec --no-startup-id ${PANIC_CMD}"

    if [[ -f "${i3_config}" ]]; then
        if grep -qF "picrypt panic" "${i3_config}" 2>/dev/null; then
            log_ok "i3 config already contains a picrypt panic binding."
        else
            log_info "Appending keybinding to ${i3_config}..."
            {
                echo ""
                echo "# Picrypt panic lock — emergency lock all devices"
                echo "${bind_line}"
            } >> "${i3_config}"
            log_ok "Added to i3 config."
        fi
    else
        log_warn "i3 config file not found at expected locations."
        log_warn "Searched: ~/.config/i3/config, ~/.i3/config"
    fi

    echo ""
    log_info "Add this line to your i3 config if not automatically added:"
    echo ""
    echo "    ${bind_line}"
    echo ""
    log_info "Then reload i3: \$mod+Shift+r"
}

setup_sway() {
    log_info "Configuring sway keyboard shortcut..."

    local sway_config="${HOME}/.config/sway/config"
    local bind_line="bindsym \$mod+Shift+l exec ${PANIC_CMD}"

    if [[ -f "${sway_config}" ]]; then
        if grep -qF "picrypt panic" "${sway_config}" 2>/dev/null; then
            log_ok "sway config already contains a picrypt panic binding."
        else
            log_info "Appending keybinding to ${sway_config}..."
            {
                echo ""
                echo "# Picrypt panic lock — emergency lock all devices"
                echo "${bind_line}"
            } >> "${sway_config}"
            log_ok "Added to sway config."
        fi
    else
        log_warn "sway config not found at ${sway_config}."
    fi

    echo ""
    log_info "Add this line to your sway config if not automatically added:"
    echo ""
    echo "    ${bind_line}"
    echo ""
    log_info "Then reload sway: swaymsg reload"
}

setup_hyprland() {
    log_info "Configuring Hyprland keyboard shortcut..."

    local hypr_config="${HOME}/.config/hypr/hyprland.conf"
    local bind_line="bind = CTRL SHIFT, L, exec, ${PANIC_CMD}"

    if [[ -f "${hypr_config}" ]]; then
        if grep -qF "picrypt panic" "${hypr_config}" 2>/dev/null; then
            log_ok "Hyprland config already contains a picrypt panic binding."
        else
            log_info "Appending keybinding to ${hypr_config}..."
            {
                echo ""
                echo "# Picrypt panic lock — emergency lock all devices"
                echo "${bind_line}"
            } >> "${hypr_config}"
            log_ok "Added to Hyprland config."
        fi
    else
        log_warn "Hyprland config not found at ${hypr_config}."
    fi

    echo ""
    log_info "Add this line to your Hyprland config if not automatically added:"
    echo ""
    echo "    ${bind_line}"
    echo ""
}

setup_xbindkeys() {
    log_info "Configuring xbindkeys fallback..."

    if ! command -v xbindkeys &>/dev/null; then
        log_warn "xbindkeys is not installed."
        log_warn "Install it: sudo apt install xbindkeys  (Debian/Ubuntu)"
        log_warn "            sudo pacman -S xbindkeys    (Arch)"
        log_warn "            sudo dnf install xbindkeys  (Fedora)"
    fi

    local xbindkeys_config="${HOME}/.xbindkeysrc"

    if [[ -f "${xbindkeys_config}" ]] && grep -qF "picrypt panic" "${xbindkeys_config}" 2>/dev/null; then
        log_ok "xbindkeys config already contains a picrypt panic binding."
    else
        log_info "Adding keybinding to ${xbindkeys_config}..."
        cat >> "${xbindkeys_config}" << EOF

# Picrypt panic lock — emergency lock all devices
"${PANIC_CMD}"
  control+shift+l
EOF
        log_ok "Added to ${xbindkeys_config}"
    fi

    echo ""
    log_info "Restart xbindkeys to apply:"
    log_info "  killall xbindkeys 2>/dev/null; xbindkeys"
    log_info ""
    log_info "To start xbindkeys on login, add to your ~/.xinitrc or ~/.xprofile:"
    log_info "  xbindkeys &"
}

# --------------------------------------------------------------------------- #
# Route to the appropriate setup function
# --------------------------------------------------------------------------- #

case "${DETECTED_DE}" in
    gnome)
        setup_gnome
        ;;
    kde)
        setup_kde
        ;;
    i3)
        setup_i3
        ;;
    sway)
        setup_sway
        ;;
    hyprland)
        setup_hyprland
        ;;
    xbindkeys)
        setup_xbindkeys
        ;;
    unknown)
        log_warn "Could not detect desktop environment."
        log_warn "Falling back to xbindkeys (works with most X11 environments)."
        echo ""
        setup_xbindkeys
        echo ""
        log_info "If you use a specific DE/WM, re-run with --de <name>:"
        log_info "  ./${SCRIPT_NAME} --de gnome"
        log_info "  ./${SCRIPT_NAME} --de kde"
        log_info "  ./${SCRIPT_NAME} --de i3"
        log_info "  ./${SCRIPT_NAME} --de sway"
        log_info "  ./${SCRIPT_NAME} --de hyprland"
        ;;
    *)
        die "Unsupported desktop environment: ${DETECTED_DE}. Use --de to specify one of: gnome, kde, i3, sway, hyprland, xbindkeys"
        ;;
esac

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

echo ""
log_info "=== Linux Hotkey Setup Summary ==="
log_info "  Desktop:   ${DETECTED_DE}"
log_info "  Command:   ${PANIC_CMD}"
log_info "  Shortcut:  ${SHORTCUT_HUMAN}"
echo ""
log_info "To remove, reverse the changes for your DE (see output above)."
