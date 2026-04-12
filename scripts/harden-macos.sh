#!/usr/bin/env bash
# harden-macos.sh — Harden macOS against encryption key leakage via swap/hibernate.
#
# VeraCrypt keeps decryption keys in RAM while volumes are mounted. Hibernation
# writes RAM contents to disk (sleepimage), where keys can be recovered later.
# This script disables hibernation and related power states, removes the sleep
# image, and verifies FileVault status (macOS encrypts swap only when FileVault
# is enabled).
#
# Must be run with sudo. Safe to run multiple times (idempotent).

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly SLEEPIMAGE="/var/vm/sleepimage"

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
# Pre-flight checks
# --------------------------------------------------------------------------- #

if [[ "$(uname -s)" != "Darwin" ]]; then
    die "This script is for macOS only. Detected: $(uname -s)"
fi

if [[ $EUID -ne 0 ]]; then
    die "Must be run as root. Use: sudo ./${SCRIPT_NAME}"
fi

# --------------------------------------------------------------------------- #
# 1. Disable hibernation and related power-save modes
# --------------------------------------------------------------------------- #

log_info "Disabling hibernation (hibernatemode 0)..."
if pmset -a hibernatemode 0; then
    log_ok "hibernatemode set to 0."
else
    die "Failed to set hibernatemode."
fi

log_info "Disabling standby..."
if pmset -a standby 0; then
    log_ok "standby set to 0."
else
    die "Failed to set standby."
fi

log_info "Disabling autopoweroff..."
if pmset -a autopoweroff 0; then
    log_ok "autopoweroff set to 0."
else
    die "Failed to set autopoweroff."
fi

# On newer Apple Silicon Macs, proximitywake and tcpkeepalive can also trigger
# partial wake states. Disable if available (non-fatal if unsupported).
if pmset -g custom 2>/dev/null | grep -q "proximitywake"; then
    log_info "Disabling proximitywake..."
    if pmset -a proximitywake 0 2>/dev/null; then
        log_ok "proximitywake disabled."
    else
        log_warn "Could not disable proximitywake (non-fatal)."
    fi
fi

# --------------------------------------------------------------------------- #
# 2. Remove existing sleep image
# --------------------------------------------------------------------------- #

log_info "Removing existing sleep image at ${SLEEPIMAGE}..."

if [[ -e "${SLEEPIMAGE}" ]]; then
    # Remove immutable flag if already set (from a previous run).
    chflags nouchg "${SLEEPIMAGE}" 2>/dev/null || true
    rm -f "${SLEEPIMAGE}"
    log_ok "Removed ${SLEEPIMAGE}."
else
    log_info "No existing sleep image found at ${SLEEPIMAGE}."
fi

# --------------------------------------------------------------------------- #
# 3. Create immutable zero-byte replacement
# --------------------------------------------------------------------------- #

log_info "Creating immutable zero-byte replacement at ${SLEEPIMAGE}..."

# Ensure parent directory exists (it always should, but be explicit).
if [[ ! -d "$(dirname "${SLEEPIMAGE}")" ]]; then
    die "Directory $(dirname "${SLEEPIMAGE}") does not exist. Something is wrong with this system."
fi

touch "${SLEEPIMAGE}"
chflags uchg "${SLEEPIMAGE}"
log_ok "Created immutable zero-byte ${SLEEPIMAGE}."

# Verify it's actually immutable.
# stat -f %Xf returns file flags on macOS; 0x2 is UF_IMMUTABLE (uchg).
file_flags="$(stat -f '%Xf' "${SLEEPIMAGE}" 2>/dev/null || echo "0")"
if (( file_flags & 0x2 )); then
    log_ok "Verified: ${SLEEPIMAGE} has uchg flag set."
else
    log_warn "Could not verify uchg flag on ${SLEEPIMAGE}. Check manually: ls -lO ${SLEEPIMAGE}"
fi

# --------------------------------------------------------------------------- #
# 4. Verify current pmset settings
# --------------------------------------------------------------------------- #

log_info "Verifying pmset settings..."
current_hibernate="$(pmset -g | grep hibernatemode | awk '{print $2}' || echo "unknown")"
current_standby="$(pmset -g | grep -w standby | awk '{print $2}' || echo "unknown")"
current_autopoweroff="$(pmset -g | grep autopoweroff | awk '{print $2}' || echo "unknown")"

if [[ "${current_hibernate}" == "0" ]]; then
    log_ok "hibernatemode = 0"
else
    log_warn "hibernatemode = ${current_hibernate} (expected 0)"
fi

if [[ "${current_standby}" == "0" ]]; then
    log_ok "standby = 0"
else
    log_warn "standby = ${current_standby} (expected 0)"
fi

if [[ "${current_autopoweroff}" == "0" ]]; then
    log_ok "autopoweroff = 0"
else
    log_warn "autopoweroff = ${current_autopoweroff} (expected 0)"
fi

# --------------------------------------------------------------------------- #
# 5. Check FileVault status
# --------------------------------------------------------------------------- #

log_info "Checking FileVault status..."

fdesetup_output="$(fdesetup status 2>&1 || true)"

if echo "${fdesetup_output}" | grep -qi "FileVault is On"; then
    log_ok "FileVault is ON. macOS encrypts swap automatically when FileVault is enabled."
elif echo "${fdesetup_output}" | grep -qi "FileVault is Off"; then
    log_warn "FileVault is OFF."
    log_warn "Without FileVault, macOS swap files are NOT encrypted."
    log_warn "Encryption keys that get paged to swap could be recovered from disk."
    log_warn "Strongly recommended: enable FileVault via System Settings > Privacy & Security > FileVault."
else
    log_warn "Could not determine FileVault status. Output was: ${fdesetup_output}"
    log_warn "Manually verify: fdesetup status"
fi

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

echo ""
log_info "=== macOS Hardening Summary ==="
log_info "  hibernatemode  = 0  (no RAM-to-disk on sleep)"
log_info "  standby        = 0  (no deep standby)"
log_info "  autopoweroff   = 0  (no auto power off)"
log_info "  sleepimage     = immutable zero-byte file"
log_info ""
log_info "These settings persist across reboots."
log_info "To undo: sudo pmset -a hibernatemode 3 && sudo chflags nouchg ${SLEEPIMAGE} && sudo rm ${SLEEPIMAGE}"
