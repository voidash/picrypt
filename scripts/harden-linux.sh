#!/usr/bin/env bash
# harden-linux.sh — Harden Linux against encryption key leakage via swap/hibernate.
#
# VeraCrypt keeps decryption keys in RAM while volumes are mounted. Hibernation
# writes RAM to disk, and unencrypted swap can leak keys. This script disables
# hibernation via systemd, and optionally configures encrypted swap or disables
# swap entirely.
#
# Must be run with sudo. Safe to run multiple times (idempotent).
#
# Flags:
#   --disable-swap    Remove swap entirely instead of encrypting it.
#   --encrypt-swap    Configure dm-crypt encrypted swap with a random key per boot.
#   --yes             Skip confirmation prompts (non-interactive mode).

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME

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

confirm() {
    if [[ "${AUTO_YES}" == "true" ]]; then
        return 0
    fi
    local prompt="$1"
    printf "%s [y/N] " "${prompt}"
    read -r answer
    [[ "${answer}" =~ ^[Yy]$ ]]
}

# --------------------------------------------------------------------------- #
# Parse arguments
# --------------------------------------------------------------------------- #

DISABLE_SWAP="false"
ENCRYPT_SWAP="false"
AUTO_YES="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --disable-swap)
            DISABLE_SWAP="true"
            shift
            ;;
        --encrypt-swap)
            ENCRYPT_SWAP="true"
            shift
            ;;
        --yes|-y)
            AUTO_YES="true"
            shift
            ;;
        -h|--help)
            echo "Usage: sudo ./${SCRIPT_NAME} [--disable-swap | --encrypt-swap] [--yes]"
            echo ""
            echo "Options:"
            echo "  --disable-swap   Turn off swap entirely (swapoff + remove from fstab)"
            echo "  --encrypt-swap   Configure dm-crypt encrypted swap with random key per boot"
            echo "  --yes, -y        Skip confirmation prompts"
            echo ""
            echo "If neither --disable-swap nor --encrypt-swap is given, the script only"
            echo "disables hibernation and prints current swap status."
            exit 0
            ;;
        *)
            die "Unknown argument: $1. Use --help for usage."
            ;;
    esac
done

if [[ "${DISABLE_SWAP}" == "true" && "${ENCRYPT_SWAP}" == "true" ]]; then
    die "Cannot use both --disable-swap and --encrypt-swap. Pick one."
fi

# --------------------------------------------------------------------------- #
# Pre-flight checks
# --------------------------------------------------------------------------- #

if [[ "$(uname -s)" != "Linux" ]]; then
    die "This script is for Linux only. Detected: $(uname -s)"
fi

if [[ $EUID -ne 0 ]]; then
    die "Must be run as root. Use: sudo ./${SCRIPT_NAME}"
fi

# --------------------------------------------------------------------------- #
# 1. Print current swap status
# --------------------------------------------------------------------------- #

echo ""
log_info "=== Current Swap Status ==="
if swapon --show 2>/dev/null | grep -q .; then
    swapon --show
else
    log_info "No swap currently active."
fi
echo ""

# --------------------------------------------------------------------------- #
# 2. Disable hibernation via systemd
# --------------------------------------------------------------------------- #

log_info "Disabling hibernation targets via systemd..."

HIBERNATE_TARGETS=(
    "hibernate.target"
    "hybrid-sleep.target"
    "suspend-then-hibernate.target"
)

for target in "${HIBERNATE_TARGETS[@]}"; do
    # Check current state before masking.
    current_state="$(systemctl is-enabled "${target}" 2>/dev/null || echo "unknown")"
    if [[ "${current_state}" == "masked" ]]; then
        log_ok "${target} is already masked."
    else
        if systemctl mask "${target}" 2>/dev/null; then
            log_ok "Masked ${target}."
        else
            log_warn "Failed to mask ${target}. systemd may not manage this target on your system."
        fi
    fi
done

# Also prevent logind from triggering hibernate.
LOGIND_CONF="/etc/systemd/logind.conf"
if [[ -f "${LOGIND_CONF}" ]]; then
    log_info "Checking logind.conf for hibernate settings..."
    # Ensure HandleLidSwitch doesn't hibernate.
    for setting in HandleLidSwitch HandleLidSwitchExternalPower HandleLidSwitchDocked; do
        current_value="$(grep -E "^${setting}=" "${LOGIND_CONF}" 2>/dev/null | cut -d= -f2 || true)"
        if [[ "${current_value}" == "hibernate" || "${current_value}" == "hybrid-sleep" || "${current_value}" == "suspend-then-hibernate" ]]; then
            log_warn "${setting}=${current_value} in logind.conf — this would hibernate the system."
            log_warn "Change to 'suspend' or 'ignore' manually: ${LOGIND_CONF}"
        fi
    done
fi

# --------------------------------------------------------------------------- #
# 3. Handle swap based on flags
# --------------------------------------------------------------------------- #

if [[ "${DISABLE_SWAP}" == "true" ]]; then
    # ------------------------------------------------------------------- #
    # 3a. Disable swap entirely
    # ------------------------------------------------------------------- #
    log_info "Disabling swap entirely..."

    # Turn off all active swap.
    if swapon --show 2>/dev/null | grep -q .; then
        log_info "Running swapoff -a..."
        if swapoff -a; then
            log_ok "All swap deactivated."
        else
            die "swapoff -a failed. Some swap may be in use. Free memory or kill processes first."
        fi
    else
        log_info "No active swap to turn off."
    fi

    # Comment out swap entries in /etc/fstab.
    if grep -qE '^\s*[^#].*\sswap\s' /etc/fstab 2>/dev/null; then
        log_info "Commenting out swap entries in /etc/fstab..."
        # Back up fstab before modifying.
        cp /etc/fstab "/etc/fstab.bak.$(date +%Y%m%d%H%M%S)"
        sed -i.bak -E 's|^(\s*[^#].*\sswap\s)|# DISABLED by picrypt harden-linux.sh: \1|' /etc/fstab
        log_ok "Swap entries commented out in /etc/fstab. Backup saved."
    else
        log_info "No active swap entries found in /etc/fstab."
    fi

    # Disable any swap-related systemd units.
    for unit in $(systemctl list-units --type=swap --state=active --no-legend 2>/dev/null | awk '{print $1}'); do
        log_info "Masking swap unit: ${unit}"
        if systemctl mask "${unit}" 2>/dev/null; then
            log_ok "Masked ${unit}."
        else
            log_warn "Could not mask ${unit}."
        fi
    done

elif [[ "${ENCRYPT_SWAP}" == "true" ]]; then
    # ------------------------------------------------------------------- #
    # 3b. Configure dm-crypt encrypted swap
    # ------------------------------------------------------------------- #
    log_info "Configuring encrypted swap via dm-crypt..."

    # Detect current swap device(s).
    swap_devices=()
    while IFS= read -r line; do
        dev="$(echo "${line}" | awk '{print $1}')"
        if [[ -n "${dev}" && "${dev}" != "NAME" ]]; then
            swap_devices+=("${dev}")
        fi
    done < <(swapon --show --noheadings 2>/dev/null || true)

    if [[ ${#swap_devices[@]} -eq 0 ]]; then
        # Check fstab for a swap device that's not currently active.
        fstab_swap="$(grep -E '^\s*[^#].*\sswap\s' /etc/fstab 2>/dev/null | awk '{print $1}' | head -1 || true)"
        if [[ -n "${fstab_swap}" ]]; then
            swap_devices+=("${fstab_swap}")
            log_info "Found swap device in fstab (not currently active): ${fstab_swap}"
        else
            die "No swap device found (neither active nor in fstab). Cannot configure encrypted swap. Specify a partition manually."
        fi
    fi

    if [[ ${#swap_devices[@]} -gt 1 ]]; then
        log_warn "Multiple swap devices detected. Will only configure the first one."
        log_warn "Devices: ${swap_devices[*]}"
    fi

    SWAP_DEV="${swap_devices[0]}"

    # Resolve symlinks (e.g., /dev/disk/by-uuid/... -> /dev/sdaX).
    SWAP_DEV_RESOLVED="$(readlink -f "${SWAP_DEV}" 2>/dev/null || echo "${SWAP_DEV}")"
    log_info "Target swap device: ${SWAP_DEV_RESOLVED}"

    # Refuse to encrypt-swap a partition that looks like an LVM or LUKS container.
    if cryptsetup isLuks "${SWAP_DEV_RESOLVED}" 2>/dev/null; then
        log_ok "Swap device ${SWAP_DEV_RESOLVED} is already a LUKS device. Swap is already encrypted."
    else
        if ! confirm "This will DESTROY all data on ${SWAP_DEV_RESOLVED} and configure it as encrypted swap. Continue?"; then
            log_info "Aborted by user."
            exit 0
        fi

        # Turn off swap on this device.
        swapoff "${SWAP_DEV_RESOLVED}" 2>/dev/null || true

        # Back up crypttab.
        CRYPTTAB="/etc/crypttab"
        if [[ -f "${CRYPTTAB}" ]]; then
            cp "${CRYPTTAB}" "${CRYPTTAB}.bak.$(date +%Y%m%d%H%M%S)"
        fi

        # Check if there's already a crypttab entry for this device.
        crypttab_entry="swap  ${SWAP_DEV_RESOLVED}  /dev/urandom  swap,cipher=aes-xts-plain64,size=256"

        if grep -qF "${SWAP_DEV_RESOLVED}" "${CRYPTTAB}" 2>/dev/null; then
            log_info "Entry for ${SWAP_DEV_RESOLVED} already exists in ${CRYPTTAB}. Replacing..."
            sed -i.bak "\|${SWAP_DEV_RESOLVED}|d" "${CRYPTTAB}"
        fi

        echo "${crypttab_entry}" >> "${CRYPTTAB}"
        log_ok "Added crypttab entry: ${crypttab_entry}"

        # Update fstab: replace the raw swap device with /dev/mapper/swap.
        if grep -qE "^\s*${SWAP_DEV_RESOLVED}\s+.*swap" /etc/fstab 2>/dev/null; then
            log_info "Updating /etc/fstab to use /dev/mapper/swap..."
            cp /etc/fstab "/etc/fstab.bak.$(date +%Y%m%d%H%M%S)"
            sed -i.bak "s|^${SWAP_DEV_RESOLVED}\(.*swap\)|/dev/mapper/swap\1|" /etc/fstab
            log_ok "Updated fstab."
        elif grep -qE "^\s*/dev/mapper/swap\s" /etc/fstab 2>/dev/null; then
            log_ok "fstab already references /dev/mapper/swap."
        else
            log_info "Adding /dev/mapper/swap entry to fstab..."
            echo "/dev/mapper/swap  none  swap  sw  0  0" >> /etc/fstab
            log_ok "Added /dev/mapper/swap to fstab."
        fi

        log_ok "Encrypted swap configured. It will activate on next boot with a random key."
        log_info "To activate now without rebooting, run:"
        log_info "  cryptdisks_start swap && swapon /dev/mapper/swap"
    fi

else
    # ------------------------------------------------------------------- #
    # 3c. No swap action requested — just inform
    # ------------------------------------------------------------------- #
    echo ""
    log_info "No swap modification requested."
    log_info "Use --disable-swap to turn off swap entirely."
    log_info "Use --encrypt-swap to configure dm-crypt encrypted swap."
    log_info ""

    # Warn if swap is active and unencrypted.
    if swapon --show 2>/dev/null | grep -q .; then
        while IFS= read -r line; do
            dev="$(echo "${line}" | awk '{print $1}')"
            if [[ -n "${dev}" && "${dev}" != "NAME" ]]; then
                dev_resolved="$(readlink -f "${dev}" 2>/dev/null || echo "${dev}")"
                if cryptsetup isLuks "${dev_resolved}" 2>/dev/null; then
                    log_ok "Swap device ${dev_resolved} is LUKS-encrypted."
                elif [[ "${dev_resolved}" == /dev/mapper/* ]]; then
                    log_ok "Swap device ${dev_resolved} is a dm-crypt device (likely encrypted)."
                elif [[ "${dev_resolved}" == /dev/zram* ]]; then
                    log_ok "Swap device ${dev_resolved} is zram (compressed RAM, not disk — safe)."
                else
                    log_warn "Swap device ${dev_resolved} appears UNENCRYPTED."
                    log_warn "Encryption keys paged to this swap can be recovered from disk."
                fi
            fi
        done < <(swapon --show --noheadings 2>/dev/null)
    fi
fi

# --------------------------------------------------------------------------- #
# 4. Print final swap status
# --------------------------------------------------------------------------- #

echo ""
log_info "=== Final Swap Status ==="
if swapon --show 2>/dev/null | grep -q .; then
    swapon --show
else
    log_info "No swap currently active."
fi

# --------------------------------------------------------------------------- #
# 5. Additional kernel parameter hardening recommendations
# --------------------------------------------------------------------------- #

echo ""
log_info "=== Additional Recommendations ==="
log_info "Consider adding these kernel parameters to your bootloader (GRUB/systemd-boot):"
log_info "  - 'nohibernate' — prevents hibernation at the kernel level"
log_info "  - 'page_poison=1' — poisons freed pages to prevent data recovery"
log_info ""
log_info "For GRUB, edit /etc/default/grub and add to GRUB_CMDLINE_LINUX:"
log_info "  GRUB_CMDLINE_LINUX=\"... nohibernate page_poison=1\""
log_info "Then run: sudo update-grub"

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

echo ""
log_info "=== Linux Hardening Summary ==="
log_info "  Hibernation targets: masked"
if [[ "${DISABLE_SWAP}" == "true" ]]; then
    log_info "  Swap: disabled entirely"
elif [[ "${ENCRYPT_SWAP}" == "true" ]]; then
    log_info "  Swap: encrypted via dm-crypt (random key per boot)"
else
    log_info "  Swap: unchanged (see warnings above if unencrypted)"
fi
log_info ""
log_info "To undo hibernation masking:"
log_info "  sudo systemctl unmask hibernate.target hybrid-sleep.target suspend-then-hibernate.target"
