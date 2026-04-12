#!/usr/bin/env bash
# install.sh — self-bootstrapping picrypt installer
#
# Downloads a verified release tarball from GitHub Releases, validates
# SHA256 + cosign keyless signature against the release.yml workflow
# identity, then runs the embedded deploy/install-server.sh or
# deploy/install-client.sh.
#
# Usage:
#   # Server (Linux only — Pi or any Tailscale-attached box)
#   curl -fsSL https://raw.githubusercontent.com/voidash/picrypt/main/install.sh \
#     | sudo bash -s -- server
#
#   # Client (macOS or Linux)
#   curl -fsSL https://raw.githubusercontent.com/voidash/picrypt/main/install.sh \
#     | bash -s -- client
#
# Environment variables:
#   PICRYPT_VERSION       Release tag to install. Default: latest.
#   PICRYPT_REPO          GitHub owner/repo. Default: voidash/picrypt.
#   PICRYPT_SKIP_VERIFY   Set to 1 to skip cosign signature verification.
#                         DO NOT use this except for emergency debugging.
#   PICRYPT_KEEP_WORKDIR  Set to 1 to keep the temp work directory after install.

set -euo pipefail

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

REPO="${PICRYPT_REPO:-voidash/picrypt}"
VERSION="${PICRYPT_VERSION:-latest}"
SKIP_VERIFY="${PICRYPT_SKIP_VERIFY:-0}"
KEEP_WORKDIR="${PICRYPT_KEEP_WORKDIR:-0}"

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

log()  { printf "[INFO]  %s\n" "$*"; }
ok()   { printf "[OK]    %s\n" "$*"; }
warn() { printf "[WARN]  %s\n" "$*" >&2; }
err()  { printf "[ERROR] %s\n" "$*" >&2; }
die()  { err "$@"; exit 1; }

# --------------------------------------------------------------------------- #
# Args
# --------------------------------------------------------------------------- #

usage() {
    cat <<'USAGE'
Usage: install.sh <server|client> [-- <args passed to deploy script>]

Modes:
  server   Install picrypt-server (Linux only). Requires sudo.
  client   Install picrypt-client (macOS or Linux).

Environment:
  PICRYPT_VERSION       release tag (default: latest)
  PICRYPT_REPO          owner/repo  (default: voidash/picrypt)
  PICRYPT_SKIP_VERIFY   1 = skip cosign verification (NOT recommended)
  PICRYPT_KEEP_WORKDIR  1 = keep tmp dir after install
USAGE
}

if [[ $# -lt 1 ]]; then
    usage >&2
    exit 2
fi

MODE="$1"
shift
case "${MODE}" in
    server|client) ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown mode: ${MODE}"; usage >&2; exit 2 ;;
esac

# Anything after `--` is forwarded to the deploy script.
DEPLOY_ARGS=()
if [[ $# -gt 0 && "$1" == "--" ]]; then
    shift
    DEPLOY_ARGS=("$@")
fi

# --------------------------------------------------------------------------- #
# Detect target triple
# --------------------------------------------------------------------------- #

detect_target() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "${os}" in
        Linux)
            case "${arch}" in
                x86_64|amd64)         echo "x86_64-unknown-linux-musl" ;;
                aarch64|arm64)        echo "aarch64-unknown-linux-musl" ;;
                *) die "Unsupported Linux architecture: ${arch}" ;;
            esac
            ;;
        Darwin)
            if [[ "${MODE}" == "server" ]]; then
                die "picrypt-server is Linux-only. Run on a Linux/Tailscale host."
            fi
            case "${arch}" in
                arm64)  echo "aarch64-apple-darwin" ;;
                x86_64) echo "x86_64-apple-darwin" ;;
                *) die "Unsupported macOS architecture: ${arch}" ;;
            esac
            ;;
        *)
            die "Unsupported OS: ${os}. Supported: Linux, Darwin."
            ;;
    esac
}

TARGET="$(detect_target)"
log "Target: ${TARGET}"

# --------------------------------------------------------------------------- #
# Tooling preflight
# --------------------------------------------------------------------------- #

need() {
    command -v "$1" >/dev/null 2>&1 || die "Required tool not found: $1"
}

need curl
need tar
need uname

# Pick the SHA256 verifier we have
if command -v sha256sum >/dev/null 2>&1; then
    SHA256_CMD=(sha256sum -c)
elif command -v shasum >/dev/null 2>&1; then
    SHA256_CMD=(shasum -a 256 -c)
else
    die "Neither sha256sum nor shasum is available — cannot verify checksum"
fi

# --------------------------------------------------------------------------- #
# Resolve version
# --------------------------------------------------------------------------- #

if [[ "${VERSION}" == "latest" ]]; then
    log "Resolving latest release tag from github.com/${REPO}..."
    # GitHub redirects /releases/latest to the actual tag URL.
    VERSION="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/${REPO}/releases/latest" 2>/dev/null \
        | sed 's|.*/tag/||')"
    if [[ -z "${VERSION}" || "${VERSION}" == */* ]]; then
        die "Could not resolve latest release tag for ${REPO}"
    fi
fi
ok "Version: ${VERSION}"

# --------------------------------------------------------------------------- #
# Download
# --------------------------------------------------------------------------- #

ASSET="picrypt-${VERSION}-${TARGET}.tar.gz"
URL_BASE="https://github.com/${REPO}/releases/download/${VERSION}"

WORKDIR="$(mktemp -d -t picrypt-install-XXXXXX)"
if [[ "${KEEP_WORKDIR}" != "1" ]]; then
    trap 'rm -rf "${WORKDIR}"' EXIT
else
    log "Keeping workdir at ${WORKDIR} (PICRYPT_KEEP_WORKDIR=1)"
fi

cd "${WORKDIR}"

fetch() {
    local url="$1" dest="$2"
    log "Downloading $(basename "${dest}")..."
    curl -fsSL --retry 3 --retry-delay 2 -o "${dest}" "${url}" \
        || die "Failed to download ${url}"
}

fetch "${URL_BASE}/${ASSET}"        "${ASSET}"
fetch "${URL_BASE}/${ASSET}.sha256" "${ASSET}.sha256"

# --------------------------------------------------------------------------- #
# Verify SHA256 (always)
# --------------------------------------------------------------------------- #

log "Verifying SHA256..."
"${SHA256_CMD[@]}" "${ASSET}.sha256" >/dev/null \
    || die "SHA256 verification FAILED — refusing to install"
ok "SHA256 verified"

# --------------------------------------------------------------------------- #
# Verify cosign signature (default; skippable for emergencies)
# --------------------------------------------------------------------------- #

ensure_cosign() {
    if command -v cosign >/dev/null 2>&1; then
        return 0
    fi

    log "cosign not found — installing static binary from sigstore/cosign..."
    local cs_os cs_arch dest
    cs_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$(uname -m)" in
        x86_64|amd64) cs_arch="amd64" ;;
        aarch64|arm64) cs_arch="arm64" ;;
        *) die "Cannot install cosign for arch $(uname -m). Install manually: https://docs.sigstore.dev/cosign/installation/" ;;
    esac

    if [[ "$(id -u)" -eq 0 ]]; then
        dest="/usr/local/bin/cosign"
    else
        dest="${HOME}/.local/bin/cosign"
        mkdir -p "$(dirname "${dest}")"
    fi

    local url="https://github.com/sigstore/cosign/releases/latest/download/cosign-${cs_os}-${cs_arch}"
    curl -fsSL --retry 3 -o "${dest}" "${url}" \
        || die "Failed to download cosign from ${url}"
    chmod +x "${dest}"

    # Make it discoverable for the rest of this script
    case ":${PATH}:" in
        *":$(dirname "${dest}"):"*) ;;
        *) export PATH="$(dirname "${dest}"):${PATH}" ;;
    esac
    ok "cosign installed at ${dest}"
}

if [[ "${SKIP_VERIFY}" == "1" ]]; then
    warn "PICRYPT_SKIP_VERIFY=1 — skipping cosign signature verification."
    warn "You are trusting the SHA256 alone. Do not do this in production."
else
    fetch "${URL_BASE}/${ASSET}.sig" "${ASSET}.sig"
    fetch "${URL_BASE}/${ASSET}.crt" "${ASSET}.crt"

    ensure_cosign

    log "Verifying cosign keyless signature against release.yml workflow identity..."
    cosign verify-blob \
        --certificate "${ASSET}.crt" \
        --signature   "${ASSET}.sig" \
        --certificate-identity-regexp "^https://github\\.com/${REPO}/\\.github/workflows/release\\.yml@refs/tags/.*$" \
        --certificate-oidc-issuer     "https://token.actions.githubusercontent.com" \
        "${ASSET}" >/dev/null 2>&1 \
        || die "cosign verification FAILED — refusing to install. The artifact is NOT a legitimate ${REPO} release build."
    ok "cosign signature verified — built by ${REPO}/.github/workflows/release.yml at tag ${VERSION}"
fi

# --------------------------------------------------------------------------- #
# Extract
# --------------------------------------------------------------------------- #

log "Extracting ${ASSET}..."
tar -xzf "${ASSET}"

EXTRACTED="picrypt-${VERSION}-${TARGET}"
[[ -d "${EXTRACTED}" ]] || die "Tarball did not extract to expected directory: ${EXTRACTED}"
cd "${EXTRACTED}"

# --------------------------------------------------------------------------- #
# Hand off to the embedded deploy script
# --------------------------------------------------------------------------- #

case "${MODE}" in
    server)
        if [[ "$(id -u)" -ne 0 ]]; then
            die "Server install must run as root. Re-run with sudo."
        fi
        [[ -f ./picrypt-server ]]            || die "picrypt-server binary missing from tarball"
        [[ -x ./deploy/install-server.sh ]]  || chmod +x ./deploy/install-server.sh
        # Make sure all helper scripts are executable
        chmod +x ./deploy/*.sh ./scripts/*.sh 2>/dev/null || true
        log "Running deploy/install-server.sh..."
        ./deploy/install-server.sh --binary ./picrypt-server "${DEPLOY_ARGS[@]}"
        ;;

    client)
        [[ -f ./picrypt-client ]]            || die "picrypt-client binary missing from tarball"
        if [[ -x ./deploy/install-client.sh || -f ./deploy/install-client.sh ]]; then
            chmod +x ./deploy/install-client.sh
            log "Running deploy/install-client.sh..."
            ./deploy/install-client.sh --binary ./picrypt-client "${DEPLOY_ARGS[@]}"
        else
            # Fallback: just install the binary in a sensible place.
            warn "deploy/install-client.sh missing from tarball — installing binary only."
            local_dest="${HOME}/.local/bin"
            [[ "$(id -u)" -eq 0 ]] && local_dest="/usr/local/bin"
            mkdir -p "${local_dest}"
            install -m 0755 ./picrypt-client "${local_dest}/picrypt"
            ok "Installed picrypt to ${local_dest}/picrypt"
        fi
        ;;
esac

ok "Installation complete."
