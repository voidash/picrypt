# picrypt — VeraCrypt remote key management
# Usage: just <recipe>

# Show available recipes
default:
    @just --list

# Build all workspace crates (debug)
build:
    cargo build --workspace

# Build all workspace crates (release)
release:
    cargo build --workspace --release

# Run all workspace tests
test:
    cargo test --workspace

# Run E2E server API tests (no VeraCrypt/sudo needed)
e2e:
    ./tests/e2e.sh

# Run E2E VeraCrypt volume tests (requires VeraCrypt + sudo)
e2e-veracrypt:
    sudo ./tests/e2e-veracrypt.sh

# Run flexitest functional tests (Python, starts real server processes)
functional:
    cd functional-tests && uv run ./entry.py

# Run specific functional test
functional-test NAME:
    cd functional-tests && uv run ./entry.py -t {{NAME}}

# List functional tests
functional-list:
    cd functional-tests && uv run ./entry.py --list

# Cross-compile server for Raspberry Pi (aarch64)
build-pi:
    cross build --release --target aarch64-unknown-linux-gnu -p picrypt-server

# Cross-compile client for Linux x86_64
build-linux:
    cross build --release --target x86_64-unknown-linux-gnu -p picrypt-client

# Cross-compile client for Windows x86_64
build-windows:
    cross build --release --target x86_64-pc-windows-gnu -p picrypt-client

# Build client for the current host (release)
build-client:
    cargo build --release -p picrypt-client

# Deploy server to a Raspberry Pi over SSH
deploy-pi HOST: build-pi
    #!/usr/bin/env bash
    set -euo pipefail
    BINARY="target/aarch64-unknown-linux-gnu/release/picrypt-server"
    SERVICE="deploy/picrypt-server.service"
    INSTALL_SCRIPT="deploy/install-server.sh"
    if [[ ! -f "${BINARY}" ]]; then
        echo "ERROR: binary not found at ${BINARY}" >&2
        exit 1
    fi
    if [[ ! -f "${SERVICE}" ]]; then
        echo "ERROR: service file not found at ${SERVICE}" >&2
        exit 1
    fi
    echo "Uploading binary and service file to {{HOST}}..."
    scp "${BINARY}" "{{HOST}}:/tmp/picrypt-server"
    scp "${SERVICE}" "{{HOST}}:/tmp/picrypt-server.service"
    if [[ -f "${INSTALL_SCRIPT}" ]]; then
        scp "${INSTALL_SCRIPT}" "{{HOST}}:/tmp/install-server.sh"
        echo "Running install script on {{HOST}}..."
        ssh "{{HOST}}" "chmod +x /tmp/install-server.sh && sudo /tmp/install-server.sh --binary /tmp/picrypt-server"
    else
        echo "No install script found. Installing manually..."
        ssh "{{HOST}}" "\
            sudo install -o root -g root -m 0755 /tmp/picrypt-server /usr/local/bin/picrypt-server && \
            sudo install -o root -g root -m 0644 /tmp/picrypt-server.service /etc/systemd/system/picrypt-server.service && \
            sudo systemctl daemon-reload && \
            sudo systemctl enable --now picrypt-server.service \
        "
    fi
    echo "Deploy complete. Check status with: ssh {{HOST}} sudo systemctl status picrypt-server"

# Run the server locally with debug logging
run-server:
    RUST_LOG=debug cargo run -p picrypt-server

# Run the client locally with optional arguments
run-client *ARGS:
    cargo run -p picrypt-client -- {{ARGS}}

# Run format check and clippy lints
check:
    cargo fmt --check
    cargo clippy --workspace -- -D warnings

# Generate a random admin token (base64, 32 bytes)
gen-admin-token:
    @openssl rand -base64 32

# Generate a random 6-digit lock PIN
gen-lock-pin:
    @printf "%06d\n" "$(( RANDOM * RANDOM % 1000000 ))"
