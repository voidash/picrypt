# picrypt

**Network-gated VeraCrypt key escrow with a global panic lock.**

picrypt holds the keyfiles to your encrypted VeraCrypt volumes on a separate
machine — typically a Raspberry Pi behind Tailscale — and hands them out to
authenticated clients on demand. If the key server is unreachable (yanked,
seized, panicked), every connected device loses access to its volumes within
seconds.

This is not a general-purpose secrets manager. It exists for one threat model:
**physical seizure or coercion**, where the attacker has your laptop and is
pointing a wrench at you.

> ⚠️ **Status:** v0.1.0. Real cryptography, real VeraCrypt integration, real
> tests, but no third-party security audit. Read the
> [Security model](#security-model) before relying on it.

---

## Threat model

### What we defend against

- **Cold seizure.** Your laptop gets taken while you are away from it. Without
  a live network path to the key server, the volumes cannot be re-mounted.
- **Coerced unlock.** Anyone with the lock PIN can hit one HTTP endpoint and
  re-seal the server. Within `heartbeat_timeout_secs` (default: 120s), every
  connected client auto-dismounts. The Android widget makes this a single tap.
- **Server compromise → key exfiltration is bounded by being sealed.** The
  server stores the master key encrypted at rest (Argon2id + AES-256-GCM). It
  is only decrypted in RAM after the operator unseals it with the master
  password. Reboot = sealed = useless to an attacker who only has the disk.

### What we explicitly do not defend against

- **A live, mounted device that is seized in the warm state.** If your laptop
  is open, decrypted, and unlocked, the data is plaintext on screen. picrypt
  cannot help you. Lock your screen and/or trigger a panic before handing it
  over.
- **Memory forensics on a running unsealed server.** The master key lives in
  mlock'd RAM while the server is active. A sufficiently-resourced attacker
  with physical access to the running Pi can extract it. The mitigation is to
  trigger panic lock as soon as the Pi is in unfriendly hands.
- **Backdoored hardware, malicious VeraCrypt builds, kernel-level malware on
  the client, or rubber-hose attacks against the operator who knows the master
  password.** picrypt is one layer in defense in depth, not a substitute for
  the rest of it.

---

## Architecture

```
   ┌─────────────────┐  HTTPS over     ┌──────────────────────┐
   │  laptop A       │  Tailscale      │  picrypt-server      │
   │  picrypt-client │ ───────────────▶│  (Raspberry Pi)      │
   │  + VeraCrypt    │  fetch keyfile  │                      │
   └─────────────────┘  + heartbeat    │  encrypted at rest:  │
                                       │  master_key.enc      │
   ┌─────────────────┐                 │                      │
   │  laptop B       │ ───────────────▶│  in RAM when active: │
   │  picrypt-client │                 │  - master_key        │
   └─────────────────┘                 │  - per-device keys   │
                                       │                      │
   ┌─────────────────┐                 │  state machine:      │
   │  Android widget │ ───POST /lock──▶│  Sealed → Active     │
   │  (panic button) │                 │       ↑       ↓      │
   └─────────────────┘                 │       └── Locked     │
                                       └──────────────────────┘
```

- `picrypt-server` runs on a small always-on machine (Pi 4 / Pi 5 / mini PC)
  joined to a Tailscale tailnet. It listens **only** on the Tailscale interface.
- `picrypt-client` runs on each device that wants to mount an encrypted volume.
  It fetches the per-device keyfile, hands it to VeraCrypt via a FIFO (the key
  is never written to disk), then sends a heartbeat every `heartbeat_interval_secs`.
  If two consecutive heartbeats fail, the client force-dismounts and exits.
- The Android app is a single widget. One tap → confirmation → POST `/lock`.
  The server transitions Active → Sealed and stops handing out keys; every
  connected client dismounts within the heartbeat window.

---

## Repo layout

```
crates/
  common/   shared types, crypto primitives (Argon2id, AES-256-GCM)
  server/   axum HTTP + WebSocket server, sealed/active state machine
  client/   CLI: init, register, unlock (mount + heartbeat loop), panic
android/    panic-lock widget (Kotlin, AndroidX)
deploy/     install scripts and systemd unit
scripts/    OS hardening scripts (Linux, macOS, Windows)
functional-tests/
            Python integration tests using flexitest. Spawns a real server,
            performs real VeraCrypt mount/dismount on Linux + macOS.
```

---

## Quick start

### 1. Server (Raspberry Pi or any Linux box on your tailnet)

Download the verified release binary (see [Verifying releases](#verifying-releases)
below):

```bash
# x86_64 Linux example — substitute your arch
curl -LO https://github.com/voidash/picrypt/releases/download/v0.1.0/picrypt-server-x86_64-unknown-linux-musl.tar.gz
curl -LO https://github.com/voidash/picrypt/releases/download/v0.1.0/picrypt-server-x86_64-unknown-linux-musl.tar.gz.sig
curl -LO https://github.com/voidash/picrypt/releases/download/v0.1.0/picrypt-server-x86_64-unknown-linux-musl.tar.gz.crt

cosign verify-blob \
  --certificate picrypt-server-x86_64-unknown-linux-musl.tar.gz.crt \
  --signature   picrypt-server-x86_64-unknown-linux-musl.tar.gz.sig \
  --certificate-identity-regexp 'https://github.com/voidash/picrypt/.*' \
  --certificate-oidc-issuer     https://token.actions.githubusercontent.com \
  picrypt-server-x86_64-unknown-linux-musl.tar.gz

tar xzf picrypt-server-x86_64-unknown-linux-musl.tar.gz
sudo ./deploy/install-server.sh --binary ./picrypt-server
```

The installer will:

- Create a `picrypt` system user
- Install the binary to `/usr/local/bin/picrypt-server`
- Generate `/home/picrypt/.picrypt/server.toml` with a fresh **admin token** and
  **lock PIN** (printed once — save them)
- Install and start `picrypt-server.service` via systemd
- Run the Linux hardening script (firewall, sysctls, kernel params)

The server starts in the **sealed** state. To bring it up:

```bash
curl -X POST http://<tailscale-ip>:7123/unseal \
  -H 'Content-Type: application/json' \
  -d '{"password":"<your-master-password>"}'
```

The first unseal call sets the master password. Re-using the same password
afterwards is what unseals subsequent times.

### 2. Client (your laptop)

```bash
curl -LO https://github.com/voidash/picrypt/releases/download/v0.1.0/picrypt-client-aarch64-apple-darwin.tar.gz
# ... verify with cosign as above ...
tar xzf picrypt-client-aarch64-apple-darwin.tar.gz
sudo install -m 0755 picrypt-client /usr/local/bin/

picrypt-client init --server-url http://<tailscale-ip>:7123
picrypt-client register --name "$(hostname)" --admin-token <admin-token>
# This writes ~/.picrypt/client.toml with a per-device auth token.
```

To create a new VeraCrypt vault with the server-managed keyfile and start
mounting it:

```bash
picrypt-client create-vault --container ~/vault.hc --size 10G --mount-point ~/Vault
picrypt-client unlock   # mounts everything in client.toml + runs heartbeat
```

`picrypt-client unlock` is the daemon. Leave it running. If the server
disappears, it will auto-dismount within the heartbeat timeout.

### 3. Android panic widget

Build and install from the `android/` directory. Configure the server URL and
lock PIN inside the app, then add the widget to your home screen. Tap → confirm
→ everything dismounts, everywhere.

---

## Security model

| Component | Where the key lives |
|---|---|
| Master key at rest | `master_key.enc` on the server's disk, encrypted with Argon2id-derived key from the operator's password (AES-256-GCM) |
| Master key when active | mlock'd in server RAM, zeroized on lock/seal |
| Per-device keyfiles | Generated on registration, stored encrypted under the master key |
| Keyfile in transit | HTTPS over Tailscale (WireGuard + Noise; mutual auth via Tailscale ACLs) |
| Keyfile on the client | Never written to disk. Passed to VeraCrypt over a FIFO (`mkfifo`), then zeroized in the writer thread |
| Authentication | Per-device bearer token, generated server-side at registration |
| Authorization to lock | 6-digit lock PIN (separate from admin token) |
| State transitions | Mutex-guarded, atomic. No race between concurrent unseal/lock requests |
| Rate limiting | Sliding-window per-IP for unseal/lock attempts |
| Bootstrap protection | Admin token cannot be issued without first unsealing |
| PIN handling | Constant-time comparison; length checked before content |

The server has **no Internet egress requirement** and **no DNS resolution**.
Configure your tailnet ACL so only the laptops you care about can hit it on
port 7123.

---

## Verifying releases

All release binaries are signed with [cosign keyless signing][cosign] via
GitHub Actions OIDC. There is **no long-lived signing key**. Each signature is
backed by a transparency log entry in [Rekor][rekor] tying the artifact to a
specific commit, workflow file, and run ID.

Install cosign:

```bash
brew install cosign           # macOS
# or: https://docs.sigstore.dev/cosign/installation/
```

Verify (example for the server binary):

```bash
cosign verify-blob \
  --certificate picrypt-server-x86_64-unknown-linux-musl.tar.gz.crt \
  --signature   picrypt-server-x86_64-unknown-linux-musl.tar.gz.sig \
  --certificate-identity-regexp '^https://github\.com/voidash/picrypt/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer     https://token.actions.githubusercontent.com \
  picrypt-server-x86_64-unknown-linux-musl.tar.gz
```

If verification fails, **do not run the binary**. Open an issue.

[cosign]: https://docs.sigstore.dev/cosign/overview/
[rekor]: https://docs.sigstore.dev/rekor/overview/

---

## Building from source

```bash
# Build server + client for your host
cargo build --release

# Run unit tests
cargo test --workspace

# Run functional tests (requires VeraCrypt + sudo NOPASSWD entry)
cd functional-tests
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./entry.py
```

Cross-compile targets used by CI:

- `x86_64-unknown-linux-musl` — static, no glibc dependency
- `aarch64-unknown-linux-musl` — static, for Pi 4 / Pi 5
- `x86_64-apple-darwin` / `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

---

## Contributing

Issues and PRs welcome. Before submitting changes that touch the crypto layer,
the state machine, or the auth model, please open an issue first to discuss the
threat-model implications.

All contributions are accepted under the Apache-2.0 license (see [LICENSE](LICENSE)).

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

This project is provided **as is**, without warranty of any kind. See the
license for full disclaimers. You are operating it on your own machines and
your own threat model — read the code, run the tests, audit before you trust.
