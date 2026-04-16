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

> ⚠️ **Status:** v0.1.12. Real cryptography, real VeraCrypt integration, real
> tests, persistent client daemon with auto-remount across lock/unseal cycles,
> Tailscale Funnel panic path with a browser PWA, vault-bound service hooks.
> No third-party security audit. Read the [Security model](#security-model)
> before relying on it.
>
> **Recent versions** — see commit history for details:
> - **0.1.12** — post-mount / pre-dismount service hooks per volume
> - **0.1.11** — panic-listener CORS for browser-originated panic
> - **0.1.10** — client daemon starts in standby if server is sealed at boot
> - **0.1.9**  — persistent client daemon survives lock/unseal cycles
> - **0.1.8**  — standalone panic-listener bridge (Tailscale Funnel)
> - **0.1.7**  — mandatory dual-factor unseal (master password + YubiKey)

---

## Threat model

### What we defend against

- **Cold seizure.** Your laptop gets taken while you are away from it. Without
  a live network path to the key server, the volumes cannot be re-mounted.
- **Coerced unlock.** Anyone with a valid panic token can hit one HTTP endpoint
  and re-seal the server. Every connected client dismounts within a second
  via WebSocket LOCK broadcast (fallback: `heartbeat_timeout_secs`, default
  300s). From v0.1.9 onwards clients also auto-remount when you re-unseal,
  so there's no manual re-run per device. Panic sources: curl against the
  Tailnet endpoint, Android HTTP Shortcuts, or a browser PWA hosted at a
  public URL behind Tailscale Funnel.
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
  common/          shared types, crypto primitives (Argon2id, AES-256-GCM,
                   dual-factor key derivation)
  server/          axum HTTP + WebSocket server, sealed/active state machine,
                   Lock + Unsealed broadcasts
  client/          CLI + persistent daemon: init, register, unlock (mount +
                   heartbeat loop that survives lock/unseal cycles), panic,
                   create-container, dual-factor enroll/finalize
  panic-listener/  tight bridge binary on the server host. Accepts
                   authenticated POST /panic from the public internet
                   (typically via Tailscale Funnel) and forwards to local
                   /lock. Has per-contact token auth, configurable CORS, and
                   runs as its own systemd unit with sandboxing.
android/           panic-lock widget (Kotlin, AndroidX)
deploy/            install scripts and systemd units
scripts/           OS hardening scripts (Linux, macOS, Windows)
functional-tests/  Python integration tests using flexitest. Spawns a real
                   server, performs real VeraCrypt mount/dismount on
                   Linux + macOS.
```

---

## Quick start

### 1. Server (Raspberry Pi or any Linux box on your tailnet)

**Option A: automated release download** (recommended). The install script
downloads the tarball, verifies SHA256, verifies the cosign signature (if
cosign is installed), extracts the binaries, and installs both `picrypt-server`
and `picrypt-panic-listener`:

```bash
# Get the install script (from a git clone or direct download)
curl -fsSL -o install-server.sh \
  https://raw.githubusercontent.com/voidash/picrypt/main/deploy/install-server.sh
chmod +x install-server.sh

sudo ./install-server.sh --release v0.1.12
```

**Option B: manual download + verify.** If you prefer to handle the download
and verification yourself:

```bash
# aarch64 example for Raspberry Pi — substitute your arch
TAG=v0.1.12
ARCH=aarch64-unknown-linux-musl
curl -LO "https://github.com/voidash/picrypt/releases/download/${TAG}/picrypt-${TAG}-${ARCH}.tar.gz"
curl -LO "https://github.com/voidash/picrypt/releases/download/${TAG}/picrypt-${TAG}-${ARCH}.tar.gz.sha256"
curl -LO "https://github.com/voidash/picrypt/releases/download/${TAG}/picrypt-${TAG}-${ARCH}.tar.gz.sig"
curl -LO "https://github.com/voidash/picrypt/releases/download/${TAG}/picrypt-${TAG}-${ARCH}.tar.gz.crt"

shasum -a 256 -c "picrypt-${TAG}-${ARCH}.tar.gz.sha256"
cosign verify-blob \
  --certificate "picrypt-${TAG}-${ARCH}.tar.gz.crt" \
  --signature   "picrypt-${TAG}-${ARCH}.tar.gz.sig" \
  --certificate-identity-regexp '^https://github\.com/voidash/picrypt/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer     https://token.actions.githubusercontent.com \
  "picrypt-${TAG}-${ARCH}.tar.gz"

tar xzf "picrypt-${TAG}-${ARCH}.tar.gz"
cd "picrypt-${TAG}-${ARCH}"
sudo ./deploy/install-server.sh --binary ./picrypt-server
```

The installer will:

- Create a `picrypt` system user
- Install the binary to `/usr/local/bin/picrypt-server`
- Generate `/var/lib/picrypt/.picrypt/server.toml` with a fresh **admin token** and
  **lock PIN** (printed once — save them)
- Create `picrypt-panic` user, install the panic-listener binary and service,
  generate `/etc/picrypt/panic.toml` with a fresh **contact token** (printed once)
- Install and start both `picrypt-server.service` and
  `picrypt-panic-listener.service` via systemd
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

**Option A: automated release download:**

```bash
curl -fsSL -o install-client.sh \
  https://raw.githubusercontent.com/voidash/picrypt/main/deploy/install-client.sh
chmod +x install-client.sh

./install-client.sh --release v0.1.12
```

**Option B: manual download + install:**

```bash
TAG=v0.1.12
# macOS Apple Silicon example — substitute your target
ARCH=aarch64-apple-darwin
curl -LO "https://github.com/voidash/picrypt/releases/download/${TAG}/picrypt-${TAG}-${ARCH}.tar.gz"
# ... verify SHA256 + cosign as shown above for the server ...
tar xzf "picrypt-${TAG}-${ARCH}.tar.gz"
cd "picrypt-${TAG}-${ARCH}"
./deploy/install-client.sh --binary ./picrypt-client
```

The installer prompts for the server URL and admin token, then registers the
device. It also offers to set up a persistent daemon that starts at login.

To create a new VeraCrypt vault with the server-managed keyfile and start
mounting it:

```bash
picrypt create-container --path ~/vault.hc --size 10G --mount-point ~/Vault
picrypt unlock   # persistent daemon: mounts, heartbeats, auto-remounts on unseal
```

`picrypt unlock` is the persistent daemon (v0.1.9+). Leave it running. It
survives server lock/unseal cycles and auto-remounts when the server comes
back. If the server disappears, it auto-dismounts within the heartbeat timeout.

### 3. Android panic widget

Build and install from the `android/` directory. Configure the server URL and
lock PIN inside the app, then add the widget to your home screen. Tap → confirm
→ everything dismounts, everywhere.

---

## Security model

| Component | Where the key lives |
|---|---|
| Master key at rest | `encrypted_master_key_pw.bin` (single-factor) or `encrypted_master_key_pw_yk.bin` (v0.1.7+ dual-factor) on the server's disk, encrypted with an Argon2id-derived key from the operator's password — and, in dual-factor mode, combined with the operator's YubiKey HMAC-SHA1 response. AES-256-GCM for the outer wrap. |
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
| Dual-factor unseal (v0.1.7+) | Requires BOTH master password AND a YubiKey HMAC-SHA1 response at every unseal. The YubiKey lives on the client box; the server never touches the hardware. Defeats coercion scenarios where only the password is extracted. |

The server has **no Internet egress requirement** and **no DNS resolution**.
Configure your tailnet ACL so only the laptops you care about can hit it on
port 7123.

## Dual-factor unseal (v0.1.7+)

By default, picrypt unseals with only a master password. If coercion resistance
matters to you — i.e. "someone might force me to hand over the password" —
enable dual-factor unseal: every unseal then requires **both** the master
password and a touch of a YubiKey that you keep physically separated from
the server.

**How the crypto works.** At enrollment, the server picks a combined wrapping
key by running `SHA-256-family-of-KDF(pw_key || yk_key)` where `pw_key` is the
Argon2id-derived password key and `yk_key` is an Argon2id expansion of the
YubiKey's 20-byte HMAC-SHA1 response. The master key is re-encrypted under
this combined key. Decryption — and therefore unseal — requires **both**
inputs to be correct. Missing either one produces a different combined key
and AES-GCM tag verification fails. There is no partial-derive path.

**Enrollment ceremony** (do this on your trusted workstation with a YubiKey
plugged in):

```bash
# 1. Program a 20-byte HMAC-SHA1 secret into YubiKey slot 2.
#    Save the hex secret to paper/safe — this is your recovery material.
openssl rand -hex 20
# → a1b2c3d4e5f67890abcdef0123456789abcdef01   (example)

ykman otp chalresp --touch 2 a1b2c3d4e5f67890abcdef0123456789abcdef01

# 2. Verify: challenge-response should produce the same 20 bytes
#    that HMAC-SHA1(secret, challenge) produces in software.
CHALLENGE=$(openssl rand -hex 32)
ykchalresp -2 -H -x "$CHALLENGE"
# Cross-check against:
# python3 -c 'import hmac,hashlib; print(hmac.new(bytes.fromhex("a1b2c3..."), bytes.fromhex("'$CHALLENGE'"), hashlib.sha1).hexdigest())'

# 3. If you want multiple YubiKeys (recommended), program each with
#    the SAME secret so any of them can unseal:
ykman otp chalresp --touch 2 a1b2c3d4e5f67890abcdef0123456789abcdef01

# 4. Enroll against the server. You need the admin token + master password.
picrypt enroll-dual-factor \
    --admin-token "$(cat ~/admin-token.txt)" \
    --password-file ~/.master-password

# 5. Test the new path. Lock the server, then unseal — you'll be
#    prompted for both the password and a YubiKey touch.
picrypt panic --pin <your-lock-pin>
picrypt unseal

# 6. Once you're sure dual-factor works, finalize to delete the old
#    single-factor blob from the server. This is a one-way door.
picrypt finalize-dual-factor
```

**Paper backup.** The 20-byte secret you generated in step 1 IS your recovery
material. Store it somewhere safe (paper in a fireproof safe, password manager,
etched into a metal plate, whatever). If every YubiKey you programmed is lost
AND you have the paper, you can still recover: the offline recovery script
(`picrypt-offline-recover.py`, in the `master-omv/` bundle) accepts a
`--yk-secret-file` flag and reconstructs the HMAC-SHA1 response in software.
You do not need working YubiKey hardware to recover from paper. You do not
need the picrypt-server to recover — just the master password, the paper
secret, and the server's `data/` directory (or the backup of it).

**What dual-factor does NOT protect against.**

- **Attacker who reaches the YubiKey AND the master password.** If both are in
  the same room when the attacker arrives, dual-factor buys you nothing. The
  whole point is physical separation — keep the YubiKey somewhere the
  password-extractor can't touch.
- **Attacker with root on the running server during Active state.** The
  combined key is in server RAM while the server is unsealed. A memory dump
  yields everything. Dual-factor protects the transition *into* Active, not
  the Active state itself.
- **Lost paper backup AND lost all YubiKeys.** If both are gone, the data
  directory's dual-factor blob is unrecoverable. This is by design — it's what
  makes dual-factor meaningful — but it means you MUST have at least one
  working factor at all times.

---

## Vault-bound service hooks (v0.1.12+)

Each volume in `client.toml` can declare shell commands that run automatically
when the vault mounts or is about to dismount. This lets you tie services to
the vault lifecycle — e.g. starting a database only while the encrypted volume
is available, and stopping it before dismount so nothing writes to a vanishing
mountpoint.

```toml
# ~/.picrypt/client.toml example
[[volumes]]
container_path = "~/vault.hc"
mount_point = "~/Vault"
post_mount_command = "sudo /bin/systemctl start my-service"
pre_dismount_command = "sudo /bin/systemctl stop my-service"
```

- `post_mount_command` runs via `sh -c` after a successful mount (30s timeout).
- `pre_dismount_command` runs before dismount (5s timeout; child gets SIGKILL
  on timeout so the dismount isn't blocked indefinitely).

**Sudoers pattern.** If the hook needs root (e.g. `systemctl start`), grant
passwordless sudo for exactly the commands it runs. Create
`/etc/sudoers.d/picrypt-hooks`:

```
youruser ALL=(root) NOPASSWD: /bin/systemctl start my-service, \
                               /bin/systemctl stop my-service
```

Keep the allow-list tight — only the specific `systemctl start/stop` commands
the hooks actually need. Validate with `sudo visudo -cf /etc/sudoers.d/picrypt-hooks`
before relying on it.

---

## System-level daemon for headless clients

The install script sets up a **user-level** systemd service (or macOS
LaunchAgent) that starts `picrypt unlock` at login. This works for laptops
where someone logs in interactively.

For headless machines (e.g. an always-on NAS that should mount its vault at
boot without anyone logging in), you need a **system-level** unit instead.
The install script does not create this automatically because it requires
root-level decisions about which user runs the daemon and how credentials
are managed.

Example `/etc/systemd/system/picrypt-unlock.service`:

```ini
[Unit]
Description=picrypt persistent unlock daemon
After=network-online.target tailscaled.service
Wants=network-online.target
Requires=tailscaled.service

[Service]
Type=simple
User=youruser
Group=youruser
ExecStart=/usr/local/bin/picrypt unlock
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info
Environment=HOME=/home/youruser

[Install]
WantedBy=multi-user.target
```

Enable with `sudo systemctl enable --now picrypt-unlock.service`. The daemon
will start at boot (before any user logs in) and will survive reboots. It
enters standby if the server is sealed and auto-mounts when you unseal.

If your vault has service hooks that need `sudo`, make sure the sudoers
allow-list (see [Vault-bound service hooks](#vault-bound-service-hooks-v0112))
covers the user running the daemon.

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
