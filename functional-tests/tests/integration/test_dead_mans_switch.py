"""Dead man's switch test — Pi suddenly killed, client must auto-dismount.

This is the most important security test. It proves that if the Pi gets
seized/unplugged, every connected device automatically dismounts within
the heartbeat timeout.

Test flow:
1. Start picrypt-server, unseal, register device
2. Create VeraCrypt container
3. Write client.toml with low heartbeat timeouts (5s timeout, 1s interval)
4. Spawn `picrypt-client unlock` as subprocess (mounts volume + heartbeat)
5. Wait for mount to be established
6. KILL -9 the server process (simulates Pi yanked)
7. Wait for heartbeat timeout to fire
8. Verify the daemon process exited
9. Verify the volume is no longer mounted
10. Verify files are inaccessible
"""

from __future__ import annotations

import base64
import logging
import os
import shutil
import signal
import subprocess
import tempfile
import time

import flexitest

from common.base_test import PicryptTest

logger = logging.getLogger(__name__)

# Detect prerequisites
_VERACRYPT_BIN: str | None = None
if os.path.isfile("/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"):
    _VERACRYPT_BIN = "/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"
elif shutil.which("veracrypt"):
    _VERACRYPT_BIN = shutil.which("veracrypt")

# Find picrypt-client binary
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
_PICRYPT_CLIENT: str | None = None
for path in [
    os.path.join(_REPO_ROOT, "target", "release", "picrypt-client"),
    os.path.join(_REPO_ROOT, "target", "debug", "picrypt-client"),
]:
    if os.path.isfile(path):
        _PICRYPT_CLIENT = path
        break


def _can_sudo_veracrypt() -> bool:
    if _VERACRYPT_BIN is None:
        return False
    try:
        r = subprocess.run(
            ["sudo", "-n", _VERACRYPT_BIN, "--text", "--version"],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _is_mounted(mount_point: str) -> bool:
    """Check if mount_point is in the mount table."""
    try:
        r = subprocess.run(["mount"], capture_output=True, text=True, timeout=5)
        return mount_point in r.stdout
    except Exception:
        return False


if _VERACRYPT_BIN is not None and _PICRYPT_CLIENT is not None:

    @flexitest.register
    class TestDeadMansSwitch(PicryptTest):
        """Pi suddenly killed → client auto-dismounts via heartbeat timeout."""

        def __init__(self, ctx: flexitest.InitContext):
            ctx.set_env("dead_mans_switch_test")

        def main(self, ctx: flexitest.RunContext):
            assert _VERACRYPT_BIN is not None
            assert _PICRYPT_CLIENT is not None
            vc = _VERACRYPT_BIN
            client_bin = _PICRYPT_CLIENT

            if not _can_sudo_veracrypt():
                self.info("SKIP: needs passwordless sudo for veracrypt")
                return True

            server = self.get_server()

            tmpdir = tempfile.mkdtemp(prefix="picrypt-deadmans-")
            client_home = os.path.join(tmpdir, "client_home")
            picrypt_dir = os.path.join(client_home, ".picrypt")
            os.makedirs(picrypt_dir)
            container = os.path.join(tmpdir, "vault.hc")
            mount_point = os.path.join(tmpdir, "Vault")
            keyfile_path = os.path.join(tmpdir, "keyfile.bin")
            os.makedirs(mount_point, exist_ok=True)

            client_proc: subprocess.Popen | None = None

            try:
                # ===========================================================
                # SETUP: Unseal, register, create container
                # ===========================================================
                server.unseal("dead-mans-test-pw")
                self.info("Setup: Server unsealed")

                dev = server.register_device("dead-mans-device")
                device_id = dev["device_id"]
                auth_token = dev["auth_token"]
                keyfile_bytes = base64.b64decode(dev["keyfile"])

                with open(keyfile_path, "wb") as f:
                    f.write(keyfile_bytes)
                os.chmod(keyfile_path, 0o600)

                # Create container
                r = subprocess.run(
                    [
                        vc, "--text", "--create", container,
                        "--size=2M", "--encryption=AES", "--hash=SHA-512",
                        "--filesystem=FAT", f"--keyfiles={keyfile_path}",
                        "--random-source=/dev/urandom", "--password=",
                        "--pim=0", "--volume-type=normal", "--non-interactive",
                    ],
                    capture_output=True, text=True, timeout=30,
                )
                assert r.returncode == 0, f"Container creation failed: {r.stderr}"
                self.info("Setup: Container created")

                # ===========================================================
                # Write client config with LOW heartbeat timeouts
                # ===========================================================
                config_path = os.path.join(picrypt_dir, "client.toml")
                client_config = f"""\
server_url = "{server.props['http_url']}"
fallback_urls = []
device_id = "{device_id}"
auth_token = "{auth_token}"
heartbeat_timeout_secs = 5
heartbeat_interval_secs = 1
sleep_detection = false

[[volumes]]
container = "{container}"
mount_point = "{mount_point}"
"""
                with open(config_path, "w") as f:
                    f.write(client_config)
                os.chmod(config_path, 0o600)
                self.info("Setup: Client config written (5s heartbeat timeout)")

                # ===========================================================
                # STEP 1: Spawn client daemon — picrypt unlock
                # ===========================================================
                # The unlock command mounts volumes and runs heartbeat loop.
                # We need to invoke veracrypt with sudo, so we wrap the binary.
                # Actually, picrypt-client invokes veracrypt directly. On macOS,
                # mount needs root. Run the WHOLE client as sudo so it inherits.
                env = {
                    **os.environ,
                    "HOME": client_home,
                    "RUST_LOG": "info",
                }
                client_log = os.path.join(tmpdir, "client.log")
                log_fh = open(client_log, "w")

                # Run as user — picrypt-client now uses `sudo veracrypt`
                # internally for mount/dismount operations.
                client_proc = subprocess.Popen(
                    [client_bin, "unlock"],
                    env=env,
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                )
                self.info(f"Step 1: Client daemon spawned (pid {client_proc.pid})")

                # ===========================================================
                # STEP 2: Wait for mount to establish
                # ===========================================================
                mount_established = False
                for _ in range(30):  # Up to 15 seconds
                    if _is_mounted(mount_point):
                        mount_established = True
                        break
                    if client_proc.poll() is not None:
                        # Daemon died early
                        log_fh.flush()
                        with open(client_log) as f:
                            log_content = f.read()
                        raise AssertionError(
                            f"Client daemon exited early (code {client_proc.returncode}): {log_content}"
                        )
                    time.sleep(0.5)

                assert mount_established, "Volume did not mount within 15s"
                self.info(f"Step 2: Volume mounted at {mount_point}")

                # ===========================================================
                # STEP 3: Write a canary file to prove the mount works
                # ===========================================================
                canary_path = os.path.join(mount_point, "canary.txt")
                canary_content = f"survived-pi-yank-{os.getpid()}"
                # We need root to write to a root-mounted volume
                subprocess.run(
                    ["sudo", "-n", "tee", canary_path],
                    input=canary_content,
                    capture_output=True, text=True, timeout=5,
                )
                self.info(f"Step 3: Canary written to mounted volume")

                # ===========================================================
                # STEP 4: KILL THE SERVER (simulate Pi yanked)
                # ===========================================================
                # Get the server's pid via the flexitest service
                server_pid = server.proc.pid  # type: ignore[attr-defined]
                self.info(f"Step 4: Killing server (pid {server_pid}) — simulating Pi yanked")
                os.kill(server_pid, signal.SIGKILL)

                # Wait briefly for the OS to deliver the signal
                time.sleep(0.5)
                # Note: os.kill(pid, 0) is unreliable for zombies. Trust that
                # SIGKILL worked and verify by attempting to hit the server.
                try:
                    import requests
                    requests.get(f"{server.props['http_url']}/heartbeat", timeout=1)
                    raise AssertionError("Server still responding after SIGKILL")
                except (requests.ConnectionError, requests.Timeout):
                    pass  # Good — server is unreachable
                self.info("Step 4: Server is unreachable (killed)")

                # ===========================================================
                # STEP 5: Wait for heartbeat timeout (5s) + buffer
                # ===========================================================
                self.info("Step 5: Waiting for client heartbeat timeout (up to 30s)...")

                # Poll for daemon exit + dismount
                deadline = time.monotonic() + 30
                daemon_exited = False
                volume_dismounted = False
                while time.monotonic() < deadline:
                    if client_proc.poll() is not None:
                        daemon_exited = True
                    if not _is_mounted(mount_point):
                        volume_dismounted = True
                    if daemon_exited and volume_dismounted:
                        break
                    time.sleep(0.5)

                # Read client log for diagnostics
                log_fh.flush()
                with open(client_log) as f:
                    log_content = f.read()

                # ===========================================================
                # STEP 6: Verify daemon exited
                # ===========================================================
                if not daemon_exited:
                    raise AssertionError(
                        f"Client daemon did not exit after server killed. Log:\n{log_content}"
                    )
                self.info(f"Step 6: Client daemon exited (code {client_proc.returncode})")

                # ===========================================================
                # STEP 7: Verify volume is dismounted
                # ===========================================================
                if not volume_dismounted:
                    raise AssertionError(
                        f"Volume still mounted after daemon exited. Log:\n{log_content}"
                    )
                self.info("Step 7: Volume dismounted")

                # ===========================================================
                # STEP 8: Verify files are inaccessible
                # ===========================================================
                assert not os.path.isfile(canary_path), \
                    f"Canary file still visible after Pi-kill dismount: {canary_path}"
                self.info("Step 8: Canary file inaccessible — DEAD MAN'S SWITCH WORKED")

                # Verify the log mentions the heartbeat timeout / dismount
                assert "dismount" in log_content.lower() or "timeout" in log_content.lower(), \
                    f"Daemon log doesn't mention dismount/timeout:\n{log_content}"

                self.info("=== DEAD MAN'S SWITCH TEST PASSED ===")

            finally:
                # Cleanup
                if client_proc and client_proc.poll() is None:
                    try:
                        client_proc.terminate()
                        client_proc.wait(timeout=5)
                    except Exception:
                        try:
                            client_proc.kill()
                        except Exception:
                            pass
                # Force dismount any leftover mounts
                subprocess.run(
                    ["sudo", "-n", vc, "--text", "--dismount", "--force"],
                    capture_output=True,
                )
                shutil.rmtree(tmpdir, ignore_errors=True)

            return True
