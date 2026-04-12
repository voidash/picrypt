"""Pi-kill recovery: data must survive a hard server kill + restart cycle.

Worst-case scenario test. Mount a vault, write a canary plus a 4 MB binary
file, then SIGKILL the picrypt-server. Wait for the client daemon to dismount
via the heartbeat-timeout dead man's switch, then RESTART the same server
with the same data dir, re-unseal with the same password, re-mount the vault
using the same keyfile, and verify both files are byte-identical.

This is what happens after a real seizure recovery: the Pi was unplugged,
you got it back, it boots, and you want every byte of your data exactly
as you left it.

Requires: VeraCrypt installed, picrypt-client built, sudo NOPASSWD for
veracrypt. Skips cleanly otherwise.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import random
import shutil
import signal
import subprocess
import tempfile
import time

import flexitest
import requests

from common.base_test import PicryptTest
from common.persistence_helpers import (
    PICRYPT_CLIENT,
    VERACRYPT_BIN,
    can_sudo_veracrypt,
    is_mounted,
    read_from_mount,
    vc_create,
    vc_dismount_all,
    vc_mount,
    wait_for_server_ready,
    write_to_mount,
)

logger = logging.getLogger(__name__)


if VERACRYPT_BIN is not None and PICRYPT_CLIENT is not None:

    @flexitest.register
    class TestDataSurvivesPiKillRecovery(PicryptTest):
        """Pi killed → daemon dismounts → Pi back up → remount → data intact."""

        def __init__(self, ctx: flexitest.InitContext):
            ctx.set_env("data_persistence_pi_kill")

        def main(self, ctx: flexitest.RunContext):
            assert VERACRYPT_BIN is not None
            assert PICRYPT_CLIENT is not None

            if not can_sudo_veracrypt():
                self.info("SKIP: needs passwordless sudo for veracrypt")
                return True

            server = self.get_server()
            master_password = "data-persistence-test-pw"

            tmpdir = tempfile.mkdtemp(prefix="picrypt-data-persist-")
            client_home = os.path.join(tmpdir, "client_home")
            picrypt_dir = os.path.join(client_home, ".picrypt")
            os.makedirs(picrypt_dir)
            container = os.path.join(tmpdir, "vault.hc")
            mount_point = os.path.join(tmpdir, "Vault")
            keyfile_path = os.path.join(tmpdir, "keyfile.bin")
            os.makedirs(mount_point, exist_ok=True)

            client_proc: subprocess.Popen | None = None
            new_server_proc: subprocess.Popen | None = None

            try:
                # ---- Setup
                server.unseal(master_password)
                self.info("Setup: server unsealed")

                dev = server.register_device("data-persistence-test")
                device_id = dev["device_id"]
                auth_token = dev["auth_token"]
                keyfile_bytes = base64.b64decode(dev["keyfile"])
                with open(keyfile_path, "wb") as f:
                    f.write(keyfile_bytes)
                os.chmod(keyfile_path, 0o600)

                r = vc_create(container, "8M", keyfile_path)
                assert r.returncode == 0, f"vault create failed: {r.stderr}"
                self.info("Setup: vault created")

                # Capture server cmd BEFORE we kill it — we need it for restart.
                server_cmd = list(server.proc.args)  # type: ignore[attr-defined]
                server_url = server.props["http_url"]

                # ---- Spawn picrypt-client daemon with low heartbeat timeout
                config_path = os.path.join(picrypt_dir, "client.toml")
                with open(config_path, "w") as f:
                    f.write(f"""\
server_url = "{server_url}"
fallback_urls = []
device_id = "{device_id}"
auth_token = "{auth_token}"
heartbeat_timeout_secs = 5
heartbeat_interval_secs = 1
sleep_detection = false

[[volumes]]
container = "{container}"
mount_point = "{mount_point}"
""")
                os.chmod(config_path, 0o600)

                client_log = os.path.join(tmpdir, "client.log")
                log_fh = open(client_log, "w")
                client_proc = subprocess.Popen(
                    [PICRYPT_CLIENT, "unlock"],
                    env={**os.environ, "HOME": client_home, "RUST_LOG": "info"},
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                )
                self.info(f"Step 1: client daemon spawned (pid {client_proc.pid})")

                # ---- Wait for mount
                mounted = False
                for _ in range(30):
                    if is_mounted(mount_point):
                        mounted = True
                        break
                    if client_proc.poll() is not None:
                        log_fh.flush()
                        with open(client_log) as f:
                            raise AssertionError(f"client died before mount: {f.read()}")
                    time.sleep(0.5)
                assert mounted, "vault did not mount within 15s"
                self.info(f"Step 2: vault mounted at {mount_point}")

                # ---- Write canary + 4MB binary
                canary_text = f"survived-pi-yank-{os.getpid()}-{time.time()}"
                canary_bytes = canary_text.encode()
                write_to_mount(os.path.join(mount_point, "canary.txt"), canary_bytes)

                rng = random.Random(0xCAFEBABE)
                binary_payload = bytes(rng.randint(0, 255) for _ in range(4 * 1024 * 1024))
                binary_sha = hashlib.sha256(binary_payload).hexdigest()
                write_to_mount(os.path.join(mount_point, "data.bin"), binary_payload)
                self.info(f"Step 3: wrote canary + 4MB binary (sha256={binary_sha[:16]}...)")

                subprocess.run(["sync"], timeout=5)
                self.info("Step 3b: fsync flushed")

                # ---- KILL the server hard
                kill_time = time.monotonic()
                self.info(f"Step 4: SIGKILL server (pid {server.proc.pid})")  # type: ignore[attr-defined]
                os.kill(server.proc.pid, signal.SIGKILL)  # type: ignore[attr-defined]

                # ---- Wait for daemon to exit + volume to dismount
                deadline = time.monotonic() + 30
                daemon_exited = False
                volume_dismounted = False
                while time.monotonic() < deadline:
                    if client_proc.poll() is not None:
                        daemon_exited = True
                    if not is_mounted(mount_point):
                        volume_dismounted = True
                    if daemon_exited and volume_dismounted:
                        break
                    time.sleep(0.3)

                log_fh.flush()
                with open(client_log) as f:
                    log_content = f.read()
                assert daemon_exited, f"daemon did not exit:\n{log_content}"
                assert volume_dismounted, f"volume not dismounted:\n{log_content}"
                self.info(
                    f"Step 5: daemon exited & dismounted "
                    f"({time.monotonic() - kill_time:.1f}s after kill)"
                )

                # ---- Restart the SAME server using the SAME cmd (same datadir)
                self.info("Step 6: restarting picrypt-server with same data dir")
                new_server_proc = subprocess.Popen(
                    server_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                wait_for_server_ready(server_url, timeout=10)
                self.info("Step 6b: restarted server is ready")

                # ---- Re-unseal with the SAME password
                r = requests.post(
                    f"{server_url}/unseal",
                    json={"password": master_password},
                    timeout=10,
                )
                assert r.status_code == 200, f"re-unseal failed: {r.text}"
                assert r.json()["state"] == "active"
                self.info("Step 7: server re-unsealed with same password")

                # ---- Re-fetch the keyfile and verify it's identical
                r = requests.get(
                    f"{server_url}/key/{device_id}",
                    headers={"Authorization": f"Bearer {auth_token}"},
                    timeout=5,
                )
                assert r.status_code == 200, f"key fetch failed: {r.text}"
                refetched = base64.b64decode(r.json()["keyfile"])
                assert refetched == keyfile_bytes, \
                    "keyfile changed after server restart — KEYSTORE CORRUPTION"
                self.info("Step 8: keyfile is byte-identical after restart")

                # ---- Re-mount the vault
                r = vc_mount(container, mount_point, keyfile_path)
                assert r.returncode == 0, f"remount failed: {r.stderr}"
                assert is_mounted(mount_point), "remount did not appear in mount table"
                self.info("Step 9: vault remounted")

                # ---- Verify both files survived byte-for-byte
                recovered_canary = read_from_mount(os.path.join(mount_point, "canary.txt"))
                assert recovered_canary == canary_bytes, \
                    f"canary corrupted!\n  expected: {canary_bytes!r}\n  got:      {recovered_canary!r}"
                self.info("Step 10a: canary.txt intact")

                recovered_binary = read_from_mount(os.path.join(mount_point, "data.bin"))
                recovered_sha = hashlib.sha256(recovered_binary).hexdigest()
                assert len(recovered_binary) == len(binary_payload), \
                    f"binary file size mismatch: {len(recovered_binary)} vs {len(binary_payload)}"
                assert recovered_sha == binary_sha, \
                    f"binary file checksum mismatch:\n  expected: {binary_sha}\n  got:      {recovered_sha}"
                self.info(f"Step 10b: data.bin intact (sha256={recovered_sha[:16]}...)")

                self.info("=== DATA SURVIVED PI-KILL + RECOVERY ===")

            finally:
                if client_proc and client_proc.poll() is None:
                    try:
                        client_proc.terminate()
                        client_proc.wait(timeout=5)
                    except Exception:
                        try:
                            client_proc.kill()
                        except Exception:
                            pass
                vc_dismount_all()
                if new_server_proc and new_server_proc.poll() is None:
                    try:
                        new_server_proc.terminate()
                        new_server_proc.wait(timeout=5)
                    except Exception:
                        try:
                            new_server_proc.kill()
                        except Exception:
                            pass
                shutil.rmtree(tmpdir, ignore_errors=True)

            return True
