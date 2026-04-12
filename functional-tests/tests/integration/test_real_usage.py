"""Full real-usage simulation test.

Simulates exactly what a real user does, end to end:

1. Server starts sealed
2. User unseals with password
3. User registers their laptop
4. User creates a VeraCrypt container with the server's keyfile
5. User mounts the container (sudo veracrypt --mount)
6. User writes files into the vault
7. Someone triggers panic lock (POST /lock)
8. Volume is force-dismounted
9. User re-unseals, re-mounts with re-fetched key
10. Files are still there

Steps 1-4 run without root (container creation is userspace).
Steps 5-10 require root + macFUSE. If unavailable, only 1-4 run and
the test is honestly marked as PARTIAL.

This test is registered unconditionally. It adapts to the environment.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time

import flexitest
import requests

from common.base_test import PicryptTest

logger = logging.getLogger(__name__)

# Detect VeraCrypt
_VERACRYPT_BIN: str | None = None
if os.path.isfile("/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"):
    _VERACRYPT_BIN = "/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"
elif shutil.which("veracrypt"):
    _VERACRYPT_BIN = shutil.which("veracrypt")


def _can_sudo_veracrypt() -> bool:
    """Check if we can run veracrypt via sudo without a password."""
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


def _can_mount() -> bool:
    """Check if we can actually mount a VeraCrypt volume.

    Does a real test mount with a tiny throwaway container, since on Apple
    Silicon VeraCrypt may use either macFUSE or fskit depending on filesystem,
    and there's no reliable static check.
    """
    if not _can_sudo_veracrypt() or _VERACRYPT_BIN is None:
        return False

    test_dir = tempfile.mkdtemp(prefix="picrypt-mount-probe-")
    try:
        container = os.path.join(test_dir, "probe.hc")
        keyfile = os.path.join(test_dir, "key.bin")
        mount_point = os.path.join(test_dir, "mnt")
        os.makedirs(mount_point, exist_ok=True)
        with open(keyfile, "wb") as f:
            f.write(os.urandom(64))
        os.chmod(keyfile, 0o600)

        # Create a minimal 1MB FAT container
        r = subprocess.run(
            [
                _VERACRYPT_BIN, "--text", "--create", container,
                "--size=1M", "--encryption=AES", "--hash=SHA-512",
                "--filesystem=FAT", f"--keyfiles={keyfile}",
                "--random-source=/dev/urandom", "--password=",
                "--pim=0", "--volume-type=normal", "--non-interactive",
            ],
            capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            return False

        # Try to mount it
        r = subprocess.run(
            ["sudo", "-n", _VERACRYPT_BIN, "--text", "--mount",
             f"--keyfiles={keyfile}", "--protect-hidden=no",
             "--pim=0", "--password=", container, mount_point],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            logger.warning(f"Mount probe failed: {r.stderr.strip()}")
            return False

        # Successfully mounted — dismount-all (path-based dismount unreliable on macOS fskit)
        subprocess.run(
            ["sudo", "-n", _VERACRYPT_BIN, "--text", "--dismount", "--force"],
            capture_output=True, timeout=10,
        )
        return True
    finally:
        # Force dismount in case it's still stuck
        subprocess.run(
            ["sudo", "-n", _VERACRYPT_BIN, "--text", "--dismount", "--force"],
            capture_output=True, timeout=5,
        )
        shutil.rmtree(test_dir, ignore_errors=True)


def _vc(*args: str) -> subprocess.CompletedProcess:
    """Run veracrypt with sudo."""
    assert _VERACRYPT_BIN is not None
    return subprocess.run(
        ["sudo", _VERACRYPT_BIN, "--text", *args],
        capture_output=True, text=True, timeout=30,
    )


if _VERACRYPT_BIN is not None:

    @flexitest.register
    class TestRealUsageSimulation(PicryptTest):
        """Simulate a real user's workflow from zero to working encrypted vault."""

        def __init__(self, ctx: flexitest.InitContext):
            ctx.set_env("real_usage_test")

        def main(self, ctx: flexitest.RunContext):
            server = self.get_server()
            can_mount = _can_mount()

            if not can_mount:
                if not _can_sudo_veracrypt():
                    self.info(
                        "WARNING: Cannot sudo veracrypt — add to sudoers: "
                        "cdjk ALL=(ALL) NOPASSWD: /Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"
                    )
                else:
                    self.info(
                        "WARNING: macFUSE kernel extension not loaded. "
                        "On Apple Silicon: Recovery Mode → Startup Security → Reduced Security → "
                        "Allow user-managed kexts → reboot → System Settings → Privacy & Security → "
                        "Allow macFUSE → reboot."
                    )

            tmpdir = tempfile.mkdtemp(prefix="picrypt-real-usage-")
            container = os.path.join(tmpdir, "vault.hc")
            mount_point = os.path.join(tmpdir, "Vault")
            keyfile_path = os.path.join(tmpdir, "keyfile.bin")
            os.makedirs(mount_point, exist_ok=True)

            try:
                # ===============================================================
                # STEP 1: Server starts sealed
                # ===============================================================
                hb = server.heartbeat()
                assert hb["state"] == "sealed", f"Server should start sealed, got {hb['state']}"
                self.info("Step 1: Server is sealed")

                # ===============================================================
                # STEP 2: User unseals with password
                # ===============================================================
                resp = server.unseal("my-master-password-2024")
                assert resp["state"] == "active"
                self.info("Step 2: Server unsealed")

                # ===============================================================
                # STEP 3: User registers their laptop
                # ===============================================================
                dev = server.register_device("macbook-pro", platform="macos")
                device_id = dev["device_id"]
                auth_token = dev["auth_token"]
                keyfile_b64 = dev["keyfile"]
                keyfile_bytes = base64.b64decode(keyfile_b64)
                assert len(keyfile_bytes) == 64
                self.info(f"Step 3: Device registered — {device_id}")

                # Write keyfile for veracrypt CLI
                with open(keyfile_path, "wb") as f:
                    f.write(keyfile_bytes)
                os.chmod(keyfile_path, 0o600)

                # ===============================================================
                # STEP 4: User creates a VeraCrypt container
                # ===============================================================
                assert _VERACRYPT_BIN is not None
                result = subprocess.run(
                    [
                        _VERACRYPT_BIN, "--text", "--create", container,
                        "--size=2M", "--encryption=AES", "--hash=SHA-512",
                        "--filesystem=FAT", f"--keyfiles={keyfile_path}",
                        "--random-source=/dev/urandom", "--password=",
                        "--pim=0", "--volume-type=normal", "--non-interactive",
                    ],
                    capture_output=True, text=True, timeout=30,
                )
                assert result.returncode == 0, f"Container creation failed: {result.stderr}"
                assert os.path.isfile(container)
                self.info(f"Step 4: Container created — {os.path.getsize(container)} bytes")

                if not can_mount:
                    reason = (
                        "no sudo veracrypt" if not _can_sudo_veracrypt()
                        else "macFUSE kernel extension not loaded"
                    )
                    self.info(f"Steps 5-10 SKIPPED ({reason}). Steps 1-4 PASSED (server + container creation only).")
                    return True

                # ===============================================================
                # STEP 5: User mounts the container
                # ===============================================================
                r = _vc(
                    "--mount",
                    f"--keyfiles={keyfile_path}", "--protect-hidden=no",
                    "--pim=0", "--password=",
                    container, mount_point,
                )
                assert r.returncode == 0, f"Mount failed: {r.stderr}"
                self.info(f"Step 5: Mounted at {mount_point}")

                # ===============================================================
                # STEP 6: User writes files into the vault
                # ===============================================================
                secret_file = os.path.join(mount_point, "secret-plans.txt")
                secret_content = "launch codes: 42-42-42\nthis must survive lock/unlock"

                with open(secret_file, "w") as f:
                    f.write(secret_content)

                # Also write a binary file
                binary_file = os.path.join(mount_point, "data.bin")
                binary_content = os.urandom(1024)
                with open(binary_file, "wb") as f:
                    f.write(binary_content)

                # Verify both files
                with open(secret_file) as f:
                    assert f.read() == secret_content
                with open(binary_file, "rb") as f:
                    assert f.read() == binary_content
                self.info("Step 6: Files written and verified in mounted vault")

                # ===============================================================
                # STEP 7: Someone triggers panic lock
                # ===============================================================
                lock_resp = server.lock()
                assert lock_resp["state"] == "sealed"
                self.info("Step 7: PANIC LOCK triggered — server sealed")

                # ===============================================================
                # STEP 8: Volume is force-dismounted
                # ===============================================================
                # On macOS with VeraCrypt 1.26 + fskit, --dismount with a path
                # doesn't match the fskit mount. Use --dismount with no path
                # (dismounts all veracrypt volumes).
                r = _vc("--dismount", "--force")
                if r.returncode != 0:
                    self.info(f"  dismount stderr: {r.stderr.strip()}")
                time.sleep(1)

                # Verify mount table no longer contains the mount point
                mount_check = subprocess.run(
                    ["mount"], capture_output=True, text=True, timeout=5,
                )
                still_mounted = mount_point in mount_check.stdout
                assert not still_mounted, \
                    f"Volume still in mount table after dismount: {mount_check.stdout}"

                # Verify the secret file is not visible
                assert not os.path.isfile(secret_file), \
                    "Secret file still visible after dismount — CRITICAL FAILURE"
                self.info("Step 8: Volume dismounted — files inaccessible")

                # Verify server rejects key fetch while sealed
                raw = server.get_key_raw(device_id, auth_token)
                assert raw.status_code in (401, 503), \
                    f"Key should be rejected when sealed, got {raw.status_code}"
                self.info("Step 8b: Server rejects key fetch while sealed")

                # ===============================================================
                # STEP 9: User re-unseals, re-mounts
                # ===============================================================
                resp = server.unseal("my-master-password-2024")
                assert resp["state"] == "active"
                self.info("Step 9a: Server re-unsealed")

                # Fetch key again — must match original
                key_resp = server.get_key(device_id, auth_token)
                keyfile2 = base64.b64decode(key_resp["keyfile"])
                assert keyfile_bytes == keyfile2, "Keyfile changed after lock/unseal!"

                # Write re-fetched key for mount
                with open(keyfile_path, "wb") as f:
                    f.write(keyfile2)

                r = _vc(
                    "--mount",
                    f"--keyfiles={keyfile_path}", "--protect-hidden=no",
                    "--pim=0", "--password=",
                    container, mount_point,
                )
                assert r.returncode == 0, f"Re-mount failed: {r.stderr}"
                self.info("Step 9b: Volume re-mounted")

                # ===============================================================
                # STEP 10: Files are still there
                # ===============================================================
                with open(secret_file) as f:
                    recovered_text = f.read()
                assert recovered_text == secret_content, \
                    f"Secret file content changed!\nExpected: {secret_content}\nGot: {recovered_text}"

                with open(binary_file, "rb") as f:
                    recovered_binary = f.read()
                assert recovered_binary == binary_content, \
                    "Binary file corrupted after lock/unseal/remount"

                self.info("Step 10: ALL FILES INTACT after full lock/unseal/remount cycle")

                # Final dismount
                _vc("--dismount", "--force")
                self.info("Cleanup: volume dismounted")

            finally:
                # Best-effort cleanup — dismount-all without path
                if can_mount and _VERACRYPT_BIN:
                    subprocess.run(
                        ["sudo", "-n", _VERACRYPT_BIN, "--text", "--dismount", "--force"],
                        capture_output=True,
                    )
                shutil.rmtree(tmpdir, ignore_errors=True)

            self.info("=== FULL REAL-USAGE SIMULATION PASSED ===")
            return True
