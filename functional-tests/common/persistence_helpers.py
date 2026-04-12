"""Shared helpers for the data-persistence integration tests.

These tests all do roughly the same thing — create a vault with the server's
keyfile, mount it via real veracrypt + sudo, write some content, dismount,
remount, verify. The boilerplate lives here so the individual test files
can stay focused on the specific scenario they're proving.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time

# --------------------------------------------------------------------------- #
# Prerequisite detection
# --------------------------------------------------------------------------- #

VERACRYPT_BIN: str | None = None
if os.path.isfile("/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"):
    VERACRYPT_BIN = "/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"
elif shutil.which("veracrypt"):
    VERACRYPT_BIN = shutil.which("veracrypt")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PICRYPT_CLIENT: str | None = None
for _p in [
    os.path.join(REPO_ROOT, "target", "release", "picrypt-client"),
    os.path.join(REPO_ROOT, "target", "debug", "picrypt-client"),
]:
    if os.path.isfile(_p):
        PICRYPT_CLIENT = _p
        break


def can_sudo_veracrypt() -> bool:
    """True iff we can run veracrypt via sudo without a password."""
    if VERACRYPT_BIN is None:
        return False
    try:
        r = subprocess.run(
            ["sudo", "-n", VERACRYPT_BIN, "--text", "--version"],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def is_mounted(mount_point: str) -> bool:
    """True iff `mount_point` appears in the kernel mount table."""
    try:
        r = subprocess.run(["mount"], capture_output=True, text=True, timeout=5)
        return mount_point in r.stdout
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# VeraCrypt CLI wrappers
# --------------------------------------------------------------------------- #

def vc_create(container: str, size: str, keyfile: str, filesystem: str = "FAT") -> subprocess.CompletedProcess:
    """Create a VeraCrypt container (no sudo needed for create)."""
    assert VERACRYPT_BIN is not None
    return subprocess.run(
        [
            VERACRYPT_BIN, "--text", "--create", container,
            f"--size={size}", "--encryption=AES", "--hash=SHA-512",
            f"--filesystem={filesystem}", f"--keyfiles={keyfile}",
            "--random-source=/dev/urandom", "--password=",
            "--pim=0", "--volume-type=normal", "--non-interactive",
        ],
        capture_output=True, text=True, timeout=180,
    )


def vc_mount(container: str, mount_point: str, keyfile: str) -> subprocess.CompletedProcess:
    """Mount a VeraCrypt container with sudo (kernel mount needs root)."""
    assert VERACRYPT_BIN is not None
    return subprocess.run(
        [
            "sudo", "-n", VERACRYPT_BIN, "--text", "--mount",
            f"--keyfiles={keyfile}", "--protect-hidden=no",
            "--pim=0", "--password=",
            container, mount_point,
        ],
        capture_output=True, text=True, timeout=30,
    )


def vc_dismount_all() -> subprocess.CompletedProcess:
    """Dismount EVERY veracrypt volume.

    Path-based dismount is unreliable on macOS fskit, so we always dismount
    everything between phases. Caller is expected to be running this against
    a test-only host.
    """
    assert VERACRYPT_BIN is not None
    return subprocess.run(
        ["sudo", "-n", VERACRYPT_BIN, "--text", "--dismount", "--force"],
        capture_output=True, text=True, timeout=15,
    )


# --------------------------------------------------------------------------- #
# File I/O helpers
#
# VeraCrypt mounts FAT volumes with a default umask that lets the invoking
# user write — both on macOS via fskit and on Linux via dmsetup. So we can
# use plain Python I/O here. If a future filesystem (ext4, etc.) needs root
# writes, the test will fail loudly with EACCES rather than silently masking
# it with `sudo tee`.
# --------------------------------------------------------------------------- #

def write_to_mount(path: str, content: bytes) -> None:
    """Write `content` to a file inside a mounted volume."""
    with open(path, "wb") as f:
        f.write(content)


def read_from_mount(path: str) -> bytes:
    """Read a file from inside a mounted volume."""
    with open(path, "rb") as f:
        return f.read()


def cp_to_mount(src: str, dst: str) -> None:
    """Copy a (potentially large) file into a mounted volume."""
    import shutil as _sh
    _sh.copyfile(src, dst)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# HTTP server probing
# --------------------------------------------------------------------------- #

def wait_for_server_ready(url: str, timeout: float = 10.0) -> None:
    """Block until `GET {url}/heartbeat` returns 200, or timeout."""
    import requests
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"{url}/heartbeat", timeout=1)
            if r.status_code == 200:
                return
        except (requests.ConnectionError, requests.Timeout):
            pass
        time.sleep(0.2)
    raise TimeoutError(f"server at {url} did not become ready within {timeout}s")
