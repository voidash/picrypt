"""Single ~50 MB file round-trips through a panic-lock + remount cycle.

Generates a 50 MB file with deterministic-pseudo-random content (so partial
corruption is detectable, not just a fill of zeros), copies it into a vault,
locks the server, dismounts, re-unseals, remounts, and verifies the SHA256
of the recovered file matches.
"""

from __future__ import annotations

import base64
import logging
import os
import shutil
import subprocess
import tempfile
import time

import flexitest

from common.base_test import PicryptTest
from common.persistence_helpers import (
    VERACRYPT_BIN,
    can_sudo_veracrypt,
    is_mounted,
    sha256_file,
    cp_to_mount,
    vc_create,
    vc_dismount_all,
    vc_mount,
)

logger = logging.getLogger(__name__)


if VERACRYPT_BIN is not None:

    @flexitest.register
    class TestDataPersistenceLargeFile(PicryptTest):
        """A 50 MB file survives a panic-lock + remount cycle."""

        def __init__(self, ctx: flexitest.InitContext):
            ctx.set_env("data_persistence_large_file")

        def main(self, ctx: flexitest.RunContext):
            assert VERACRYPT_BIN is not None

            if not can_sudo_veracrypt():
                self.info("SKIP: needs passwordless sudo for veracrypt")
                return True

            server = self.get_server()
            server.unseal("large-file-test-pw")

            dev = server.register_device("large-file-test")
            keyfile_bytes = base64.b64decode(dev["keyfile"])

            tmpdir = tempfile.mkdtemp(prefix="picrypt-large-file-")
            container = os.path.join(tmpdir, "vault.hc")
            mount_point = os.path.join(tmpdir, "Vault")
            keyfile_path = os.path.join(tmpdir, "keyfile.bin")
            large_file_src = os.path.join(tmpdir, "src.bin")
            os.makedirs(mount_point, exist_ok=True)

            try:
                with open(keyfile_path, "wb") as f:
                    f.write(keyfile_bytes)
                os.chmod(keyfile_path, 0o600)

                # Generate 50 MB of pseudo-random bytes deterministically.
                # Uses os.urandom — much faster than a Python random.Random
                # loop and we don't need reproducibility, only checksum match.
                self.info("generating 50MB source file...")
                payload_size = 50 * 1024 * 1024
                with open(large_file_src, "wb") as f:
                    remaining = payload_size
                    while remaining > 0:
                        chunk = min(1024 * 1024, remaining)
                        f.write(os.urandom(chunk))
                        remaining -= chunk
                expected_sha = sha256_file(large_file_src)
                self.info(f"source sha256={expected_sha[:16]}...")

                # 80 MB vault — fits the 50 MB payload comfortably.
                r = vc_create(container, "80M", keyfile_path)
                assert r.returncode == 0, f"vault create failed: {r.stderr}"

                r = vc_mount(container, mount_point, keyfile_path)
                assert r.returncode == 0, f"mount failed: {r.stderr}"
                self.info("vault mounted")

                # Copy the large file in via sudo cp (avoids piping 50MB
                # through Python+`tee`).
                dst = os.path.join(mount_point, "large.bin")
                cp_to_mount(large_file_src, dst)
                subprocess.run(["sync"], timeout=10)
                self.info("wrote 50MB into vault")

                # Dismount + remount cycle
                server.lock()
                vc_dismount_all()
                time.sleep(1)
                assert not is_mounted(mount_point), "still mounted after dismount"

                server.unseal("large-file-test-pw")
                r = vc_mount(container, mount_point, keyfile_path)
                assert r.returncode == 0, f"remount failed: {r.stderr}"
                self.info("remounted")

                # Hash the recovered file directly from the mount —
                # sha256_file streams in 1 MB chunks so memory stays small.
                actual_sha = sha256_file(dst)
                actual_size = os.path.getsize(dst)
                assert actual_size == payload_size, \
                    f"size mismatch: {actual_size} vs {payload_size}"
                assert actual_sha == expected_sha, \
                    f"sha256 mismatch:\n  expected: {expected_sha}\n  got:      {actual_sha}"

                self.info(f"=== 50MB FILE INTACT (sha256={actual_sha[:16]}...) ===")

            finally:
                vc_dismount_all()
                shutil.rmtree(tmpdir, ignore_errors=True)

            return True
