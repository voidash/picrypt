"""Many small/medium files round-trip through a panic-lock + remount cycle.

50 files, sizes from 1 KB to 1 MB, deterministic-random content. Hash each
on write, dismount via panic-lock, re-unseal, remount, hash again. Every
checksum must match.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import random
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
    read_from_mount,
    vc_create,
    vc_dismount_all,
    vc_mount,
    write_to_mount,
)

logger = logging.getLogger(__name__)


if VERACRYPT_BIN is not None:

    @flexitest.register
    class TestDataPersistenceManyFiles(PicryptTest):
        """50 files of varying sizes survive a panic-lock + remount cycle."""

        def __init__(self, ctx: flexitest.InitContext):
            ctx.set_env("data_persistence_many_files")

        def main(self, ctx: flexitest.RunContext):
            assert VERACRYPT_BIN is not None

            if not can_sudo_veracrypt():
                self.info("SKIP: needs passwordless sudo for veracrypt")
                return True

            server = self.get_server()
            server.unseal("many-files-test-pw")

            dev = server.register_device("many-files-test")
            keyfile_bytes = base64.b64decode(dev["keyfile"])

            tmpdir = tempfile.mkdtemp(prefix="picrypt-many-files-")
            container = os.path.join(tmpdir, "vault.hc")
            mount_point = os.path.join(tmpdir, "Vault")
            keyfile_path = os.path.join(tmpdir, "keyfile.bin")
            os.makedirs(mount_point, exist_ok=True)

            try:
                with open(keyfile_path, "wb") as f:
                    f.write(keyfile_bytes)
                os.chmod(keyfile_path, 0o600)

                # 64 MB vault — comfortably holds 50 files up to 1 MB each.
                r = vc_create(container, "64M", keyfile_path)
                assert r.returncode == 0, f"vault create failed: {r.stderr}"
                self.info("vault created (64M)")

                r = vc_mount(container, mount_point, keyfile_path)
                assert r.returncode == 0, f"mount failed: {r.stderr}"
                self.info(f"vault mounted at {mount_point}")

                # Generate 50 files with deterministic-random content.
                rng = random.Random(0xDEADBEEF)
                expected: dict[str, str] = {}
                sizes = [
                    1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072,
                    262144, 524288, 1048576,
                ]
                self.info("writing 50 files...")
                total_bytes = 0
                for i in range(50):
                    name = f"file_{i:03d}.bin"
                    size = sizes[i % len(sizes)]
                    content = bytes(rng.randint(0, 255) for _ in range(size))
                    write_to_mount(os.path.join(mount_point, name), content)
                    expected[name] = hashlib.sha256(content).hexdigest()
                    total_bytes += size

                self.info(f"wrote 50 files, {total_bytes} bytes total")
                subprocess.run(["sync"], timeout=5)

                # Panic-lock + dismount
                server.lock()
                vc_dismount_all()
                time.sleep(1)
                assert not is_mounted(mount_point), "still mounted after dismount"
                self.info("dismounted via panic-lock")

                # Re-unseal + remount
                server.unseal("many-files-test-pw")
                r = vc_mount(container, mount_point, keyfile_path)
                assert r.returncode == 0, f"remount failed: {r.stderr}"
                self.info("re-unsealed + remounted")

                # Verify every checksum
                self.info("verifying 50 file checksums...")
                mismatches: list[str] = []
                for name, expected_sha in expected.items():
                    file_path = os.path.join(mount_point, name)
                    if not os.path.isfile(file_path):
                        mismatches.append(f"{name}: MISSING")
                        continue
                    content = read_from_mount(file_path)
                    actual = hashlib.sha256(content).hexdigest()
                    if actual != expected_sha:
                        mismatches.append(
                            f"{name}: expected {expected_sha[:16]}..., got {actual[:16]}..."
                        )

                if mismatches:
                    raise AssertionError(
                        f"{len(mismatches)} of 50 files corrupted/missing:\n  "
                        + "\n  ".join(mismatches[:10])
                    )

                self.info("=== ALL 50 FILES INTACT ===")

            finally:
                vc_dismount_all()
                shutil.rmtree(tmpdir, ignore_errors=True)

            return True
