"""Test VeraCrypt container operations.

TestVeraCryptContainerCreation: No root needed — tests create container with server keyfile.
"""

from __future__ import annotations

import base64
import logging
import os
import shutil
import subprocess
import tempfile

import flexitest

from common.base_test import PicryptTest

logger = logging.getLogger(__name__)

# Detect VeraCrypt binary
_VERACRYPT_BIN: str | None = None
if os.path.isfile("/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"):
    _VERACRYPT_BIN = "/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"
elif shutil.which("veracrypt"):
    _VERACRYPT_BIN = shutil.which("veracrypt")

if _VERACRYPT_BIN is None:
    logger.warning("VeraCrypt not installed — no VeraCrypt tests registered.")
else:
    _VC = _VERACRYPT_BIN

    @flexitest.register
    class TestVeraCryptContainerCreation(PicryptTest):
        """Create a VeraCrypt container using a server-managed keyfile.

        Does NOT require root — container creation is a userspace file operation.
        Validates the full flow: server unseal → register → get keyfile → veracrypt --create.
        """

        def __init__(self, ctx: flexitest.InitContext):
            ctx.set_env("veracrypt_test")

        def main(self, ctx: flexitest.RunContext):
            server = self.get_server()
            server.unseal("functional-test-pw")

            # Register a device and get its keyfile
            dev = server.register_device("vc-create-test")
            keyfile_bytes = base64.b64decode(dev["keyfile"])
            assert len(keyfile_bytes) == 64, f"Expected 64-byte keyfile, got {len(keyfile_bytes)}"

            tmpdir = tempfile.mkdtemp(prefix="picrypt-vc-create-")
            container = os.path.join(tmpdir, "test.hc")
            keyfile_path = os.path.join(tmpdir, "keyfile.bin")

            try:
                # Write keyfile to temp file
                with open(keyfile_path, "wb") as f:
                    f.write(keyfile_bytes)
                os.chmod(keyfile_path, 0o600)

                # Create 1MB container (small, fast)
                self.info("Creating 1MB VeraCrypt container...")
                result = subprocess.run(
                    [
                        _VC, "--text", "--create", container,
                        "--size=1M", "--encryption=AES", "--hash=SHA-512",
                        "--filesystem=FAT", f"--keyfiles={keyfile_path}",
                        "--random-source=/dev/urandom", "--password=",
                        "--pim=0", "--volume-type=normal", "--non-interactive",
                    ],
                    capture_output=True, text=True, timeout=30,
                )

                if result.returncode != 0:
                    self.info(f"stdout: {result.stdout}")
                    self.info(f"stderr: {result.stderr}")
                    raise AssertionError(f"veracrypt --create failed with exit {result.returncode}")

                # Verify container file exists and has correct size
                assert os.path.isfile(container), "Container file not created"
                size = os.path.getsize(container)
                assert size == 1048576, f"Expected 1MB container, got {size} bytes"
                self.info(f"Container created: {size} bytes")

                # Verify container is not all zeros (actually encrypted)
                with open(container, "rb") as f:
                    header = f.read(512)
                assert header != b"\x00" * 512, "Container header is all zeros — not encrypted"
                self.info("Container header contains encrypted data")

                # Lock server, re-unseal, fetch key again — verify it matches
                server.lock()
                server.unseal("functional-test-pw")
                key2 = server.get_key(dev["device_id"], dev["auth_token"])
                keyfile2 = base64.b64decode(key2["keyfile"])
                assert keyfile_bytes == keyfile2, "Keyfile changed after lock/unseal"
                self.info("Keyfile survived lock/unseal — container can be re-mounted with same key")

            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)

            return True
