"""Postgres data persistence inside a picrypt vault.

The most demanding data-persistence test. Creates a vault, formats it
with a Unix-permissions-aware filesystem, runs `initdb`, starts a
postgres process pointed at the vault, creates a database with a table
and rows, stops postgres, dismounts the vault, re-unseals + remounts,
restarts postgres, queries the rows back, and verifies them exactly.

This answers the load-bearing question: "if I put a real database
data dir into a picrypt vault, will it survive a lock + remount cycle
without losing or corrupting any rows?"

Filesystem strategy:
  Linux:  vault is created with --filesystem=ext4 in a single veracrypt
          call. Postgres can use ext4 directly.
  macOS:  vault is created with --filesystem=none. After mount, veracrypt
          exposes a raw device node (/dev/diskN). We format the raw
          device as APFS with `diskutil eraseDisk APFS`, which auto-
          mounts under /Volumes. Postgres uses the APFS mount.

Skips cleanly when any prereq is missing:
  - VeraCrypt not installed or not sudo-NOPASSWD-callable
  - Postgres binaries (initdb, postgres, pg_ctl, psql) not on PATH
  - macOS: diskutil refuses to format the raw veracrypt device

Each phase is logged so a failed run shows exactly which step regressed.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any

import flexitest

from common.base_test import PicryptTest
from common.persistence_helpers import (
    VERACRYPT_BIN,
    can_sudo_veracrypt,
    is_mounted,
    vc_create,
    vc_dismount_all,
    vc_mount,
)

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Postgres binary detection
# --------------------------------------------------------------------------- #

_PG_BINS: dict[str, str] = {}
for _name in ("initdb", "postgres", "pg_ctl", "psql"):
    _path = shutil.which(_name)
    if _path:
        _PG_BINS[_name] = _path


def _have_postgres() -> bool:
    return all(b in _PG_BINS for b in ("initdb", "postgres", "pg_ctl", "psql"))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _free_port(start: int = 25500, end: int = 25600) -> int:
    """Return a free TCP port in [start, end)."""
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"no free TCP port in [{start}, {end})")


def _run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """subprocess.run wrapper that captures + decodes."""
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


# --- macOS APFS-over-veracrypt path -----------------------------------------

def _vc_mount_no_filesystem(container: str, keyfile: str) -> tuple[bool, str]:
    """Mount a --filesystem=none veracrypt container.

    Returns (ok, output). The mount has no filesystem; the caller must
    discover the device node via _vc_find_device() and format it.
    """
    assert VERACRYPT_BIN is not None
    r = _run(
        [
            "sudo", "-n", VERACRYPT_BIN, "--text", "--mount",
            f"--keyfiles={keyfile}", "--protect-hidden=no",
            "--pim=0", "--password=", "--filesystem=none",
            container,
        ],
        timeout=30,
    )
    return (r.returncode == 0, r.stdout + r.stderr)


def _vc_find_device(container: str) -> str | None:
    """Return the /dev/diskN node veracrypt assigned to a mounted container."""
    assert VERACRYPT_BIN is not None
    r = _run(
        ["sudo", "-n", VERACRYPT_BIN, "--text", "--list", "--verbose"],
        timeout=10,
    )
    if r.returncode != 0:
        return None
    # Verbose output blocks look like:
    #   Slot: 1
    #   Volume: /path/to/container.hc
    #   Virtual Device: /dev/disk5
    #   ...
    blocks = re.split(r"\n\s*\n", r.stdout)
    for block in blocks:
        if container in block:
            m = re.search(r"Virtual Device:\s*(\S+)", block)
            if m:
                return m.group(1)
    return None


def _diskutil_format_apfs(device: str, volume_name: str) -> tuple[bool, str]:
    """Format a raw block device as APFS. Returns (ok, output)."""
    r = _run(
        ["diskutil", "eraseDisk", "APFS", volume_name, device],
        timeout=60,
    )
    return (r.returncode == 0, r.stdout + r.stderr)


def _diskutil_unmount_apfs(volume_name: str) -> None:
    _run(["diskutil", "unmount", f"/Volumes/{volume_name}"], timeout=15)


def _diskutil_mount_apfs(device: str) -> tuple[bool, str]:
    """Re-mount an existing APFS-formatted disk by raw device node.

    `diskutil mount` operates on a single volume; an APFS container has
    a partition scheme + an inner synthesized volume, so we need
    `mountDisk` to mount everything on the disk.
    """
    r = _run(["diskutil", "mountDisk", device], timeout=15)
    return (r.returncode == 0, r.stdout + r.stderr)


# --- Postgres lifecycle helpers ----------------------------------------------

def _pg_init(data_dir: str) -> tuple[bool, str]:
    r = _run(
        [_PG_BINS["initdb"], "-D", data_dir, "--no-locale", "--encoding=UTF8",
         "--auth-local=trust", "--auth-host=trust", "--username=postgres"],
        timeout=120,
    )
    return (r.returncode == 0, r.stdout + r.stderr)


def _pg_start(data_dir: str, port: int, log_file: str, socket_dir: str) -> tuple[bool, str]:
    # -k <dir>: where to put the unix socket
    # -p <port>: TCP port
    # -h "": disable TCP listening (use socket only) — set to "127.0.0.1" if we want TCP
    options = f"-p {port} -k {socket_dir} -h 127.0.0.1"
    r = _run(
        [_PG_BINS["pg_ctl"], "-D", data_dir, "-l", log_file,
         "-o", options, "start", "-w", "-t", "30"],
        timeout=60,
    )
    return (r.returncode == 0, r.stdout + r.stderr)


def _pg_stop(data_dir: str) -> tuple[bool, str]:
    r = _run(
        [_PG_BINS["pg_ctl"], "-D", data_dir, "stop", "-m", "fast", "-w", "-t", "30"],
        timeout=60,
    )
    return (r.returncode == 0, r.stdout + r.stderr)


def _psql(socket_dir: str, port: int, sql: str) -> tuple[bool, str]:
    r = _run(
        [_PG_BINS["psql"], "-h", socket_dir, "-p", str(port),
         "-U", "postgres", "-d", "postgres",
         "-At", "-c", sql],
        timeout=30,
    )
    return (r.returncode == 0, r.stdout + r.stderr)


# --------------------------------------------------------------------------- #
# Test
# --------------------------------------------------------------------------- #

if VERACRYPT_BIN is not None:

    @flexitest.register
    class TestPostgresPersistence(PicryptTest):
        """A real postgres data dir survives a vault dismount + remount cycle."""

        def __init__(self, ctx: flexitest.InitContext):
            ctx.set_env("postgres_persistence")

        def main(self, ctx: flexitest.RunContext):
            assert VERACRYPT_BIN is not None

            if not can_sudo_veracrypt():
                self.info("SKIP: needs passwordless sudo for veracrypt")
                return True

            if not _have_postgres():
                missing = [
                    n for n in ("initdb", "postgres", "pg_ctl", "psql")
                    if n not in _PG_BINS
                ]
                self.info(f"SKIP: postgres not installed (missing: {', '.join(missing)})")
                return True

            self.info(f"postgres binaries: initdb={_PG_BINS['initdb']}")

            server = self.get_server()
            server.unseal("postgres-test-pw")

            dev = server.register_device("postgres-test")
            keyfile_bytes = base64.b64decode(dev["keyfile"])

            tmpdir = tempfile.mkdtemp(prefix="picrypt-pg-")
            container = os.path.join(tmpdir, "vault.hc")
            mount_point = os.path.join(tmpdir, "Vault")
            keyfile_path = os.path.join(tmpdir, "keyfile.bin")
            socket_dir = os.path.join(tmpdir, "pgsock")
            os.makedirs(mount_point, exist_ok=True)
            os.makedirs(socket_dir, exist_ok=True)

            # Path to the data dir inside the mounted vault — populated below
            # depending on platform.
            data_dir: str | None = None
            apfs_volume_name = "PicryptPgVault"
            apfs_device: str | None = None
            postgres_started = False
            port = _free_port()
            self.info(f"selected postgres port: {port}")

            try:
                with open(keyfile_path, "wb") as f:
                    f.write(keyfile_bytes)
                os.chmod(keyfile_path, 0o600)

                # =========================================================
                # PHASE A: create vault + format with a Unix-perm filesystem
                # =========================================================

                if sys.platform == "linux":
                    self.info("phase A: creating ext4 vault (Linux)")
                    r = vc_create(container, "256M", keyfile_path, filesystem="ext4")
                    assert r.returncode == 0, f"vault create failed: {r.stderr}"

                    r = vc_mount(container, mount_point, keyfile_path)
                    assert r.returncode == 0, f"mount failed: {r.stderr}"
                    assert is_mounted(mount_point), "mount not in mount table"
                    self.info(f"phase A: ext4 vault mounted at {mount_point}")

                    # Postgres requires the data dir owner to be the postgres
                    # user. Run all postgres commands as the current user
                    # and chown the dir to ourselves explicitly.
                    data_dir = os.path.join(mount_point, "pgdata")
                    subprocess.run(
                        ["sudo", "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}", mount_point],
                        check=False, timeout=10,
                    )
                    os.makedirs(data_dir, exist_ok=True)
                    os.chmod(data_dir, 0o700)

                elif sys.platform == "darwin":
                    self.info("phase A: creating none-fs vault + APFS format (macOS)")
                    r = vc_create(container, "256M", keyfile_path, filesystem="none")
                    assert r.returncode == 0, f"vault create failed: {r.stderr}"

                    ok, out = _vc_mount_no_filesystem(container, keyfile_path)
                    assert ok, f"vc mount (no fs) failed: {out}"

                    apfs_device = _vc_find_device(container)
                    assert apfs_device, "could not find virtual device for vault"
                    self.info(f"phase A: vault is at {apfs_device}")

                    ok, out = _diskutil_format_apfs(apfs_device, apfs_volume_name)
                    if not ok:
                        self.info(f"SKIP: diskutil eraseDisk failed: {out}")
                        return True
                    self.info(f"phase A: APFS volume formatted as /Volumes/{apfs_volume_name}")

                    apfs_mount = f"/Volumes/{apfs_volume_name}"
                    data_dir = os.path.join(apfs_mount, "pgdata")
                    os.makedirs(data_dir, exist_ok=True)
                    os.chmod(data_dir, 0o700)

                else:
                    self.info(f"SKIP: unsupported platform {sys.platform}")
                    return True

                assert data_dir is not None

                # =========================================================
                # PHASE B: initdb, start postgres, write rows
                # =========================================================

                self.info("phase B: initdb")
                ok, out = _pg_init(data_dir)
                assert ok, f"initdb failed:\n{out}"

                pg_log = os.path.join(tmpdir, "pg.log")
                self.info("phase B: starting postgres")
                ok, out = _pg_start(data_dir, port, pg_log, socket_dir)
                if not ok:
                    log_tail = ""
                    if os.path.exists(pg_log):
                        with open(pg_log) as f:
                            log_tail = f.read()[-2000:]
                    raise AssertionError(f"pg_ctl start failed:\n{out}\nLog:\n{log_tail}")
                postgres_started = True
                self.info(f"phase B: postgres running on port {port}")

                ok, out = _psql(socket_dir, port, "CREATE DATABASE picrypt_test")
                assert ok, f"create database failed: {out}"

                ok, out = _psql(socket_dir, port,
                                "CREATE TABLE picrypt_test_rows (id int primary key, val text)")
                # The CREATE TABLE goes to postgres db, not picrypt_test —
                # use a single-statement form that targets the test db.
                # We'll just use the public schema in postgres db itself
                # for simplicity.
                ok, out = _psql(socket_dir, port,
                                "DROP TABLE IF EXISTS picrypt_test_rows; "
                                "CREATE TABLE picrypt_test_rows (id int primary key, val text)")
                assert ok, f"create table failed: {out}"

                # Insert 100 rows
                self.info("phase B: inserting 100 rows")
                values = ",".join(f"({i}, 'row-content-{i*7}')" for i in range(100))
                ok, out = _psql(socket_dir, port,
                                f"INSERT INTO picrypt_test_rows VALUES {values}")
                assert ok, f"insert failed: {out}"

                # Verify count + sample row
                ok, out = _psql(socket_dir, port,
                                "SELECT count(*) FROM picrypt_test_rows")
                assert ok and out.strip() == "100", f"row count wrong: {out}"

                ok, out = _psql(socket_dir, port,
                                "SELECT val FROM picrypt_test_rows WHERE id = 42")
                assert ok and out.strip() == "row-content-294", f"sample row wrong: {out}"
                self.info("phase B: 100 rows written and verified live")

                # CHECKPOINT to flush WAL → data files (so we know everything
                # is on disk before we dismount)
                ok, out = _psql(socket_dir, port, "CHECKPOINT")
                assert ok, f"CHECKPOINT failed: {out}"
                self.info("phase B: CHECKPOINT issued")

                # =========================================================
                # PHASE C: stop postgres, dismount, server lock
                # =========================================================

                self.info("phase C: stopping postgres")
                ok, out = _pg_stop(data_dir)
                assert ok, f"pg_ctl stop failed: {out}"
                postgres_started = False

                subprocess.run(["sync"], timeout=5)

                if sys.platform == "darwin" and apfs_device:
                    _diskutil_unmount_apfs(apfs_volume_name)
                    time.sleep(0.5)

                vc_dismount_all()
                time.sleep(1)
                self.info("phase C: vault dismounted")

                # Lock the picrypt server too — proves the keystore round-trip.
                server.lock()
                self.info("phase C: picrypt server locked")

                # =========================================================
                # PHASE D: re-unseal, remount, restart postgres
                # =========================================================

                self.info("phase D: re-unsealing picrypt server")
                server.unseal("postgres-test-pw")

                if sys.platform == "linux":
                    r = vc_mount(container, mount_point, keyfile_path)
                    assert r.returncode == 0, f"remount failed: {r.stderr}"
                    self.info("phase D: ext4 vault remounted")
                else:  # darwin
                    ok, out = _vc_mount_no_filesystem(container, keyfile_path)
                    assert ok, f"vc remount (no fs) failed: {out}"
                    new_device = _vc_find_device(container)
                    assert new_device, "could not find device after remount"
                    apfs_device = new_device  # for cleanup
                    ok, out = _diskutil_mount_apfs(new_device)
                    assert ok, f"diskutil mount apfs failed: {out}"
                    self.info(f"phase D: APFS volume remounted at /Volumes/{apfs_volume_name}")

                # On Linux, after dismount + remount, the device node may
                # have changed and the data dir owner needs to be us again
                # for postgres to start. (On ext4 the perms persist, so this
                # is mostly a no-op, but harmless.)
                if sys.platform == "linux":
                    subprocess.run(
                        ["sudo", "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}", mount_point],
                        check=False, timeout=10,
                    )

                self.info("phase D: starting postgres against recovered data dir")
                ok, out = _pg_start(data_dir, port, pg_log, socket_dir)
                if not ok:
                    log_tail = ""
                    if os.path.exists(pg_log):
                        with open(pg_log) as f:
                            log_tail = f.read()[-3000:]
                    raise AssertionError(
                        f"pg_ctl restart failed:\n{out}\nLog:\n{log_tail}"
                    )
                postgres_started = True
                self.info("phase D: postgres restarted")

                # =========================================================
                # PHASE E: verify all rows are exactly as we left them
                # =========================================================

                ok, out = _psql(socket_dir, port,
                                "SELECT count(*) FROM picrypt_test_rows")
                assert ok and out.strip() == "100", \
                    f"row count after recovery: expected 100, got {out!r}"

                # Verify every row exactly
                ok, out = _psql(
                    socket_dir, port,
                    "SELECT id || ',' || val FROM picrypt_test_rows ORDER BY id",
                )
                assert ok, f"select all failed: {out}"
                lines = out.strip().split("\n")
                assert len(lines) == 100, f"expected 100 lines, got {len(lines)}"
                for i, line in enumerate(lines):
                    expected = f"{i},row-content-{i*7}"
                    assert line == expected, \
                        f"row {i} corrupted: expected {expected!r}, got {line!r}"

                self.info("=== POSTGRES DATA INTACT — ALL 100 ROWS VERIFIED ===")

            finally:
                # Best-effort teardown in reverse order
                if postgres_started and data_dir:
                    try:
                        _pg_stop(data_dir)
                    except Exception:
                        pass
                if sys.platform == "darwin":
                    try:
                        _diskutil_unmount_apfs(apfs_volume_name)
                    except Exception:
                        pass
                vc_dismount_all()
                shutil.rmtree(tmpdir, ignore_errors=True)

            return True
