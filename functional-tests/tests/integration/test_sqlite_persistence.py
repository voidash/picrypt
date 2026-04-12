"""SQLite database persistence inside a picrypt vault.

SQLite is the natural opposite of postgres: a single .db file, no daemon,
no Unix-permissions requirement. The test is small but valuable because
SQLite makes specific guarantees about atomic commits via its journal/WAL,
and we want to make sure those guarantees hold across a vault dismount +
remount cycle.

Flow:
  1. Create a vault (FAT — works on both Linux and macOS)
  2. Mount via veracrypt + sudo
  3. Open sqlite3 db inside the vault, create schema, insert 500 rows
     across two tables, COMMIT, close
  4. Panic-lock + dismount
  5. Re-unseal + remount
  6. Re-open the db, verify every row in both tables
  7. Insert one more row to prove the db is still writable after recovery
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time

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


if VERACRYPT_BIN is not None:

    @flexitest.register
    class TestSqlitePersistence(PicryptTest):
        """A real SQLite database survives a vault dismount + remount cycle."""

        def __init__(self, ctx: flexitest.InitContext):
            ctx.set_env("sqlite_persistence")

        def main(self, ctx: flexitest.RunContext):
            assert VERACRYPT_BIN is not None

            if not can_sudo_veracrypt():
                self.info("SKIP: needs passwordless sudo for veracrypt")
                return True

            server = self.get_server()
            server.unseal("sqlite-test-pw")

            dev = server.register_device("sqlite-test")
            keyfile_bytes = base64.b64decode(dev["keyfile"])

            tmpdir = tempfile.mkdtemp(prefix="picrypt-sqlite-")
            container = os.path.join(tmpdir, "vault.hc")
            mount_point = os.path.join(tmpdir, "Vault")
            keyfile_path = os.path.join(tmpdir, "keyfile.bin")
            os.makedirs(mount_point, exist_ok=True)

            try:
                with open(keyfile_path, "wb") as f:
                    f.write(keyfile_bytes)
                os.chmod(keyfile_path, 0o600)

                # 16 MB vault — comfortably holds the test schema + 500 rows.
                r = vc_create(container, "16M", keyfile_path)
                assert r.returncode == 0, f"vault create failed: {r.stderr}"
                self.info("vault created (16M)")

                r = vc_mount(container, mount_point, keyfile_path)
                assert r.returncode == 0, f"mount failed: {r.stderr}"
                self.info(f"vault mounted at {mount_point}")

                db_path = os.path.join(mount_point, "data.db")

                # ----------------------------------------------------------
                # PHASE A: write schema + 500 rows
                # ----------------------------------------------------------
                self.info("phase A: opening sqlite + writing schema")
                con = sqlite3.connect(db_path)
                cur = con.cursor()
                cur.executescript("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        created_at REAL NOT NULL
                    );
                    CREATE TABLE notes (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        body BLOB NOT NULL,
                        body_sha256 TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    );
                    CREATE INDEX notes_by_user ON notes(user_id);
                """)

                now = time.time()
                users = [
                    (i, f"user-{i:03d}", f"user{i:03d}@example.test", now + i)
                    for i in range(50)
                ]
                cur.executemany(
                    "INSERT INTO users (id, name, email, created_at) VALUES (?, ?, ?, ?)",
                    users,
                )

                # 10 notes per user → 500 total. Use binary BLOB content with
                # checksum so we can detect any byte-level corruption.
                notes_expected: dict[int, str] = {}  # note_id -> sha256
                notes: list[tuple[int, int, bytes, str]] = []
                for note_id in range(500):
                    user_id = note_id // 10
                    body = (f"note-{note_id}-body-".encode()
                            + os.urandom(64)
                            + f"-end-{note_id}".encode())
                    sha = hashlib.sha256(body).hexdigest()
                    notes.append((note_id, user_id, body, sha))
                    notes_expected[note_id] = sha

                cur.executemany(
                    "INSERT INTO notes (id, user_id, body, body_sha256) VALUES (?, ?, ?, ?)",
                    notes,
                )
                con.commit()
                con.close()
                self.info(f"phase A: wrote 50 users + 500 notes ({len(notes_expected)} sha256s recorded)")

                # ----------------------------------------------------------
                # PHASE B: panic-lock + dismount
                # ----------------------------------------------------------
                subprocess.run(["sync"], timeout=5)
                server.lock()
                vc_dismount_all()
                time.sleep(1)
                assert not is_mounted(mount_point), "still mounted after dismount"
                self.info("phase B: dismounted via panic-lock")

                # ----------------------------------------------------------
                # PHASE C: re-unseal + remount + re-open db
                # ----------------------------------------------------------
                server.unseal("sqlite-test-pw")
                r = vc_mount(container, mount_point, keyfile_path)
                assert r.returncode == 0, f"remount failed: {r.stderr}"
                self.info("phase C: re-unsealed + remounted")

                con = sqlite3.connect(db_path)
                cur = con.cursor()

                # Integrity check — sqlite's built-in scan for corrupt pages
                cur.execute("PRAGMA integrity_check")
                integrity = cur.fetchall()
                assert integrity == [("ok",)], \
                    f"sqlite integrity_check failed: {integrity}"
                self.info("phase C: PRAGMA integrity_check = ok")

                # ----------------------------------------------------------
                # PHASE D: verify every row
                # ----------------------------------------------------------
                cur.execute("SELECT COUNT(*) FROM users")
                user_count = cur.fetchone()[0]
                assert user_count == 50, f"user count: expected 50, got {user_count}"

                cur.execute("SELECT COUNT(*) FROM notes")
                note_count = cur.fetchone()[0]
                assert note_count == 500, f"note count: expected 500, got {note_count}"

                # Verify every note's checksum matches what we stored
                cur.execute("SELECT id, body, body_sha256 FROM notes ORDER BY id")
                mismatches: list[str] = []
                for row in cur.fetchall():
                    note_id, body, stored_sha = row
                    actual_sha = hashlib.sha256(body).hexdigest()
                    if actual_sha != stored_sha:
                        mismatches.append(
                            f"note {note_id}: body hash {actual_sha[:16]}... "
                            f"vs stored {stored_sha[:16]}..."
                        )
                    if note_id not in notes_expected:
                        mismatches.append(f"note {note_id}: not in expected set")
                    elif notes_expected[note_id] != stored_sha:
                        mismatches.append(
                            f"note {note_id}: stored hash drifted from original"
                        )

                if mismatches:
                    raise AssertionError(
                        f"{len(mismatches)} of 500 notes corrupted:\n  "
                        + "\n  ".join(mismatches[:10])
                    )
                self.info("phase D: all 50 users + 500 notes intact (every BLOB sha256 matches)")

                # ----------------------------------------------------------
                # PHASE E: prove the db is still writable after recovery
                # ----------------------------------------------------------
                cur.execute(
                    "INSERT INTO users (id, name, email, created_at) VALUES (?, ?, ?, ?)",
                    (9999, "post-recovery", "post@example.test", time.time()),
                )
                con.commit()
                cur.execute("SELECT name FROM users WHERE id = 9999")
                assert cur.fetchone() == ("post-recovery",), \
                    "post-recovery insert did not round-trip"
                con.close()
                self.info("phase E: db is writable after recovery")

                self.info("=== SQLITE DB INTACT — 50 users + 500 notes verified, db still writable ===")

            finally:
                vc_dismount_all()
                shutil.rmtree(tmpdir, ignore_errors=True)

            return True
