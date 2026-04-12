"""Test wrong password rejection."""

import flexitest

from common.base_test import PicryptTest


@flexitest.register
class TestWrongPasswordRejected(PicryptTest):
    """Wrong password returns 401 after initialization."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("wrong_pw_test")

    def main(self, ctx: flexitest.RunContext):
        server = self.get_server()
        server.unseal("functional-test-pw")
        server.lock()

        raw = server.unseal_raw("wrong-password")
        assert raw.status_code == 401, f"Expected 401, got {raw.status_code}"
        self.info("Wrong password rejected")

        resp = server.unseal("functional-test-pw")
        assert resp["state"] == "active"
        self.info("Correct password accepted after failure")

        return True
