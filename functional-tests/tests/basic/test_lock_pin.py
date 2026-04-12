"""Test lock PIN enforcement."""

import flexitest

from common.base_test import PicryptTest


@flexitest.register
class TestLockPinEnforcement(PicryptTest):
    """Lock PIN must be correct to lock the server."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic_with_pin")

    def main(self, ctx: flexitest.RunContext):
        server = self.get_server()
        server.ensure_active()
        url = server.props["http_url"]

        # No PIN → 401
        import requests
        r = requests.post(f"{url}/lock", json={}, timeout=5)
        assert r.status_code == 401, f"No-PIN lock: expected 401, got {r.status_code}"
        self.info("Lock without PIN rejected")

        # Wrong PIN → 401
        r = requests.post(f"{url}/lock", json={"pin": "000000"}, timeout=5)
        assert r.status_code == 401, f"Wrong-PIN lock: expected 401, got {r.status_code}"
        self.info("Wrong PIN rejected")

        # Correct PIN → success
        resp = server.lock(pin="123456")
        assert resp["state"] == "sealed"
        self.info("Correct PIN accepted, server sealed")

        return True
