"""Test admin token authentication."""

import requests
import flexitest

from common.base_test import PicryptTest


@flexitest.register
class TestAdminTokenRequired(PicryptTest):
    """Device management requires admin token."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        server = self.get_server()
        server.ensure_active()
        url = server.props["http_url"]

        r = requests.post(
            f"{url}/devices/register",
            json={"device_name": "rogue", "platform": "linux"},
            timeout=5,
        )
        assert r.status_code == 401, f"Expected 401, got {r.status_code}"
        self.info("Unauthenticated register rejected")

        r = requests.get(f"{url}/devices", timeout=5)
        assert r.status_code == 401, f"Expected 401, got {r.status_code}"
        self.info("Unauthenticated list rejected")

        headers = {"Authorization": f"Bearer {server.props['admin_token']}"}
        r = requests.post(
            f"{url}/devices/register",
            json={"device_name": "legit", "platform": "linux"},
            headers=headers,
            timeout=5,
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        self.info("Authenticated register succeeded")

        r = requests.get(f"{url}/devices", headers=headers, timeout=5)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        assert len(r.json()["devices"]) == 1
        self.info("Authenticated list succeeded")

        return True
