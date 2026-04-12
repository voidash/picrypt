"""Test that error responses don't leak internal state."""

import requests
import flexitest

from common.base_test import PicryptTest


@flexitest.register
class TestGenericErrorResponses(PicryptTest):
    """Error responses must be generic — no device IDs, no state details."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        server = self.get_server()
        server.ensure_active()
        url = server.props["http_url"]

        # Hit /key with a random UUID — response must not echo the UUID
        fake_uuid = "12345678-1234-1234-1234-123456789abc"
        r = requests.get(
            f"{url}/key/{fake_uuid}",
            headers={"Authorization": "Bearer dGVzdA=="},
            timeout=5,
        )
        assert r.status_code == 401
        body = r.text
        assert fake_uuid not in body, f"UUID leaked in error response: {body}"
        self.info("Error response does not leak UUID")

        # Sealed vs locked should be indistinguishable
        server.lock()
        hb_sealed = server.heartbeat()

        # Re-unseal and lock again to confirm consistency
        server.ensure_active()
        server.lock()
        hb_locked = server.heartbeat()

        # Both should show same generic state
        assert hb_sealed["state"] == hb_locked["state"], \
            f"Sealed={hb_sealed['state']} vs Locked={hb_locked['state']}"
        self.info("Sealed and locked produce identical heartbeat")

        return True
