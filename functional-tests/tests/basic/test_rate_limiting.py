"""Test unseal rate limiting."""

import flexitest

from common.base_test import PicryptTest


@flexitest.register
class TestRateLimiting(PicryptTest):
    """Failed unseal attempts trigger rate limiting."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("rate_limit_test")

    def main(self, ctx: flexitest.RunContext):
        server = self.get_server()
        server.unseal("functional-test-pw")
        server.lock()

        for i in range(5):
            raw = server.unseal_raw(f"wrong-{i}")
            assert raw.status_code == 401, f"Attempt {i}: expected 401, got {raw.status_code}"

        raw = server.unseal_raw("still-wrong")
        assert raw.status_code == 500, f"Expected 500 (rate limit), got {raw.status_code}"
        self.info(f"Rate limit triggered after 6 failures (HTTP {raw.status_code})")

        return True
