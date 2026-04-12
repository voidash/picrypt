"""Test the complete server lifecycle: unseal → register → key → lock → re-unseal."""

import flexitest

from common.base_test import PicryptTest


@flexitest.register
class TestServerLifecycle(PicryptTest):
    """Full server lifecycle through a single lock/unseal cycle."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("lifecycle_test")

    def main(self, ctx: flexitest.RunContext):
        server = self.get_server()

        # 1. Server starts sealed
        hb = server.heartbeat()
        assert hb["state"] == "sealed", f"Expected sealed, got {hb['state']}"

        # 2. Unseal
        resp = server.unseal("functional-test-pw")
        assert resp["state"] == "active"
        self.info("Server unsealed")

        # 3. Register device
        dev = server.register_device("lifecycle-device")
        device_id = dev["device_id"]
        auth_token = dev["auth_token"]
        keyfile = dev["keyfile"]
        assert device_id
        assert auth_token
        assert keyfile
        self.info(f"Registered device: {device_id}")

        # 4. Fetch key — must match
        key_resp = server.get_key(device_id, auth_token)
        assert key_resp["keyfile"] == keyfile, "Keyfile mismatch after registration"

        # 5. Lock
        lock_resp = server.lock()
        assert lock_resp["state"] == "sealed"
        self.info("Server locked")

        # 6. Key should fail when sealed
        raw = server.get_key_raw(device_id, auth_token)
        assert raw.status_code in (401, 503), f"Expected 401/503, got {raw.status_code}"

        # 7. Re-unseal with same password
        resp = server.unseal("functional-test-pw")
        assert resp["state"] == "active"

        # 8. Key should still work and match
        key_resp2 = server.get_key(device_id, auth_token)
        assert key_resp2["keyfile"] == keyfile, "Keyfile changed after lock/unseal cycle"
        self.info("Keyfile survived lock/unseal")

        return True
