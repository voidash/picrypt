"""Test device revocation."""

import flexitest

from common.base_test import PicryptTest


@flexitest.register
class TestDeviceRevocation(PicryptTest):
    """Revoked device cannot access keys; other devices unaffected."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        server = self.get_server()
        server.ensure_active()

        # Register two devices
        dev_a = server.register_device("device-a")
        dev_b = server.register_device("device-b")

        # Both can get keys
        assert server.get_key(dev_a["device_id"], dev_a["auth_token"])
        assert server.get_key(dev_b["device_id"], dev_b["auth_token"])
        self.info("Both devices can access keys")

        # Revoke device A
        server.revoke_device(dev_a["device_id"])
        self.info("Device A revoked")

        # Device A can no longer get key
        raw = server.get_key_raw(dev_a["device_id"], dev_a["auth_token"])
        assert raw.status_code == 401, f"Revoked device got {raw.status_code}"
        self.info("Revoked device rejected")

        # Device B still works
        key_b = server.get_key(dev_b["device_id"], dev_b["auth_token"])
        assert key_b["keyfile"] == dev_b["keyfile"]
        self.info("Non-revoked device still works")

        return True
