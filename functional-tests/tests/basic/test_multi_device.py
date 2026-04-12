"""Test multi-device isolation."""

import flexitest

from common.base_test import PicryptTest


@flexitest.register
class TestMultiDeviceIsolation(PicryptTest):
    """Register multiple devices, verify key isolation."""

    def __init__(self, ctx: flexitest.InitContext):
        ctx.set_env("basic")

    def main(self, ctx: flexitest.RunContext):
        server = self.get_server()
        server.ensure_active()

        devices = []
        for i in range(3):
            dev = server.register_device(f"device-{i}")
            devices.append(dev)

        for i, dev in enumerate(devices):
            key = server.get_key(dev["device_id"], dev["auth_token"])
            assert key["keyfile"] == dev["keyfile"], f"Device {i} keyfile mismatch"

        raw = server.get_key_raw(devices[1]["device_id"], devices[0]["auth_token"])
        assert raw.status_code == 401, "Cross-device key access should fail"

        keyfiles = [d["keyfile"] for d in devices]
        assert len(set(keyfiles)) == 3, "All keyfiles must be unique"

        self.info("3 devices registered with proper isolation")
        return True
