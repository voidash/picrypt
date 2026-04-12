"""PicryptServer service wrapper for flexitest."""

from __future__ import annotations

import base64
import os
import time
from typing import Any, TypedDict

import flexitest
import requests


class PicryptServerProps(TypedDict):
    http_port: int
    http_url: str
    datadir: str
    admin_token: str
    lock_pin: str | None


class PicryptServerService(flexitest.service.ProcService):
    """Wraps a running picrypt-server process with HTTP client helpers."""

    props: PicryptServerProps

    def __init__(
        self,
        props: PicryptServerProps,
        cmd: list[str],
        stdout: str | None = None,
    ):
        super().__init__(dict(props), cmd, stdout)

    def ensure_active(self, password: str = "functional-test-pw") -> None:
        """Ensure the server is active — unseal if sealed."""
        hb = self.heartbeat()
        if hb["state"] != "active":
            self.unseal(password)

    def wait_for_ready(self, timeout: int = 10) -> None:
        """Poll /heartbeat until the server responds."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                r = requests.get(f"{self.props['http_url']}/heartbeat", timeout=2)
                if r.status_code == 200:
                    return
            except requests.ConnectionError:
                pass
            time.sleep(0.2)
        raise TimeoutError(f"picrypt-server did not become ready within {timeout}s")

    # ------------------------------------------------------------------
    # HTTP API helpers
    # ------------------------------------------------------------------

    def heartbeat(self) -> dict[str, Any]:
        r = requests.get(f"{self.props['http_url']}/heartbeat", timeout=5)
        r.raise_for_status()
        return r.json()

    def unseal(self, password: str) -> dict[str, Any]:
        r = requests.post(
            f"{self.props['http_url']}/unseal",
            json={"password": password},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def lock(self, pin: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if pin is not None:
            body["pin"] = pin
        r = requests.post(
            f"{self.props['http_url']}/lock",
            json=body,
            timeout=5,
        )
        r.raise_for_status()
        return r.json()

    def register_device(self, name: str, platform: str = "linux") -> dict[str, Any]:
        r = requests.post(
            f"{self.props['http_url']}/devices/register",
            json={"device_name": name, "platform": platform},
            headers={"Authorization": f"Bearer {self.props['admin_token']}"},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()

    def get_key(self, device_id: str, auth_token: str) -> dict[str, Any]:
        r = requests.get(
            f"{self.props['http_url']}/key/{device_id}",
            headers={"Authorization": f"Bearer {auth_token}"},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()

    def get_key_raw(self, device_id: str, auth_token: str) -> requests.Response:
        """Return the raw Response (for checking status codes on failure)."""
        return requests.get(
            f"{self.props['http_url']}/key/{device_id}",
            headers={"Authorization": f"Bearer {auth_token}"},
            timeout=5,
        )

    def list_devices(self) -> dict[str, Any]:
        r = requests.get(
            f"{self.props['http_url']}/devices",
            headers={"Authorization": f"Bearer {self.props['admin_token']}"},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()

    def revoke_device(self, device_id: str) -> dict[str, Any]:
        r = requests.post(
            f"{self.props['http_url']}/devices/{device_id}/revoke",
            headers={"Authorization": f"Bearer {self.props['admin_token']}"},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()

    def unseal_raw(self, password: str) -> requests.Response:
        """Return raw Response for status code checks."""
        return requests.post(
            f"{self.props['http_url']}/unseal",
            json={"password": password},
            timeout=30,
        )
