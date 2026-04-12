"""Factory for picrypt-server instances."""

from __future__ import annotations

import base64
import os
import secrets

import flexitest

from common.services.server import PicryptServerProps, PicryptServerService


class PicryptServerFactory(flexitest.Factory):
    """Creates picrypt-server instances with isolated data directories."""

    def __init__(self, port_range: range, binary_path: str | None = None):
        ports = list(port_range)
        super().__init__(ports)
        # Find the binary
        if binary_path and os.path.isfile(binary_path):
            self._binary = binary_path
        else:
            # Try common locations
            repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            candidates = [
                os.path.join(repo_root, "target", "release", "picrypt-server"),
                os.path.join(repo_root, "target", "debug", "picrypt-server"),
            ]
            self._binary = next((c for c in candidates if os.path.isfile(c)), "picrypt-server")

    @flexitest.with_ectx("ctx")
    def create(
        self,
        lock_pin: str | None = None,
        **kwargs,
    ) -> PicryptServerService:
        ctx: flexitest.EnvContext = kwargs["ctx"]

        datadir = ctx.make_service_dir("picrypt_server")
        http_port = self.next_port()
        logfile = os.path.join(datadir, "server.log")

        # Generate admin token
        admin_token = base64.b64encode(secrets.token_bytes(32)).decode()

        # Server reads config from $HOME/.picrypt/server.toml
        picrypt_dir = os.path.join(datadir, ".picrypt")
        data_dir = os.path.join(picrypt_dir, "data")
        devices_dir = os.path.join(data_dir, "devices")
        os.makedirs(devices_dir, exist_ok=True)

        config_path = os.path.join(picrypt_dir, "server.toml")
        config_content = f"""\
listen_addr = "127.0.0.1:{http_port}"
data_dir = "{data_dir}"
dead_man_timeout_secs = 0
admin_token = "{admin_token}"
"""
        if lock_pin:
            config_content += f'lock_pin = "{lock_pin}"\n'

        with open(config_path, "w") as f:
            f.write(config_content)
        os.chmod(config_path, 0o600)

        # Build command — use env to set HOME so server reads config from datadir
        rust_log = os.environ.get("RUST_LOG", "info")
        cmd = ["/usr/bin/env", f"HOME={datadir}", f"RUST_LOG={rust_log}", self._binary]

        props: PicryptServerProps = {
            "http_port": http_port,
            "http_url": f"http://127.0.0.1:{http_port}",
            "datadir": datadir,
            "admin_token": admin_token,
            "lock_pin": lock_pin,
        }

        svc = PicryptServerService(props, cmd, stdout=logfile)
        try:
            svc.start()
            svc.wait_for_ready(timeout=10)
        except Exception as e:
            try:
                svc.stop()
            except Exception:
                pass
            raise RuntimeError(f"Failed to start picrypt-server: {e}") from e

        return svc
