"""Basic environment: single picrypt-server."""

from __future__ import annotations

from typing import cast

import flexitest

from common.config import ServiceType
from factories.server import PicryptServerFactory


class BasicEnv(flexitest.EnvConfig):
    """One picrypt-server instance, unsealed and ready."""

    def __init__(self, lock_pin: str | None = None):
        self._lock_pin = lock_pin

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        factory = cast(PicryptServerFactory, ectx.get_factory(ServiceType.PicryptServer))
        server = factory.create(lock_pin=self._lock_pin)
        return flexitest.LiveEnv({ServiceType.PicryptServer: server})


class BasicEnvWithPin(flexitest.EnvConfig):
    """One picrypt-server with a lock PIN configured."""

    def init(self, ectx: flexitest.EnvContext) -> flexitest.LiveEnv:
        factory = cast(PicryptServerFactory, ectx.get_factory(ServiceType.PicryptServer))
        server = factory.create(lock_pin="123456")
        return flexitest.LiveEnv({ServiceType.PicryptServer: server})
