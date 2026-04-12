"""Base test class for picrypt functional tests."""

from __future__ import annotations

import logging

import flexitest

from .config import ServiceType
from .services.server import PicryptServerService


class PicryptTest(flexitest.Test):
    """Base class for picrypt functional tests."""

    runctx: flexitest.RunContext | None = None

    def premain(self, ctx: flexitest.RunContext):
        self.runctx = ctx

    def get_server(self) -> PicryptServerService:
        assert self.runctx is not None, "premain() must run before get_server()"
        svc = self.runctx.get_service(ServiceType.PicryptServer)
        assert isinstance(svc, PicryptServerService)
        return svc

    def info(self, msg: str):
        logging.getLogger("picrypt.test").info(msg)
