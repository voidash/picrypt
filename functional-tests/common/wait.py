"""Polling/wait utilities."""

from __future__ import annotations

import time
from typing import Callable, TypeVar

T = TypeVar("T")


def wait_until(
    fn: Callable[[], bool],
    error_with: str = "Timed out",
    timeout: int = 30,
    step: float = 0.5,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if fn():
                return
        except Exception:
            pass
        time.sleep(step)
    raise AssertionError(error_with)


def wait_until_with_value(
    fn: Callable[[], T],
    predicate: Callable[[T], bool],
    error_with: str = "Timed out",
    timeout: int = 30,
    step: float = 0.5,
) -> T:
    deadline = time.monotonic() + timeout
    last_value = None
    while time.monotonic() < deadline:
        try:
            last_value = fn()
            if predicate(last_value):
                return last_value
        except Exception:
            pass
        time.sleep(step)
    raise AssertionError(f"{error_with} (last value: {last_value})")
