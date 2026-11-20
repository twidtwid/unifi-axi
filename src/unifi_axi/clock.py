"""Time seams. Every caller uses `clock.now_ts()` etc. so tests can replace them."""

import time


def now_ts() -> float:
    return time.time()


def monotonic() -> float:
    return time.monotonic()


def sleep(seconds: float) -> None:
    time.sleep(seconds)
