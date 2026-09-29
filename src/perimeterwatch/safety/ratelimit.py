"""Per-host async token buckets, so no single service gets hammered."""

from __future__ import annotations

import asyncio
import time


class _Bucket:
    def __init__(self, rate: float, burst: float) -> None:
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.burst, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep((1 - self.tokens) / self.rate)


class RateLimiter:
    def __init__(self, default_rps: float = 2.0) -> None:
        self.default_rps = default_rps
        self._buckets: dict[str, _Bucket] = {}
        self._overrides: dict[str, tuple[float, float]] = {}

    def set_limit(self, host: str, rps: float, burst: float = 1.0) -> None:
        self._overrides[host] = (rps, burst)
        self._buckets.pop(host, None)

    async def acquire(self, host: str) -> None:
        bucket = self._buckets.get(host)
        if bucket is None:
            rate, burst = self._overrides.get(host, (self.default_rps, max(1.0, self.default_rps)))
            bucket = self._buckets[host] = _Bucket(rate, burst)
        await bucket.acquire()
