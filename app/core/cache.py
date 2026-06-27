"""Simple in-memory TTL cache for OSINT API responses."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class TTLCache(Generic[T]):
    """Thread-safe async TTL cache to reduce OSINT API rate-limit hits."""

    def __init__(self, ttl_seconds: int = 3600, max_entries: int = 10_000) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._store: dict[str, tuple[float, T]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> T | None:
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            return value

    async def set(self, key: str, value: T) -> None:
        async with self._lock:
            if len(self._store) >= self._max_entries:
                self._evict_oldest()
            self._store[key] = (time.monotonic() + self._ttl, value)

    def _evict_oldest(self) -> None:
        if not self._store:
            return
        oldest_key = min(self._store, key=lambda k: self._store[k][0])
        del self._store[oldest_key]


# Shared cache instance; TTL configured at startup in main.py lifespan.
osint_cache: TTLCache[dict[str, Any]] = TTLCache()
