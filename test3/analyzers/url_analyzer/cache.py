"""TTL Caching engine."""
from __future__ import annotations

import asyncio
import time
from typing import Any

class TTLCache:
    """In-memory TTL cache with async-safe get/set."""

    def __init__(self, ttl_seconds: int) -> None:
        self.ttl_seconds = ttl_seconds
        self._cache: dict[str, tuple[Any, float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Any | None:
        """Get a value from cache if valid."""
        async with self._lock:
            if key in self._cache:
                value, expiry = self._cache[key]
                if time.time() < expiry:
                    return value
                else:
                    del self._cache[key]
        return None

    async def set(self, key: str, value: Any) -> None:
        """Set a value in the cache with the configured TTL."""
        expiry = time.time() + self.ttl_seconds
        async with self._lock:
            self._cache[key] = (value, expiry)

    async def invalidate(self, key: str) -> None:
        """Invalidate a specific key."""
        async with self._lock:
            self._cache.pop(key, None)

    async def clear(self) -> None:
        """Clear the entire cache."""
        async with self._lock:
            self._cache.clear()

# Global singleton
cache = TTLCache(ttl_seconds=3600)
