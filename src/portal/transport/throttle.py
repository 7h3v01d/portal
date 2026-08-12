# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Connection admission throttling (Gate 3.1).

Pure and clock-injected so the policy is unit-tested without sockets or real
time; the TLS listener wires it in at connection admission. Three layers:

  - **per-source rate:** new connections per source per sliding window;
  - **per-source concurrency:** simultaneous in-handshake connections per source;
  - **global in-flight cap:** total connections currently handshaking.

Admission covers the pre-auth handshake window — the abusable phase, where an
attacker opens many sockets cheaply. Established connections live independently
(bounded separately by the accept queue). Keys grow only with active sources and
are pruned as windows empty."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable


class SlidingWindowRateLimiter:
    """Allow at most `max_events` per `window_seconds` per key."""

    def __init__(
        self,
        max_events: int,
        window_seconds: float,
        clock: Callable[[], float] | None = None,
        max_tracked_keys: int = 8192,
    ) -> None:
        self._max = max_events
        self._window = window_seconds
        self._clock = clock or time.monotonic
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._max_tracked_keys = max_tracked_keys
        self._last_sweep = self._clock()

    def _sweep(self, now: float) -> None:
        """Drop keys whose window has fully emptied. Bounds memory to sources
        seen within the last window — without this, a stream of distinct source
        keys (a botnet / spoofed IPs) grows the map forever, which would make the
        rate limiter itself a memory-exhaustion vector."""
        cutoff = now - self._window
        dead = []
        for key, q in self._events.items():
            while q and q[0] <= cutoff:
                q.popleft()
            if not q:
                dead.append(key)
        for key in dead:
            del self._events[key]
        self._last_sweep = now

    def allow(self, key: str) -> bool:
        now = self._clock()
        # Sweep on a cadence (at most once per window) and immediately if the map
        # has grown past its bound, so peak and steady-state memory are capped.
        if now - self._last_sweep >= self._window or len(self._events) > self._max_tracked_keys:
            self._sweep(now)

        q = self._events[key]
        cutoff = now - self._window
        while q and q[0] <= cutoff:
            q.popleft()
        if len(q) >= self._max:
            if not q:  # shouldn't happen given the check, but keep the map clean
                del self._events[key]
            return False
        q.append(now)
        return True

    @property
    def tracked_keys(self) -> int:
        return len(self._events)


class ConcurrencyLimiter:
    """Cap concurrent holders per key and globally."""

    def __init__(self, per_key_max: int, global_max: int) -> None:
        self._per_key_max = per_key_max
        self._global_max = global_max
        self._per_key: dict[str, int] = defaultdict(int)
        self._global = 0

    def acquire(self, key: str) -> bool:
        if self._global >= self._global_max:
            return False
        if self._per_key.get(key, 0) >= self._per_key_max:  # .get avoids spurious entries
            return False
        self._per_key[key] += 1
        self._global += 1
        return True

    def release(self, key: str) -> None:
        if self._per_key.get(key, 0) > 0:
            self._per_key[key] -= 1
            self._global -= 1
            if self._per_key[key] == 0:
                del self._per_key[key]  # keep the map small

    @property
    def in_flight(self) -> int:
        return self._global


class Admission:
    """A granted admission slot. `release()` is idempotent and must be called when
    the handshake completes (success or failure)."""

    __slots__ = ("_limiter", "_key", "_released")

    def __init__(self, limiter: ConcurrencyLimiter, key: str) -> None:
        self._limiter = limiter
        self._key = key
        self._released = False

    def release(self) -> None:
        if not self._released:
            self._released = True
            self._limiter.release(self._key)


class ConnectionThrottle:
    def __init__(
        self,
        *,
        per_source_rate: int,
        window_seconds: float,
        per_source_concurrent: int,
        global_in_flight: int,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._rate = SlidingWindowRateLimiter(per_source_rate, window_seconds, clock)
        self._conc = ConcurrencyLimiter(per_source_concurrent, global_in_flight)

    def admit(self, source: str) -> Admission | None:
        """Return an Admission if the connection is allowed, else None (drop it).
        Concurrency is acquired first so a rate token isn't spent on a connection
        that a full concurrency cap would reject anyway."""
        if not self._conc.acquire(source):
            return None
        if not self._rate.allow(source):
            self._conc.release(source)
            return None
        return Admission(self._conc, source)

    @property
    def in_flight(self) -> int:
        return self._conc.in_flight
