# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Frame pacing — the FPS limiter, kept pure and clock-injected so it can be
tested deterministically without real time or a real capture device."""

from __future__ import annotations

from typing import Callable


class FrameClock:
    """Decides when the next frame is due for a target FPS. A monotonic clock is
    required (elapsed-time logic); the default is time.monotonic, injectable for
    tests."""

    __slots__ = ("_interval", "_clock", "_next_deadline")

    def __init__(self, target_fps: int, clock: Callable[[], float] | None = None) -> None:
        if target_fps <= 0:
            raise ValueError("target_fps must be positive")
        import time

        self._interval = 1.0 / target_fps
        self._clock = clock or time.monotonic
        self._next_deadline = self._clock()

    @property
    def interval(self) -> float:
        return self._interval

    def time_until_next(self) -> float:
        """Seconds to wait until the next frame is due (0 if already due)."""
        return max(0.0, self._next_deadline - self._clock())

    def mark_emitted(self) -> None:
        """Advance the deadline after emitting a frame. Advances by whole
        intervals from the previous deadline so a slow frame doesn't permanently
        skew the cadence, but if we've fallen far behind we resync to now rather
        than bursting a backlog of frames."""
        now = self._clock()
        self._next_deadline += self._interval
        if self._next_deadline < now - self._interval:
            self._next_deadline = now + self._interval

    def due(self) -> bool:
        return self._clock() >= self._next_deadline
