# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The capture session — backend-agnostic runtime around any CaptureBackend.

Owns the concerns that are NOT specific to DXcam, so they can be tested on any OS
against the synthetic backend:

  - **pacing:** emit at target FPS via FrameClock (pure, clock-injected);
  - **pause/resume:** stop producing without tearing down the device;
  - **resolution / monitor change:** detect when a frame's dimensions differ from
    what we started with and fire `on_display_change` (Gate 4);
  - **device-loss recovery:** a backend error (sleep/wake, monitor switch) is
    caught and the device restarted, up to a bounded number of attempts (Gate 4);
  - **bounded queue:** the latest frames only, drop-oldest, so a slow consumer
    can never grow memory without bound (gets ahead of Phase 5's gate).

The loop is factored so `_produce_one()` (grab + timestamp + size-check) can be
driven directly in tests without real timing.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Callable

from ..common.errors import CaptureError
from ..common.logging import get_logger
from .base import CaptureBackend, Frame
from .pacing import FrameClock

_log = get_logger("capture.session")

DisplayChangeCallback = Callable[[int, int, int, int], None]  # old_w, old_h, new_w, new_h


class CaptureSession:
    def __init__(
        self,
        backend: CaptureBackend,
        display_id: str,
        target_fps: int = 30,
        *,
        clock: Callable[[], float] | None = None,
        max_queue: int = 2,
        max_recovery_attempts: int = 3,
        on_display_change: DisplayChangeCallback | None = None,
    ) -> None:
        self._backend = backend
        self._display_id = display_id
        self._target_fps = target_fps
        self._clock = clock or time.monotonic
        self._frame_clock = FrameClock(target_fps, clock=self._clock)
        self._max_recovery = max_recovery_attempts
        self._on_display_change = on_display_change

        self._paused = False
        self._running = False
        self._task: asyncio.Task | None = None
        self._queue: deque[Frame] = deque(maxlen=max_queue)
        self._frame_available = asyncio.Event()
        self._terminal_error: Exception | None = None  # set when the producer dies

        self._cur_w: int | None = None
        self._cur_h: int | None = None

    # --- lifecycle ---
    async def start(self) -> None:
        self._backend.start(self._display_id, self._target_fps)
        d = next((x for x in self._backend.list_displays() if x.display_id == self._display_id), None)
        if d is not None:
            self._cur_w, self._cur_h = d.width, d.height
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        try:
            self._backend.stop()
        except Exception:  # noqa: BLE001
            pass

    def pause(self) -> None:
        self._paused = True

    def resume(self) -> None:
        self._paused = False

    @property
    def is_paused(self) -> bool:
        return self._paused

    @property
    def is_running(self) -> bool:
        return self._running

    # --- frame access ---
    async def get(self) -> Frame:
        """Await the next available frame, or raise CaptureError if the producer
        has terminated (so an encoder/viewer can never hang on a frame that will
        never arrive)."""
        while True:
            if self._queue:
                return self._queue.popleft()
            if self._terminal_error is not None:
                raise CaptureError(str(self._terminal_error))
            if not self._running and not self._queue:
                raise CaptureError("capture is not running")
            self._frame_available.clear()
            await self._frame_available.wait()

    def _enqueue(self, frame: Frame) -> None:
        self._queue.append(frame)  # deque(maxlen) drops the oldest automatically
        self._frame_available.set()

    # --- core (testable directly) ---
    async def _produce_one(self) -> Frame | None:
        """One grab. Returns a frame, or None if paused / no new frame. Detects a
        size change and fires the callback. Raises CaptureError on device loss so
        the loop can recover."""
        if self._paused:
            return None
        frame = self._backend.get_frame()  # may raise CaptureError
        if frame is None:
            return None
        if (self._cur_w, self._cur_h) != (frame.width, frame.height) and self._cur_w is not None:
            old_w, old_h = self._cur_w, self._cur_h
            self._cur_w, self._cur_h = frame.width, frame.height
            if self._on_display_change:
                self._on_display_change(old_w, old_h, frame.width, frame.height)
        else:
            self._cur_w, self._cur_h = frame.width, frame.height
        return frame

    async def _restart_backend(self) -> None:
        """A single stop+start attempt. Tolerates failure — the loop decides
        whether to keep trying based on the consecutive-failure count."""
        try:
            self._backend.stop()
        except Exception:  # noqa: BLE001
            pass
        try:
            self._backend.start(self._display_id, self._target_fps)
        except Exception:  # noqa: BLE001
            pass  # next _produce_one will raise again and bump the counter

    def _terminate(self, error: Exception | None) -> None:
        self._running = False
        self._terminal_error = error
        self._frame_available.set()  # wake any get() waiter so it can raise

    async def _run(self) -> None:
        # Count CONSECUTIVE failed capture cycles — reset by a successful frame —
        # so a backend that keeps failing after a successful restart still
        # terminates, and every failure path yields (no tight busy loop).
        consecutive_failures = 0
        try:
            while self._running:
                wait = self._frame_clock.time_until_next()
                if wait > 0:
                    await asyncio.sleep(wait)
                if not self._running:
                    break
                try:
                    frame = await self._produce_one()
                except CaptureError as exc:
                    consecutive_failures += 1
                    if consecutive_failures > self._max_recovery:
                        self._terminate(exc)
                        break
                    await asyncio.sleep(0.05 * consecutive_failures)  # always yields, backoff
                    await self._restart_backend()
                    continue
                if frame is not None:
                    consecutive_failures = 0  # a good frame resets recovery
                    self._enqueue(frame)
                    self._frame_clock.mark_emitted()
                else:
                    await asyncio.sleep(self._frame_clock.interval)
        except Exception as exc:  # noqa: BLE001 — e.g. a callback raising
            self._terminate(exc)
        finally:
            if self._running:
                self._terminate(None)
