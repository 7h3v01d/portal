# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Encode pipeline — pulls captured frames, encodes them, exposes a packet stream.

Owns the concerns that make a long-lived encode session safe (Gate 5):
  - **bounded memory:** a bounded, drop-oldest output queue (never a keyframe) so
    a 30-minute session with a slow consumer can't grow RAM;
  - **resolution change:** when a frame's geometry differs from the encoder's, the
    encoder is reopened at the new size and a keyframe forced — no crash, no
    garbled stream;
  - **encoder-failure recovery:** an encode error triggers a bounded reopen (like
    capture recovery), counting CONSECUTIVE failures reset by a good packet, so a
    permanently broken encoder terminates instead of spinning;
  - **terminal signal:** `get()` raises rather than hanging once the producer dies.

The frame source is any object with `async get() -> Frame` (CaptureSession fits),
so the pipeline is testable against a fake source + synthetic encoder.
"""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Protocol

from ..capture.base import Frame
from ..common.errors import EncodeError
from ..common.logging import get_logger
from .base import EncodedPacket, VideoEncoder

_log = get_logger("encode.pipeline")


class FrameSource(Protocol):
    async def get(self) -> Frame: ...


class EncodePipeline:
    def __init__(
        self,
        source: FrameSource,
        encoder: VideoEncoder,
        *,
        width: int,
        height: int,
        fps: int = 30,
        bitrate: int = 6_000_000,
        max_queue: int = 8,
        max_recovery_attempts: int = 3,
    ) -> None:
        self._source = source
        self._encoder = encoder
        self._w = width
        self._h = height
        self._fps = fps
        self._bitrate = bitrate
        self._max_recovery = max_recovery_attempts

        self._running = False
        self._task: asyncio.Task | None = None
        self._queue: deque[EncodedPacket] = deque(maxlen=max_queue)
        self._available = asyncio.Event()
        self._terminal: Exception | None = None

    async def start(self) -> None:
        self._encoder.open(self._w, self._h, self._fps, self._bitrate)
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
            self._encoder.close()
        except Exception:  # noqa: BLE001
            pass

    def request_keyframe(self) -> None:
        self._encoder.request_keyframe()

    @property
    def is_running(self) -> bool:
        return self._running

    async def get(self) -> EncodedPacket:
        """Await the next encoded packet, or raise if the pipeline has terminated."""
        while True:
            if self._queue:
                return self._queue.popleft()
            if self._terminal is not None:
                raise EncodeError(str(self._terminal))
            if not self._running:
                raise EncodeError("encode pipeline is not running")
            self._available.clear()
            await self._available.wait()

    def _enqueue(self, packet: EncodedPacket) -> None:
        # Never drop a keyframe: if the queue is full and the oldest is a keyframe,
        # drop the newest non-keyframe instead so decoders can still resync.
        if len(self._queue) == self._queue.maxlen and self._queue[0].is_keyframe and not packet.is_keyframe:
            return
        self._queue.append(packet)
        self._available.set()

    def _terminate(self, error: Exception | None) -> None:
        self._running = False
        self._terminal = error
        self._available.set()

    async def _reconfigure(self, width: int, height: int) -> None:
        self._w, self._h = width, height
        self._encoder.open(width, height, self._fps, self._bitrate)
        self._encoder.request_keyframe()
        _log.info("encoder reconfigured to %dx%d", width, height)

    async def _run(self) -> None:
        consecutive_failures = 0
        try:
            while self._running:
                frame = await self._source.get()  # raises if capture terminated
                if (frame.width, frame.height) != (self._w, self._h):
                    await self._reconfigure(frame.width, frame.height)
                try:
                    packets = self._encoder.encode(frame)
                except EncodeError as exc:
                    consecutive_failures += 1
                    if consecutive_failures > self._max_recovery:
                        self._terminate(exc)
                        break
                    await asyncio.sleep(0.02 * consecutive_failures)
                    try:
                        self._encoder.open(self._w, self._h, self._fps, self._bitrate)
                        self._encoder.request_keyframe()
                    except Exception:  # noqa: BLE001
                        pass  # next encode raises again -> counter climbs -> terminal
                    continue
                if packets:
                    consecutive_failures = 0
                    for p in packets:
                        self._enqueue(p)
        except EncodeError as exc:
            self._terminate(exc)
        except Exception as exc:  # noqa: BLE001 — e.g. source terminated
            self._terminate(exc)
        finally:
            if self._running:
                self._terminate(None)
