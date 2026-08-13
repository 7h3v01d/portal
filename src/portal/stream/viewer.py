# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Controller-side screen viewer.

Requests a stream (STREAM_START), reads the host's geometry (STREAM_PARAMS), then
pulls encoded packets off the bulk channel, unpacks and decodes them into
displayable RGB frames. A viewer that joins mid-stream (or after packet loss)
asks for a keyframe and the decoder drops packets until the first IDR.

The decoded-frame delivery is transport- and render-agnostic: a Qt widget (thin,
validated on the rig) simply blits the RGB frames this yields."""

from __future__ import annotations

import asyncio
from collections import deque

from ..common.errors import EncodeError
from ..common.logging import get_logger
from ..decode.pyav_decoder import DecodedFrame, PyAvDecoder
from ..encode.wire import unpack_packet
from ..protocol.codec import build, decode, encode
from ..protocol.messages import EmptyPayload, MessageType, StreamStartPayload
from ..transport.base import TransportConnection

_log = get_logger("stream.viewer")


class ScreenViewer:
    def __init__(self, decoder: PyAvDecoder | None = None, *, max_queue: int = 4) -> None:
        self._decoder = decoder or PyAvDecoder()
        self._conn: TransportConnection | None = None
        self._running = False
        self._task: asyncio.Task | None = None
        self._queue: deque[DecodedFrame] = deque(maxlen=max_queue)
        self._available = asyncio.Event()
        self._terminal: Exception | None = None
        self.width = 0
        self.height = 0
        self.fps = 0

    async def start(self, conn: TransportConnection, fps: int = 30, bitrate: int = 6_000_000) -> None:
        self._conn = conn
        await conn.send_control(encode(build(
            MessageType.STREAM_START, StreamStartPayload(fps=fps, bitrate=bitrate), sequence=1
        )))
        params = decode(await conn.recv_control())
        if params.type is not MessageType.STREAM_PARAMS:
            raise EncodeError("host did not send stream parameters")
        self.width, self.height, self.fps = params.payload.width, params.payload.height, params.payload.fps
        self._running = True
        self._task = asyncio.create_task(self._run())

    async def request_keyframe(self) -> None:
        if self._conn is not None:
            self._decoder.reset()
            await self._conn.send_control(encode(build(MessageType.STREAM_KEYFRAME, EmptyPayload(), sequence=1)))

    async def stop(self) -> None:
        self._running = False
        if self._conn is not None:
            try:
                await self._conn.send_control(encode(build(MessageType.STREAM_STOP, EmptyPayload(), sequence=1)))
            except Exception:  # noqa: BLE001
                pass
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def get(self) -> DecodedFrame:
        while True:
            if self._queue:
                return self._queue.popleft()
            if self._terminal is not None:
                raise EncodeError(str(self._terminal))
            if not self._running:
                raise EncodeError("viewer is not running")
            self._available.clear()
            await self._available.wait()

    def _enqueue(self, frame: DecodedFrame) -> None:
        self._queue.append(frame)  # drop-oldest via maxlen; showing latest is fine
        self._available.set()

    def _terminate(self, error: Exception | None) -> None:
        self._running = False
        self._terminal = error
        self._available.set()

    async def _run(self) -> None:
        try:
            while self._running:
                raw = await self._conn.recv_video()  # raises on disconnect
                packet = unpack_packet(raw)
                for frame in self._decoder.decode(packet.data, packet.is_keyframe, packet.timestamp_ns):
                    self._enqueue(frame)
        except Exception as exc:  # noqa: BLE001
            self._terminate(exc)
        finally:
            if self._running:
                self._terminate(None)
