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

RESYNC_RETRY_SECONDS = 0.5  # while awaiting resync, re-request a keyframe no more often than this


class ScreenViewer:
    def __init__(self, decoder: PyAvDecoder | None = None, *, max_queue: int = 4,
                 clock=None) -> None:
        import time

        self._decoder = decoder or PyAvDecoder()
        self._clock = clock or time.monotonic
        self._conn: TransportConnection | None = None
        self._running = False
        self._task: asyncio.Task | None = None
        self._queue: deque[DecodedFrame] = deque(maxlen=max_queue)
        self._available = asyncio.Event()
        self._terminal: Exception | None = None
        self._awaiting_resync = False  # True after a drop, until a keyframe re-syncs
        self._total_drops = 0
        self._last_keyframe_request = 0.0
        self.width = 0
        self.height = 0
        self.fps = 0

    @property
    def total_drops(self) -> int:
        return self._total_drops

    async def start(self, conn: TransportConnection, fps: int = 30, bitrate: int = 6_000_000) -> None:
        self._conn = conn
        await conn.send_control(encode(build(
            MessageType.STREAM_START, StreamStartPayload(fps=fps, bitrate=bitrate), sequence=1
        )))
        params = decode(await conn.recv_control())
        if params.type is not MessageType.STREAM_PARAMS:
            raise EncodeError("host did not send stream parameters")
        self.width, self.height, self.fps = params.payload.width, params.payload.height, params.payload.fps
        # Set the starting expected geometry (already ceiling-checked by
        # StreamParamsPayload). A later keyframe-bound resolution change carried in
        # the packet header is allowed by the decoder (Gate 5), not rejected.
        self._decoder.expect_geometry(self.width, self.height)
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
                receipt = await self._conn.recv_video()  # raises on disconnect
                await self._process_receipt(receipt)
        except Exception as exc:  # noqa: BLE001
            self._terminate(exc)
        finally:
            if self._running:
                self._terminate(None)

    async def _process_receipt(self, receipt) -> None:
        """Handle one received video frame: loss detection + bounded resync, then
        decode. Extracted so the recovery policy is tested against THIS code, not
        a copy of it."""
        if receipt.dropped > 0:
            # Count EVERY drop for truthful telemetry — including drops that occur
            # while already resyncing.
            self._total_drops += receipt.dropped
            if not self._awaiting_resync:
                # First loss: reset the decoder (drops until the next IDR) and ask
                # the host for a keyframe.
                self._awaiting_resync = True
                self._decoder.reset()
                await self._send_keyframe_request()
                _log.info("video loss (%d) — requested resync keyframe", receipt.dropped)
        # Retry check runs on EVERY packet while awaiting resync — not only when
        # this packet reported a drop. Otherwise a lost recovery-IDR followed by
        # clean (dropped == 0) packets would never re-trigger the request and the
        # viewer could wait forever. THIS is what makes recovery actually bounded.
        if self._awaiting_resync and (self._clock() - self._last_keyframe_request) >= RESYNC_RETRY_SECONDS:
            await self._send_keyframe_request()
            _log.info("still awaiting resync — re-requested keyframe (timer)")
        packet = unpack_packet(receipt.data)
        frames = self._decoder.decode(
            packet.data, packet.is_keyframe, packet.timestamp_ns,
            declared=(packet.width, packet.height),
        )
        if frames and self._awaiting_resync:
            self._awaiting_resync = False  # a decoded frame after reset => resynced
        for frame in frames:
            # Keep the viewer's advertised geometry current after a validated live
            # resize — Phase 7 input mapping must never map against a stale
            # resolution (host is now frame.width x frame.height).
            if (frame.width, frame.height) != (self.width, self.height):
                self.width, self.height = frame.width, frame.height
            self._enqueue(frame)

    async def _send_keyframe_request(self) -> None:
        self._last_keyframe_request = self._clock()
        if self._conn is not None:
            try:
                await self._conn.send_control(
                    encode(build(MessageType.STREAM_KEYFRAME, EmptyPayload(), sequence=1))
                )
            except Exception:  # noqa: BLE001
                pass
