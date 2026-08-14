# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Host-side screen publisher.

Ties CaptureSession -> EncodePipeline -> the transport's bulk channel, gated by
the `screen.publish` capability. The controller asks to start (STREAM_START); the
host announces geometry (STREAM_PARAMS) and streams encoded packets on the bulk
channel until STREAM_STOP, a revoke, or disconnect.

Authority: publishing requires a `screen.publish` token, checked before the
stream starts AND on every packet — a revoke stops the stream on the very next
frame (instant revocation), exactly like the transfer engine's mid-stream check.
"""

from __future__ import annotations

import asyncio

from ..capture.session import CaptureSession
from ..common.errors import PermissionDeniedError
from ..common.logging import get_logger
from ..encode.pipeline import EncodePipeline
from ..encode.wire import pack_packet
from ..protocol.capabilities import Capability
from ..protocol.codec import build, decode, encode
from ..protocol.messages import EmptyPayload, MessageType, StreamParamsPayload
from ..security.authority import CancellationToken
from ..transport.base import TransportConnection

_log = get_logger("stream.publish")


class ScreenPublisher:
    def __init__(self, capture: CaptureSession, encoder, token: CancellationToken) -> None:
        self._capture = capture
        self._encoder = encoder
        self._token = token
        self._stop = asyncio.Event()

    def _require_publish(self) -> None:
        if self._token.capability is not Capability.SCREEN_PUBLISH:
            raise PermissionDeniedError("publishing requires screen.publish")
        if not self._token.valid:
            raise PermissionDeniedError("screen.publish is not currently authorised")

    async def serve(self, conn: TransportConnection, width: int, height: int, fps: int, bitrate: int,
                    *, start_msg=None) -> None:
        """Wait for STREAM_START (unless the coordinator already read it and passes
        it as start_msg), then publish until stop/revoke/disconnect."""
        self._require_publish()

        if start_msg is None:
            # Race the (possibly long) STREAM_START wait against revocation so a
            # revoke here doesn't let us start capture/encode on stale authority.
            started = await self._recv_control_or_revoked(conn)
        else:
            started = start_msg  # coordinator consumed it and granted consent first
        if started is None or started.type is not MessageType.STREAM_START:
            return
        if not self._token.valid:  # re-check after the await, before any side effect
            return
        fps = started.payload.fps
        bitrate = started.payload.bitrate

        await self._capture.start()
        pipeline = EncodePipeline(self._capture, self._encoder, width=width, height=height,
                                  fps=fps, bitrate=bitrate)
        await pipeline.start()

        await conn.send_control(encode(build(
            MessageType.STREAM_PARAMS, StreamParamsPayload(width=width, height=height, fps=fps), sequence=1
        )))

        control_task = asyncio.create_task(self._control_loop(conn, pipeline))
        try:
            while not self._stop.is_set():
                if not self._token.valid:  # instant revocation (pre-await)
                    _log.info("screen.publish revoked — stopping stream")
                    break
                packet = await self._get_frame_or_revoked(pipeline)
                if packet is None:  # revoked while awaiting a frame
                    _log.info("screen.publish revoked during frame wait — stopping")
                    break
                # CRITICAL: re-check AFTER the await and BEFORE the privileged send.
                # Without this, a revoke landing during get() still ships one frame.
                if not self._token.valid:
                    _log.info("screen.publish revoked before send — dropping frame")
                    break
                await conn.send_video(pack_packet(packet))
        except Exception:  # noqa: BLE001 — disconnect / pipeline terminal
            pass
        finally:
            control_task.cancel()
            await pipeline.stop()
            await self._capture.stop()

    async def _recv_control_or_revoked(self, conn: TransportConnection):
        """await recv_control, but abort promptly if the token is revoked."""
        recv = asyncio.ensure_future(conn.recv_control())
        rev = asyncio.ensure_future(self._token.wait_invalid())
        try:
            done, _pending = await asyncio.wait({recv, rev}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (recv, rev):
                if not t.done():
                    t.cancel()
        if recv in done and self._token.valid:
            return decode(recv.result())
        return None

    async def _get_frame_or_revoked(self, pipeline: EncodePipeline):
        """await the next packet, but abort promptly if the token is revoked."""
        get = asyncio.ensure_future(pipeline.get())
        rev = asyncio.ensure_future(self._token.wait_invalid())
        try:
            done, _pending = await asyncio.wait({get, rev}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (get, rev):
                if not t.done():
                    t.cancel()
        if get in done and self._token.valid:
            return get.result()
        return None

    async def _control_loop(self, conn: TransportConnection, pipeline: EncodePipeline) -> None:
        try:
            while True:
                ctl = decode(await conn.recv_control())
                if ctl.type is MessageType.STREAM_STOP:
                    self._stop.set()
                    return
                if ctl.type is MessageType.STREAM_KEYFRAME:
                    pipeline.request_keyframe()
        except Exception:  # noqa: BLE001 — disconnect
            self._stop.set()
