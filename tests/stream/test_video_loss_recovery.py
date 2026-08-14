# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""A4d: encoded-video loss must be self-healing, not silently corrupting.

Uses the REAL encoder and decoder. Forces the transport to drop packets (including
the IDR), then proves the viewer detects the loss, resets the decoder, requests a
keyframe, and resumes decoding once a fresh IDR arrives — bounded recovery."""

from __future__ import annotations

import asyncio
import time

import pytest

pytest.importorskip("av")
pytest.importorskip("numpy")

from portal.capture.base import Frame, PixelFormat
from portal.decode.pyav_decoder import PyAvDecoder
from portal.encode.pyav_backend import PyAvEncoder
from portal.encode.wire import pack_packet
from portal.protocol.codec import decode
from portal.protocol.messages import MessageType
from portal.stream.viewer import ScreenViewer

import sys
sys.path.insert(0, "tests/transfer")
from conftest import make_memory_pair


def _bgra(w, h, v):
    stride = w * 4
    buf = bytearray(stride * h)
    for i in range(0, len(buf), 4):
        buf[i], buf[i + 1], buf[i + 2], buf[i + 3] = v & 0xFF, (v + 30) & 0xFF, (v + 60) & 0xFF, 255
    return Frame(memoryview(bytes(buf)), w, h, stride, PixelFormat.BGRA8, time.monotonic_ns(), "SYN-0")


@pytest.mark.asyncio
async def test_viewer_recovers_from_encoded_packet_loss():
    host_conn, viewer_conn = make_memory_pair()

    enc = PyAvEncoder(); enc.open(320, 240, 30, 1_000_000)

    # Produce a real GOP: IDR + several P-frames.
    packets = []
    for i in range(12):
        packets += enc.encode(_bgra(320, 240, 80 + i * 6))
    assert packets[0].is_keyframe

    viewer = ScreenViewer(PyAvDecoder())
    # Wire the viewer's connection/decoder without the full start() handshake.
    viewer._conn = viewer_conn
    viewer._running = True
    viewer._task = asyncio.create_task(viewer._run())
    try:
        # Overflow the drop-oldest video buffer (maxlen 4) so the IDR and early
        # P-frames are DROPPED before the viewer consumes anything.
        for p in packets:
            await host_conn.send_video(pack_packet(p))
        await asyncio.sleep(0.1)

        # The viewer should have seen dropped>0 and requested a keyframe.
        keyframe_requested = False
        for _ in range(20):
            try:
                msg = decode(host_conn._in_control.get_nowait())
                if msg.type is MessageType.STREAM_KEYFRAME:
                    keyframe_requested = True
                    break
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.02)
        assert keyframe_requested, "viewer did not request a resync keyframe after loss"
        assert viewer.total_drops > 0

        # Host honours the request: encode a fresh IDR and send it.
        enc.request_keyframe()
        idr = enc.encode(_bgra(320, 240, 200))
        idr += enc.flush()
        for p in idr:
            await host_conn.send_video(pack_packet(p))

        # The viewer resyncs and produces a decoded frame again — bounded recovery.
        frame = await asyncio.wait_for(viewer.get(), timeout=8)
        assert frame.width == 320 and frame.height == 240
    finally:
        viewer._running = False
        viewer._task.cancel()
        try:
            await viewer._task
        except asyncio.CancelledError:
            pass
        enc.close()
