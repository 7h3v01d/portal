# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The capture->encode path composed: synthetic capture frames driven through the
pipeline into the REAL libx264 encoder, producing a decodable stream."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("av")
pytest.importorskip("numpy")

from portal.capture.session import CaptureSession
from portal.capture.synthetic import SyntheticCaptureBackend
from portal.encode.pipeline import EncodePipeline
from portal.encode.pyav_backend import PyAvEncoder


@pytest.mark.asyncio
async def test_capture_frames_encode_to_h264():
    backend = SyntheticCaptureBackend(width=320, height=240)
    session = CaptureSession(backend, "SYN-0", target_fps=1000, max_queue=4)
    await session.start()
    pipe = EncodePipeline(session, PyAvEncoder(), width=320, height=240, fps=30,
                          bitrate=1_000_000, max_queue=16)
    await pipe.start()
    try:
        packets = [await asyncio.wait_for(pipe.get(), timeout=5) for _ in range(10)]
        assert packets[0].is_keyframe
        assert all(p.width == 320 and p.height == 240 for p in packets)
        assert sum(len(p.data) for p in packets) > 0
    finally:
        await pipe.stop()
        await session.stop()
