# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Gate 5 logic against the synthetic encoder: reconfigure on resolution change,
bounded encoder-failure recovery, bounded output (no RAM growth), keyframe
protection, and a terminal signal so get() can't hang."""

from __future__ import annotations

import asyncio
import time

import pytest

from portal.capture.base import Frame, PixelFormat
from portal.common.errors import EncodeError
from portal.encode.pipeline import EncodePipeline
from portal.encode.synthetic import SyntheticEncoder


def _frame(w=640, h=360):
    stride = w * 4
    return Frame(memoryview(bytes(stride * h)), w, h, stride, PixelFormat.BGRA8,
                 time.monotonic_ns(), "SYN-0")


class FakeSource:
    """Async frame source. Yields frames of a given size; can switch size or raise."""

    def __init__(self, w=640, h=360):
        self.w, self.h = w, h
        self.raise_after: int | None = None
        self._count = 0

    async def get(self) -> Frame:
        self._count += 1
        if self.raise_after is not None and self._count > self.raise_after:
            raise EncodeError("source terminated")
        await asyncio.sleep(0)  # yield
        return _frame(self.w, self.h)


@pytest.mark.asyncio
async def test_first_packet_is_keyframe():
    pipe = EncodePipeline(FakeSource(), SyntheticEncoder(), width=640, height=360, fps=1000)
    await pipe.start()
    try:
        pkt = await asyncio.wait_for(pipe.get(), timeout=2)
        assert pkt.is_keyframe
    finally:
        await pipe.stop()


@pytest.mark.asyncio
async def test_resolution_change_reopens_encoder_and_forces_keyframe():
    src = FakeSource(640, 360)
    enc = SyntheticEncoder()
    pipe = EncodePipeline(src, enc, width=640, height=360, fps=1000)
    await pipe.start()
    try:
        await asyncio.wait_for(pipe.get(), timeout=2)  # initial keyframe
        src.w, src.h = 1920, 1080  # display switched
        # Pull packets until we observe the new geometry with a keyframe.
        saw_reconfig_keyframe = False
        for _ in range(50):
            p = await asyncio.wait_for(pipe.get(), timeout=2)
            if (p.width, p.height) == (1920, 1080) and p.is_keyframe:
                saw_reconfig_keyframe = True
                break
        assert saw_reconfig_keyframe
        assert (1920, 1080) in enc.opened_geometries  # encoder was reopened
    finally:
        await pipe.stop()


@pytest.mark.asyncio
async def test_transient_encoder_failure_recovers():
    enc = SyntheticEncoder()
    enc.set_encode_failures(2)  # two failures, then works
    pipe = EncodePipeline(FakeSource(), enc, width=640, height=360, fps=1000,
                          max_recovery_attempts=3)
    await pipe.start()
    try:
        pkt = await asyncio.wait_for(pipe.get(), timeout=3)
        assert pkt is not None
        assert pipe.is_running
    finally:
        await pipe.stop()


@pytest.mark.asyncio
async def test_permanent_encoder_failure_terminates_bounded():
    enc = SyntheticEncoder()
    enc.set_encode_failures(10_000)  # never recovers
    pipe = EncodePipeline(FakeSource(), enc, width=640, height=360, fps=1000,
                          max_recovery_attempts=3)
    await pipe.start()
    with pytest.raises(EncodeError):
        await asyncio.wait_for(pipe.get(), timeout=3)
    assert not pipe.is_running
    await pipe.stop()


@pytest.mark.asyncio
async def test_source_termination_propagates():
    src = FakeSource()
    src.raise_after = 3
    pipe = EncodePipeline(src, SyntheticEncoder(), width=640, height=360, fps=1000)
    await pipe.start()
    with pytest.raises(EncodeError):
        for _ in range(100):
            await asyncio.wait_for(pipe.get(), timeout=3)
    await pipe.stop()


@pytest.mark.asyncio
async def test_bounded_queue_never_drops_keyframe():
    # Fill a small queue; a keyframe at the head must survive while newer
    # non-keyframes are dropped (decoders can still resync).
    from portal.encode.base import EncodedPacket

    pipe = EncodePipeline(FakeSource(), SyntheticEncoder(), width=640, height=360,
                          fps=1000, max_queue=3)
    key = EncodedPacket(b"k", True, 0, 0, 640, 360)
    pipe._enqueue(key)  # noqa: SLF001
    for i in range(10):
        pipe._enqueue(EncodedPacket(b"d", False, i + 1, 0, 640, 360))  # noqa: SLF001
    q = list(pipe._queue)  # noqa: SLF001
    assert len(q) == 3
    assert q[0].is_keyframe  # the keyframe was never dropped
