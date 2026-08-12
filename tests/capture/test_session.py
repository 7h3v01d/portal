# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Gate 4 logic, tested against the synthetic backend on any OS: display
enumeration, pause, resolution-change detection, device-loss recovery, frame
timestamps, and the bounded drop-oldest queue."""

from __future__ import annotations

import asyncio

import pytest

from portal.common.errors import CaptureError
from portal.capture.base import Frame
from portal.capture.session import CaptureSession
from portal.capture.synthetic import SyntheticCaptureBackend


def test_enumeration_and_display_ids():
    b = SyntheticCaptureBackend()
    displays = b.list_displays()
    assert {d.display_id for d in displays} == {"SYN-0", "SYN-1"}
    assert any(d.primary for d in displays)


def test_start_unknown_display_raises():
    b = SyntheticCaptureBackend()
    with pytest.raises(CaptureError):
        b.start("NOPE")


@pytest.mark.asyncio
async def test_produce_one_yields_timestamped_frame():
    b = SyntheticCaptureBackend()
    b.start("SYN-0")
    session = CaptureSession(b, "SYN-0", target_fps=30)
    session._cur_w, session._cur_h = 640, 360  # noqa: SLF001
    f = await session._produce_one()  # noqa: SLF001
    assert isinstance(f, Frame)
    assert f.timestamp_ns > 0
    assert f.width == 640 and f.stride == 640 * 4


@pytest.mark.asyncio
async def test_pause_produces_no_frame():
    b = SyntheticCaptureBackend()
    b.start("SYN-0")
    session = CaptureSession(b, "SYN-0")
    session.pause()
    assert await session._produce_one() is None  # noqa: SLF001
    session.resume()
    assert await session._produce_one() is not None  # noqa: SLF001


@pytest.mark.asyncio
async def test_resolution_change_fires_callback():
    changes = []
    b = SyntheticCaptureBackend(width=640, height=360)
    b.start("SYN-0")
    session = CaptureSession(
        b, "SYN-0",
        on_display_change=lambda ow, oh, nw, nh: changes.append((ow, oh, nw, nh)),
    )
    session._cur_w, session._cur_h = 640, 360  # noqa: SLF001
    await session._produce_one()  # noqa: SLF001  (640x360, no change)
    b.set_next_size(1920, 1080)
    await session._produce_one()  # noqa: SLF001  (size change)
    assert changes == [(640, 360, 1920, 1080)]


@pytest.mark.asyncio
async def test_permanently_failing_backend_terminates_bounded():
    # Finding 4: a backend that fails EVERY grab (even though restart "succeeds")
    # must terminate after a bounded number of CONSECUTIVE failures, not loop
    # forever — and get() must then raise, not hang.
    b = SyntheticCaptureBackend()
    session = CaptureSession(b, "SYN-0", target_fps=1000, max_recovery_attempts=3)
    b.fail_times(10_000)  # never recovers
    await session.start()
    with pytest.raises(CaptureError):
        await asyncio.wait_for(session.get(), timeout=3.0)
    assert not session.is_running
    await session.stop()


@pytest.mark.asyncio
async def test_transient_failure_then_good_frame_resets_counter():
    # A couple of failures followed by success must NOT terminate — a good frame
    # resets the consecutive-failure count.
    b = SyntheticCaptureBackend()
    session = CaptureSession(b, "SYN-0", target_fps=1000, max_recovery_attempts=3)
    b.fail_times(2)  # two failures, then frames flow
    await session.start()
    try:
        frame = await asyncio.wait_for(session.get(), timeout=3.0)
        assert frame is not None
        assert session.is_running
    finally:
        await session.stop()


@pytest.mark.asyncio
async def test_get_raises_when_display_callback_kills_producer():
    # Finding 7: an exception in on_display_change terminates the producer; get()
    # must raise rather than hang forever.
    def boom(*_):
        raise RuntimeError("callback exploded")

    b = SyntheticCaptureBackend(width=640, height=360)
    session = CaptureSession(b, "SYN-0", target_fps=1000, on_display_change=boom)
    await session.start()
    b.set_next_size(1920, 1080)  # triggers the callback -> raises -> terminal
    with pytest.raises(CaptureError):
        await asyncio.wait_for(session.get(), timeout=3.0)
    await session.stop()


@pytest.mark.asyncio
async def test_bounded_queue_drops_oldest():
    b = SyntheticCaptureBackend()
    b.start("SYN-0")
    session = CaptureSession(b, "SYN-0", max_queue=2)
    # Enqueue three frames into a maxlen-2 queue.
    for _ in range(3):
        f = await session._produce_one()  # noqa: SLF001
        session._enqueue(f)  # noqa: SLF001
    # Only the two most recent survive — memory can't grow without bound.
    assert len(session._queue) == 2  # noqa: SLF001


@pytest.mark.asyncio
async def test_full_loop_delivers_frames():
    b = SyntheticCaptureBackend()
    session = CaptureSession(b, "SYN-0", target_fps=1000, max_queue=4)
    await session.start()
    try:
        frame = await session.get()
        assert isinstance(frame, Frame)
        assert frame.timestamp_ns > 0
    finally:
        await session.stop()
    assert not session.is_running
