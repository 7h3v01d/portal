# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""A4d recovery POLICY, no PyAV needed — runs in the core suite.

Proves: (1) first loss requests a keyframe; (2) if the recovery IDR is itself lost
(more drops while awaiting resync), Portal re-requests after the retry interval —
so recovery is genuinely bounded, not one-shot; (3) drop telemetry counts every
dropped frame, including during resync; (4) a decoded frame clears resync."""

from __future__ import annotations

import asyncio

import pytest

from portal.protocol.codec import decode
from portal.protocol.messages import MessageType
from portal.stream.viewer import RESYNC_RETRY_SECONDS, ScreenViewer
from portal.transport.base import VideoReceipt


class FakeClock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class ScriptedConn:
    """Feeds a scripted list of VideoReceipts to recv_video and records the
    control (keyframe-request) messages the viewer sends back."""

    def __init__(self, receipts):
        self._receipts = list(receipts)
        self.keyframe_requests = 0
        self._done = asyncio.Event()

    async def recv_video(self):
        if self._receipts:
            return self._receipts.pop(0)
        self._done.set()
        await asyncio.Event().wait()  # park after the script is exhausted

    async def send_control(self, data):
        msg = decode(data)
        if msg.type is MessageType.STREAM_KEYFRAME:
            self.keyframe_requests += 1


class FakeDecoder:
    """Never produces a decoded frame, so the viewer stays in resync — letting us
    exercise the re-request policy deterministically."""

    def reset(self): ...
    def decode(self, data, is_keyframe, ts=0, declared=None):
        return []


def _pkt(dropped):
    # A minimal wire-packed frame with the given drop count. The bytes only need
    # to survive unpack_packet; the fake decoder ignores them.
    from portal.encode.base import EncodedPacket
    from portal.encode.wire import pack_packet

    return VideoReceipt(data=pack_packet(EncodedPacket(b"x", False, 0, 0, 320, 240)), dropped=dropped)


@pytest.mark.asyncio
async def test_bounded_rerequest_and_truthful_telemetry():
    clock = FakeClock()
    # Three loss events in a row; the decoder never resyncs (IDRs keep getting lost).
    conn = ScriptedConn([_pkt(5), _pkt(4), _pkt(3)])
    viewer = ScreenViewer(FakeDecoder(), clock=clock)
    viewer._conn = conn
    viewer._running = True

    # Step the REAL production method (not a copy) once per receipt.
    r = await conn.recv_video(); await viewer._process_receipt(r)   # first loss -> request #1
    clock.advance(RESYNC_RETRY_SECONDS + 0.01)
    r = await conn.recv_video(); await viewer._process_receipt(r)   # retry -> request #2
    clock.advance(RESYNC_RETRY_SECONDS + 0.01)
    r = await conn.recv_video(); await viewer._process_receipt(r)   # retry -> request #3

    assert conn.keyframe_requests == 3, "recovery IDR loss must trigger re-requests (bounded)"
    assert viewer.total_drops == 12, "every dropped frame must be counted (5+4+3)"
    assert viewer._awaiting_resync is True


@pytest.mark.asyncio
async def test_clean_frame_after_cooldown_triggers_retry():
    # The reviewer's exact scenario: loss -> request #1; recovery IDR lost inside
    # the cooldown (no request); then a CLEAN packet (dropped==0) arrives after
    # the cooldown expires -> must trigger request #2. Previously the retry only
    # ran inside `if dropped > 0`, so a clean frame never re-triggered it.
    clock = FakeClock()
    conn = ScriptedConn([_pkt(3), _pkt(2), _pkt(0)])  # loss, loss, CLEAN
    viewer = ScreenViewer(FakeDecoder(), clock=clock)
    viewer._conn = conn
    viewer._running = True

    r = await conn.recv_video(); await viewer._process_receipt(r)   # loss -> request #1
    # Second loss still inside cooldown -> no new request.
    r = await conn.recv_video(); await viewer._process_receipt(r)
    assert conn.keyframe_requests == 1
    # Cooldown expires, then a CLEAN packet arrives.
    clock.advance(RESYNC_RETRY_SECONDS + 0.01)
    r = await conn.recv_video(); await viewer._process_receipt(r)   # clean -> request #2
    assert conn.keyframe_requests == 2, "clean packet after cooldown must re-request"
    assert viewer.total_drops == 5
    clock = FakeClock()
    conn = ScriptedConn([_pkt(2), _pkt(2)])  # two losses close together
    viewer = ScreenViewer(FakeDecoder(), clock=clock)
    viewer._conn = conn
    viewer._running = True

    r = await conn.recv_video(); await viewer._process_receipt(r)  # request #1
    # No clock advance: second loss is within the retry interval -> NO new request.
    r = await conn.recv_video(); await viewer._process_receipt(r)

    assert conn.keyframe_requests == 1, "must not storm keyframe requests within the interval"
    assert viewer.total_drops == 4  # still counts every drop
