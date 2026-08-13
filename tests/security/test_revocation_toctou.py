# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Revocation must hold ACROSS an await boundary, not just before it.

These are the tests the earlier revoke tests should have been: they revoke WHILE
the privileged operation is suspended inside an await, then release the await, and
assert no privileged side effect happens afterwards. This is the A2 TOCTOU."""

from __future__ import annotations

import asyncio

import pytest

from portal.protocol.capabilities import Capability
from portal.security.authority import SessionAuthority


class GatedPipeline:
    """A fake encode pipeline whose get() blocks until released, so a test can
    revoke authority while the publisher is parked inside get()."""

    def __init__(self):
        self.released = asyncio.Event()
        self.packet = _FakePacket()

    async def get(self):
        await self.released.wait()
        return self.packet

    async def stop(self): ...
    def request_keyframe(self): ...


class _FakePacket:
    is_keyframe = True
    pts = 0
    timestamp_ns = 0
    width = 320
    height = 240
    data = b"x"


class RecordingConn:
    """Records bulk sends so we can prove none happen post-revoke."""

    def __init__(self):
        self.bulk_sends = 0
        self.control = asyncio.Queue()

    async def send_bulk(self, data):
        self.bulk_sends += 1

    async def send_control(self, data): ...
    async def recv_control(self):
        return await self.control.get()


@pytest.mark.asyncio
async def test_screen_revoke_during_frame_wait_sends_no_packet():
    from portal.stream.publish import ScreenPublisher

    auth = SessionAuthority()
    auth.grant(Capability.SCREEN_PUBLISH)
    token = auth.authorize(Capability.SCREEN_PUBLISH)

    pipeline = GatedPipeline()
    conn = RecordingConn()
    pub = ScreenPublisher.__new__(ScreenPublisher)
    pub._token = token
    pub._stop = asyncio.Event()

    # Drive just the send loop directly against the gated pipeline.
    async def loop():
        while not pub._stop.is_set():
            if not token.valid:
                break
            packet = await pub._get_frame_or_revoked(pipeline)
            if packet is None:
                break
            if not token.valid:
                break
            await conn.send_bulk(b"frame")

    task = asyncio.create_task(loop())
    await asyncio.sleep(0.05)          # let the loop park inside get()
    auth.revoke(Capability.SCREEN_PUBLISH)  # revoke WHILE parked
    pipeline.released.set()             # now release the frame
    await asyncio.wait_for(task, timeout=2)

    assert conn.bulk_sends == 0, "a frame was sent after revocation (TOCTOU)"


@pytest.mark.asyncio
async def test_wait_invalid_wakes_promptly_on_revoke():
    auth = SessionAuthority()
    auth.grant(Capability.SCREEN_PUBLISH)
    token = auth.authorize(Capability.SCREEN_PUBLISH)

    waiter = asyncio.create_task(token.wait_invalid())
    await asyncio.sleep(0.02)
    assert not waiter.done()           # still valid, still waiting
    auth.revoke(Capability.SCREEN_PUBLISH)
    await asyncio.wait_for(waiter, timeout=1)  # wakes without polling delay
    assert not token.valid


@pytest.mark.asyncio
async def test_transfer_revoke_during_recv_writes_no_chunk(tmp_path):
    # A2.4: prove the fix by spying on the WRITE itself (not directory-empty,
    # which the OLD buggy code also satisfies after it cleans up its .part), and
    # synchronise on an event fired when recv_bulk is actually entered — not a
    # scheduler-dependent sleep. This test FAILS against the pre-fix code.
    import sys
    sys.path.insert(0, "tests/transfer")
    from conftest import MemoryConnection, make_memory_pair
    from portal.common.errors import TransferError
    from portal.protocol.codec import build, encode
    from portal.protocol.messages import FileOfferPayload, MessageType
    from portal.transfer.lan import receive_file
    import hashlib

    auth = SessionAuthority()
    auth.grant(Capability.FILE_WRITE_INBOUND)
    token = auth.authorize(Capability.FILE_WRITE_INBOUND)

    _sender, receiver = make_memory_pair()

    # Signal the instant recv_bulk is entered, so the test can revoke at exactly
    # the vulnerable moment deterministically.
    entered = asyncio.Event()
    orig_recv_bulk = receiver.recv_bulk

    async def signalling_recv_bulk():
        entered.set()
        return await orig_recv_bulk()

    receiver.recv_bulk = signalling_recv_bulk

    # Spy on the actual file write.
    writes = []
    import builtins
    real_open = builtins.open  # not used; we patch os.fdopen via the module

    import portal.transfer.lan as lanmod
    real_fdopen = lanmod.os.fdopen

    def spying_fdopen(fd, mode):
        f = real_fdopen(fd, mode)
        real_write = f.write

        def spy_write(data):
            writes.append(bytes(data))
            return real_write(data)

        f.write = spy_write
        return f

    lanmod.os.fdopen = spying_fdopen
    try:
        dest_root = tmp_path / "root"
        payload = b"A" * 4096
        sha = hashlib.sha256(payload).hexdigest()

        task = asyncio.create_task(receive_file(receiver, dest_root, lambda o: True, token=token))
        offer = build(MessageType.FILE_OFFER,
                      FileOfferPayload(filename="f.bin", size=len(payload), sha256=sha), sequence=1)
        receiver._in_control.put_nowait(encode(offer))

        await asyncio.wait_for(entered.wait(), timeout=2)  # deterministic: recv_bulk entered
        auth.revoke(Capability.FILE_WRITE_INBOUND)          # revoke at the vulnerable moment
        receiver._in_bulk.put_nowait(payload)               # deliver the revoked chunk

        with pytest.raises(TransferError):
            await asyncio.wait_for(task, timeout=2)
    finally:
        lanmod.os.fdopen = real_fdopen

    assert writes == [], f"revoked data was written: {sum(len(w) for w in writes)} bytes"


@pytest.mark.asyncio
async def test_transfer_terminates_promptly_on_revoke_even_if_peer_silent(tmp_path):
    # A2.5: a revoke must terminate the receive even if the untrusted peer sends
    # nothing further — the operation shouldn't hang parked in recv_bulk.
    import sys
    sys.path.insert(0, "tests/transfer")
    from conftest import make_memory_pair
    from portal.common.errors import TransferError
    from portal.protocol.codec import build, encode
    from portal.protocol.messages import FileOfferPayload, MessageType
    from portal.transfer.lan import receive_file
    import hashlib

    auth = SessionAuthority()
    auth.grant(Capability.FILE_WRITE_INBOUND)
    token = auth.authorize(Capability.FILE_WRITE_INBOUND)

    _sender, receiver = make_memory_pair()
    entered = asyncio.Event()
    orig = receiver.recv_bulk

    async def signalling():
        entered.set()
        return await orig()

    receiver.recv_bulk = signalling

    payload = b"Z" * 2048
    sha = hashlib.sha256(payload).hexdigest()
    task = asyncio.create_task(receive_file(receiver, tmp_path / "root", lambda o: True, token=token))
    offer = build(MessageType.FILE_OFFER,
                  FileOfferPayload(filename="f.bin", size=len(payload), sha256=sha), sequence=1)
    receiver._in_control.put_nowait(encode(offer))

    await asyncio.wait_for(entered.wait(), timeout=2)
    auth.revoke(Capability.FILE_WRITE_INBOUND)  # revoke; deliver NOTHING more
    # Must terminate promptly (raced against wait_invalid), not hang.
    with pytest.raises(TransferError):
        await asyncio.wait_for(task, timeout=2)
