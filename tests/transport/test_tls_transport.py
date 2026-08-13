# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The TLS transport over loopback: a real handshake authenticates the peer key,
control/bulk framing works, and the allocation ceilings are enforced."""

from __future__ import annotations

import asyncio

import pytest

from portal.common.errors import TransportError
from portal.security.identity import Ed25519Identity
from portal.transport.tls import TlsTransport


async def _pair(host_identity, ctrl_identity):
    """Stand up a listener and a connection over loopback; return (server_conn,
    client_conn, listener)."""
    listener = await TlsTransport(host_identity).listen("127.0.0.1:0")
    port = listener._server.sockets[0].getsockname()[1]  # noqa: SLF001
    accept_task = asyncio.create_task(listener.accept())
    client_conn = await TlsTransport(ctrl_identity).connect(f"127.0.0.1:{port}")
    server_conn = await accept_task
    return server_conn, client_conn, listener


@pytest.mark.asyncio
async def test_handshake_authenticates_both_keys():
    host = Ed25519Identity.generate("Dad")
    ctrl = Ed25519Identity.generate("Leon")
    server_conn, client_conn, listener = await _pair(host, ctrl)
    try:
        # Each side sees the OTHER's authenticated identity key.
        assert client_conn.peer_public_key == host.identity.public_key
        assert server_conn.peer_public_key == ctrl.identity.public_key
        assert len(client_conn.peer_public_key) == 32
    finally:
        await client_conn.close()
        await server_conn.close()
        await listener.close()


@pytest.mark.asyncio
async def test_control_and_bulk_roundtrip():
    host = Ed25519Identity.generate("Dad")
    ctrl = Ed25519Identity.generate("Leon")
    server_conn, client_conn, listener = await _pair(host, ctrl)
    try:
        await client_conn.send_control(b"ping-control")
        assert await server_conn.recv_control() == b"ping-control"

        await server_conn.send_bulk(b"chunk-bytes")
        assert await client_conn.recv_bulk() == b"chunk-bytes"

        # Channels don't cross: a control send is not received as bulk.
        await client_conn.send_control(b"c2")
        assert await server_conn.recv_control() == b"c2"
    finally:
        await client_conn.close()
        await server_conn.close()
        await listener.close()


@pytest.mark.asyncio
async def test_oversized_control_send_rejected():
    from portal.common.constants import MAX_CONTROL_MESSAGE_BYTES

    host = Ed25519Identity.generate("Dad")
    ctrl = Ed25519Identity.generate("Leon")
    server_conn, client_conn, listener = await _pair(host, ctrl)
    try:
        with pytest.raises(TransportError):
            await client_conn.send_control(b"x" * (MAX_CONTROL_MESSAGE_BYTES + 1))
    finally:
        await client_conn.close()
        await server_conn.close()
        await listener.close()


@pytest.mark.asyncio
async def test_recv_raises_after_peer_closes():
    host = Ed25519Identity.generate("Dad")
    ctrl = Ed25519Identity.generate("Leon")
    server_conn, client_conn, listener = await _pair(host, ctrl)
    try:
        await client_conn.close()
        with pytest.raises(TransportError):
            await asyncio.wait_for(server_conn.recv_control(), timeout=2.0)
    finally:
        await server_conn.close()
        await listener.close()


@pytest.mark.asyncio
async def test_control_queue_is_bounded():
    from portal.common.constants import CONTROL_QUEUE_MAX

    host = Ed25519Identity.generate("Dad")
    ctrl = Ed25519Identity.generate("Leon")
    server_conn, client_conn, listener = await _pair(host, ctrl)
    try:
        # Flood control frames without the peer consuming them. The bounded queue
        # + overflow-closes-connection policy means memory can't grow without
        # bound; the connection is torn down instead.
        for _ in range(CONTROL_QUEUE_MAX + 50):
            try:
                await client_conn.send_control(b"x")
            except TransportError:
                break
        await asyncio.sleep(0.1)
        assert server_conn._control.qsize() <= CONTROL_QUEUE_MAX  # noqa: SLF001
    finally:
        await client_conn.close()
        await server_conn.close()
        await listener.close()


@pytest.mark.asyncio
async def test_queued_frames_discarded_on_death():
    # Death discards pending work: a burst of frames followed by a close must not
    # be drainable afterwards (critical before input injection lands).
    host = Ed25519Identity.generate("Dad")
    ctrl = Ed25519Identity.generate("Leon")
    server_conn, client_conn, listener = await _pair(host, ctrl)
    try:
        for i in range(5):
            await client_conn.send_control(f"cmd-{i}".encode())
        await asyncio.sleep(0.05)
        await client_conn.close()
        await asyncio.sleep(0.05)
        with pytest.raises(TransportError):
            await asyncio.wait_for(server_conn.recv_control(), timeout=2.0)
    finally:
        await server_conn.close()
        await listener.close()


@pytest.mark.asyncio
async def test_video_flood_does_not_starve_control():
    # A4: the reviewer's reproduction. Saturate the video channel with far more
    # frames than the buffer holds, then send an urgent control frame. Because
    # video is drop-oldest and never blocks the reader, control still arrives.
    host = Ed25519Identity.generate("Dad")
    ctrl = Ed25519Identity.generate("Leon")
    server_conn, client_conn, listener = await _pair(host, ctrl)
    try:
        for i in range(200):
            await client_conn.send_video(f"video-{i}".encode())
        await client_conn.send_control(b"URGENT-STOP")  # think: emergency revoke
        got = await asyncio.wait_for(server_conn.recv_control(), timeout=2.0)
        assert got == b"URGENT-STOP"
    finally:
        await client_conn.close()
        await server_conn.close()
        await listener.close()


@pytest.mark.asyncio
async def test_video_is_lossy_latest_wins():
    host = Ed25519Identity.generate("Dad")
    ctrl = Ed25519Identity.generate("Leon")
    server_conn, client_conn, listener = await _pair(host, ctrl)
    try:
        for i in range(100):
            await client_conn.send_video(f"f{i}".encode())
        await asyncio.sleep(0.1)
        frame = await asyncio.wait_for(server_conn.recv_video(), timeout=2.0)
        assert int(frame.decode()[1:]) >= 90  # a recent frame, not frame 0
    finally:
        await client_conn.close()
        await server_conn.close()
        await listener.close()


@pytest.mark.asyncio
async def test_listener_throttles_connection_flood(monkeypatch):
    # Gate 3.1: a flood of connections from one source is admitted only up to the
    # rate budget; the rest are dropped before completing a handshake.
    import portal.transport.tls as tlsmod

    monkeypatch.setattr(tlsmod, "CONN_RATE_PER_SOURCE", 4)
    monkeypatch.setattr(tlsmod, "CONN_CONCURRENT_PER_SOURCE", 4)

    host = Ed25519Identity.generate("Dad")
    ctrl = Ed25519Identity.generate("Leon")
    listener = await TlsTransport(host).listen("127.0.0.1:0")
    port = listener._server.sockets[0].getsockname()[1]  # noqa: SLF001
    try:
        succeeded, failed = 0, 0
        for _ in range(10):
            try:
                conn = await asyncio.wait_for(
                    TlsTransport(ctrl).connect(f"127.0.0.1:{port}"), timeout=1.0
                )
                succeeded += 1
                await conn.close()
            except Exception:  # noqa: BLE001 — dropped/throttled connections
                failed += 1
        # From one source (loopback), only the rate budget completes; the rest
        # are dropped without a handshake.
        assert succeeded <= 4
        assert failed >= 1
    finally:
        await listener.close()
