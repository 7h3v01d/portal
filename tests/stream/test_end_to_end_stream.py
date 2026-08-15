# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The whole screen-share loop over the real TLS transport: host captures
(synthetic) -> encodes (real libx264) -> streams over TLS -> viewer decodes to
RGB frames. Plus capability gating and instant revocation."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("av")
pytest.importorskip("numpy")

from portal.capture.session import CaptureSession
from portal.capture.synthetic import SyntheticCaptureBackend
from portal.common.errors import PermissionDeniedError
from portal.decode.pyav_decoder import PyAvDecoder
from portal.encode.pyav_backend import PyAvEncoder
from portal.protocol.capabilities import Capability
from portal.security.authority import SessionAuthority
from portal.security.identity import Ed25519Identity
from portal.stream.publish import ScreenPublisher
from portal.stream.viewer import ScreenViewer
from portal.transport.tls import TlsTransport


async def _tls_pair():
    host_id = Ed25519Identity.generate("Dad")
    ctrl_id = Ed25519Identity.generate("Leon")
    listener = await TlsTransport(host_id).listen("127.0.0.1:0")
    port = listener.sockname[1]  # noqa: SLF001
    accept = asyncio.create_task(listener.accept())
    ctrl_conn = await TlsTransport(ctrl_id).connect(f"127.0.0.1:{port}")
    host_conn = await accept
    return host_conn, ctrl_conn, listener


def _publish_token():
    auth = SessionAuthority()
    auth.grant(Capability.SCREEN_PUBLISH)
    return auth, auth.authorize(Capability.SCREEN_PUBLISH)


@pytest.mark.asyncio
async def test_full_screen_share_loop():
    host_conn, ctrl_conn, listener = await _tls_pair()
    backend = SyntheticCaptureBackend(320, 240)
    capture = CaptureSession(backend, "SYN-0", target_fps=1000, max_queue=4)
    _auth, token = _publish_token()
    publisher = ScreenPublisher(capture, PyAvEncoder(), token)
    viewer = ScreenViewer(PyAvDecoder())

    pub_task = asyncio.create_task(
        publisher.serve(host_conn, width=320, height=240, fps=30, bitrate=1_000_000)
    )
    try:
        await viewer.start(ctrl_conn, fps=30, bitrate=1_000_000)
        assert (viewer.width, viewer.height) == (320, 240)
        # Pull real decoded frames off the wire.
        frame = await asyncio.wait_for(viewer.get(), timeout=8)
        assert frame.width == 320 and frame.height == 240
        assert len(frame.rgb) == 320 * 240 * 3
    finally:
        await viewer.stop()
        pub_task.cancel()
        try:
            await pub_task
        except asyncio.CancelledError:
            pass
        await host_conn.close()
        await ctrl_conn.close()
        await listener.close()


@pytest.mark.asyncio
async def test_publish_requires_screen_capability():
    # A token for the wrong capability must not authorise publishing.
    auth = SessionAuthority()
    auth.grant(Capability.FILE_WRITE_INBOUND)
    wrong = auth.authorize(Capability.FILE_WRITE_INBOUND)
    backend = SyntheticCaptureBackend(320, 240)
    capture = CaptureSession(backend, "SYN-0")
    publisher = ScreenPublisher(capture, PyAvEncoder(), wrong)

    host_conn, ctrl_conn, listener = await _tls_pair()
    try:
        with pytest.raises(PermissionDeniedError):
            await publisher.serve(host_conn, 320, 240, 30, 1_000_000)
    finally:
        await host_conn.close()
        await ctrl_conn.close()
        await listener.close()


@pytest.mark.asyncio
async def test_revoke_stops_the_stream():
    host_conn, ctrl_conn, listener = await _tls_pair()
    backend = SyntheticCaptureBackend(320, 240)
    capture = CaptureSession(backend, "SYN-0", target_fps=1000, max_queue=4)
    auth, token = _publish_token()
    publisher = ScreenPublisher(capture, PyAvEncoder(), token)
    viewer = ScreenViewer(PyAvDecoder())

    pub_task = asyncio.create_task(publisher.serve(host_conn, 320, 240, 30, 1_000_000))
    try:
        await viewer.start(ctrl_conn, fps=30, bitrate=1_000_000)
        await asyncio.wait_for(viewer.get(), timeout=8)  # streaming confirmed
        auth.revoke(Capability.SCREEN_PUBLISH)             # pull authority
        # The publisher stops; the viewer's stream ends (get eventually raises).
        with pytest.raises(Exception):
            for _ in range(2000):
                await asyncio.wait_for(viewer.get(), timeout=8)
    finally:
        await viewer.stop()
        pub_task.cancel()
        try:
            await pub_task
        except asyncio.CancelledError:
            pass
        await host_conn.close()
        await ctrl_conn.close()
        await listener.close()
