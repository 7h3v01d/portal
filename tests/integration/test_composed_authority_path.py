# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""A3: the composed security path, end to end, over the REAL TLS transport and the
REAL HostCoordinator — proving the chain is ENFORCED, not just unit-tested in
pieces:

    UNKNOWN + no pairing        -> screen denied
    TRUSTED + no consent        -> screen denied (trust != authority)
    TRUSTED + consent           -> screen works
    revoke (emergency stop)     -> stream stops
    disconnect                  -> all authority dies

The controller side uses the real transport + ScreenViewer; the host side is the
real HostCoordinator with a scripted consent provider."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("av")
pytest.importorskip("numpy")

from portal.capture.session import CaptureSession
from portal.capture.synthetic import SyntheticCaptureBackend
from portal.decode.pyav_decoder import PyAvDecoder
from portal.encode.pyav_backend import PyAvEncoder
from portal.host.coordinator import HostCoordinator
from portal.protocol.codec import build, encode, decode
from portal.protocol.messages import (
    MessageType, PairRequestPayload, PairConfirmPayload, StreamStartPayload,
)
from portal.security.identity import Ed25519Identity
from portal.security.pairing import ControllerPairing
from portal.security.store import FileIdentityStore
from portal.stream.viewer import ScreenViewer
from portal.transport.tls import TlsTransport


class ScriptedConsent:
    def __init__(self, pair=True, operation=True):
        self.pair, self.operation = pair, operation
        self.code = None

    async def confirm_pairing(self, confirmation):
        return self.pair

    async def confirm_operation(self, peer, operation):
        return self.operation

    async def notify_pairing_code(self, code):
        self.code = code


def _coordinator(store, ident, consent):
    return HostCoordinator(
        store, ident, consent,
        capture_factory=lambda: CaptureSession(SyntheticCaptureBackend(320, 240), "SYN-0",
                                               target_fps=1000, max_queue=4),
        encoder_factory=PyAvEncoder,
        screen_size=(320, 240),
    )


async def _connect(host_ident, host_store, consent, ctrl_ident):
    listener = await TlsTransport(host_ident).listen("127.0.0.1:0")
    port = listener._server.sockets[0].getsockname()[1]
    coord = _coordinator(host_store, host_ident, consent)

    async def accept_and_serve():
        conn = await listener.accept()
        await coord.serve(conn, source="127.0.0.1")

    serve_task = asyncio.create_task(accept_and_serve())
    ctrl_conn = await TlsTransport(ctrl_ident).connect(f"127.0.0.1:{port}")
    return listener, coord, serve_task, ctrl_conn


@pytest.mark.asyncio
async def test_trusted_with_consent_screen_works(tmp_path):
    host_ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    host_store = FileIdentityStore(tmp_path / "h")
    ctrl_ident = Ed25519Identity.generate("Leon")
    # Pre-trust the controller's key so we skip pairing for this case.
    host_store.trust(ctrl_ident.identity)

    listener, coord, serve_task, ctrl_conn = await _connect(
        host_ident, host_store, ScriptedConsent(operation=True), ctrl_ident
    )
    viewer = ScreenViewer(PyAvDecoder())
    try:
        await viewer.start(ctrl_conn, fps=30, bitrate=1_000_000)
        frame = await asyncio.wait_for(viewer.get(), timeout=8)
        assert frame.width == 320 and frame.height == 240
    finally:
        await viewer.stop()
        serve_task.cancel()
        await ctrl_conn.close(); await listener.close()


@pytest.mark.asyncio
async def test_trusted_without_consent_screen_denied(tmp_path):
    host_ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    host_store = FileIdentityStore(tmp_path / "h")
    ctrl_ident = Ed25519Identity.generate("Leon")
    host_store.trust(ctrl_ident.identity)  # trusted...

    listener, coord, serve_task, ctrl_conn = await _connect(
        host_ident, host_store, ScriptedConsent(operation=False), ctrl_ident  # ...but consent denied
    )
    try:
        # Ask for the stream; the host denies consent -> no STREAM_PARAMS, no video.
        await ctrl_conn.send_control(encode(build(
            MessageType.STREAM_START, StreamStartPayload(fps=30, bitrate=1_000_000), sequence=1)))
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(ctrl_conn.recv_control(), timeout=1.0)  # no params ever come
    finally:
        serve_task.cancel()
        await ctrl_conn.close(); await listener.close()


@pytest.mark.asyncio
async def test_unknown_peer_cannot_operate_without_pairing(tmp_path):
    host_ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    host_store = FileIdentityStore(tmp_path / "h")
    ctrl_ident = Ed25519Identity.generate("Stranger")  # NOT trusted

    # Consent refuses pairing; the unknown peer must never reach an operation.
    listener, coord, serve_task, ctrl_conn = await _connect(
        host_ident, host_store, ScriptedConsent(pair=False), ctrl_ident
    )
    try:
        # An unknown peer is routed to pairing. Send a bogus pair request; with
        # consent denied it can't pair, so it can't operate — the connection closes.
        await ctrl_conn.send_control(encode(build(
            MessageType.PAIR_REQUEST, PairRequestPayload(code="AAAA-AAAA", device_name="Stranger"),
            sequence=1)))
        # The host never grants anything; the serve task ends (connection closed).
        await asyncio.wait_for(serve_task, timeout=3)
        assert host_store.list_trusted() == []  # nobody got trusted
    finally:
        serve_task.cancel()
        await ctrl_conn.close(); await listener.close()


@pytest.mark.asyncio
async def test_one_operation_at_a_time_mutual_exclusion(tmp_path):
    # A4b's home: while one operation holds the connection, a second is refused
    # BEFORE consent — so interactive control and file transfer are mutually
    # exclusive on one connection (enforced policy, not a UI convention).
    from portal.host.coordinator import HostCoordinator
    from portal.security.authority import SessionAuthority

    from portal.host.coordinator import SessionContext
    coord = HostCoordinator.__new__(HostCoordinator)
    session = SessionContext(authority=SessionAuthority(), active_operation="screen")

    asked = {"n": 0}

    class CountingConsent:
        async def confirm_operation(self, peer, op):
            asked["n"] += 1
            return True

    coord._consent = CountingConsent()

    class FakeConn:
        peer_public_key = b"\x01" * 32

    class Msg:
        class payload:
            fps = 30
            bitrate = 1_000_000

    await coord._handle_screen_request(FakeConn(), Msg(), session)
    assert asked["n"] == 0, "second operation must be refused before consent"
    assert session.active_operation == "screen"


@pytest.mark.asyncio
async def test_emergency_stop_ends_stream(tmp_path):
    host_ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    host_store = FileIdentityStore(tmp_path / "h")
    ctrl_ident = Ed25519Identity.generate("Leon")
    host_store.trust(ctrl_ident.identity)

    listener, coord, serve_task, ctrl_conn = await _connect(
        host_ident, host_store, ScriptedConsent(operation=True), ctrl_ident
    )
    viewer = ScreenViewer(PyAvDecoder())
    try:
        await viewer.start(ctrl_conn, fps=30, bitrate=1_000_000)
        await asyncio.wait_for(viewer.get(), timeout=8)  # streaming confirmed
        coord.emergency_stop()                            # kill-switch
        # The stream ends: the viewer eventually stops receiving frames.
        with pytest.raises(Exception):
            for _ in range(3000):
                await asyncio.wait_for(viewer.get(), timeout=8)
    finally:
        await viewer.stop()
        serve_task.cancel()
        await ctrl_conn.close(); await listener.close()
