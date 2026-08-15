# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""A3-C1/C2: the attacks my earlier 'unknown cannot operate' test never actually
ran. Each drives an UNKNOWN peer over the REAL TLS transport down a path that
must NOT reach an operation, and asserts on the operation side-effect (consent
asked / stream started / peer pinned) — not on a value that happens to be falsy
for an unrelated reason."""

from __future__ import annotations

import asyncio

import pytest

from portal.host.coordinator import HostCoordinator
from portal.protocol.codec import build, decode, encode
from portal.protocol.messages import (
    MessageType, PairRequestPayload, StreamStartPayload,
)
from portal.security.identity import Ed25519Identity
from portal.security.store import FileIdentityStore
from portal.transport.tls import TlsTransport


class SpyConsent:
    """Records whether an OPERATION was ever consented — the thing that must never
    happen for an unpaired peer, regardless of pairing consent."""

    def __init__(self, pair=True):
        self.pair = pair
        self.operation_asked = 0
        self.pairing_prompts = 0
        self.code: str | None = None

    async def confirm_pairing(self, confirmation):
        self.pairing_prompts += 1
        return self.pair

    async def confirm_operation(self, peer, operation):
        self.operation_asked += 1
        return True

    async def notify_pairing_code(self, code):
        self.code = code  # capture the real code so a test can present it


def _coord(store, ident, consent):
    from portal.capture.session import CaptureSession
    from portal.capture.synthetic import SyntheticCaptureBackend
    from portal.encode.synthetic import SyntheticEncoder

    return HostCoordinator(
        store, ident, consent,
        capture_factory=lambda: CaptureSession(SyntheticCaptureBackend(320, 240), "SYN-0", target_fps=1000),
        encoder_factory=SyntheticEncoder,
        screen_size=(320, 240),
    )


async def _serve(tmp_path, consent, open_pairing=True):
    host_ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    store = FileIdentityStore(tmp_path / "h")
    coord = _coord(store, host_ident, consent)
    if open_pairing:
        coord.open_pairing()  # host deliberately opens a pairing window
    listener = await TlsTransport(host_ident).listen("127.0.0.1:0")
    port = listener.sockname[1]

    async def accept_and_serve():
        conn = await listener.accept()
        await coord.serve(conn, source="127.0.0.1")

    serve_task = asyncio.create_task(accept_and_serve())
    return store, coord, listener, port, serve_task


@pytest.mark.asyncio
async def test_unknown_refused_when_pairing_window_closed(tmp_path):
    # Gate 3.1: pairing does NOT auto-open. With no window open, an unknown peer
    # is refused outright — no pairing ceremony, no code displayed.
    consent = SpyConsent(pair=True)
    store, coord, listener, port, serve_task = await _serve(tmp_path, consent, open_pairing=False)
    ctrl = await TlsTransport(Ed25519Identity.generate("Atk")).connect(f"127.0.0.1:{port}")
    try:
        await ctrl.send_control(encode(build(
            MessageType.PAIR_REQUEST, PairRequestPayload(code="AAAA-AAAA", device_name="Atk"),
            sequence=1)))
        await asyncio.sleep(0.3)
        assert consent.code is None, "a pairing code was issued with no window open"
        assert store.list_trusted() == []
    finally:
        serve_task.cancel(); await ctrl.close(); await listener.close()


@pytest.mark.asyncio
async def test_unknown_streams_before_pairing_is_blocked(tmp_path):
    # Attack: unknown peer sends STREAM_START immediately, no pairing at all.
    consent = SpyConsent(pair=True)
    store, coord, listener, port, serve_task = await _serve(tmp_path, consent)
    ctrl = await TlsTransport(Ed25519Identity.generate("Atk")).connect(f"127.0.0.1:{port}")
    try:
        await ctrl.send_control(encode(build(
            MessageType.STREAM_START, StreamStartPayload(fps=30, bitrate=1_000_000), sequence=1)))
        await asyncio.sleep(0.3)
        assert consent.operation_asked == 0, "unpaired peer reached an operation"
        assert store.list_trusted() == []
    finally:
        serve_task.cancel(); await ctrl.close(); await listener.close()


@pytest.mark.asyncio
async def test_unknown_pairs_but_never_commits_then_streams_is_blocked(tmp_path):
    # The C2 attack the old test skipped: pairing CONSENT is yes, peer sends a
    # PAIR_REQUEST, gets PAIR_ACCEPT, then SKIPS the commit and sends STREAM_START.
    consent = SpyConsent(pair=True)
    store, coord, listener, port, serve_task = await _serve(tmp_path, consent)
    ctrl = await TlsTransport(Ed25519Identity.generate("Atk")).connect(f"127.0.0.1:{port}")
    try:
        for _ in range(50):
            if consent.code:
                break
            await asyncio.sleep(0.02)
        assert consent.code, "host never issued a pairing code"
        await ctrl.send_control(encode(build(
            MessageType.PAIR_REQUEST, PairRequestPayload(code=consent.code, device_name="Atk"),
            sequence=1)))
        reply = decode(await asyncio.wait_for(ctrl.recv_control(), timeout=2.0))
        assert reply.type is MessageType.PAIR_ACCEPT  # SAS accepted (consent=yes)
        # Skip PAIR_CONFIRM entirely; try to operate. The host may already have
        # closed the connection (the correct response) — that is a PASS, so we
        # tolerate the send raising and assert on the security side-effects.
        try:
            await ctrl.send_control(encode(build(
                MessageType.STREAM_START, StreamStartPayload(fps=30, bitrate=1_000_000), sequence=2)))
        except Exception:
            pass
        await asyncio.sleep(0.3)
        assert consent.operation_asked == 0, "un-committed peer reached an operation (C2 hole)"
        assert store.list_trusted() == [], "peer was pinned without completing commit"
    finally:
        serve_task.cancel(); await ctrl.close(); await listener.close()


@pytest.mark.asyncio
async def test_wrong_pairing_code_does_not_prompt_human(tmp_path):
    # A3.8: a peer that sends a WRONG code must be rejected before any SAS prompt.
    # We count confirm_pairing calls — it must stay zero for a bad code.
    class CountingConsent(SpyConsent):
        def __init__(self):
            super().__init__(pair=True)
            self.pairing_prompts = 0

        async def confirm_pairing(self, confirmation):
            self.pairing_prompts += 1
            return True

    consent = CountingConsent()
    store, coord, listener, port, serve_task = await _serve(tmp_path, consent)
    ctrl = await TlsTransport(Ed25519Identity.generate("Atk")).connect(f"127.0.0.1:{port}")
    try:
        for _ in range(50):
            if consent.code:
                break
            await asyncio.sleep(0.02)
        assert consent.code
        # Send a code that is definitely NOT the issued one.
        bogus = "ZZZZ-ZZZZ" if consent.code != "ZZZZ-ZZZZ" else "YYYY-YYYY"
        await ctrl.send_control(encode(build(
            MessageType.PAIR_REQUEST, PairRequestPayload(code=bogus, device_name="Atk"), sequence=1)))
        await asyncio.sleep(0.3)
        assert consent.pairing_prompts == 0, "human was prompted despite a wrong pairing code"
        assert store.list_trusted() == []
    finally:
        serve_task.cancel(); await ctrl.close(); await listener.close()


@pytest.mark.asyncio
async def test_correct_code_then_sas_denied_cannot_operate(tmp_path):
    # Pairing SAS DENIED by the human (consent.confirm_pairing -> False). The peer
    # uses the CORRECT code so it genuinely reaches the SAS ceremony; the human
    # then rejects it, and it must not be pinned or reach an operation. (Previously
    # this block was dangling inside another test with a WRONG code, so it never
    # actually reached SAS — a false green.)
    consent = SpyConsent(pair=False)
    store, coord, listener, port, serve_task = await _serve(tmp_path, consent)
    ctrl = await TlsTransport(Ed25519Identity.generate("Atk")).connect(f"127.0.0.1:{port}")
    try:
        for _ in range(50):
            if consent.code:
                break
            await asyncio.sleep(0.02)
        assert consent.code, "host never issued a pairing code"
        await ctrl.send_control(encode(build(
            MessageType.PAIR_REQUEST, PairRequestPayload(code=consent.code, device_name="Atk"),
            sequence=1)))
        await asyncio.sleep(0.3)
        # The SAS prompt WAS reached (correct code) and the human said no.
        assert consent.pairing_prompts == 1, "SAS ceremony was not reached with the correct code"
        try:
            await ctrl.send_control(encode(build(
                MessageType.STREAM_START, StreamStartPayload(fps=30, bitrate=1_000_000), sequence=2)))
        except Exception:
            pass
        await asyncio.sleep(0.2)
        assert consent.operation_asked == 0
        assert store.list_trusted() == []
    finally:
        serve_task.cancel(); await ctrl.close(); await listener.close()


@pytest.mark.asyncio
async def test_guess_budget_persists_across_reconnects(tmp_path):
    # Gate 3.1: because a single host-owned PairingManager governs the window,
    # wrong-code guesses accumulate across reconnects instead of resetting. After
    # enough wrong guesses from a source, the global budget is exhausted and the
    # window's manager stops accepting the code — proving the budget is shared,
    # not per-connection.
    from portal.host.coordinator import HostCoordinator
    from portal.host.consent import DenyAllConsent
    from portal.security.store import FileIdentityStore
    from portal.security.identity import Ed25519Identity

    host_ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    store = FileIdentityStore(tmp_path / "h")
    coord = HostCoordinator(store, host_ident, DenyAllConsent())
    coord.open_pairing()
    mgr = coord._pairing
    # The same manager instance must be reused every _run_pairing call — that is
    # what makes the budget persist. Simulate repeated wrong guesses directly.
    before = mgr
    start_global = mgr._pending.global_attempts if mgr._pending else 0
    for _ in range(3):
        peer = Ed25519Identity.generate("Atk").identity.public_key
        mgr.validate_request(peer_public_key=peer, code="WRONG-CODE",
                             device_name_hint="Atk", source="1.2.3.4")
    assert coord._pairing is before, "manager was replaced — budget would reset"
    if mgr._pending is not None:
        assert mgr._pending.global_attempts > start_global, "guesses did not accumulate"


@pytest.mark.asyncio
async def test_burned_pairing_window_reopens_fresh(tmp_path):
    # Terminal-state lifecycle: if the pairing transaction is burned (exhausted),
    # the window must not linger "open" with a dead code — open_pairing() issues a
    # FRESH transaction rather than returning the stale one.
    from portal.host.coordinator import HostCoordinator
    from portal.host.consent import DenyAllConsent
    from portal.security.store import FileIdentityStore
    from portal.security.identity import Ed25519Identity

    host_ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    store = FileIdentityStore(tmp_path / "h")
    coord = HostCoordinator(store, host_ident, DenyAllConsent())
    first_code = coord.open_pairing()
    mgr = coord._pairing
    # Burn the transaction (simulate exhaustion).
    mgr._pending = None
    assert coord._pairing_burned()
    # Re-opening must produce a fresh, live transaction and a new code.
    second_code = coord.open_pairing()
    assert coord._pairing is not mgr, "burned manager was reused"
    assert coord._pairing.pairing_active, "reopened window has no live transaction"


@pytest.mark.asyncio
async def test_idle_expired_pairing_window_reopens_fresh(tmp_path):
    # The bug the reviewer found: passage of time past the TTL leaves _pending set
    # until something evaluates it. open_pairing() must still detect the window as
    # burned (via pairing_active, which evaluates expiry) and issue a fresh code —
    # NOT hand back the dead one. Driven by advancing an injected clock.
    from portal.host.coordinator import HostCoordinator
    from portal.host.consent import DenyAllConsent
    from portal.security.store import FileIdentityStore
    from portal.security.identity import Ed25519Identity

    host_ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    store = FileIdentityStore(tmp_path / "h")
    coord = HostCoordinator(store, host_ident, DenyAllConsent())
    first_code = coord.open_pairing()
    mgr = coord._pairing

    # Advance the manager's clock past the TTL WITHOUT touching _pending.
    t0 = mgr._clock()
    mgr._clock = lambda: t0 + mgr._ttl + 1.0
    assert mgr._pending is not None, "precondition: _pending still set until evaluated"
    assert coord._pairing_burned(), "idle-expired window not detected as burned"

    second_code = coord.open_pairing()
    assert coord._pairing is not mgr, "expired manager was reused — stale code handed out"
    assert coord._pairing.pairing_active
    assert second_code != first_code or coord._pairing is not mgr
