# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Host coordinator — the composed security path (A3).

Everything before this file was a well-built *component*. This is where they
become an enforced *path*: an authenticated connection is classified against the
trust store, an unknown peer may only pair (never operate), a trusted peer still
needs explicit human consent per operation, consent grants a capability, the
capability authorises exactly one operation, and revoke/disconnect tears down all
authority. Nothing here trusts a connection just because it authenticated.

Invariants this coordinator enforces (not assumes):
  - **Trust ≠ authority.** classify_peer decides TRUSTED/UNKNOWN by full-key
    comparison; UNKNOWN peers reach only the pairing path.
  - **Consent is per-operation.** A trusted peer's request runs `confirm_operation`
    before any capability is granted. No consent → no grant → no operation.
  - **One operation at a time (A4b).** While an operation holds the connection, a
    second is refused — so interactive control and file transfer are mutually
    exclusive on one connection. When input injection lands it is just another
    operation under this same lock; the exclusion is policy, not a UI convention.
  - **The coordinator owns the SessionAuthority (B4).** It is created per session,
    lives on this loop, and `revoke_all()` runs on teardown — so a dropped
    connection kills every capability. `emergency_stop()` is the kill-switch hook
    Phase 7 will bind to a hotkey.
"""

from __future__ import annotations

from enum import Enum

from ..common.logging import get_logger, redact

PAIRING_TIMEOUT_SECONDS = 60.0  # an unknown peer must complete pairing within this


class _PairingStep(Enum):
    PAIRED = "paired"                       # key pinned via completed commit — may proceed
    NO_REQUEST = "no_request"               # timed out / disconnected before a request
    NOT_A_PAIR_REQUEST = "not_a_pair_request"  # first message wasn't a pair request
    REJECTED = "rejected"                   # bad code / SAS declined
    NO_COMMIT = "no_commit"                 # accepted but no PAIR_CONFIRM followed
    COMMIT_FAILED = "commit_failed"         # commit nonce/key mismatch
from ..protocol.capabilities import Capability
from ..protocol.codec import build, decode, encode
from ..protocol.messages import (
    EmptyPayload,
    MessageType,
    PairAcceptPayload,
    PairRequestPayload,
)
from ..security.authority import SessionAuthority
from ..security.identity import Ed25519Identity, IdentityStore
from ..security.pairing import PairingManager, PairingOutcome
from ..security.session import TrustStatus, authenticated_peer, classify_peer
from ..stream.publish import ScreenPublisher
from ..transport.base import TransportConnection
from .consent import HostConsent

_log = get_logger("host.coordinator")


class HostCoordinator:
    def __init__(
        self,
        store: IdentityStore,
        identity: Ed25519Identity,
        consent: HostConsent,
        *,
        capture_factory=None,
        encoder_factory=None,
        screen_size: tuple[int, int] = (1920, 1080),
    ) -> None:
        self._store = store
        self._identity = identity
        self._consent = consent
        self._capture_factory = capture_factory
        self._encoder_factory = encoder_factory
        self._screen_w, self._screen_h = screen_size
        self._authority: SessionAuthority | None = None
        self._active_operation: str | None = None

    def emergency_stop(self) -> None:
        """Kill-switch: revoke every capability on the live session at once. Safe
        to call from a hotkey handler. Phase 7 binds this to Ctrl+Alt+Shift+F12."""
        if self._authority is not None:
            self._authority.revoke_all()
            self._active_operation = None  # let the session accept new operations after
            _log.info("emergency stop — all capabilities revoked")

    async def serve(self, conn: TransportConnection, source: str = "unknown") -> None:
        """Handle one authenticated connection through the full path.

        State machine (no fall-through): a connection is in exactly one of
        UNKNOWN or TRUSTED. UNKNOWN may ONLY pair; it reaches a session solely by
        transitioning to TRUSTED via a *completed* pairing (commit → key pinned).
        Any other pairing outcome closes the connection. This makes 'unknown peers
        can only pair, never operate' a structural property, not an incidental one."""
        status = classify_peer(self._store, conn)

        if status is TrustStatus.UNKNOWN:
            outcome = await self._run_pairing(conn, source)
            if outcome is not _PairingStep.PAIRED:
                _log.info("pairing did not complete (%s) — closing", outcome.value)
                await conn.close()
                return

        # SINGLE, UNCONDITIONAL session-entry gate. The trust store is the only
        # source of truth: whether the peer arrived already-trusted or just paired,
        # it MUST be pinned in the store right now to open a session. This one
        # check — not scattered return values — is what makes "unknown/unpaired
        # peers cannot operate" a structural invariant. It is unit-tested directly.
        if not self._may_open_session(conn):
            _log.warning("session entry refused — peer is not a pinned trusted device")
            await conn.close()
            return

        self._authority = SessionAuthority()
        peer = authenticated_peer(conn)
        _log.info("session established with trusted peer %s", redact(peer.device_id))
        try:
            await self._session_loop(conn)
        finally:
            self._teardown()

    def _may_open_session(self, conn: TransportConnection) -> bool:
        """The one gate to a session: the transport-authenticated key must be a
        pinned, trusted device in the store. Deterministically unit-tested."""
        return classify_peer(self._store, conn) is TrustStatus.TRUSTED

    def _teardown(self) -> None:
        if self._authority is not None:
            self._authority.revoke_all()  # disconnect kills all authority
        self._authority = None
        self._active_operation = None

    async def _run_pairing(self, conn: TransportConnection, source: str) -> "_PairingStep":
        """Drive host-side pairing for an unknown peer. Returns PAIRED only if the
        peer's key was actually pinned via a completed commit; every other path
        returns a non-PAIRED status and the caller closes. An unknown peer can
        reach ONLY this method — never an operation."""
        import asyncio

        mgr = PairingManager(self._store, self._identity.identity.public_key)
        code = mgr.begin_pairing()
        await self._consent.notify_pairing_code(code)  # host UI displays it

        try:
            req = decode(await asyncio.wait_for(conn.recv_control(), timeout=PAIRING_TIMEOUT_SECONDS))
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001 — timeout / disconnect
            return _PairingStep.NO_REQUEST
        if req.type is not MessageType.PAIR_REQUEST:
            # An unknown peer's first message MUST be a pair request. Anything else
            # (e.g. STREAM_START) is refused here — it cannot reach a session.
            return _PairingStep.NOT_A_PAIR_REQUEST

        peer_key = conn.peer_public_key  # authenticated by the transport

        from ..security.identity import DeviceIdentity
        from ..security.pairing import PairingConfirmation, compute_sas

        peer_id = DeviceIdentity.from_public_key(peer_key, device_name="")
        sas = compute_sas(self._identity.identity.public_key, peer_key)
        confirmation = PairingConfirmation(peer=peer_id, sas=sas, fingerprint=peer_id.fingerprint())
        approved = await self._consent.confirm_pairing(confirmation)

        result = mgr.handle_request(
            peer_public_key=peer_key,
            code=req.payload.code,
            device_name_hint=req.payload.device_name,
            confirm=lambda _c: approved,
            source=source,
        )
        if result.outcome is not PairingOutcome.PENDING_COMMIT:
            _log.info("pairing rejected: %s", result.outcome.value)
            return _PairingStep.REJECTED

        await conn.send_control(encode(build(
            MessageType.PAIR_ACCEPT,
            PairAcceptPayload(device_name=self._identity.identity.device_name, nonce=result.nonce),
            sequence=1,
        )))
        try:
            confirm = decode(await asyncio.wait_for(conn.recv_control(), timeout=PAIRING_TIMEOUT_SECONDS))
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001
            return _PairingStep.NO_COMMIT
        if confirm.type is not MessageType.PAIR_CONFIRM:
            # Sent something other than the commit (e.g. STREAM_START) — NOT paired.
            return _PairingStep.NO_COMMIT
        committed = mgr.commit(peer_key, confirm.payload.nonce)
        return _PairingStep.PAIRED if committed.ok else _PairingStep.COMMIT_FAILED

    async def _session_loop(self, conn: TransportConnection) -> None:
        """Handle operation requests from a trusted peer, one at a time."""
        while True:
            try:
                msg = decode(await conn.recv_control())
            except Exception:  # noqa: BLE001 — disconnect
                return
            if msg.type is MessageType.STREAM_START:
                await self._handle_screen_request(conn, msg)
            elif msg.type is MessageType.STREAM_STOP:
                continue
            # Other operations (file receive, future input) dispatch here under the
            # same single-operation lock.

    async def _handle_screen_request(self, conn: TransportConnection, start_msg) -> None:
        # Mutual exclusion (A4b): refuse a second operation while one is active.
        if self._active_operation is not None:
            _log.info("screen request refused — operation '%s' already active", self._active_operation)
            return
        peer = authenticated_peer(conn)
        if not await self._consent.confirm_operation(peer, "screen"):
            _log.info("screen request denied by host consent")
            return  # trusted, but no consent -> no grant, no operation

        if self._authority is None:  # real guard, not an assert (-O strips asserts)
            return
        self._authority.grant(Capability.SCREEN_PUBLISH)
        token = self._authority.authorize(Capability.SCREEN_PUBLISH)
        self._active_operation = "screen"
        try:
            capture = self._capture_factory()
            encoder = self._encoder_factory()
            publisher = ScreenPublisher(capture, encoder, token)
            await publisher.serve(
                conn, self._screen_w, self._screen_h, start_msg.payload.fps,
                start_msg.payload.bitrate, start_msg=start_msg,
            )
        finally:
            # Always clear the active operation AND drop the capability, even if
            # the operation crashed — otherwise a wedged flag would refuse all
            # future operations on this session (M1).
            if self._authority is not None:
                self._authority.revoke(Capability.SCREEN_PUBLISH)
            self._active_operation = None
