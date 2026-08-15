# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""A3.7: two concurrent sessions must not share authority state.

The previous build stored SessionAuthority on the coordinator instance, so a
second session overwrote the first's authority and either session's teardown
revoked the other's. This test fails against that design and passes once authority
lives in a per-session context."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from portal.host.coordinator import HostCoordinator
from portal.host.consent import DenyAllConsent
from portal.protocol.capabilities import Capability
from portal.security.identity import Ed25519Identity
from portal.security.store import FileIdentityStore


class _Conn:
    def __init__(self, key: bytes):
        self._key = key
        self.closed = False

    @property
    def peer_public_key(self) -> bytes:
        return self._key

    async def recv_control(self):
        # Park forever: the test drives session lifecycle directly, not via wire.
        await asyncio.Event().wait()

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_two_sessions_have_independent_authority(tmp_path: Path):
    ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    store = FileIdentityStore(tmp_path / "h")
    a = Ed25519Identity.generate("A").identity
    b = Ed25519Identity.generate("B").identity
    store.trust(a)
    store.trust(b)
    coord = HostCoordinator(store, ident, DenyAllConsent())

    # Start two concurrent sessions.
    s1 = asyncio.create_task(coord.serve(_Conn(a.public_key)))
    s2 = asyncio.create_task(coord.serve(_Conn(b.public_key)))
    await asyncio.sleep(0.05)  # let both enter their session loops

    # Reach into each live session's authority and grant a capability, simulating
    # an in-flight operation on each.
    ctx1 = coord._sessions_for_test()[0]
    ctx2 = coord._sessions_for_test()[1]
    ctx1.authority.grant(Capability.SCREEN_PUBLISH)
    ctx2.authority.grant(Capability.SCREEN_PUBLISH)
    tok2 = ctx2.authority.authorize(Capability.SCREEN_PUBLISH)
    assert tok2.valid

    # Session 1 tears down. It must NOT affect session 2's authority.
    s1.cancel()
    try:
        await s1
    except asyncio.CancelledError:
        pass
    await asyncio.sleep(0.05)

    assert tok2.valid, "session 1 teardown revoked session 2's authority (shared state)"

    s2.cancel()
    try:
        await s2
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_serve_awaits_connection_close_on_teardown(tmp_path: Path):
    # The connection must be actually CLOSED when serve() returns — not merely
    # scheduled (a fire-and-forget close can be dropped if the loop stops right
    # after). Uses a slow close() to distinguish "awaited" from "scheduled".
    ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    store = FileIdentityStore(tmp_path / "h")
    peer = Ed25519Identity.generate("Leon").identity
    store.trust(peer)
    coord = HostCoordinator(store, ident, DenyAllConsent())

    class SlowClosingConn:
        def __init__(self, key):
            self._key = key
            self.closed = False

        @property
        def peer_public_key(self):
            return self._key

        async def recv_control(self):
            raise ConnectionError("peer gone")  # end the session immediately

        async def close(self):
            await asyncio.sleep(0.05)  # slow close
            self.closed = True

    conn = SlowClosingConn(peer.public_key)
    await coord.serve(conn)  # should not return until close() has completed
    assert conn.closed, "serve() returned before the connection was actually closed"
    assert coord._sessions_for_test() == []  # session removed from the registry
