# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The single session-entry gate, tested DETERMINISTICALLY (no transport timing).

`_may_open_session` is the one structural invariant that makes 'unpaired/unknown
peers cannot operate' true: a session opens only for a key pinned in the store.
This test is revert-proof — it fails if the gate is weakened to always-allow."""

from __future__ import annotations

from pathlib import Path

from portal.host.coordinator import HostCoordinator
from portal.host.consent import DenyAllConsent
from portal.security.identity import Ed25519Identity
from portal.security.store import FileIdentityStore


class _Conn:
    def __init__(self, key: bytes):
        self._key = key

    @property
    def peer_public_key(self) -> bytes:
        return self._key


def _coord(store, ident):
    return HostCoordinator(store, ident, DenyAllConsent())


def test_gate_denies_unpinned_key(tmp_path: Path):
    ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    store = FileIdentityStore(tmp_path / "h")
    stranger = Ed25519Identity.generate("Stranger").identity.public_key
    coord = _coord(store, ident)
    # An unpinned (unknown / never-committed) key must NOT open a session.
    assert coord._may_open_session(_Conn(stranger)) is False


def test_gate_allows_pinned_key(tmp_path: Path):
    ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    store = FileIdentityStore(tmp_path / "h")
    leon = Ed25519Identity.generate("Leon").identity
    store.trust(leon)  # pinned
    coord = _coord(store, ident)
    assert coord._may_open_session(_Conn(leon.public_key)) is True


def test_gate_denies_after_key_revoked(tmp_path: Path):
    ident = FileIdentityStore(tmp_path / "h").load_or_create("Dad")
    store = FileIdentityStore(tmp_path / "h")
    leon = Ed25519Identity.generate("Leon").identity
    store.trust(leon)
    store.revoke(leon.public_key)  # un-pinned again
    coord = _coord(store, ident)
    assert coord._may_open_session(_Conn(leon.public_key)) is False
