# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The session layer turns an authenticated connection into a trust decision by
full-key comparison — trusted proceeds, unknown must pair."""

from __future__ import annotations

from pathlib import Path

from portal.security.identity import DeviceIdentity, Ed25519Identity
from portal.security.session import TrustStatus, authenticated_peer, classify_peer
from portal.security.store import FileIdentityStore
from portal.transport.base import TransportConnection


class _Conn(TransportConnection):
    def __init__(self, key: bytes) -> None:
        self._key = key

    @property
    def peer_public_key(self) -> bytes:
        return self._key

    @property
    def is_connected(self) -> bool:
        return True

    async def send_control(self, data): ...
    async def recv_control(self): ...
    async def send_bulk(self, data): ...
    async def recv_bulk(self): ...
    async def send_video(self, data): ...
    async def recv_video(self): ...
    async def close(self): ...


def test_unknown_peer_must_pair(tmp_path: Path):
    store = FileIdentityStore(tmp_path)
    store.load_or_create("Dad")
    peer_key = Ed25519Identity.generate("Stranger").identity.public_key
    assert classify_peer(store, _Conn(peer_key)) is TrustStatus.UNKNOWN


def test_trusted_peer_proceeds(tmp_path: Path):
    store = FileIdentityStore(tmp_path)
    store.load_or_create("Dad")
    leon = Ed25519Identity.generate("Leon").identity
    store.trust(leon)
    assert classify_peer(store, _Conn(leon.public_key)) is TrustStatus.TRUSTED


def test_authenticated_peer_id_derived_from_key(tmp_path: Path):
    from portal.security.identity import device_id_for

    key = Ed25519Identity.generate("Leon").identity.public_key
    peer = authenticated_peer(_Conn(key))
    assert peer.device_id == device_id_for(key)
