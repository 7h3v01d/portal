# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""On-disk identity store: stable identity across restarts, trust keyed on the
full public key, and passphrase protection of the private key."""

from __future__ import annotations

from pathlib import Path

import pytest

from portal.common.errors import IdentityError
from portal.security.identity import DeviceIdentity, Ed25519Identity
from portal.security.store import FileIdentityStore


def test_identity_is_stable_across_restarts(tmp_path: Path):
    first = FileIdentityStore(tmp_path).load_or_create("Dad-PC")
    second = FileIdentityStore(tmp_path).load_or_create("Dad-PC")
    assert first.identity.device_id == second.identity.device_id
    assert first.identity.public_key == second.identity.public_key


def test_private_key_encrypted_with_passphrase(tmp_path: Path):
    FileIdentityStore(tmp_path, passphrase="correct horse").load_or_create("A")
    # Reload with the right passphrase works...
    reopened = FileIdentityStore(tmp_path, passphrase="correct horse").load_or_create("A")
    assert reopened.identity.public_key
    # ...and the wrong passphrase fails without leaking why.
    with pytest.raises(IdentityError):
        FileIdentityStore(tmp_path, passphrase="wrong").load_or_create("A")


def test_pem_on_disk_is_not_plaintext_key_when_encrypted(tmp_path: Path):
    FileIdentityStore(tmp_path, passphrase="pw").load_or_create("A")
    pem = (tmp_path / "identity.pem").read_text()
    assert "ENCRYPTED" in pem


def _peer(name="Leon-PC") -> DeviceIdentity:
    return Ed25519Identity.generate(name).identity


def test_trust_roundtrip_and_idempotent(tmp_path: Path):
    store = FileIdentityStore(tmp_path)
    peer = _peer()
    assert not store.is_trusted(peer)
    store.trust(peer)
    store.trust(peer)  # idempotent
    assert store.is_trusted(peer)
    assert len(store.list_trusted()) == 1


def test_trust_persists_across_instances(tmp_path: Path):
    peer = _peer()
    FileIdentityStore(tmp_path).trust(peer)
    assert FileIdentityStore(tmp_path).is_trusted(peer)


def test_revoke_by_public_key(tmp_path: Path):
    store = FileIdentityStore(tmp_path)
    peer = _peer()
    store.trust(peer)
    store.revoke(peer.public_key)
    assert not store.is_trusted(peer)


def test_trust_is_keyed_on_full_key_not_display_id(tmp_path: Path):
    # The finding-5 attack: a second device forging the trusted device's display
    # id but presenting a different key must NOT be treated as trusted.
    store = FileIdentityStore(tmp_path)
    real = _peer("Dad-PC")
    store.trust(real)
    attacker_key = Ed25519Identity.generate("attacker").identity.public_key
    spoof = DeviceIdentity(device_id=real.device_id, device_name="Dad-PC", public_key=attacker_key)
    assert real.device_id == spoof.device_id
    assert store.is_trusted(real)
    assert not store.is_trusted(spoof)


def test_get_trusted_peer_is_lookup_only(tmp_path: Path):
    store = FileIdentityStore(tmp_path)
    peer = _peer("Dad-PC")
    store.trust(peer)
    found = store.get_trusted_peer(peer.device_id)
    assert found is not None and found.public_key == peer.public_key
    assert store.get_trusted_peer("0000-0000-0000-0000") is None


def test_malformed_trusted_rows_are_skipped_not_trusted(tmp_path: Path):
    (tmp_path / "trusted.json").write_text('[{"device_id": "x"}, "junk", 123]')
    store = FileIdentityStore(tmp_path)
    assert store.list_trusted() == []


def test_trusted_row_with_non_32_byte_key_is_skipped(tmp_path: Path):
    # Finding 3, persistence side: a stored key that is not canonical Ed25519
    # material must not load as a trusted identity.
    (tmp_path / "trusted.json").write_text(
        '[{"device_id": "AAAA-AAAA-AAAA-AAAA", "device_name": "x", "public_key": "00"}]'
    )
    assert FileIdentityStore(tmp_path).list_trusted() == []


def test_trusted_row_device_id_is_recomputed_from_key(tmp_path: Path):
    # The stored device_id is not trusted; it is derived from the key on load.
    from portal.security.identity import device_id_for

    peer = _peer("Dad-PC")
    store = FileIdentityStore(tmp_path)
    store.trust(peer)
    # Tamper the stored id; the loaded id must still match the key.
    import json
    rows = json.loads((tmp_path / "trusted.json").read_text())
    rows[0]["device_id"] = "FFFF-FFFF-FFFF-FFFF"
    (tmp_path / "trusted.json").write_text(json.dumps(rows))
    loaded = FileIdentityStore(tmp_path).list_trusted()[0]
    assert loaded.device_id == device_id_for(peer.public_key)
