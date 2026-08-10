# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Gate 2: pairing is attended, single-use, expiring, rate-limited, and binds
trust to the authenticated key — never to a peer-supplied identity."""

from __future__ import annotations

from pathlib import Path

import pytest

from portal.security.identity import Ed25519Identity, device_id_for
from portal.security.pairing import (
    DEFAULT_MAX_ATTEMPTS,
    PairingManager,
    PairingOutcome,
    generate_code,
)
from portal.security.store import FileIdentityStore


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def make(tmp_path: Path, **kw):
    store = FileIdentityStore(tmp_path)
    clock = FakeClock()
    mgr = PairingManager(store, clock=clock, **kw)
    return store, clock, mgr


def peer_key() -> bytes:
    return Ed25519Identity.generate("Leon-PC").identity.public_key


def test_happy_path_pins_authenticated_key(tmp_path: Path):
    store, _clock, mgr = make(tmp_path)
    code = mgr.begin_pairing()
    key = peer_key()
    result = mgr.handle_request(key, code, "Leon-PC", confirm=lambda _: True)
    assert result.outcome is PairingOutcome.ACCEPTED
    assert result.peer.public_key == key
    # id is derived from the key, not supplied by the peer.
    assert result.peer.device_id == device_id_for(key)
    assert store.is_trusted(result.peer)


def test_code_is_single_use(tmp_path: Path):
    _store, _clock, mgr = make(tmp_path)
    code = mgr.begin_pairing()
    mgr.handle_request(peer_key(), code, "Leon-PC", confirm=lambda _: True)
    # Replaying the same code finds no active pairing.
    again = mgr.handle_request(peer_key(), code, "Leon-PC", confirm=lambda _: True)
    assert again.outcome is PairingOutcome.NO_ACTIVE_PAIRING


def test_expired_code_rejected(tmp_path: Path):
    _store, clock, mgr = make(tmp_path, ttl=60)
    code = mgr.begin_pairing()
    clock.advance(61)
    result = mgr.handle_request(peer_key(), code, "Leon-PC", confirm=lambda _: True)
    assert result.outcome is PairingOutcome.EXPIRED


def test_wrong_code_rejected_then_exhausted(tmp_path: Path):
    _store, _clock, mgr = make(tmp_path, max_attempts=3)
    mgr.begin_pairing()
    for _ in range(2):
        r = mgr.handle_request(peer_key(), "AAAA-AAAA", "x", confirm=lambda _: True)
        assert r.outcome is PairingOutcome.BAD_CODE
    # Third wrong attempt hits the cap and burns the code.
    r = mgr.handle_request(peer_key(), "AAAA-AAAA", "x", confirm=lambda _: True)
    assert r.outcome is PairingOutcome.EXHAUSTED
    assert not mgr.pairing_active


def test_correct_code_after_exhaustion_fails(tmp_path: Path):
    _store, _clock, mgr = make(tmp_path, max_attempts=DEFAULT_MAX_ATTEMPTS)
    code = mgr.begin_pairing()
    for _ in range(DEFAULT_MAX_ATTEMPTS):
        mgr.handle_request(peer_key(), "AAAA-AAAA", "x", confirm=lambda _: True)
    # Code is burned; even the right code no longer works.
    r = mgr.handle_request(peer_key(), code, "Leon-PC", confirm=lambda _: True)
    assert r.outcome is PairingOutcome.NO_ACTIVE_PAIRING


def test_declined_confirmation_does_not_pin(tmp_path: Path):
    store, _clock, mgr = make(tmp_path)
    code = mgr.begin_pairing()
    key = peer_key()
    r = mgr.handle_request(key, code, "Leon-PC", confirm=lambda _: False)
    assert r.outcome is PairingOutcome.DENIED_BY_USER
    assert not store.is_trusted(r.peer)


def test_no_pairing_when_not_in_pairing_mode(tmp_path: Path):
    _store, _clock, mgr = make(tmp_path)
    r = mgr.handle_request(peer_key(), "AAAA-AAAA", "x", confirm=lambda _: True)
    assert r.outcome is PairingOutcome.NO_ACTIVE_PAIRING


def test_already_trusted_is_idempotent(tmp_path: Path):
    store, _clock, mgr = make(tmp_path)
    key = peer_key()
    code = mgr.begin_pairing()
    mgr.handle_request(key, code, "Leon-PC", confirm=lambda _: True)
    code2 = mgr.begin_pairing()
    # confirm=False, but an already-trusted key short-circuits before the gate.
    r = mgr.handle_request(key, code2, "Leon-PC", confirm=lambda _: False)
    assert r.outcome is PairingOutcome.ALREADY_TRUSTED


def test_payload_supplied_name_is_sanitised(tmp_path: Path):
    _store, _clock, mgr = make(tmp_path)
    code = mgr.begin_pairing()
    with pytest.raises(Exception):
        # A control-character name is rejected by the display-text guard.
        mgr.handle_request(peer_key(), code, "Leon\nPC", confirm=lambda _: True)


def test_generated_code_charset():
    code = generate_code()
    assert "-" in code
    assert all(ch in "ABCDEFGHJKMNPQRSTUVWXYZ23456789-" for ch in code)
    # No ambiguous characters.
    assert not any(ch in code for ch in "ILO01")
