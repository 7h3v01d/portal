# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Gate 2: pairing is attended (SAS ceremony), single-use, expiring, rate-limited,
mutual, and binds trust to the authenticated key — never a peer-supplied one."""

from __future__ import annotations

from pathlib import Path

import pytest

from portal.security.identity import Ed25519Identity, device_id_for
from portal.security.pairing import (
    DEFAULT_MAX_ATTEMPTS,
    ControllerPairing,
    PairingManager,
    PairingOutcome,
    compute_sas,
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


def host(tmp_path: Path, **kw):
    store = FileIdentityStore(tmp_path / "host")
    own = store.load_or_create("Dad-PC").identity.public_key
    mgr = PairingManager(store, own, clock=FakeClock(), **kw)
    return store, own, mgr


def a_key(name="Leon-PC") -> bytes:
    return Ed25519Identity.generate(name).identity.public_key


YES = lambda _c: True   # noqa: E731  (SAS matched)
NO = lambda _c: False   # noqa: E731  (SAS mismatch / declined)


# --- host-side primitive --------------------------------------------------
def test_happy_path_pins_authenticated_key(tmp_path):
    store, _own, mgr = host(tmp_path)
    code = mgr.begin_pairing()
    key = a_key()
    r = mgr.handle_request(key, code, "Leon-PC", confirm=YES)
    assert r.outcome is PairingOutcome.PENDING_COMMIT
    assert r.peer.public_key == key
    assert r.peer.device_id == device_id_for(key)
    assert not store.is_trusted(r.peer)  # not until commit
    committed = mgr.commit(r.nonce)
    assert committed.outcome is PairingOutcome.ACCEPTED
    assert store.is_trusted(committed.peer)


def test_single_use(tmp_path):
    _s, _o, mgr = host(tmp_path)
    code = mgr.begin_pairing()
    mgr.handle_request(a_key(), code, "Leon-PC", confirm=YES)
    again = mgr.handle_request(a_key(), code, "Leon-PC", confirm=YES)
    assert again.outcome is PairingOutcome.NO_ACTIVE_PAIRING


def test_expiry(tmp_path):
    store = FileIdentityStore(tmp_path / "h")
    own = store.load_or_create("Dad").identity.public_key
    clock = FakeClock()
    mgr = PairingManager(store, own, clock=clock, ttl=60)
    code = mgr.begin_pairing()
    clock.advance(61)
    assert mgr.handle_request(a_key(), code, "x", confirm=YES).outcome is PairingOutcome.EXPIRED


def test_wrong_then_exhausted(tmp_path):
    _s, _o, mgr = host(tmp_path, max_attempts=3)
    mgr.begin_pairing()
    assert mgr.handle_request(a_key(), "AAAA-AAAA", "x", confirm=YES).outcome is PairingOutcome.BAD_CODE
    assert mgr.handle_request(a_key(), "AAAA-AAAA", "x", confirm=YES).outcome is PairingOutcome.BAD_CODE
    assert mgr.handle_request(a_key(), "AAAA-AAAA", "x", confirm=YES).outcome is PairingOutcome.EXHAUSTED
    assert not mgr.pairing_active


def test_correct_code_after_exhaustion_fails(tmp_path):
    _s, _o, mgr = host(tmp_path, max_attempts=DEFAULT_MAX_ATTEMPTS)
    code = mgr.begin_pairing()
    for _ in range(DEFAULT_MAX_ATTEMPTS):
        mgr.handle_request(a_key(), "AAAA-AAAA", "x", confirm=YES)
    assert mgr.handle_request(a_key(), code, "Leon-PC", confirm=YES).outcome is PairingOutcome.NO_ACTIVE_PAIRING


def test_declined_sas_does_not_pin(tmp_path):
    store, _o, mgr = host(tmp_path)
    code = mgr.begin_pairing()
    key = a_key()
    r = mgr.handle_request(key, code, "Leon-PC", confirm=NO)
    assert r.outcome is PairingOutcome.DENIED_BY_USER
    assert not store.is_trusted(r.peer)


def test_malformed_peer_key_never_trusted(tmp_path):
    # Finding 3: a non-32-byte key must be refused, not persisted, even with the
    # correct code and an approving user.
    store, _o, mgr = host(tmp_path)
    for bad in [b"", b"\x00", b"\x00" * 31, b"\x00" * 33, b"\x00" * 1024]:
        code = mgr.begin_pairing()
        r = mgr.handle_request(bad, code, "x", confirm=YES)
        assert r.outcome is PairingOutcome.DENIED_BY_USER
    assert store.list_trusted() == []


# --- SAS strength / MITM detection ----------------------------------------
def test_sas_is_order_independent():
    a, b = a_key("A"), a_key("B")
    assert compute_sas(a, b) == compute_sas(b, a)


def test_sas_is_at_least_80_bits():
    # 80 bits = 20 hex chars, rendered in groups of 4.
    import secrets

    sas = compute_sas(secrets.token_bytes(32), secrets.token_bytes(32))
    hex_only = sas.replace("-", "")
    assert len(hex_only) == 20  # 80 bits
    assert all(c in "0123456789ABCDEF" for c in hex_only)


def test_sas_space_has_no_collisions_over_many_pairs():
    # This test FAILS on the old 20-bit SAS (birthday collision well before 5000
    # pairs) and passes on 80-bit. Uses raw 32-byte values, no keygen, for speed.
    import secrets

    seen = set()
    for _ in range(5000):
        sas = compute_sas(secrets.token_bytes(32), secrets.token_bytes(32))
        assert sas not in seen
        seen.add(sas)


def test_sas_resists_key_grinding_attack():
    # The reviewer's exact attack: an active MITM fixes its controller-side key,
    # reads the controller SAS, then grinds a host-side key until the host SAS
    # matches. At 80 bits a bounded search finds nothing.
    import secrets

    controller = a_key("C")
    host_k = a_key("H")
    attacker_ctrl_side = a_key("M1")
    target = compute_sas(controller, attacker_ctrl_side)

    for _ in range(200_000):
        candidate = secrets.token_bytes(32)
        if compute_sas(candidate, host_k) == target:
            raise AssertionError("SAS collision found — entropy too low")
    # No collision in 200k tries (would be near-certain at 20 bits).


# --- controller side + mutual pairing -------------------------------------
def test_controller_pins_host_after_sas(tmp_path):
    cstore = FileIdentityStore(tmp_path / "c")
    controller_key = cstore.load_or_create("Leon-PC").identity.public_key
    host_key = a_key("Dad-PC")
    cp = ControllerPairing(cstore, controller_key, host_key)
    r = cp.handle_accept("Dad-PC", confirm=YES)
    assert r.outcome is PairingOutcome.ACCEPTED
    assert cstore.is_trusted(r.peer)
    assert r.peer.public_key == host_key


def test_controller_and_host_compute_same_sas(tmp_path):
    cstore = FileIdentityStore(tmp_path / "c")
    controller_key = cstore.load_or_create("Leon").identity.public_key
    hstore = FileIdentityStore(tmp_path / "h")
    host_key = hstore.load_or_create("Dad").identity.public_key
    cp = ControllerPairing(cstore, controller_key, host_key)
    assert cp.sas() == compute_sas(host_key, controller_key)


def test_generated_code_charset():
    code = generate_code()
    assert "-" in code and not any(ch in code for ch in "ILO01")
