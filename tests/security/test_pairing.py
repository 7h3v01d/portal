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
    committed = mgr.commit(key, r.nonce)
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


def test_wrong_guesses_throttle_the_source_not_the_code(tmp_path):
    # A source spends its own budget and is throttled; the code is NOT burned, so
    # a legitimate pairing can still complete.
    _s, _o, mgr = host(tmp_path, per_source_attempts=3)
    code = mgr.begin_pairing()
    for _ in range(2):
        assert mgr.handle_request(a_key(), "AAAA-AAAA", "x", confirm=YES, source="1.2.3.4").outcome \
            is PairingOutcome.BAD_CODE
    assert mgr.handle_request(a_key(), "AAAA-AAAA", "x", confirm=YES, source="1.2.3.4").outcome \
        is PairingOutcome.SOURCE_THROTTLED
    # The code is still active for everyone else.
    assert mgr.pairing_active


def test_attacker_source_cannot_grief_legitimate_source(tmp_path):
    # The griefing DoS the earlier review flagged: an attacker burning guesses
    # from their IP must not lock out the real user's IP.
    store, _o, mgr = host(tmp_path, per_source_attempts=3)
    code = mgr.begin_pairing()
    for _ in range(5):  # attacker floods and gets throttled
        mgr.handle_request(a_key(), "ZZZZ-ZZZZ", "x", confirm=YES, source="9.9.9.9")
    # The legitimate user, from a different source, still pairs.
    key = a_key()
    r = mgr.handle_request(key, code, "Leon-PC", confirm=YES, source="192.168.0.50")
    assert r.outcome is PairingOutcome.PENDING_COMMIT
    assert mgr.commit(key, r.nonce).outcome is PairingOutcome.ACCEPTED


def test_global_backstop_burns_code(tmp_path):
    # A distributed attempt across many sources still hits a global cap.
    _s, _o, mgr = host(tmp_path, per_source_attempts=2, global_attempts=6)
    mgr.begin_pairing()
    outcomes = []
    for i in range(6):
        outcomes.append(
            mgr.handle_request(a_key(), "AAAA-AAAA", "x", confirm=YES, source=f"src-{i}").outcome
        )
    assert PairingOutcome.EXHAUSTED in outcomes
    assert not mgr.pairing_active


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


def test_sas_is_160_bits():
    # 160-bit output -> ~80-bit generic (birthday) collision resistance.
    import secrets

    sas = compute_sas(secrets.token_bytes(32), secrets.token_bytes(32))
    hex_only = sas.replace("-", "")
    assert len(hex_only) == 40  # 160 bits
    assert all(c in "0123456789ABCDEF" for c in hex_only)


def test_sas_resists_one_sided_preimage():
    # Fixed attacker key on one leg, grind the other: a preimage search (2**n).
    import secrets

    controller, host_k, attacker_ctrl = a_key("C"), a_key("H"), a_key("M1")
    target = compute_sas(controller, attacker_ctrl)
    for _ in range(100_000):
        if compute_sas(secrets.token_bytes(32), host_k) == target:
            raise AssertionError("one-sided collision found")


def _sas_truncated(key_a: bytes, key_b: bytes, bits: int) -> int:
    # Same construction as compute_sas, truncated, for modelling the attack at a
    # tractable width.
    import hashlib

    lo, hi = sorted((bytes(key_a), bytes(key_b)))
    digest = hashlib.sha256(b"portal-sas-v1" + lo + hi).digest()
    return int.from_bytes(digest, "big") & ((1 << bits) - 1)


def test_two_sided_claw_is_the_real_threat_model():
    # This is the model the previous review flagged: an active MITM chooses BOTH
    # keys and searches for SAS(C, M1) == SAS(M2, H) — a birthday/claw search at
    # ~2**(n/2), NOT a 2**n preimage. Demonstrated at a small width so it runs
    # fast, proving the construction has only n/2-bit collision resistance and
    # justifying the 160-bit production output.
    import secrets

    bits = 32  # ~2**16 expected work per side — trivial
    C, H = a_key("C"), a_key("H")
    left: dict[int, bytes] = {}
    for _ in range(200_000):
        m1 = secrets.token_bytes(32)
        left[_sas_truncated(C, m1, bits)] = m1
    found = False
    for _ in range(200_000):
        m2 = secrets.token_bytes(32)
        if _sas_truncated(m2, H, bits) in left:
            found = True
            break
    assert found, "expected a two-sided collision at 32 bits (birthday bound)"


def test_production_sas_output_is_160_bits():
    # Locks the width so the collision resistance stays ~80 bits.
    from portal.security.pairing import SAS_BYTES

    assert SAS_BYTES == 20  # 160 bits


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


def test_begin_pairing_refused_while_awaiting_commit(tmp_path):
    # Finding 2: a pending commit must not silently coexist with a new pairing.
    from portal.common.errors import PairingError

    _s, _o, mgr = host(tmp_path)
    code = mgr.begin_pairing()
    r = mgr.handle_request(a_key(), code, "Leon-PC", confirm=YES)
    assert r.outcome is PairingOutcome.PENDING_COMMIT
    assert mgr.awaiting_commit
    with pytest.raises(PairingError):
        mgr.begin_pairing()
    # After an explicit cancel, a fresh pairing is allowed again.
    mgr.cancel()
    assert isinstance(mgr.begin_pairing(), str)


def test_slow_sas_ceremony_gets_full_commit_ttl(tmp_path):
    # Finding 6: the commit TTL starts after the human finishes the SAS, so a
    # slow ceremony doesn't eat the commit window.
    store = FileIdentityStore(tmp_path / "h")
    own = store.load_or_create("Dad").identity.public_key
    clock = FakeClock()
    mgr = PairingManager(store, own, clock=clock, ttl=100)
    code = mgr.begin_pairing()
    key = a_key()

    def slow_confirm(_c):
        clock.advance(90)  # human takes 90s comparing the SAS
        return True

    r = mgr.handle_request(key, code, "Leon", confirm=slow_confirm)
    assert r.outcome is PairingOutcome.PENDING_COMMIT
    # 90s elapsed during the ceremony, but the commit window is still ~100s.
    clock.advance(50)
    assert mgr.commit(key, r.nonce).outcome is PairingOutcome.ACCEPTED
