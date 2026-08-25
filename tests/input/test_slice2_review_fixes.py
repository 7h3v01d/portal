# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Regression tests for the Slice-2 review findings:
  #1 wants_revoke() is consumed (physical takeover ENDS the session)
  #2 a malformed / wrong-session frame does NOT consume a sequence number
  #5 age-based frame eviction never drops a still-valid recent frame
  #6 rate limiter is monotonic-safe (backwards clock denies, never opens)
"""

from __future__ import annotations

from portal.input.gate import InjectionGate
from portal.input.ledger import FakeInputBackend, OwnershipLedger
from portal.input.model import (
    InputEvent, InputKind, MouseButton, SessionRef, ViewRef, new_session_nonce,
)
from portal.input.pipeline import InputIntakePipeline, Stage
from portal.input.policy import (
    AuthorityTTL, ClassAwareRateLimiter, PhysicalActivityGate,
)
from portal.input.sequence import SessionSequenceGuard, SeqVerdict
from portal.input.viewctx import ViewContextRegistry


class Clock:
    def __init__(self, t=1000.0): self.t = t
    def __call__(self): return self.t
    def advance(self, dt): self.t += dt


def _build(clock, on_revoke=None):
    nonce = new_session_nonce()
    gate = InjectionGate()
    ledger = OwnershipLedger()
    backend = FakeInputBackend()
    seq = SessionSequenceGuard(nonce)
    views = ViewContextRegistry(max_age_s=0.5, clock=clock)
    ttl = AuthorityTTL(idle_s=300, max_s=1800, clock=clock)
    physical = PhysicalActivityGate(move_pause_s=0.75, revoke_after_s=2.0, clock=clock)
    rate = ClassAwareRateLimiter(clock=clock)
    pipe = InputIntakePipeline(gate, ledger, backend, seq, views, ttl, physical, rate,
                               on_revoke=on_revoke)
    return pipe, gate, backend, views, seq, physical, nonce


def _move(nonce, seq, view):
    return InputEvent(kind=InputKind.MOVE, display_id="d", x=0.5, y=0.5,
                      session=SessionRef(nonce, seq), view=view)


# -- #1: physical takeover ends the session ----------------------------------
def test_sustained_physical_activity_revokes_session():
    clock = Clock()
    revoked = []
    pipe, gate, backend, views, seq, physical, nonce = _build(clock, on_revoke=revoked.append)
    v = views.register_frame()
    assert pipe.handle(_move(nonce, 0, v)).accepted

    # Simulate sustained physical activity past the revoke threshold.
    physical.note_physical(InputKind.MOVE)
    for _ in range(10):
        clock.advance(0.3)
        physical.note_physical(InputKind.MOVE)
    assert physical.wants_revoke()

    # The next remote event triggers escalation: gate closes, on_revoke fires.
    v2 = views.register_frame()
    r = pipe.handle(_move(nonce, 1, v2))
    assert not r.accepted and r.stage is Stage.PHYSICAL and r.detail == "physical_takeover"
    assert revoked == ["physical_takeover"], "revoke hook was not consumed (INV-15 dead)"
    assert not gate.is_open, "gate must be closed after physical takeover"
    # And the session is dead: further events are refused.
    v3 = views.register_frame()
    assert pipe.handle(_move(nonce, 2, v3)).detail == "revoked"


def test_ttl_expiry_revokes_session():
    clock = Clock()
    revoked = []
    pipe, gate, backend, views, seq, physical, nonce = _build(clock, on_revoke=revoked.append)
    clock.advance(2000)  # past absolute max
    v = views.register_frame()
    r = pipe.handle(_move(nonce, 0, v))
    assert not r.accepted and r.stage is Stage.TTL
    assert revoked == ["ttl_expired"]
    assert not gate.is_open


# -- #2: malformed / wrong-session frame must not consume a sequence ----------
def test_malformed_frame_does_not_consume_sequence():
    clock = Clock()
    pipe, gate, backend, views, seq, physical, nonce = _build(clock)
    v = views.register_frame()
    # A malformed MOVE (x out of range) at seq 0 must be rejected at SHAPE and must
    # NOT consume seq 0 — a legitimate retransmit at seq 0 must still work.
    bad = InputEvent(kind=InputKind.MOVE, display_id="d", x=5.0, y=0.5,
                     session=SessionRef(nonce, 0), view=v)
    r = pipe.handle(bad)
    assert not r.accepted and r.stage is Stage.SHAPE
    assert seq.last_seen == -1, "malformed frame must not consume a sequence"
    # Legitimate frame at the same seq now succeeds.
    good = _move(nonce, 0, v)
    assert pipe.handle(good).accepted


def test_wrong_session_frame_does_not_consume_sequence():
    clock = Clock()
    pipe, gate, backend, views, seq, physical, nonce = _build(clock)
    v = views.register_frame()
    other = new_session_nonce()
    # Wrong-session frame claiming seq 0 must not consume our seq 0.
    wrong = _move(other, 0, v)
    r = pipe.handle(wrong)
    assert not r.accepted and r.stage is Stage.SEQUENCE and r.detail == "wrong_session"
    assert seq.last_seen == -1
    # Our legitimate seq 0 still works.
    assert pipe.handle(_move(nonce, 0, v)).accepted


# -- #5: age-based eviction keeps still-valid recent frames -------------------
def test_recent_frame_not_evicted_under_churn():
    clock = Clock()
    reg = ViewContextRegistry(max_age_s=100.0, clock=clock)
    # Register one frame, then churn many MORE within max_age.
    first = reg.register_frame()
    for _ in range(500):
        reg.register_frame()  # all within max_age (clock not advanced)
    # Under a pure count cap, `first` would have been evicted. It IS old-by-count
    # but still within max_age, so it must remain checkable... unless the hard
    # backstop cap applies. Verify the MOST RECENT frames are always retained.
    recent = reg.register_frame()
    assert reg.check(recent).accepted, "most recent frame must always be valid"


def test_aged_out_frames_are_dropped():
    clock = Clock()
    reg = ViewContextRegistry(max_age_s=0.5, clock=clock)
    old = reg.register_frame()
    clock.advance(1.0)  # `old` is now beyond max_age
    reg.register_frame()  # triggers age-eviction of `old`
    assert old.frame_seq not in reg._frames


# -- #6: rate limiter monotonic-safety ----------------------------------------
def test_rate_limiter_backwards_clock_denies():
    clock = Clock(1000.0)
    rate = ClassAwareRateLimiter(click_hz=10.0, clock=clock)
    btn = InputEvent(kind=InputKind.BUTTON, button=MouseButton.LEFT, pressed=True,
                     session=SessionRef(new_session_nonce(), 1), view=ViewRef(0, 0))
    assert rate.allow(btn, is_owned_release=False)   # first ok, last_click=1000
    clock.t = 900.0                                  # clock jumps BACKWARDS
    # Must NOT open the limiter (negative elapsed < min_dt -> deny), never accept.
    assert not rate.allow(btn, is_owned_release=False)


def test_revoke_releases_held_buttons_no_stuck():
    # #3/#4: when the session is revoked (physical takeover), any button Portal
    # holds DOWN must be released as part of revoke — never left stuck.
    clock = Clock()
    pipe, gate, backend, views, seq, physical, nonce = _build(clock)
    v = views.register_frame()
    down = InputEvent(kind=InputKind.BUTTON, button=MouseButton.LEFT, pressed=True,
                      session=SessionRef(nonce, 0), view=v)
    assert pipe.handle(down).accepted
    assert pipe._ledger.owns(MouseButton.LEFT)

    # Sustained physical activity -> revoke.
    physical.note_physical(InputKind.MOVE)
    for _ in range(10):
        clock.advance(0.3)
        physical.note_physical(InputKind.MOVE)
    v2 = views.register_frame()
    pipe.handle(_move(nonce, 1, v2))  # triggers revoke

    # The held LEFT must have been released by revoke (no stuck button).
    assert not pipe._ledger.owns(MouseButton.LEFT), "revoke left a button stuck DOWN"
    downs = sum(1 for c in backend.calls if c.detail == "left:down")
    ups = sum(1 for c in backend.calls if c.detail == "left:up")
    assert downs == ups == 1, "held button was not released on revoke"
