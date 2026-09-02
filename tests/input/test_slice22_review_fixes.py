# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Slice-2.2 review blockers — composition-seam bugs between good invariants:
  #1 backend count != 1 must NOT commit (confirmed-submission enforced centrally)
  #2 ambiguous submission is FATAL to the session
  #3 live capability token re-checked INSIDE the gate (revoked cap => no injection)
  #4 owned UP survives a stale-view transition (no stuck button)
"""

from __future__ import annotations

import pytest

from portal.input.gate import InjectionGate
from portal.input.ledger import FakeInputBackend, OwnershipLedger
from portal.input.model import (
    InputEvent, InputKind, MouseButton, SessionRef, ViewRef, new_session_nonce,
)
from portal.input.pipeline import InputIntakePipeline, Stage
from portal.input.policy import AuthorityTTL, ClassAwareRateLimiter, PhysicalActivityGate
from portal.input.sequence import SessionSequenceGuard
from portal.input.viewctx import ViewContextRegistry
from portal.security.authority import SessionAuthority
from portal.protocol.capabilities import Capability


class Clock:
    def __init__(self, t=1000.0): self.t = t
    def __call__(self): return self.t
    def advance(self, dt): self.t += dt


class CountBackend:
    """Backend whose submission count is configurable, to attack the confirmed-
    submission rule (returns `count` instead of 1)."""
    def __init__(self, count=1):
        self.count = count
        self.calls = []
    def move(self, x, y, d): self.calls.append(("move", d)); return self.count
    def button(self, b, p): self.calls.append(("button", b, p)); return self.count
    def wheel(self, delta): self.calls.append(("wheel", delta)); return self.count


def _build(clock, backend=None, token=None, on_revoke=None):
    nonce = new_session_nonce()
    gate = InjectionGate()
    ledger = OwnershipLedger()
    backend = backend or FakeInputBackend()
    seq = SessionSequenceGuard(nonce)
    views = ViewContextRegistry(max_age_s=0.5, clock=clock)
    ttl = AuthorityTTL(idle_s=300, max_s=1800, clock=clock)
    physical = PhysicalActivityGate(clock=clock)
    rate = ClassAwareRateLimiter(clock=clock)
    pipe = InputIntakePipeline(gate, ledger, backend, seq, views, ttl, physical, rate,
                               token=token, on_revoke=on_revoke)
    return pipe, gate, ledger, backend, views, nonce


def _move(nonce, seq, view):
    return InputEvent(kind=InputKind.MOVE, display_id="d", x=0.5, y=0.5,
                      session=SessionRef(nonce, seq), view=view)


def _btn(nonce, seq, view, pressed, button=MouseButton.LEFT):
    return InputEvent(kind=InputKind.BUTTON, button=button, pressed=pressed,
                      session=SessionRef(nonce, seq), view=view)


# -- #1: backend count != 1 must not commit ----------------------------------
def test_backend_zero_count_does_not_commit():
    clock = Clock()
    backend = CountBackend(count=0)
    pipe, gate, ledger, _, views, nonce = _build(clock, backend=backend)
    v = views.register_frame()
    r = pipe.handle(_btn(nonce, 0, v, True))
    assert not r.accepted, "count=0 must not be accepted"
    assert not ledger.owns(MouseButton.LEFT), "ledger committed on unconfirmed submission"


def test_backend_two_count_does_not_commit():
    clock = Clock()
    backend = CountBackend(count=2)
    pipe, gate, ledger, _, views, nonce = _build(clock, backend=backend)
    v = views.register_frame()
    r = pipe.handle(_btn(nonce, 0, v, True))
    assert not r.accepted
    assert not ledger.owns(MouseButton.LEFT)


# -- #2: ambiguous submission is fatal ---------------------------------------
def test_ambiguous_submission_is_fatal():
    clock = Clock()
    backend = CountBackend(count=2)  # ambiguous
    revoked = []
    pipe, gate, ledger, _, views, nonce = _build(clock, backend=backend, on_revoke=revoked.append)
    v = views.register_frame()
    r = pipe.handle(_btn(nonce, 0, v, True))
    assert not r.accepted and r.stage is Stage.GATE and r.detail.startswith("fatal")
    assert revoked == ["ambiguous_submission"], "ambiguous submission did not revoke"
    assert not gate.is_open, "gate must close on ambiguous submission"
    # Fatal: even a subsequently 'healthy' event is refused forever.
    backend.count = 1
    v2 = views.register_frame()
    assert pipe.handle(_move(nonce, 1, v2)).detail == "fatal"


# -- #3: live capability re-check inside the gate ----------------------------
def test_revoked_capability_blocks_injection_even_with_open_gate():
    clock = Clock()
    authority = SessionAuthority()
    authority.grant(Capability.INPUT_INJECT_MOUSE)
    token = authority.authorize(Capability.INPUT_INJECT_MOUSE)
    backend = FakeInputBackend()
    revoked = []
    pipe, gate, ledger, _, views, nonce = _build(clock, backend=backend, token=token,
                                                  on_revoke=revoked.append)
    v = views.register_frame()
    assert pipe.handle(_move(nonce, 0, v)).accepted   # works while valid
    assert len(backend.calls) == 1

    # Revoke the CAPABILITY. The gate is still open (synchronization != authority).
    authority.revoke(Capability.INPUT_INJECT_MOUSE)
    assert not token.valid
    assert gate.is_open  # gate itself hasn't been closed

    clock.advance(1.0)  # avoid rate-limiting so the event reaches the gate check
    v2 = views.register_frame()
    r = pipe.handle(_move(nonce, 1, v2))
    assert not r.accepted and r.detail == "capability_revoked", \
        "revoked capability + open gate must NOT inject (A2/B5)"
    assert len(backend.calls) == 1, "no backend call after capability revoke"


# -- #4: owned UP survives a stale-view transition ---------------------------
def test_owned_up_not_dropped_by_stale_view():
    clock = Clock()
    pipe, gate, ledger, backend, views, nonce = _build(clock)
    v = views.register_frame()
    assert pipe.handle(_btn(nonce, 0, v, True)).accepted   # LEFT down
    assert ledger.owns(MouseButton.LEFT)

    # An ordinary view-context change (focus/geometry) bumps the epoch.
    views.bump_epoch()

    # A LEFT UP referencing the OLD view must still release the button, not be
    # dropped at the view stage — otherwise the button is stuck DOWN.
    up = _btn(nonce, 1, v, False)   # old view v (stale epoch)
    r = pipe.handle(up)
    assert r.accepted, "owned UP was dropped by stale-view check (stuck button)"
    assert not ledger.owns(MouseButton.LEFT)
    ups = sum(1 for c in backend.calls if c.kind == "button" and "up" in c.detail)
    assert ups == 1


def test_suspend_view_releases_owned_buttons():
    # The cleaner path: on a view transition the host proactively releases owned
    # buttons before bumping the epoch, so nothing is left held across the gap.
    clock = Clock()
    pipe, gate, ledger, backend, views, nonce = _build(clock)
    v = views.register_frame()
    assert pipe.handle(_btn(nonce, 0, v, True)).accepted
    assert ledger.owns(MouseButton.LEFT)
    result = pipe.suspend_view()
    assert MouseButton.LEFT in result.released
    assert not ledger.owns(MouseButton.LEFT)
