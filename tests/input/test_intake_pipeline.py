# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""INV ordering — the intake pipeline consumes the sequence BEFORE policy drops,
so a policy-dropped event can never be replayed. Plus stage-attribution checks."""

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


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def advance(self, dt): self.t += dt


def _build(clock, move_hz=240.0, click_hz=25.0):
    nonce = new_session_nonce()
    gate = InjectionGate()
    ledger = OwnershipLedger()
    backend = FakeInputBackend()
    seq = SessionSequenceGuard(nonce)
    views = ViewContextRegistry(max_age_s=0.5, clock=clock)
    ttl = AuthorityTTL(idle_s=300, max_s=1800, clock=clock)
    physical = PhysicalActivityGate(clock=clock)
    rate = ClassAwareRateLimiter(move_hz=move_hz, click_hz=click_hz, clock=clock)
    pipe = InputIntakePipeline(gate, ledger, backend, seq, views, ttl, physical, rate)
    return pipe, backend, views, seq, physical, nonce


def _move(nonce, seq, view, x=0.5, y=0.5):
    return InputEvent(kind=InputKind.MOVE, display_id="d", x=x, y=y,
                      session=SessionRef(nonce, seq), view=view)


def test_accepted_event_reaches_backend():
    clock = Clock()
    pipe, backend, views, seq, physical, nonce = _build(clock)
    v = views.register_frame()
    r = pipe.handle(_move(nonce, 0, v))
    assert r.accepted and r.stage is Stage.GATE
    assert len(backend.calls) == 1


def test_rate_dropped_event_cannot_be_replayed():
    # THE ordering property (INV-12 before INV-5): two moves at the same instant.
    # The second is rate-limited (dropped) — but its sequence was already consumed,
    # so re-sending that same seq later is rejected as stale, not executed.
    clock = Clock()
    pipe, backend, views, seq, physical, nonce = _build(clock, move_hz=1.0)  # 1 move/sec
    v = views.register_frame()

    assert pipe.handle(_move(nonce, 0, v)).accepted           # seq 0 accepted
    r = pipe.handle(_move(nonce, 1, v))                        # seq 1 same instant
    assert not r.accepted and r.stage is Stage.RATE           # dropped by rate limit
    assert seq.last_seen == 1, "sequence 1 must have been consumed despite the drop"

    # Later, even after the rate window opens, replaying seq 1 is stale.
    clock.advance(5.0)
    v2 = views.register_frame()
    replay = InputEvent(kind=InputKind.MOVE, display_id="d", x=0.5, y=0.5,
                        session=SessionRef(nonce, 1), view=v2)
    r2 = pipe.handle(replay)
    assert not r2.accepted and r2.stage is Stage.SEQUENCE     # stale seq, not executed
    assert len(backend.calls) == 1                            # only the first move ran


def test_stale_view_rejected_at_view_stage():
    clock = Clock()
    pipe, backend, views, seq, physical, nonce = _build(clock)
    v = views.register_frame()
    views.bump_epoch()  # topology changed; v is now stale
    r = pipe.handle(_move(nonce, 0, v))
    assert not r.accepted and r.stage is Stage.VIEW


def test_expired_authority_rejected_at_ttl_stage():
    clock = Clock()
    pipe, backend, views, seq, physical, nonce = _build(clock)
    clock.advance(2000)  # past max_s (grant was at construction time)
    v = views.register_frame()  # fresh view AFTER advancing, so only TTL is expired
    r = pipe.handle(_move(nonce, 0, v))
    assert not r.accepted and r.stage is Stage.TTL


def test_physical_pause_blocks_but_allows_owned_release():
    clock = Clock()
    pipe, backend, views, seq, physical, nonce = _build(clock)
    # Press LEFT down first (accepted).
    v = views.register_frame()
    down = InputEvent(kind=InputKind.BUTTON, button=MouseButton.LEFT, pressed=True,
                      session=SessionRef(nonce, 0), view=v)
    assert pipe.handle(down).accepted
    # Physical activity pauses remote injection.
    physical.note_physical(InputKind.MOVE)
    assert physical.is_paused()
    # A normal move is blocked by the pause...
    v2 = views.register_frame()
    blocked = _move(nonce, 1, v2)
    rb = pipe.handle(blocked)
    assert not rb.accepted and rb.stage is Stage.PHYSICAL
    # ...but the owned-release (LEFT up) is allowed through even while paused, so
    # the held button is not left stuck.
    v3 = views.register_frame()
    up = InputEvent(kind=InputKind.BUTTON, button=MouseButton.LEFT, pressed=False,
                    session=SessionRef(nonce, 2), view=v3)
    ru = pipe.handle(up)
    assert ru.accepted, "owned-release must pass even during physical pause"
