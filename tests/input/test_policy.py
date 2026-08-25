# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""INV-5/15/16/17 policy units, deterministic via injected clock."""

from __future__ import annotations

from portal.input.model import (
    InputEvent, InputKind, MouseButton, SessionRef, ViewRef, new_session_nonce,
)
from portal.input.policy import (
    AuthorityTTL, ClassAwareRateLimiter, ConsentCooldown, PhysicalActivityGate,
)

N = new_session_nonce()


class Clock:
    def __init__(self): self.t = 100.0
    def __call__(self): return self.t
    def advance(self, dt): self.t += dt


def _btn(pressed):
    return InputEvent(kind=InputKind.BUTTON, button=MouseButton.LEFT, pressed=pressed,
                      session=SessionRef(N, 1), view=ViewRef(0, 0))


# -- INV-5 rate limiter -------------------------------------------------------
def test_click_rate_limited():
    c = Clock()
    r = ClassAwareRateLimiter(click_hz=10.0, clock=c)  # 1 per 0.1s
    assert r.allow(_btn(True), is_owned_release=False)
    assert not r.allow(_btn(True), is_owned_release=False)  # too soon
    c.advance(0.11)  # clearly past the 0.1s window (avoid float boundary)
    assert r.allow(_btn(True), is_owned_release=False)


def test_owned_release_never_rate_limited():
    c = Clock()
    r = ClassAwareRateLimiter(click_hz=1.0, clock=c)
    # Even hammering, an owned release is always allowed (INV-5/INV-13).
    for _ in range(100):
        assert r.allow(_btn(False), is_owned_release=True)


def test_move_and_click_have_separate_budgets():
    c = Clock()
    r = ClassAwareRateLimiter(move_hz=1000.0, click_hz=1.0, clock=c)
    move = InputEvent(kind=InputKind.MOVE, display_id="d", x=0.1, y=0.1,
                      session=SessionRef(N, 1), view=ViewRef(0, 0))
    assert r.allow(_btn(True), is_owned_release=False)   # click ok
    assert r.allow(move, is_owned_release=False)         # move ok despite click budget spent


# -- INV-15 physical precedence ----------------------------------------------
def test_physical_move_pauses_then_expires():
    c = Clock()
    p = PhysicalActivityGate(move_pause_s=0.75, clock=c)
    p.note_physical(InputKind.MOVE)
    assert p.is_paused()
    c.advance(0.8)
    assert not p.is_paused()


def test_sustained_physical_activity_wants_revoke():
    c = Clock()
    p = PhysicalActivityGate(move_pause_s=0.75, revoke_after_s=2.0, clock=c)
    p.note_physical(InputKind.MOVE)
    for _ in range(10):
        c.advance(0.3)
        p.note_physical(InputKind.MOVE)  # continuous activity (< move_pause gaps)
    assert p.wants_revoke()


# -- INV-16 TTL ---------------------------------------------------------------
def test_idle_expiry():
    c = Clock()
    t = AuthorityTTL(idle_s=10, max_s=1000, clock=c)
    c.advance(11)
    assert t.expired()


def test_idle_reset_on_activity():
    c = Clock()
    t = AuthorityTTL(idle_s=10, max_s=1000, clock=c)
    c.advance(8)
    t.note_accepted()
    c.advance(8)
    assert not t.expired()  # idle timer reset


def test_absolute_max_expiry_despite_activity():
    c = Clock()
    t = AuthorityTTL(idle_s=10, max_s=100, clock=c)
    for _ in range(20):
        c.advance(6)
        t.note_accepted()  # stays non-idle...
    assert t.expired()      # ...but absolute max still fires


# -- INV-17 consent cooldown --------------------------------------------------
def test_denial_starts_cooldown_and_blocks_reprompt():
    c = Clock()
    cc = ConsentCooldown(cooldown_s=60, clock=c)
    assert cc.request_prompt().allowed
    cc.resolve_prompt(granted=False)          # user denies
    # No auto re-prompt; requests during cooldown are silently rejected.
    assert not cc.request_prompt().allowed
    c.advance(61)
    # Even after cooldown, host must re-enable (no automatic re-prompt).
    assert not cc.request_prompt().allowed
    cc.host_reenable()
    assert cc.request_prompt().allowed


def test_one_prompt_at_a_time():
    c = Clock()
    cc = ConsentCooldown(clock=c)
    assert cc.request_prompt().allowed
    assert not cc.request_prompt().allowed  # already open
    cc.resolve_prompt(granted=True)
    assert cc.request_prompt().allowed      # resolved, can prompt again
