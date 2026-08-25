# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Input policy seam — INV-5 (class-aware rate), INV-15 (local-user precedence),
INV-16 (authority TTL), INV-17 (consent cooldown).

Each policy is small, independent, and deterministic (injectable clock). The intake
pipeline composes them in a fixed order AFTER sequence consumption (INV-12) and view
validation (INV-10) and BEFORE the injection gate. A policy never mutates OS or
ledger state — it only says accept/drop for this event.

The one subtlety that is a safety property: INV-5 must NEVER drop an owned-release
(BUTTON_UP for a button Portal holds DOWN). A dropped release is a stuck button.
The rate limiter is therefore told, per event, whether it is an owned release and
exempts it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from .model import InputEvent, InputKind


class PolicyVerdict(str, Enum):
    ACCEPT = "accept"
    RATE_LIMITED = "rate_limited"
    PHYSICAL_PAUSE = "physical_pause"
    EXPIRED = "expired"
    COOLDOWN = "cooldown"          # (consent layer; not on the per-event path)


# --------------------------------------------------------------------------- #
# INV-5 — class-aware rate limiter
# --------------------------------------------------------------------------- #
class ClassAwareRateLimiter:
    """Token-bucket-ish limiter that treats event classes differently (INV-5):
      * MOVE   — coalesced/limited to a motion cadence (latest-wins upstream)
      * BUTTON down / WHEEL — rate-limited (the human-plausible ceiling)
      * BUTTON up for an owned button — a SAFETY RELEASE, never limited
    Deterministic via injected clock. Separate budgets per class so a move flood
    can't consume the button budget."""

    def __init__(self, move_hz: float = 240.0, click_hz: float = 25.0,
                 clock: Callable[[], float] | None = None) -> None:
        self._clock = clock or time.monotonic
        self._min_move_dt = 1.0 / move_hz
        self._min_click_dt = 1.0 / click_hz
        self._last_move = float("-inf")
        self._last_click = float("-inf")

    def allow(self, event: InputEvent, is_owned_release: bool) -> bool:
        now = self._clock()
        # A safety release is exempt from rate limiting (INV-5 / INV-13).
        if is_owned_release:
            return True
        # Monotonic-safety: if the clock ever moves backwards (it should not, since
        # we use time.monotonic, but a bad injected clock or a platform quirk must
        # not open the limiter), treat elapsed as 0 — i.e. deny as "too soon"
        # rather than accept. We never trust `now < last` to mean "plenty of time".
        if event.kind is InputKind.MOVE:
            elapsed = now - self._last_move
            if elapsed < self._min_move_dt:
                return False
            self._last_move = now
            return True
        if event.kind in (InputKind.BUTTON, InputKind.WHEEL):
            elapsed = now - self._last_click
            if elapsed < self._min_click_dt:
                return False
            self._last_click = now
            return True
        return False  # unknown kind: deny (deny-first)


# --------------------------------------------------------------------------- #
# INV-15 — local physical input precedence
# --------------------------------------------------------------------------- #
class PhysicalActivityGate:
    """Pauses remote injection for a grace period after PHYSICAL (non-injected)
    host input (INV-15). A physical MOVE pauses for `move_pause_s` (sliding — each
    new physical move re-arms it); a physical BUTTON/WHEEL pauses immediately for
    `button_pause_s` (stronger takeover signal). Sustained physical activity beyond
    `revoke_after_s` requests revocation (returned as a flag; the pipeline escalates
    to a real revoke). Detection of physical vs injected is the caller's job (on
    Windows, LLMHF_INJECTED); this class is the pure policy."""

    def __init__(self, move_pause_s: float = 0.75, button_pause_s: float = 1.5,
                 revoke_after_s: float = 2.5, clock: Callable[[], float] | None = None) -> None:
        self._clock = clock or time.monotonic
        self._move_pause = move_pause_s
        self._button_pause = button_pause_s
        self._revoke_after = revoke_after_s
        self._paused_until = float("-inf")
        self._activity_start: float | None = None
        self._last_activity: float | None = None

    def note_physical(self, kind: InputKind) -> None:
        """Record a physical (human) event. Extends the pause window and tracks a
        run of sustained activity for possible revocation."""
        now = self._clock()
        pause = self._button_pause if kind in (InputKind.BUTTON, InputKind.WHEEL) else self._move_pause
        self._paused_until = max(self._paused_until, now + pause)
        # Track a run of sustained activity (gaps > move_pause reset the run).
        if self._last_activity is None or (now - self._last_activity) > self._move_pause:
            self._activity_start = now
        self._last_activity = now

    def is_paused(self) -> bool:
        return self._clock() < self._paused_until

    def wants_revoke(self) -> bool:
        """True if physical activity has been sustained past the revoke threshold —
        the human is clearly driving and remote control should end, not just pause."""
        if self._activity_start is None or self._last_activity is None:
            return False
        return (self._last_activity - self._activity_start) >= self._revoke_after


# --------------------------------------------------------------------------- #
# INV-16 — input authority TTL (idle + absolute)
# --------------------------------------------------------------------------- #
class AuthorityTTL:
    """Bounds an input-authority grant's lifetime (INV-16): it expires after
    `idle_s` with no accepted input OR after `max_s` absolute, whichever first.
    Expiry ends injection exactly like a revoke; extending requires fresh consent
    (handled by the consent layer, not here)."""

    def __init__(self, idle_s: float = 300.0, max_s: float = 1800.0,
                 clock: Callable[[], float] | None = None) -> None:
        self._clock = clock or time.monotonic
        self._idle = idle_s
        self._max = max_s
        self._granted_at = self._clock()
        self._last_accepted = self._granted_at

    def note_accepted(self) -> None:
        self._last_accepted = self._clock()

    def expired(self) -> bool:
        now = self._clock()
        if now - self._granted_at >= self._max:
            return True
        if now - self._last_accepted >= self._idle:
            return True
        return False


# --------------------------------------------------------------------------- #
# INV-17 — consent prompt anti-fatigue
# --------------------------------------------------------------------------- #
@dataclass
class ConsentDecision:
    allowed: bool
    reason: str


class ConsentCooldown:
    """Prevents consent-prompt weaponisation (INV-17). At most ONE prompt exists at
    a time; a denial starts a cooldown during which remote requests are rejected
    SILENTLY and cannot raise another prompt; Portal NEVER auto-re-prompts. The host
    must explicitly re-enable a request opportunity."""

    def __init__(self, cooldown_s: float = 60.0, clock: Callable[[], float] | None = None) -> None:
        self._clock = clock or time.monotonic
        self._cooldown = cooldown_s
        self._prompt_open = False
        self._cooldown_until = float("-inf")
        self._host_reenabled = True  # host must re-enable after a denial

    def request_prompt(self) -> ConsentDecision:
        """A remote request to raise a consent prompt. Rejected during cooldown,
        while another prompt is open, or until the host re-enables after a denial."""
        now = self._clock()
        if now < self._cooldown_until:
            return ConsentDecision(False, "cooldown")
        if self._prompt_open:
            return ConsentDecision(False, "prompt_already_open")
        if not self._host_reenabled:
            return ConsentDecision(False, "awaiting_host_reenable")
        self._prompt_open = True
        return ConsentDecision(True, "prompt_opened")

    def resolve_prompt(self, granted: bool) -> None:
        """Resolve the open prompt. A denial starts the cooldown and disables
        further remote-initiated prompts until the host re-enables."""
        self._prompt_open = False
        if not granted:
            self._cooldown_until = self._clock() + self._cooldown
            self._host_reenabled = False

    def host_reenable(self) -> None:
        """The host deliberately allows remote requests to prompt again (never
        automatic)."""
        self._host_reenabled = True
