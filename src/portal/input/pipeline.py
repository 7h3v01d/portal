# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Input intake pipeline — the fixed, safety-critical order every remote event
passes before it can reach the injection gate.

The ORDER is itself an invariant and is asserted by tests:

    1. shape validation           (INV-6)  — malformed event rejected
    2. session sequence consume   (INV-12) — consume-on-seen BEFORE any policy,
                                             so a later drop can't be replayed
    3. view-context freshness     (INV-10) — must reference a current, recent view
    4. authority TTL              (INV-16) — grant not expired
    5. physical-user precedence   (INV-15) — not paused by local human activity
    6. class-aware rate limit     (INV-5)  — owned-release exempt
    7. injection gate + ledger    (INV-2/13) — the atomic critical section

Stages 2 (sequence consume) and 7 (gate) have side effects; the rest are pure
predicates. Sequence consumption MUST precede the pure policies — that is the
property that makes "rate exceeded -> dropped forever" true.

This module drives a backend + ledger through the gate but still contains NO
SendInput: the backend is injected (FakeInputBackend today).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable

from .gate import InjectionGate, SubmitOutcome
from .ledger import OwnershipLedger, legal_button_transition
from .model import InputEvent, InputKind
from .policy import AuthorityTTL, ClassAwareRateLimiter, PhysicalActivityGate
from .sequence import SessionSequenceGuard
from .viewctx import ViewContextRegistry


class Stage(str, Enum):
    SHAPE = "shape"
    SEQUENCE = "sequence"
    VIEW = "view"
    TTL = "ttl"
    PHYSICAL = "physical"
    RATE = "rate"
    LEGALITY = "legality"
    GATE = "gate"


@dataclass(frozen=True)
class IntakeResult:
    accepted: bool
    stage: Stage         # the stage that decided (where an accept passed the gate,
    detail: str = ""     #  or where a drop occurred)


class InputIntakePipeline:
    """Composes the intake stages in fixed order. One instance per host-side input
    session (it owns the sequence guard, TTL, and gate for that session)."""

    def __init__(
        self,
        gate: InjectionGate,
        ledger: OwnershipLedger,
        backend,
        sequence: SessionSequenceGuard,
        views: ViewContextRegistry,
        ttl: AuthorityTTL,
        physical: PhysicalActivityGate,
        rate: ClassAwareRateLimiter,
        on_revoke: "Callable[[str], None] | None" = None,
    ) -> None:
        self._gate = gate
        self._ledger = ledger
        self._backend = backend
        self._seq = sequence
        self._views = views
        self._ttl = ttl
        self._physical = physical
        self._rate = rate
        # Called when the pipeline decides the session must END (not just pause):
        # sustained physical activity (INV-15) or authority expiry (INV-16). The
        # host wires this to tear the session down. The pipeline closes the gate
        # itself and calls this at most once.
        self._on_revoke = on_revoke
        self._revoked = False

    def _revoke(self, reason: str) -> None:
        if self._revoked:
            return
        self._revoked = True
        self._gate.close()  # no further authority-bearing event can be submitted
        # INV-13: releasing owned buttons is a SAFETY action, permitted after the
        # gate closes. Emit UP for everything Portal holds DOWN so revocation never
        # leaves a stuck button. A failed release keeps the button owned (recorded
        # in the ReleaseResult) so the session-end path can retry.
        self._release_result = self._ledger.release_all(
            lambda b: self._backend.button(b, False)
        )
        if self._on_revoke is not None:
            self._on_revoke(reason)

    def handle(self, event: InputEvent) -> IntakeResult:
        # If already revoked, nothing more is accepted (the gate is closed too).
        if self._revoked:
            return IntakeResult(False, Stage.GATE, "revoked")

        # 1. Shape (INV-6). A malformed event never touches session state, and in
        #    particular must NOT consume a sequence number a valid retransmit needs.
        try:
            event.validate_shape()
        except ValueError as exc:
            return IntakeResult(False, Stage.SHAPE, str(exc))

        # 2a. Session attribution (INV-12, part 1). A frame whose nonce doesn't
        #     match THIS session is not ours — reject WITHOUT consuming a sequence.
        if not self._seq.attributes_to_session(event.session):
            return IntakeResult(False, Stage.SEQUENCE, "wrong_session")

        # 2b. Sequence consume-on-seen (INV-12, part 2). Now that the frame is
        #     well-formed and attributable to this session, consume its sequence
        #     BEFORE any droppable policy — so a policy-dropped event can never be
        #     replayed, while a malformed/wrong-session frame never burned a seq a
        #     legitimate retransmit needs.
        sres = self._seq.check(event.session)
        if not sres.accepted:
            return IntakeResult(False, Stage.SEQUENCE, sres.verdict.value)

        # 3. View freshness (INV-10).
        vres = self._views.check(event.view)
        if not vres.accepted:
            return IntakeResult(False, Stage.VIEW, vres.verdict.value)

        # 4. Authority TTL (INV-16). Expiry ENDS the session (revoke), not merely
        #    drops this event.
        if self._ttl.expired():
            self._revoke("ttl_expired")
            return IntakeResult(False, Stage.TTL, "expired")

        # 5. Physical-user precedence (INV-15). Sustained physical activity ENDS the
        #    session; a shorter burst only pauses. An owned-release must still reach
        #    the gate so a held button is released rather than left stuck.
        owned_release = event.is_owned_release() and (
            event.button is not None and self._ledger.owns(event.button)
        )
        if self._physical.wants_revoke():
            self._revoke("physical_takeover")
            # Still let an owned-release through the (now closed) gate? No — the gate
            # is closed; teardown/owned-release is the session-end path's job. Drop.
            return IntakeResult(False, Stage.PHYSICAL, "physical_takeover")
        if self._physical.is_paused() and not owned_release:
            return IntakeResult(False, Stage.PHYSICAL, "paused")

        # 6. Class-aware rate limit (INV-5). Owned-release is exempt.
        if not self._rate.allow(event, owned_release):
            return IntakeResult(False, Stage.RATE, "rate_limited")

        # 7. Injection gate + ledger, one atomic critical section (INV-2/13).
        def critical_section():
            # Button legality re-checked INSIDE the lock (INV-13 — the duplicate
            # DOWN race). Non-button events skip this.
            if event.kind is InputKind.BUTTON:
                if not legal_button_transition(self._ledger, event):
                    return ("illegal", None)
                self._backend.button(event.button, event.pressed)
                self._ledger.commit_button(event.button, event.pressed)
                return ("ok", None)
            if event.kind is InputKind.MOVE:
                self._backend.move(event.x, event.y, event.display_id)
                return ("ok", None)
            if event.kind is InputKind.WHEEL:
                self._backend.wheel(event.wheel_delta)
                return ("ok", None)
            return ("unknown", None)

        result = self._gate.submit(critical_section)
        if result.outcome is SubmitOutcome.GATE_CLOSED:
            return IntakeResult(False, Stage.GATE, "gate_closed")
        status, _ = result.value
        if status != "ok":
            return IntakeResult(False, Stage.LEGALITY, status)

        # A genuinely accepted event refreshes the idle TTL.
        self._ttl.note_accepted()
        return IntakeResult(True, Stage.GATE, "injected")
