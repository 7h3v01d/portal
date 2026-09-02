# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Adversarial tests for the ownership ledger — INV-13.

Covers: DOWN/UP legality, atomic commit-with-submit (no stuck button under a
teardown race), failed-release preservation, and the in-gate duplicate-DOWN race."""

from __future__ import annotations

import threading

import pytest

from portal.input.gate import InjectionGate
from portal.input.ledger import (
    AmbiguousSubmission, FakeInputBackend, InjectionError, OwnershipLedger,
    legal_button_transition,
)
from portal.input.model import (
    InputEvent, InputKind, MouseButton, SessionRef, ViewRef, new_session_nonce,
)


def _button_event(button, pressed):
    return InputEvent(kind=InputKind.BUTTON, button=button, pressed=pressed,
                      session=SessionRef(new_session_nonce(), 1), view=ViewRef(0, 0))


def test_down_then_up_tracked():
    led = OwnershipLedger()
    led.commit_button(MouseButton.LEFT, True)
    assert led.owns(MouseButton.LEFT)
    led.commit_button(MouseButton.LEFT, False)
    assert not led.owns(MouseButton.LEFT)


def test_duplicate_down_rejected():
    led = OwnershipLedger()
    led.commit_button(MouseButton.LEFT, True)
    with pytest.raises(InjectionError):
        led.commit_button(MouseButton.LEFT, True)


def test_up_for_non_owned_rejected():
    led = OwnershipLedger()
    with pytest.raises(InjectionError):
        led.commit_button(MouseButton.RIGHT, False)


def test_release_all_emits_up_for_owned_only():
    led = OwnershipLedger()
    led.commit_button(MouseButton.LEFT, True)
    led.commit_button(MouseButton.X1, True)
    released = []
    result = led.release_all(lambda b: (released.append(b), 1)[1])
    assert result.released == frozenset({MouseButton.LEFT, MouseButton.X1})
    assert result.clean
    assert led.owned == frozenset()


def test_failed_release_keeps_button_owned():
    # INV-13: a failed safety release must NOT be forgotten — the button stays
    # owned and the failure is surfaced, so Portal never loses the fact that an
    # input may still be physically DOWN.
    led = OwnershipLedger()
    led.commit_button(MouseButton.LEFT, True)
    led.commit_button(MouseButton.RIGHT, True)

    def emit_up(b):
        if b is MouseButton.LEFT:
            raise RuntimeError("simulated release failure")
        return 1

    result = led.release_all(emit_up)
    assert MouseButton.LEFT in result.failed
    assert MouseButton.RIGHT in result.released
    assert not result.clean
    # LEFT must remain owned; RIGHT was released.
    assert led.owns(MouseButton.LEFT)
    assert not led.owns(MouseButton.RIGHT)


def test_partial_submission_is_fatal():
    backend = FakeInputBackend()
    backend.ambiguous_next = True
    with pytest.raises(AmbiguousSubmission):
        backend.button(MouseButton.LEFT, True)


def test_ledger_commit_atomic_with_teardown_no_stuck_button():
    # INV-13 atomicity: kill-time teardown may land in the window between a backend
    # DOWN and its ledger commit. If commit is atomic with submit (both inside the
    # gate critical section), teardown either sees the button (releases it) or the
    # submit never ran — never a stuck button. Assert no button owned right after
    # the kill teardown (no rescuing final teardown).
    stuck_seen = False
    for _ in range(200):
        gate = InjectionGate()
        backend = FakeInputBackend()
        led = OwnershipLedger()

        def do_press():
            def cs():
                backend.button(MouseButton.LEFT, True)
                led.commit_button(MouseButton.LEFT, True)
                return True
            gate.submit(cs)

        def do_kill():
            gate.close()
            led.release_all(lambda b: backend.button(b, False))

        tp = threading.Thread(target=do_press)
        tk = threading.Thread(target=do_kill)
        tp.start(); tk.start()
        tp.join(); tk.join()

        if led.owned != frozenset():
            stuck_seen = True
            break
        downs = sum(1 for c in backend.calls if c.detail == "left:down")
        ups = sum(1 for c in backend.calls if c.detail == "left:up")
        if downs != ups:
            stuck_seen = True
            break
    assert not stuck_seen, "a LEFT DOWN was left without a matching UP — stuck button (INV-13)"


def test_duplicate_down_race_single_os_submission():
    # INV-13: two simultaneous LEFT_DOWN requests must result in EXACTLY ONE
    # backend LEFT_DOWN. The legality check must be INSIDE the gate critical
    # section (before the backend call), not a pre-check outside it, or both
    # workers observe "not owned" and both submit. A Barrier aligns both threads
    # so the race is forced, not left to chance.
    for _ in range(20):
        gate = InjectionGate()
        backend = FakeInputBackend()
        backend.delay = 0.01  # slow submission so a pre-check outside the gate
        #                       lands during another worker's in-flight submit
        led = OwnershipLedger()
        barrier = threading.Barrier(2)

        def press():
            barrier.wait()  # both threads arrive together, maximising interleave
            def cs():
                # Legality check INSIDE the critical section, before the backend.
                if not legal_button_transition(led, _button_event(MouseButton.LEFT, True)):
                    return False
                backend.button(MouseButton.LEFT, True)
                led.commit_button(MouseButton.LEFT, True)
                return True
            return gate.submit(cs)

        threads = [threading.Thread(target=press) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        downs = sum(1 for c in backend.calls if c.detail == "left:down")
        assert downs == 1, f"expected exactly 1 backend LEFT_DOWN, got {downs}"
        assert led.owns(MouseButton.LEFT)
