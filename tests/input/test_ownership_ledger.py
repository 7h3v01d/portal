# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Adversarial tests for the ownership ledger — INV-13.

Central property: the ledger commit is atomic with the OS submission (both inside
the gate critical section), so revocation can never observe a button that was
submitted DOWN but not yet recorded. Plus the DOWN/UP legality rules and the fatal
partial-submission handling."""

from __future__ import annotations

import threading
import time

import pytest

from portal.input.gate import InjectionGate
from portal.input.ledger import (
    AmbiguousSubmission, FakeInputBackend, InjectionError, OwnershipLedger,
)
from portal.input.model import MouseButton


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
    out = led.release_all(lambda b: released.append(b))
    assert set(out) == {MouseButton.LEFT, MouseButton.X1}
    assert set(released) == {MouseButton.LEFT, MouseButton.X1}
    assert led.owned == frozenset()


def test_ledger_commit_atomic_with_teardown_no_stuck_button():
    # INV-13 atomicity, the REAL harm: the kill path closes the gate AND runs
    # teardown (release_all) which may land in the window between a backend DOWN
    # submission and its ledger commit. If the commit is atomic with the submit
    # (both inside the gate critical section), teardown either sees the button
    # (releases it) or the submit never ran (nothing pressed) — never a stuck
    # button. We detect a stuck button as a backend DOWN with no matching UP.
    stuck_seen = False
    for _ in range(200):
        gate = InjectionGate()
        gate.open()
        backend = FakeInputBackend()
        led = OwnershipLedger()

        def do_press():
            def cs():
                backend.button(MouseButton.LEFT, True)     # OS submission
                led.commit_button(MouseButton.LEFT, True)  # ledger commit — ATOMIC
                return True
            gate.submit(cs)

        def do_kill():
            gate.close()
            # Teardown releases owned buttons via the backend (best-effort).
            led.release_all(lambda b: backend.button(b, False))

        tp = threading.Thread(target=do_press)
        tk = threading.Thread(target=do_kill)
        tp.start(); tk.start()
        tp.join(); tk.join()

        # The kill path already ran its teardown. With an ATOMIC commit, the
        # ledger must now be EMPTY: either the press ran fully before teardown
        # (which then released the button) or the gate closed first (press
        # dropped, nothing pressed). There is NO rescuing teardown here — a button
        # still owned now is a genuinely stuck button.
        if led.owned != frozenset():
            stuck_seen = True
            break
        downs = sum(1 for c in backend.calls if c.detail == "left:down")
        ups = sum(1 for c in backend.calls if c.detail == "left:up")
        if downs != ups:
            stuck_seen = True
            break
    assert not stuck_seen, "a LEFT DOWN was left without a matching UP — stuck button (INV-13)"



def test_partial_submission_is_fatal():
    backend = FakeInputBackend()
    backend.ambiguous_next = True
    with pytest.raises(AmbiguousSubmission):
        backend.button(MouseButton.LEFT, True)
