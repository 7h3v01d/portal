# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Adversarial tests for the injection gate — INV-2 / INV-3 total-order property,
one-shot lifecycle (INV-16), and the discriminated submit result."""

from __future__ import annotations

import threading
import time

from portal.input.gate import InjectionGate, SubmitOutcome


def test_open_gate_submits():
    gate = InjectionGate()
    res = gate.submit(lambda: "ran")
    assert res.submitted and res.value == "ran"


def test_closed_gate_drops_submission():
    gate = InjectionGate()
    gate.close()
    ran = []
    res = gate.submit(lambda: ran.append(1))
    assert res.outcome is SubmitOutcome.GATE_CLOSED
    assert ran == [], "critical section ran after gate close"


def test_gate_is_one_shot_never_reopens():
    # INV-16: a closed gate is dead forever; fresh consent must create a NEW gate.
    gate = InjectionGate()
    assert gate.submit(lambda: "x").submitted
    gate.close()
    assert gate.ever_closed
    # There is no reopen path; a fresh gate is required.
    assert not hasattr(gate, "open"), "gate must not expose a reopen method"
    assert gate.submit(lambda: "x").outcome is SubmitOutcome.GATE_CLOSED


def test_submit_result_disambiguates_none_return():
    # A critical section returning None must NOT be confused with a closed gate.
    gate = InjectionGate()
    res = gate.submit(lambda: None)
    assert res.submitted and res.value is None
    gate.close()
    res2 = gate.submit(lambda: None)
    assert res2.outcome is SubmitOutcome.GATE_CLOSED


def test_total_order_under_concurrent_kill():
    # Core INV-2/3: a kill thread closes the gate while a flood of submissions runs
    # on another thread. No critical section may run after close() returns.
    for _ in range(50):
        gate = InjectionGate()
        executed = []
        stop = threading.Event()

        def flood():
            while not stop.is_set():
                gate.submit(lambda: executed.append(1))

        t = threading.Thread(target=flood)
        t.start()
        time.sleep(0.002)
        count_at_close = gate.close()
        stop.set()
        t.join()

        assert len(executed) == count_at_close, (
            f"executed {len(executed)} but gate admitted {count_at_close} — "
            "a critical section ran after close (total order violated)"
        )
        after = []
        gate.submit(lambda: after.append(1))
        assert after == []
