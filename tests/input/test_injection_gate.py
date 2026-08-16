# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Adversarial tests for the injection gate — INV-2 / INV-3 total-order property.

The invariant under test: after close() returns, NO further submission's critical
section runs. This is a threading property (the kill-switch is another OS thread),
so the key test actually races a kill thread against a flood of submissions and
asserts that the number of critical sections that ran never exceeds the count the
gate reported at close time — i.e. the two totally order."""

from __future__ import annotations

import threading
import time

from portal.input.gate import InjectionGate


def test_closed_gate_drops_submission():
    gate = InjectionGate()
    gate.open()
    assert gate.submit(lambda: "ran") == "ran"
    gate.close()
    # After close, the critical section must NOT run.
    ran = []
    result = gate.submit(lambda: ran.append(1) or "ran")
    assert result is None
    assert ran == [], "critical section ran after gate close"


def test_reopen_after_close():
    gate = InjectionGate()
    gate.open()
    gate.close()
    assert gate.submit(lambda: "x") is None
    gate.open()
    assert gate.submit(lambda: "x") == "x"


def test_total_order_under_concurrent_kill():
    # The core INV-2/3 property: a kill thread closes the gate while a flood of
    # submissions runs on another thread. Every submission that actually executed
    # its critical section must have done so BEFORE close recorded the count — no
    # critical section may run after close() returns.
    for _ in range(50):  # repeat to shake out scheduling races
        gate = InjectionGate()
        gate.open()
        executed = []
        stop = threading.Event()

        def flood():
            i = 0
            while not stop.is_set():
                # The critical section records that it ran. If the gate is closed,
                # submit returns None and the lambda never runs.
                gate.submit(lambda i=i: executed.append(i))
                i += 1

        t = threading.Thread(target=flood)
        t.start()
        time.sleep(0.002)  # let some submissions through
        count_at_close = gate.close()
        stop.set()
        t.join()

        # No submission's critical section ran after close: the number executed
        # equals exactly the count the gate admitted while open.
        assert len(executed) == count_at_close, (
            f"executed {len(executed)} but gate admitted {count_at_close} — "
            "a critical section ran after close (total order violated)"
        )
        # And no further submit can run now.
        after = []
        gate.submit(lambda: after.append(1))
        assert after == []


def test_submit_result_propagates():
    gate = InjectionGate()
    gate.open()
    assert gate.submit(lambda: 42) == 42
