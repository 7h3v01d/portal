# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The injection gate — the heart of the B5 safety contract (INV-2 / INV-3).

The single most important property: there is a TOTAL ORDER between any injection
submission and revocation. This is a THREADING concern, not an asyncio one, because
the kill-switch is a Windows global hotkey and local-input detection uses OS
callbacks — both run on other OS threads. "No await" is necessary but not
sufficient; the check+submit and the gate-close must contend for one lock.

    submit path                         kill path
    -----------                         ---------
    with gate._lock:                    with gate._lock:
        if gate.open:                       gate.open = False   # linearization pt
            backend.send(...)               (return; async cleanup signalled
            ledger.commit(...)               separately, off the hot path)

Whichever side acquires the lock first wins deterministically:
  - submit first  -> event (and its ledger commit) is strictly BEFORE revocation
  - close first   -> the event cannot be submitted at all

An event already accepted by the OS microseconds before the flip is disclosed
residual risk (a click Windows already queued cannot be un-submitted); the gate
makes the window as small as the OS permits and never pretends to retract it.

This module has NO SendInput and NO asyncio. It takes a `submit` callable so it can
be driven by a FakeInputBackend for the entire adversarial suite before any Windows
backend exists.
"""

from __future__ import annotations

import threading
from typing import Callable, TypeVar

T = TypeVar("T")


class InjectionGateClosed(Exception):
    """Raised (internally) when a submission is attempted after the gate closed.
    Callers see a dropped event, never a delivered one."""


class InjectionGate:
    """A synchronized gate establishing a total order between submit and close.

    Usage (submit side):
        result = gate.submit(lambda: (backend.send(ev), ledger.commit(ev)))
        # returns None if the gate was closed (event dropped), else the callable's
        # return value.

    Usage (kill side, from ANY thread including a Windows hotkey thread):
        gate.close()   # synchronous, no await, no network — the linearization point
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._open = False
        # Number of submissions that actually ran their critical section while open.
        self._submitted = 0
        # Set once close() has run; used by tests/plumbing to assert quiescence.
        self._closed_at_count: int | None = None

    # -- lifecycle -----------------------------------------------------------
    def open(self) -> None:
        """Open the gate (input mode begins). Idempotent."""
        with self._lock:
            self._open = True
            self._closed_at_count = None

    def close(self) -> int:
        """Close the gate — the revocation linearization point. Synchronous and
        lock-guarded so it totally-orders against any in-progress submit. Returns
        the number of submissions that had been admitted before the flip. Safe to
        call from any thread; does NO async work and never touches the network.
        The caller is responsible for signalling asyncio cleanup afterwards via
        loop.call_soon_threadsafe (see emergency-stop plumbing, INV-3)."""
        with self._lock:
            self._open = False
            if self._closed_at_count is None:
                self._closed_at_count = self._submitted
            return self._submitted

    @property
    def is_open(self) -> bool:
        with self._lock:
            return self._open

    # -- submit --------------------------------------------------------------
    def submit(self, critical_section: Callable[[], T]) -> T | None:
        """Run `critical_section` iff the gate is open, atomically with respect to
        close(). The callable MUST contain the whole irreversible unit — the final
        authority re-check, the OS submission, and the ownership-ledger commit —
        so all of it linearizes on the same lock (INV-2, INV-13). Returns the
        callable's result, or None if the gate was closed (event dropped).

        No await, no I/O wait, and nothing that can block indefinitely may appear
        inside `critical_section`: it holds the injection lock that the kill path
        needs, so a stall here would delay emergency stop."""
        with self._lock:
            if not self._open:
                return None
            result = critical_section()
            self._submitted += 1
            return result

    # -- introspection for tests/plumbing ------------------------------------
    @property
    def submitted_count(self) -> int:
        with self._lock:
            return self._submitted
