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
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Generic, TypeVar

T = TypeVar("T")


class InjectionGateClosed(Exception):
    """Raised when a submission is attempted after the gate closed. Callers see a
    dropped event, never a delivered one."""


class SubmitOutcome(str, Enum):
    SUBMITTED = "submitted"
    GATE_CLOSED = "gate_closed"


@dataclass
class SubmitResult(Generic[T]):
    """Discriminated result of a submit — never an ambiguous None sentinel on this
    safety boundary. `outcome` distinguishes \u201cran and returned None\u201d from
    \u201cgate rejected it\u201d; `value` is the critical section's return when SUBMITTED."""
    outcome: SubmitOutcome
    value: T | None = None

    @property
    def submitted(self) -> bool:
        return self.outcome is SubmitOutcome.SUBMITTED


class InjectionGate:
    """A synchronized, ONE-SHOT gate establishing a total order between submit and
    close (INV-2/INV-3). A gate goes open -> closed exactly once and can NEVER be
    reopened: revocation/expiry kills authority, and fresh consent must create a
    NEW gate (INV-16). This makes stale references safe — once a gate has been
    closed, no holder of it can ever inject again.

    Submit side:
        res = gate.submit(lambda: (backend.button(...), ledger.commit(...)))
        if res.submitted: ...        # res.value is the critical section's return
        else: ...                    # SubmitOutcome.GATE_CLOSED — event dropped

    Kill side (any thread, incl. a Windows hotkey thread):
        gate.close()                 # synchronous, no await, no network
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Lifecycle: a gate is created OPEN and can only transition to CLOSED once.
        self._open = True
        self._ever_closed = False
        self._submitted = 0

    def close(self) -> int:
        """Close the gate — the revocation linearization point. Synchronous and
        lock-guarded so it totally-orders against any in-progress submit. Terminal:
        a closed gate is dead forever. Returns the number of submissions admitted
        before the flip. Safe from any thread; does NO async or network work \u2014 the
        caller signals asyncio cleanup afterwards via loop.call_soon_threadsafe."""
        with self._lock:
            self._open = False
            self._ever_closed = True
            return self._submitted

    @property
    def is_open(self) -> bool:
        with self._lock:
            return self._open

    @property
    def ever_closed(self) -> bool:
        with self._lock:
            return self._ever_closed

    def submit(self, critical_section: Callable[[], T]) -> SubmitResult[T]:
        """Run `critical_section` iff the gate is open, atomically with respect to
        close(). The callable MUST contain the whole irreversible unit \u2014 the final
        authority re-check, any legality check, the OS submission, and the
        ownership-ledger commit \u2014 so all of it linearizes on the same lock
        (INV-2, INV-13). Returns a discriminated SubmitResult.

        Nothing inside `critical_section` may await or block indefinitely: it holds
        the injection lock the kill path needs, so a stall would delay emergency
        stop."""
        with self._lock:
            if not self._open:
                return SubmitResult(SubmitOutcome.GATE_CLOSED)
            value = critical_section()
            self._submitted += 1
            return SubmitResult(SubmitOutcome.SUBMITTED, value)

    @property
    def submitted_count(self) -> int:
        with self._lock:
            return self._submitted
