# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Ownership ledger and a fake backend (INV-13), OS-free.

The OwnershipLedger records exactly which buttons Portal has injected as DOWN and
not yet released. Its defining safety property: the ledger commit happens INSIDE
the injection critical section, atomically with the OS submission (see gate.py /
INV-2 / INV-13). If the commit were outside the lock, revocation could observe an
empty ledger between a successful submission and its add, and leave a button stuck
DOWN with no record to release.

Rules (INV-13):
  * DOWN for an already-owned button  -> reject (duplicate)
  * UP   for a non-owned button       -> reject
  * one logical transition = one OS submission, so success is unambiguous
  * on teardown, emit UP only for owned entries, then clear
  * ambiguous/partial submission is fatal: stop, best-effort owned-release

The FakeInputBackend records calls instead of calling Windows, and can be told to
fail or to report an ambiguous/partial result so the adversarial suite can prove
the fatal-condition handling without any OS.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from ..common.errors import PortalError
from .model import InputEvent, InputKind, MouseButton


class InjectionError(PortalError):
    """A backend submission failed or returned an ambiguous result."""


class AmbiguousSubmission(InjectionError):
    """The backend could not confirm exactly one submission — a FATAL input-session
    condition (INV-13 / T-13). The caller must stop normal injection and perform
    best-effort owned-release cleanup."""


@dataclass
class _Submission:
    kind: str
    detail: str


class FakeInputBackend:
    """Records submissions without touching the OS. `submit_*` return the number of
    events accepted; the contract is one-transition = one-submission, so a healthy
    return is always 1. Set `fail_next`/`ambiguous_next` to drive error paths."""

    def __init__(self) -> None:
        self.calls: list[_Submission] = []
        self.fail_next = False
        self.ambiguous_next = False  # simulate return != 1 (partial/ambiguous)

    def _check_faults(self) -> None:
        if self.fail_next:
            self.fail_next = False
            raise InjectionError("simulated backend failure")
        if self.ambiguous_next:
            self.ambiguous_next = False
            raise AmbiguousSubmission("backend accepted != 1 events")

    def move(self, x: float, y: float, display_id: str) -> int:
        self._check_faults()
        self.calls.append(_Submission("move", f"{display_id}:{x:.4f},{y:.4f}"))
        return 1

    def button(self, button: MouseButton, pressed: bool) -> int:
        self._check_faults()
        self.calls.append(_Submission("button", f"{button.value}:{'down' if pressed else 'up'}"))
        return 1

    def wheel(self, delta: int) -> int:
        self._check_faults()
        self.calls.append(_Submission("wheel", str(delta)))
        return 1


class OwnershipLedger:
    """Tracks buttons Portal currently holds DOWN. Not thread-safe on its own — it
    is only ever mutated inside the InjectionGate critical section, which provides
    the serialization (INV-13). A dedicated lock guards teardown, which may be
    invoked from the revocation path."""

    def __init__(self) -> None:
        self._down: set[MouseButton] = set()
        self._lock = threading.Lock()

    def owns(self, button: MouseButton) -> bool:
        with self._lock:
            return button in self._down

    @property
    def owned(self) -> frozenset[MouseButton]:
        with self._lock:
            return frozenset(self._down)

    def commit_button(self, button: MouseButton, pressed: bool) -> None:
        """Record a CONFIRMED button transition. Must be called only after the
        backend confirmed exactly one submission, and only from inside the gate's
        critical section. Enforces the DOWN/UP legality rules (INV-13)."""
        with self._lock:
            if pressed:
                if button in self._down:
                    raise InjectionError(f"duplicate DOWN for owned button {button.value}")
                self._down.add(button)
            else:
                if button not in self._down:
                    raise InjectionError(f"UP for non-owned button {button.value}")
                self._down.discard(button)

    def release_all(self, emit_up) -> list[MouseButton]:
        """Teardown: emit UP for every owned button, then clear. `emit_up(button)`
        performs the actual release submission (best-effort). Returns the buttons
        released. Used on session end / revoke / kill (INV-13). Best-effort: an
        emit failure is swallowed so one stuck button can't block releasing others."""
        with self._lock:
            to_release = list(self._down)
            released: list[MouseButton] = []
            for b in to_release:
                try:
                    emit_up(b)
                    released.append(b)
                except Exception:  # noqa: BLE001 — best-effort cleanup
                    pass
            self._down.clear()
            return released


def legal_button_transition(ledger: OwnershipLedger, event: InputEvent) -> bool:
    """Pre-check the DOWN/UP legality of a BUTTON event without mutating state, so a
    duplicate/illegal transition can be dropped before it reaches the backend."""
    if event.kind is not InputKind.BUTTON or event.button is None:
        return True
    owned = ledger.owns(event.button)
    if event.pressed and owned:
        return False   # duplicate DOWN
    if not event.pressed and not owned:
        return False   # UP for non-owned
    return True
