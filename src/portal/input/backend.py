# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The canonical input backend contract (Phase 7, mouse-only MVP).

There is ONE MouseButton and ONE InputEvent, defined in model.py. There is ONE
backend protocol, defined here. Both FakeInputBackend (ledger.py) and the future
WindowsSendInputBackend implement THIS protocol, so the ledger/gate machinery is
identical whether driven by a fake or by real SendInput.

The defining contract, required by INV-13: every method returns the number of
events the backend CONFIRMS it submitted. For the mouse MVP the rule is
one-logical-transition = one-OS-submission, so a healthy return is always 1; any
other value is an ambiguous/partial submission and MUST raise (a FATAL
input-session condition, T-13). The ownership ledger only commits AFTER a confirmed
return of 1.

Coordinates are normalized [0.0, 1.0] against a stable display_id (INV-6). This
module contains no OS call, no ctypes, and no SendInput — the Windows backend is a
separate later slice, wired in only after the safety machinery is hostile-tested.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .model import MouseButton


@runtime_checkable
class InputBackend(Protocol):
    """Confirmed-submission backend. Each call returns the number of OS submissions
    made (must be exactly 1 for a single logical transition); implementations raise
    AmbiguousSubmission (see ledger.py) if they cannot confirm exactly one."""

    def move(self, x: float, y: float, display_id: str) -> int:
        """Move to normalized (x, y) in [0.0, 1.0] on `display_id` (a stable id, not
        an index, so monitor re-enumeration can't send input to the wrong screen)."""
        ...

    def button(self, button: MouseButton, pressed: bool) -> int:
        """Press (True) / release (False) a mouse button. Returns confirmed count."""
        ...

    def wheel(self, delta: int) -> int:
        """Scroll by delta. Returns confirmed count."""
        ...
