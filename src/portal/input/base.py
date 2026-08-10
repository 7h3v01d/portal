# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Input-injection interface.

Mouse and keyboard events arrive from the controller and are replayed on the
host. Coordinates are normalised 0.0–1.0 so the controlling and remote machines
can differ in resolution — the host maps them to its own display geometry.

The concrete Windows backend (SendInput via ctypes/pywin32) is Phase 7/8. It is
subject to Windows UIPI: a normal-integrity host process can drive normal apps
but not elevated windows or the secure desktop. That boundary is respected, not
worked around — see ROADMAP Phase 20.

Nothing here checks permissions; the host wraps every call in a PermissionGate
so `input.inject.mouse` / `input.inject.keyboard` must be granted first."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum


class MouseButton(str, Enum):
    LEFT = "left"
    RIGHT = "right"
    MIDDLE = "middle"


class InputBackend(ABC):
    @abstractmethod
    def move_mouse(self, x: float, y: float, display_id: str) -> None:
        """Move to normalised (x, y) in [0.0, 1.0] on the given display. Uses the
        stable display_id, not an index, so monitor re-enumeration cannot make
        remote input land on the wrong screen."""

    @abstractmethod
    def mouse_button(self, button: MouseButton, pressed: bool) -> None:
        """Press (True) or release (False) a mouse button."""

    @abstractmethod
    def mouse_wheel(self, delta: int) -> None:
        ...

    @abstractmethod
    def key(self, scan_code: int, pressed: bool) -> None:
        """Press/release by hardware scan code. Sending scan codes rather than
        characters keeps modifier state correct across keyboard layouts."""
