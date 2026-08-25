# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Pure input data model for Phase 7 (mouse-only MVP).

This module is deliberately free of any OS call, socket, or SendInput reference.
It defines the vocabulary every safety invariant in the B5 design review is stated
against: normalized coordinates, a stable display_id, the host view reference
(view_epoch + frame_seq) that INV-10 requires, and the per-session replay defence
(input_session_nonce + input_seq) that INV-12 requires independent of the transport.

Because it is pure, the InjectionGate, OwnershipLedger, policy seam, and the whole
adversarial suite can be built and revert-proven against it BEFORE any Windows
backend exists — which is the entire point of the B5 build-before-enable ordering.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from enum import Enum


class MouseButton(str, Enum):
    LEFT = "left"
    RIGHT = "right"
    MIDDLE = "middle"
    X1 = "x1"
    X2 = "x2"


class InputKind(str, Enum):
    """Event classes matter for INV-5: they are rate-limited differently, and an
    owned-release (BUTTON_UP for a button Portal holds DOWN) is a safety event that
    ordinary rate limiting must never discard."""
    MOVE = "move"
    BUTTON = "button"
    WHEEL = "wheel"


@dataclass(frozen=True)
class ViewRef:
    """The host view context an input event claims to have been made against
    (INV-10). The controller echoes the epoch and frame_seq it saw; the HOST owns
    the authoritative capture timestamp for that frame_seq and looks it up — the
    controller never supplies the age."""
    view_epoch: int
    frame_seq: int

    def __post_init__(self):
        if type(self.view_epoch) is not int or type(self.frame_seq) is not int:
            raise ValueError("view_epoch and frame_seq must be ints")
        if self.view_epoch < 0 or self.frame_seq < 0:
            raise ValueError("view_epoch and frame_seq must be non-negative")


_UINT64_MAX = 2**64 - 1


@dataclass(frozen=True)
class SessionRef:
    """Per-session replay defence (INV-12), independent of transport/A6. The nonce
    is a host-generated random 128-bit value; input_seq is strictly increasing
    within that nonce and is consumed WHEN SEEN (see InputEvent / the gate)."""
    input_session_nonce: bytes  # 16 bytes / 128 bits
    input_seq: int

    def __post_init__(self):
        if len(self.input_session_nonce) != 16:
            raise ValueError("input_session_nonce must be exactly 16 bytes (128 bits)")
        if type(self.input_seq) is not int:
            raise ValueError("input_seq must be an int")
        if not (0 <= self.input_seq <= _UINT64_MAX):
            raise ValueError(f"input_seq must be a uint64 (0..2^64-1), got {self.input_seq}")


def new_session_nonce() -> bytes:
    """A fresh random 128-bit input-session nonce. Random (not a process-local
    counter) so it cannot collide across restarts (INV-12)."""
    return secrets.token_bytes(16)


@dataclass(frozen=True)
class InputEvent:
    """A single controller-originated input event, fully described and validated
    for shape (not authority — that is the gate's job).

    Coordinates are normalized [0.0, 1.0] against a stable display_id so the
    controller and host may differ in resolution (INV-6). Fields not relevant to a
    kind are None (e.g. a MOVE has no button)."""
    kind: InputKind
    session: SessionRef
    view: ViewRef
    display_id: str | None = None       # required for MOVE
    x: float | None = None              # normalized, required for MOVE
    y: float | None = None              # normalized, required for MOVE
    button: MouseButton | None = None   # required for BUTTON
    pressed: bool | None = None         # required for BUTTON (True=down)
    wheel_delta: int | None = None      # required for WHEEL

    def validate_shape(self) -> None:
        """Structural validation only — INV-6 coordinate bounds and per-kind field
        presence. Raises ValueError on a malformed event. Authority, view freshness,
        rate, and session-sequence checks live in the gate/policy, not here."""
        if self.kind is InputKind.MOVE:
            if self.display_id is None or self.x is None or self.y is None:
                raise ValueError("MOVE requires display_id, x, y")
            if not isinstance(self.display_id, str) or self.display_id == "":
                raise ValueError("display_id must be a non-empty string")
            if type(self.x) not in (int, float) or type(self.y) not in (int, float):
                raise ValueError("coordinates must be numeric")
            if not (0.0 <= self.x <= 1.0) or not (0.0 <= self.y <= 1.0):
                raise ValueError(f"coordinates out of range: ({self.x}, {self.y})")
            if self.button is not None or self.wheel_delta is not None:
                raise ValueError("MOVE must not carry button/wheel fields")
        elif self.kind is InputKind.BUTTON:
            if self.button is None or self.pressed is None:
                raise ValueError("BUTTON requires button and pressed")
            if type(self.pressed) is not bool:
                raise ValueError("pressed must be exactly a bool")
            if not isinstance(self.button, MouseButton):
                raise ValueError("button must be a MouseButton")
            if self.x is not None or self.y is not None or self.wheel_delta is not None:
                raise ValueError("BUTTON must not carry move/wheel fields")
        elif self.kind is InputKind.WHEEL:
            if self.wheel_delta is None:
                raise ValueError("WHEEL requires wheel_delta")
            if type(self.wheel_delta) is not int:
                raise ValueError("wheel_delta must be exactly an int")
            if self.button is not None or self.x is not None or self.y is not None:
                raise ValueError("WHEEL must not carry move/button fields")
        else:  # pragma: no cover - enum is exhaustive
            raise ValueError(f"unknown input kind: {self.kind}")

    def is_owned_release(self) -> bool:
        """True if this is a BUTTON_UP — the class that INV-5 exempts from ordinary
        rate limiting when the button is owned, and INV-13 permits after revoke."""
        return self.kind is InputKind.BUTTON and self.pressed is False
