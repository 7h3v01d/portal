# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Screen-capture interface.

The captured-frame contract is fixed here so a backend swap stays a real swap:
everything outside `capture/` sees one representation regardless of whether the
backend is DXcam (NumPy under the hood) or a future native capture path. If the
contract were `image: Any`, the encoder would have to know every backend — which
is not replaceability."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class PixelFormat(str, Enum):
    BGRA8 = "bgra8"  # DXcam / Desktop Duplication native
    RGBA8 = "rgba8"
    RGB8 = "rgb8"


@dataclass(frozen=True)
class DisplayInfo:
    # `display_id` is the stable identifier; `index` can change after
    # disconnect/reconnect, sleep, dock/undock, or a driver reset, so code should
    # prefer `display_id` wherever it persists a monitor reference.
    display_id: str
    index: int
    width: int
    height: int
    name: str
    primary: bool


@dataclass(frozen=True)
class Frame:
    """One captured frame in a backend-independent form.

    Buffer ownership contract: `buffer` is a read-only snapshot that remains valid
    and unmodified for the lifetime of this Frame. A backend that recycles its
    capture memory (DXcam reuses buffers) MUST copy into the Frame so a consumer
    holding it — e.g. the encoder — never encodes memory being overwritten
    underneath it. A higher-performance retain/release scheme can replace copying
    later without changing this consumer-facing guarantee."""

    buffer: memoryview  # read-only; valid & immutable for this Frame's lifetime
    width: int
    height: int
    stride: int         # bytes per row (may exceed width * bytes_per_pixel)
    pixel_format: PixelFormat
    timestamp_ns: int   # monotonic nanoseconds at capture
    display_id: str


class CaptureBackend(ABC):
    @abstractmethod
    def list_displays(self) -> list[DisplayInfo]:
        ...

    @abstractmethod
    def start(self, display_id: str, target_fps: int = 30) -> None:
        ...

    @abstractmethod
    def stop(self) -> None:
        ...

    @abstractmethod
    def get_frame(self) -> Frame | None:
        """Latest frame, or None if none is available yet. Non-blocking."""
