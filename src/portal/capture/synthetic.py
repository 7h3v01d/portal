# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""A synthetic CaptureBackend that generates frames in memory.

Two jobs: (1) let the capture pipeline, encoder (Phase 5), and viewer (Phase 6)
be developed and tested on any OS without a Windows capture device; (2) let the
capture session's resilience logic — resolution-change detection and device-loss
recovery — be tested deterministically by making the backend change size or fail
on demand."""

from __future__ import annotations

import time

from ..common.errors import CaptureError
from .base import CaptureBackend, DisplayInfo, Frame, PixelFormat


class SyntheticCaptureBackend(CaptureBackend):
    def __init__(self, width: int = 640, height: int = 360) -> None:
        self._w = width
        self._h = height
        self._running = False
        self._counter = 0
        # Test hooks:
        self.fail_next = 0        # raise CaptureError on the next N get_frame calls
        self.next_size: tuple[int, int] | None = None  # change frame size once

    # --- test hooks ---
    def set_next_size(self, width: int, height: int) -> None:
        self.next_size = (width, height)

    def fail_times(self, n: int) -> None:
        self.fail_next = n

    # --- CaptureBackend ---
    def list_displays(self) -> list[DisplayInfo]:
        return [
            DisplayInfo(display_id="SYN-0", index=0, width=self._w, height=self._h,
                        name="Synthetic Display 0", primary=True),
            DisplayInfo(display_id="SYN-1", index=1, width=1920, height=1080,
                        name="Synthetic Display 1", primary=False),
        ]

    def start(self, display_id: str, target_fps: int = 30) -> None:
        if display_id not in {d.display_id for d in self.list_displays()}:
            raise CaptureError(f"unknown display: {display_id}")
        self._running = True
        self._counter = 0

    def stop(self) -> None:
        self._running = False

    def get_frame(self) -> Frame | None:
        if not self._running:
            raise CaptureError("capture not started")
        if self.fail_next > 0:
            self.fail_next -= 1
            raise CaptureError("synthetic device lost")
        if self.next_size is not None:
            self._w, self._h = self.next_size
            self.next_size = None
        self._counter += 1
        stride = self._w * 4
        # A cheap deterministic pattern; real backends hand over device memory.
        buf = bytearray(stride * self._h)
        buf[0] = self._counter & 0xFF  # something that changes per frame
        return Frame(
            buffer=memoryview(bytes(buf)),
            width=self._w,
            height=self._h,
            stride=stride,
            pixel_format=PixelFormat.BGRA8,
            timestamp_ns=time.monotonic_ns(),
            display_id="SYN-0",
        )
