# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""DXcam capture backend — Windows only.

A thin adapter over DXcam (Desktop Duplication API). All the pacing, pause,
resolution-change, and recovery logic lives in CaptureSession, which is
backend-agnostic and tested on any OS via the synthetic backend; this module is
just "select a display and hand over the latest frame in the Frame contract".

This file imports `dxcam` lazily so the package imports fine on non-Windows; the
backend is exercised on the target Windows rig (the `capture` extra installs
dxcam). It is deliberately small so the untested-here surface is minimal.

Notes for the Windows validation pass (Gate 4):
  - DXcam `grab()` returns None when there is no new frame since the last grab —
    mapped to Frame None (the session simply waits for the next tick).
  - On monitor switch / sleep-wake the Duplication device can be lost; grab()
    then raises, which surfaces as CaptureError and CaptureSession restarts it.
  - Output is requested as BGRA (native Desktop Duplication format) so there is
    no colour conversion on the capture path; stride is width*4, contiguous.
"""

from __future__ import annotations

import time

from ..common.errors import CaptureError
from .base import CaptureBackend, DisplayInfo, Frame, PixelFormat


class DxcamCaptureBackend(CaptureBackend):
    def __init__(self) -> None:
        self._camera = None
        self._dxcam = None
        self._display_index = 0

    def _lazy_import(self):
        if self._dxcam is None:
            try:
                import dxcam  # type: ignore
            except Exception as exc:  # noqa: BLE001
                raise CaptureError(
                    "dxcam is required for screen capture (install the 'capture' extra on Windows)"
                ) from exc
            self._dxcam = dxcam
        return self._dxcam

    def list_displays(self) -> list[DisplayInfo]:
        dxcam = self._lazy_import()
        out: list[DisplayInfo] = []
        # dxcam exposes device/output enumeration; we map outputs to displays.
        try:
            info = dxcam.device_info()  # human-readable; used for names
        except Exception:  # noqa: BLE001
            info = ""
        # Create a transient camera per output to read geometry.
        idx = 0
        while True:
            try:
                cam = dxcam.create(output_idx=idx)
            except Exception:  # noqa: BLE001
                break
            if cam is None:
                break
            try:
                w, h = cam.width, cam.height
            except Exception:  # noqa: BLE001
                w, h = 0, 0
            out.append(
                DisplayInfo(
                    display_id=f"DXGI-{idx}", index=idx, width=w, height=h,
                    name=f"Display {idx}", primary=(idx == 0),
                )
            )
            idx += 1
            if idx > 16:  # sanity bound
                break
        if not out:
            raise CaptureError("no displays found via dxcam")
        return out

    def start(self, display_id: str, target_fps: int = 30) -> None:
        dxcam = self._lazy_import()
        try:
            self._display_index = int(display_id.rsplit("-", 1)[1])
        except (ValueError, IndexError) as exc:
            raise CaptureError(f"bad display_id: {display_id!r}") from exc
        try:
            self._camera = dxcam.create(output_idx=self._display_index, output_color="BGRA")
            # start() enables DXcam's internal capture thread; we still pull
            # latest-frame via grab() and let CaptureSession pace emission.
            self._camera.start(target_fps=target_fps, video_mode=True)
        except Exception as exc:  # noqa: BLE001
            raise CaptureError(f"could not start capture: {exc}") from exc

    def stop(self) -> None:
        if self._camera is not None:
            try:
                self._camera.stop()
            except Exception:  # noqa: BLE001
                pass
            self._camera = None

    def get_frame(self) -> Frame | None:
        if self._camera is None:
            raise CaptureError("capture not started")
        try:
            arr = self._camera.get_latest_frame()
        except Exception as exc:  # noqa: BLE001 — device loss surfaces as CaptureError
            raise CaptureError(f"capture device error: {exc}") from exc
        if arr is None:
            return None
        height, width = arr.shape[0], arr.shape[1]
        return Frame(
            buffer=memoryview(arr.tobytes()),
            width=width,
            height=height,
            stride=width * 4,
            pixel_format=PixelFormat.BGRA8,
            timestamp_ns=time.monotonic_ns(),
            display_id=f"DXGI-{self._display_index}",
        )
