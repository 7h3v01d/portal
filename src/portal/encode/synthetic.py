# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""A synthetic VideoEncoder so the encode pipeline's control logic — reconfigure
on resolution change, keyframe forcing, encoder-failure recovery — can be tested
deterministically without FFmpeg. It produces tiny fake packets and records what
happened for assertions."""

from __future__ import annotations

from ..capture.base import Frame
from ..common.errors import EncodeError
from .base import EncodedPacket, VideoEncoder


class SyntheticEncoder(VideoEncoder):
    def __init__(self) -> None:
        self._open = False
        self._w = 0
        self._h = 0
        self._pts = 0
        self._force_keyframe = True
        # Observability / test hooks:
        self.open_calls = 0
        self.opened_geometries: list[tuple[int, int]] = []
        self.fail_encode_times = 0
        self.fail_open = False

    def set_encode_failures(self, n: int) -> None:
        self.fail_encode_times = n

    def open(self, width: int, height: int, fps: int, bitrate: int) -> None:
        if self.fail_open:
            raise EncodeError("synthetic open failure")
        self._open = True
        self._w, self._h = width, height
        self._force_keyframe = True
        self.open_calls += 1
        self.opened_geometries.append((width, height))

    def encode(self, frame: Frame) -> list[EncodedPacket]:
        if not self._open:
            raise EncodeError("encoder not open")
        if self.fail_encode_times > 0:
            self.fail_encode_times -= 1
            raise EncodeError("synthetic encode failure")
        is_key = self._force_keyframe
        self._force_keyframe = False
        pkt = EncodedPacket(
            data=bytes([self._pts & 0xFF]),
            is_keyframe=is_key,
            pts=self._pts,
            timestamp_ns=frame.timestamp_ns,
            width=frame.width,
            height=frame.height,
        )
        self._pts += 1
        return [pkt]

    def request_keyframe(self) -> None:
        self._force_keyframe = True

    def flush(self) -> list[EncodedPacket]:
        return []

    def close(self) -> None:
        self._open = False
