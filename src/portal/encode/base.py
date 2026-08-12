# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Video encoder interface — the seam between raw captured frames and the
compressed stream that crosses the network.

Like capture and transport, the encoder is a replaceable backend behind this
interface: a real PyAV/libx264 backend for shipping, a synthetic one for testing
the pipeline logic (reconfigure, failure recovery) without FFmpeg."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..capture.base import Frame


@dataclass(frozen=True)
class EncodedPacket:
    """One encoded, network-ready unit. `is_keyframe` marks a self-contained IDR
    a receiver can start decoding from; non-keyframes depend on prior packets."""

    data: bytes
    is_keyframe: bool
    pts: int              # presentation timestamp in encoder time base
    timestamp_ns: int     # monotonic capture time carried through, for latency stats
    width: int
    height: int


class VideoEncoder(ABC):
    """Encodes BGRA frames to a compressed bitstream. Configured for low latency
    (each input frame yields at most one output packet; no reordering) so remote
    control stays responsive."""

    @abstractmethod
    def open(self, width: int, height: int, fps: int, bitrate: int) -> None:
        """Prepare the encoder for a given geometry. Called again to reconfigure
        after a resolution change (the pipeline forces a keyframe afterwards)."""

    @abstractmethod
    def encode(self, frame: Frame) -> list[EncodedPacket]:
        """Encode one frame. May return zero packets (encoder buffering) or one;
        raises EncodeError on failure."""

    @abstractmethod
    def request_keyframe(self) -> None:
        """Force the next encoded frame to be a keyframe (IDR) — used on
        reconfigure and when a new viewer joins."""

    @abstractmethod
    def flush(self) -> list[EncodedPacket]:
        """Drain any buffered packets at end of stream."""

    @abstractmethod
    def close(self) -> None:
        """Release encoder resources."""
