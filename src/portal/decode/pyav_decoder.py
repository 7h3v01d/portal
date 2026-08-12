# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""H.264 decoder (PyAV / FFmpeg).

Takes encoded packet bytes and produces displayable frames. Output is RGB24 so a
Qt viewer can blit it directly. Like the encoder, this is genuinely tested here
because PyAV bundles FFmpeg. A decoder can only start on a keyframe, so a viewer
that joins mid-stream requests one (STREAM_KEYFRAME) and drops packets until the
first IDR arrives."""

from __future__ import annotations

from dataclasses import dataclass

from ..common.errors import EncodeError
from ..common.logging import get_logger

_log = get_logger("decode.pyav")


@dataclass(frozen=True)
class DecodedFrame:
    rgb: bytes       # tightly packed RGB24, width*height*3
    width: int
    height: int
    timestamp_ns: int


class PyAvDecoder:
    def __init__(self) -> None:
        self._ctx = None
        self._av = None
        self._started = False  # have we seen a keyframe yet?

    def _lazy(self):
        if self._av is None:
            try:
                import av  # type: ignore
            except Exception as exc:  # noqa: BLE001
                raise EncodeError("PyAV is required to decode video") from exc
            self._av = av
            self._ctx = av.CodecContext.create("h264", "r")
        return self._av

    def decode(self, data: bytes, is_keyframe: bool, timestamp_ns: int = 0) -> list[DecodedFrame]:
        """Decode one packet's bytes. Returns 0+ frames. Until the first keyframe
        is seen, non-keyframe packets are dropped (a decoder can't start on them)."""
        av = self._lazy()
        if not self._started:
            if not is_keyframe:
                return []
            self._started = True
        try:
            packet = av.packet.Packet(data)
            frames = self._ctx.decode(packet)
        except Exception as exc:  # noqa: BLE001
            raise EncodeError(f"decode failed: {exc}") from exc

        out: list[DecodedFrame] = []
        for frame in frames:
            rgb = frame.reformat(format="rgb24")
            plane = rgb.planes[0]
            width, height = rgb.width, rgb.height
            # Copy out tightly packed rows (plane may be padded to a stride).
            import builtins

            mv = memoryview(plane)
            stride = plane.line_size
            row_bytes = width * 3
            if stride == row_bytes:
                data_out = bytes(mv[: row_bytes * height])
            else:
                buf = bytearray(row_bytes * height)
                for y in range(height):
                    start = y * stride
                    buf[y * row_bytes : (y + 1) * row_bytes] = mv[start : start + row_bytes]
                data_out = bytes(buf)
            out.append(DecodedFrame(rgb=data_out, width=width, height=height, timestamp_ns=timestamp_ns))
        return out

    def reset(self) -> None:
        """Force re-sync on the next keyframe (e.g. after packet loss)."""
        self._started = False

    def close(self) -> None:
        self._ctx = None
