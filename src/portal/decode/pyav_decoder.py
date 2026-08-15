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

from ..common.constants import (
    MAX_RGB_FRAME_BYTES,
    MAX_STREAM_HEIGHT,
    MAX_STREAM_PIXELS,
    MAX_STREAM_WIDTH,
)
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
    def __init__(self, expected: "tuple[int, int] | None" = None) -> None:
        self._ctx = None
        self._av = None
        self._started = False  # have we seen a keyframe yet?
        # The geometry decoded frames must currently match. Set from STREAM_PARAMS
        # at start; a keyframe-bound, in-ceiling change re-pins it (Gate 5 resize).
        self._expected = expected

    def _lazy(self):
        if self._av is None:
            try:
                import av  # type: ignore
            except Exception as exc:  # noqa: BLE001
                raise EncodeError("PyAV is required to decode video") from exc
            self._av = av
            ctx = av.CodecContext.create("h264", "r")
            # A5 lowest layer: bound the frame size INSIDE libavcodec, before any
            # native decode work, via AVCodecContext.max_pixels (FFmpeg's documented
            # OOM/slow-decode guard). A hostile SPS claiming a gigantic geometry is
            # refused by the native decoder itself, not merely after it returns.
            try:
                ctx.max_pixels = MAX_STREAM_PIXELS
            except Exception:  # noqa: BLE001 — older PyAV may expose it via options
                try:
                    ctx.options = {"max_pixels": str(MAX_STREAM_PIXELS)}
                except Exception:  # noqa: BLE001
                    _log.warning("PyAV lacks max_pixels; relying on post-decode ceiling only")
            self._ctx = ctx
        return self._av

    def expect_geometry(self, width: int, height: int) -> None:
        """Set the geometry the next decoded frames must match (from STREAM_PARAMS
        at start). A later keyframe-bound change to a different in-ceiling geometry
        is allowed (see decode) so legitimate resolution changes still work."""
        self._expected = (width, height)

    def decode(self, data: bytes, is_keyframe: bool, timestamp_ns: int = 0,
               declared: "tuple[int, int] | None" = None) -> list[DecodedFrame]:
        """Decode one packet's bytes. Returns 0+ frames. Until the first keyframe
        is seen, non-keyframe packets are dropped. `declared` is the geometry from
        the packet's wire header, used to allow a validated resolution change."""
        av = self._lazy()
        if not self._started:
            if not is_keyframe:
                return []
            self._started = True

        # A legitimate resolution change (Gate 5) arrives as a KEYFRAME whose
        # declared geometry differs from what we currently expect. Accept it ONLY
        # if it is a keyframe AND passes the ceilings; then re-pin expectation to
        # it. A non-keyframe geometry change, or an over-ceiling one, is refused —
        # so dynamic resolution is allowed, arbitrary/mid-GOP resolution is not.
        if declared is not None and declared != self._expected:
            dw, dh = declared
            if not is_keyframe:
                raise EncodeError(f"mid-stream geometry change {dw}x{dh} without a keyframe")
            if dw < 1 or dh < 1 or dw > MAX_STREAM_WIDTH or dh > MAX_STREAM_HEIGHT \
                    or dw * dh > MAX_STREAM_PIXELS:
                raise EncodeError(f"declared geometry {dw}x{dh} exceeds ceiling")
            self._expected = declared

        try:
            packet = av.packet.Packet(data)
            frames = self._ctx.decode(packet)
        except Exception as exc:  # noqa: BLE001
            raise EncodeError(f"decode failed: {exc}") from exc

        out: list[DecodedFrame] = []
        for frame in frames:
            width, height = frame.width, frame.height
            # Defense in depth: even with max_pixels set in libavcodec, independently
            # bound the returned geometry BEFORE reformat() materialises RGB, and
            # require it match what we expect (declared header or negotiated start).
            if width < 1 or height < 1 or width * height > MAX_STREAM_PIXELS:
                raise EncodeError(
                    f"decoded frame geometry {width}x{height} exceeds pixel ceiling"
                )
            if self._expected is not None and (width, height) != self._expected:
                raise EncodeError(
                    f"decoded geometry {width}x{height} != expected {self._expected}"
                )
            rgb = frame.reformat(format="rgb24")
            plane = rgb.planes[0]
            width, height = rgb.width, rgb.height
            # Belt-and-braces on the materialised RGB payload itself.
            if width * height * 3 > MAX_RGB_FRAME_BYTES:
                raise EncodeError(f"RGB frame {width}x{height} exceeds byte ceiling")
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
