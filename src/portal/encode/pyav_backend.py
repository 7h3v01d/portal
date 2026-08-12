# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""PyAV / libx264 H.264 encoder.

Tuned for interactive screen sharing: zero-latency (no B-frames, no lookahead) so
each captured frame produces exactly one packet with no reordering, keeping the
remote-control round trip short. Input is the BGRA `Frame` from capture; libx264
wants yuv420p, so frames are converted on the way in.

PyAV bundles FFmpeg (incl. libx264) in its wheels, so unlike the DXcam capture
backend this IS exercised in CI/tests on any OS. `av` and `numpy` are imported
lazily so the package still imports without the `capture` extra installed."""

from __future__ import annotations

from fractions import Fraction

from ..capture.base import Frame, PixelFormat
from ..common.errors import EncodeError
from ..common.logging import get_logger
from .base import EncodedPacket, VideoEncoder

_log = get_logger("encode.pyav")


class PyAvEncoder(VideoEncoder):
    def __init__(self) -> None:
        self._ctx = None
        self._av = None
        self._np = None
        self._w = 0
        self._h = 0
        self._force_keyframe = True

    def _lazy(self):
        if self._av is None:
            try:
                import av  # type: ignore
                import numpy  # type: ignore
            except Exception as exc:  # noqa: BLE001
                raise EncodeError(
                    "PyAV + numpy are required for video encoding (install the 'capture' extra)"
                ) from exc
            self._av, self._np = av, numpy
        return self._av, self._np

    def open(self, width: int, height: int, fps: int, bitrate: int) -> None:
        av, _np = self._lazy()
        self.close()
        try:
            ctx = av.CodecContext.create("libx264", "w")
            ctx.width = width
            ctx.height = height
            ctx.pix_fmt = "yuv420p"
            ctx.framerate = Fraction(fps, 1)
            ctx.time_base = Fraction(1, fps)
            ctx.bit_rate = bitrate
            # zerolatency: no frame reordering/lookahead -> 1 in, 1 out, low delay.
            ctx.options = {
                "tune": "zerolatency",
                "preset": "veryfast",
                "profile": "baseline",
            }
            ctx.open()
        except Exception as exc:  # noqa: BLE001
            raise EncodeError(f"could not open encoder: {exc}") from exc
        self._ctx = ctx
        self._w, self._h = width, height
        self._force_keyframe = True

    def _to_video_frame(self, frame: Frame):
        av, np = self._av, self._np
        if frame.pixel_format is not PixelFormat.BGRA8:
            raise EncodeError(f"unsupported pixel format: {frame.pixel_format}")
        arr = np.frombuffer(frame.buffer, dtype=np.uint8)
        expected = frame.stride * frame.height
        if arr.size < expected:
            raise EncodeError("frame buffer smaller than declared geometry")
        arr = arr[:expected].reshape(frame.height, frame.stride // 4, 4)[:, : frame.width, :]
        vframe = av.VideoFrame.from_ndarray(np.ascontiguousarray(arr), format="bgra")
        return vframe.reformat(format="yuv420p")

    def encode(self, frame: Frame) -> list[EncodedPacket]:
        if self._ctx is None:
            raise EncodeError("encoder not open")
        if (frame.width, frame.height) != (self._w, self._h):
            raise EncodeError("frame geometry changed without reconfigure")
        try:
            vframe = self._to_video_frame(frame)
            if self._force_keyframe:
                vframe.pict_type = self._av.video.frame.PictureType.I
                self._force_keyframe = False
            packets = self._ctx.encode(vframe)
        except EncodeError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise EncodeError(f"encode failed: {exc}") from exc
        return [self._wrap(p, frame.timestamp_ns) for p in packets]

    def _wrap(self, packet, timestamp_ns: int) -> EncodedPacket:
        return EncodedPacket(
            data=bytes(packet),
            is_keyframe=bool(packet.is_keyframe),
            pts=int(packet.pts) if packet.pts is not None else 0,
            timestamp_ns=timestamp_ns,
            width=self._w,
            height=self._h,
        )

    def request_keyframe(self) -> None:
        self._force_keyframe = True

    def flush(self) -> list[EncodedPacket]:
        if self._ctx is None:
            return []
        try:
            packets = self._ctx.encode(None)  # flush
        except Exception:  # noqa: BLE001
            return []
        return [self._wrap(p, 0) for p in packets]

    def close(self) -> None:
        if self._ctx is not None:
            try:
                self._ctx.close()
            except Exception:  # noqa: BLE001
                pass
            self._ctx = None
