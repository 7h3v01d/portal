# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""A5: decode resource ceilings. A trusted-but-compromised peer must not be able
to negotiate or decode an oversized frame and exhaust host CPU/RAM."""

from __future__ import annotations

import pytest

from portal.common.constants import MAX_STREAM_PIXELS, MAX_STREAM_WIDTH, MAX_STREAM_HEIGHT


def test_stream_params_rejects_oversize_dimensions():
    from pydantic import ValidationError
    from portal.protocol.messages import StreamParamsPayload

    with pytest.raises(ValidationError):
        StreamParamsPayload(width=MAX_STREAM_WIDTH + 1, height=1080, fps=30)
    with pytest.raises(ValidationError):
        StreamParamsPayload(width=1920, height=MAX_STREAM_HEIGHT + 1, fps=30)


def test_stream_params_rejects_oversize_pixel_product():
    from pydantic import ValidationError
    from portal.protocol.messages import StreamParamsPayload

    # Both dimensions within the per-side cap (3840), but the PRODUCT (3840x3840
    # ≈ 14.7M px) blows the ~8.3M pixel cap — an extreme aspect ratio.
    assert 3840 <= MAX_STREAM_WIDTH and 3840 <= MAX_STREAM_HEIGHT
    assert 3840 * 3840 > MAX_STREAM_PIXELS
    with pytest.raises(ValidationError):
        StreamParamsPayload(width=3840, height=3840, fps=30)


def test_stream_params_accepts_both_4k_orientations():
    from portal.protocol.messages import StreamParamsPayload

    assert StreamParamsPayload(width=3840, height=2160, fps=30).width == 3840   # landscape
    assert StreamParamsPayload(width=2160, height=3840, fps=30).height == 3840  # portrait


def test_decoder_rejects_oversize_stream():
    pytest.importorskip("av")
    import av
    import numpy as np
    from portal.decode.pyav_decoder import PyAvDecoder
    from portal.common.errors import EncodeError

    # An oversized stream must be refused. With max_pixels set in libavcodec this
    # is caught at the NATIVE decode (avcodec_send_packet), before FFmpeg does the
    # full decode work — the lowest layer. If a PyAV build lacks max_pixels, the
    # Python post-decode ceiling catches it. Either way: EncodeError, no RGB.
    W, H = 4096, 2304  # 9.4M px > 8.3M cap
    enc = av.CodecContext.create("h264", "w")
    enc.width, enc.height, enc.pix_fmt = W, H, "yuv420p"
    enc.options = {"tune": "zerolatency"}
    packets = []
    frame = av.VideoFrame.from_ndarray(np.zeros((H, W, 3), np.uint8), format="rgb24").reformat(format="yuv420p")
    packets += enc.encode(frame)
    packets += enc.encode(None)
    assert packets

    dec = PyAvDecoder()
    with pytest.raises(EncodeError):  # native max_pixels OR python ceiling
        for p in packets:
            dec.decode(bytes(p), is_keyframe=p.is_keyframe, declared=(W, H))


def test_decoder_rejects_geometry_mismatch():
    pytest.importorskip("av")
    import av
    import numpy as np
    from portal.decode.pyav_decoder import PyAvDecoder
    from portal.common.errors import EncodeError

    # Decoder expects 320x240; a 640x480 stream whose packet header HONESTLY
    # declares 640x480 but arrives as a keyframe would be an allowed resize — so
    # to test the mismatch guard we lie: header says 320x240, bitstream is 640x480.
    W, H = 640, 480
    enc = av.CodecContext.create("h264", "w")
    enc.width, enc.height, enc.pix_fmt = W, H, "yuv420p"
    enc.options = {"tune": "zerolatency"}
    packets = []
    frame = av.VideoFrame.from_ndarray(np.zeros((H, W, 3), np.uint8), format="rgb24").reformat(format="yuv420p")
    packets += enc.encode(frame)
    packets += enc.encode(None)

    dec = PyAvDecoder(expected=(320, 240))
    with pytest.raises(EncodeError, match="expected"):
        for p in packets:
            # Lie in the declared header so it isn't treated as a legit resize.
            dec.decode(bytes(p), is_keyframe=p.is_keyframe, declared=(320, 240))


def test_decoder_allows_keyframe_bound_resolution_change():
    pytest.importorskip("av")
    import av
    import numpy as np
    from portal.decode.pyav_decoder import PyAvDecoder

    # Gate 5: a legitimate resolution change (new keyframe, honest header, within
    # ceilings) must be ACCEPTED, not treated as an attack.
    def gop(w, h):
        enc = av.CodecContext.create("h264", "w")
        enc.width, enc.height, enc.pix_fmt = w, h, "yuv420p"
        enc.options = {"tune": "zerolatency"}
        pkts = []
        f = av.VideoFrame.from_ndarray(np.zeros((h, w, 3), np.uint8), format="rgb24").reformat(format="yuv420p")
        pkts += enc.encode(f)
        pkts += enc.encode(None)
        return pkts

    dec = PyAvDecoder(expected=(320, 240))
    got = 0
    for p in gop(320, 240):
        got += len(dec.decode(bytes(p), is_keyframe=p.is_keyframe, declared=(320, 240)))
    # Now the host changes resolution to 640x480 — a new keyframe with honest header.
    for p in gop(640, 480):
        got += len(dec.decode(bytes(p), is_keyframe=p.is_keyframe, declared=(640, 480)))
    assert got >= 2, "legitimate resolution change was rejected (Gate 5 regression)"


# --- no-PyAV tests: the Python-layer invariant must be exercised in the core suite ---

class _FakeFrame:
    def __init__(self, w, h, reformat_spy):
        self.width, self.height = w, h
        self._spy = reformat_spy

    def reformat(self, format):
        self._spy.append((self.width, self.height))  # must NEVER be called for a rejected frame
        raise AssertionError("reformat() was called on a frame that should have been rejected")


def _decoder_with_fake_frames(frames, reformat_spy):
    from portal.decode.pyav_decoder import PyAvDecoder

    dec = PyAvDecoder()
    dec._started = True
    dec._av = object()  # bypass _lazy import of av

    class _Ctx:
        def decode(self, packet):
            return frames

    class _Pkt:
        def __init__(self, data):
            pass

    class _AvShim:
        packet = type("p", (), {"Packet": _Pkt})

    dec._ctx = _Ctx()
    dec._av = _AvShim()
    return dec


def test_oversized_frame_never_reaches_reformat_no_pyav():
    from portal.common.errors import EncodeError

    spy = []
    frame = _FakeFrame(5000, 3000, spy)  # 15M px > cap
    dec = _decoder_with_fake_frames([frame], spy)
    with pytest.raises(EncodeError, match="pixel ceiling"):
        dec.decode(b"x", is_keyframe=True, declared=None)
    assert spy == [], "reformat() was reached for an oversized frame"


def test_mismatched_frame_never_reaches_reformat_no_pyav():
    from portal.common.errors import EncodeError
    from portal.decode.pyav_decoder import PyAvDecoder

    spy = []
    frame = _FakeFrame(640, 480, spy)
    dec = _decoder_with_fake_frames([frame], spy)
    dec._expected = (320, 240)  # decoded 640x480 won't match, header claims 320x240
    with pytest.raises(EncodeError, match="expected"):
        dec.decode(b"x", is_keyframe=True, declared=(320, 240))
    assert spy == [], "reformat() was reached for a mismatched frame"
