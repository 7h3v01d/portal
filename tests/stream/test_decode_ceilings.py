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


def test_native_max_pixels_is_installed():
    # A5.7: prove the AVOption was actually consumed by avcodec_open2 — i.e. the
    # native ceiling is really installed, not silently dropped. _lazy() fails
    # closed if max_pixels is left unconsumed, so a successful _lazy() IS the
    # proof; we also confirm the option isn't sitting unconsumed on the context.
    pytest.importorskip("av")
    from portal.decode.pyav_decoder import PyAvDecoder

    dec = PyAvDecoder()
    dec._lazy()  # raises EncodeError if the native ceiling couldn't be established
    assert "max_pixels" not in (getattr(dec._ctx, "options", None) or {})


def test_native_ceiling_rejects_lying_oversized_bitstream():
    # A5.8 (the real one): the wire header lies with SAFE dimensions so Portal's
    # Python precheck PASSES and the packet is handed to FFmpeg — whose max_pixels
    # must then reject the oversized SPS at avcodec_send_packet. This proves the
    # native layer executes, unlike the previous false-green test where the Python
    # precheck rejected the declared geometry before FFmpeg was ever invoked.
    pytest.importorskip("av")
    import av
    import numpy as np
    from portal.decode.pyav_decoder import PyAvDecoder
    from portal.common.errors import EncodeError

    W, H = 4096, 2304  # oversized bitstream (9.4M px > 8.3M cap)
    enc = av.CodecContext.create("h264", "w")
    enc.width, enc.height, enc.pix_fmt = W, H, "yuv420p"
    enc.options = {"tune": "zerolatency"}
    packets = []
    frame = av.VideoFrame.from_ndarray(np.zeros((H, W, 3), np.uint8), format="rgb24").reformat(format="yuv420p")
    packets += enc.encode(frame)
    packets += enc.encode(None)
    assert packets

    # Instrument that native decode is actually reached with the malicious stream.
    # ctx.decode is read-only, so spy on Packet construction (immediately precedes
    # the native _ctx.decode call in PyAvDecoder.decode).
    dec = PyAvDecoder(expected=(1920, 1080))
    dec._lazy()
    native_calls = []
    real_packet = dec._av.packet.Packet

    def SpyPacket(*a, **k):
        native_calls.append(1)
        return real_packet(*a, **k)

    dec._av.packet.Packet = SpyPacket
    try:
        # The rejection MUST come from the native decode ("decode failed"), NOT the
        # Python post-decode ceiling — otherwise the test would pass even without
        # max_pixels (the returned oversized frame would be caught later). This is
        # what isolates the native layer: verified that without max_pixels the same
        # stream decodes into a 4096x2304 frame, so only max_pixels rejects it here.
        with pytest.raises(EncodeError, match="decode failed"):
            for p in packets:
                dec.decode(bytes(p), is_keyframe=p.is_keyframe, declared=(1920, 1080))
    finally:
        dec._av.packet.Packet = real_packet
    assert native_calls, "FFmpeg native decode was never reached — test is a false green"


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


def test_decoder_fails_closed_if_max_pixels_not_consumed(monkeypatch):
    # A5.7: the native ceiling MUST fail closed. If FFmpeg doesn't consume the
    # max_pixels option (left on ctx.options after open), the decoder refuses to
    # start rather than decoding hostile H.264 with no native guard.
    #
    # This runs WITHOUT PyAV: it's one of A5's most important security properties,
    # so it must be exercised in the core suite, not skipped when av is absent. We
    # inject a fake `av` module that the decoder's `import av` picks up.
    import sys
    import types
    from portal.decode.pyav_decoder import PyAvDecoder
    from portal.common.errors import EncodeError

    class FakeCtx:
        def __init__(self):
            self.options = {}

        def open(self):
            pass  # pretend open succeeded but did NOT consume max_pixels

    fake_av = types.ModuleType("av")
    fake_av.CodecContext = types.SimpleNamespace(create=lambda codec, mode: FakeCtx())
    monkeypatch.setitem(sys.modules, "av", fake_av)

    dec = PyAvDecoder()
    with pytest.raises(EncodeError, match="did not accept max_pixels"):
        dec._lazy()


def test_viewer_geometry_tracks_validated_resize():
    # A5.10 / Gate-7 readiness: after a validated live resize, the viewer's
    # advertised width/height must follow the decoded frame — Phase 7 input
    # mapping must never map against a stale resolution.
    import asyncio
    from portal.stream.viewer import ScreenViewer
    from portal.transport.base import VideoReceipt
    from portal.encode.base import EncodedPacket
    from portal.encode.wire import pack_packet

    class ResizeDecoder:
        """Returns a frame at whatever geometry the packet declares."""
        def __init__(self):
            self._n = 0

        def reset(self): ...
        def decode(self, data, is_keyframe, ts=0, declared=None):
            w, h = declared
            return [type("F", (), {"width": w, "height": h, "rgb": b"", "timestamp_ns": ts})()]

    async def go():
        v = ScreenViewer(ResizeDecoder())
        v.width, v.height = 320, 240
        # A packet declaring the new geometry (keyframe).
        pkt = EncodedPacket(b"x", True, 0, 0, 640, 480)
        await v._process_receipt(VideoReceipt(data=pack_packet(pkt), dropped=0))
        assert (v.width, v.height) == (640, 480), "viewer geometry did not follow the resize"

    asyncio.run(go())
