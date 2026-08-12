# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The full media path minus the network: encode -> wire pack -> wire unpack ->
decode -> displayable RGB frame, and the wire codec's edge cases."""

from __future__ import annotations

import time

import pytest

pytest.importorskip("av")
pytest.importorskip("numpy")

from portal.capture.base import Frame, PixelFormat
from portal.common.errors import TransferError
from portal.decode.pyav_decoder import PyAvDecoder
from portal.encode.pyav_backend import PyAvEncoder
from portal.encode.wire import pack_packet, unpack_packet


def _bgra(w, h, v):
    stride = w * 4
    buf = bytearray(stride * h)
    for i in range(0, len(buf), 4):
        buf[i], buf[i + 1], buf[i + 2], buf[i + 3] = v & 0xFF, (v + 30) & 0xFF, (v + 60) & 0xFF, 255
    return Frame(memoryview(bytes(buf)), w, h, stride, PixelFormat.BGRA8, time.monotonic_ns(), "SYN-0")


def test_wire_roundtrip_preserves_metadata():
    from portal.encode.base import EncodedPacket

    p = EncodedPacket(b"\x00\x01\x02payload", True, pts=42, timestamp_ns=1_500_000_000, width=800, height=600)
    back = unpack_packet(pack_packet(p))
    assert back.data == p.data
    assert back.is_keyframe and back.pts == 42
    assert back.width == 800 and back.height == 600
    assert back.timestamp_ns == 1_500_000_000  # ms-quantised, exact here


def test_wire_rejects_bad_magic_and_short():
    with pytest.raises(TransferError):
        unpack_packet(b"\xff" * 20)
    with pytest.raises(TransferError):
        unpack_packet(b"\x00\x01")  # shorter than header


def test_encode_wire_decode_produces_rgb_frame():
    enc = PyAvEncoder(); enc.open(320, 240, 30, 1_500_000)
    dec = PyAvDecoder()
    got = []
    for i in range(30):
        for pkt in enc.encode(_bgra(320, 240, 60 + i * 4)):
            wire = pack_packet(pkt)                 # host side: to bulk bytes
            rp = unpack_packet(wire)                # viewer side: from bulk bytes
            got += dec.decode(rp.data, rp.is_keyframe, rp.timestamp_ns)
    for pkt in enc.flush():
        got += dec.decode(pkt.data, pkt.is_keyframe)
    enc.close()
    assert len(got) >= 1
    f = got[0]
    assert f.width == 320 and f.height == 240
    assert len(f.rgb) == 320 * 240 * 3  # tightly packed RGB24


def test_decoder_waits_for_keyframe():
    dec = PyAvDecoder()
    # A non-keyframe before any keyframe is dropped (can't start a decode there).
    assert dec.decode(b"garbage", is_keyframe=False) == []
