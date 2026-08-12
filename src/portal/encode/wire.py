# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Wire framing for encoded video packets on the bulk channel.

Video is high-rate binary media, so it does NOT go through the strict JSON control
codec (that is for control messages). Each packet gets a compact fixed binary
header + the H.264 payload, carried as one bulk frame. Control (start/stop/
keyframe/params) still rides the strict codec on the control channel.

Header (13 bytes, big-endian):
    magic(1)=0xPV | flags(1) | pts(4) | width(2) | height(2) | ts_ms(4)
`flags` bit0 = keyframe. The bulk frame's own length prefix bounds total size."""

from __future__ import annotations

import struct

from ..common.errors import TransferError
from .base import EncodedPacket

_MAGIC = 0x56  # 'V'
_HEADER = struct.Struct(">BBIHHI")
_FLAG_KEYFRAME = 0x01


def pack_packet(pkt: EncodedPacket) -> bytes:
    flags = _FLAG_KEYFRAME if pkt.is_keyframe else 0
    ts_ms = (pkt.timestamp_ns // 1_000_000) & 0xFFFFFFFF
    header = _HEADER.pack(
        _MAGIC, flags, pkt.pts & 0xFFFFFFFF, pkt.width & 0xFFFF, pkt.height & 0xFFFF, ts_ms
    )
    return header + pkt.data


def unpack_packet(raw: bytes) -> EncodedPacket:
    if len(raw) < _HEADER.size:
        raise TransferError("video frame shorter than header")
    magic, flags, pts, width, height, ts_ms = _HEADER.unpack(raw[: _HEADER.size])
    if magic != _MAGIC:
        raise TransferError("bad video frame magic")
    return EncodedPacket(
        data=raw[_HEADER.size :],
        is_keyframe=bool(flags & _FLAG_KEYFRAME),
        pts=pts,
        timestamp_ns=ts_ms * 1_000_000,
        width=width,
        height=height,
    )
