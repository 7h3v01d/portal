# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""An in-memory TransportConnection pair, so the transfer engine can be tested
without real sockets while still honouring the exact interface contract."""

from __future__ import annotations

import asyncio
from collections import deque

from portal.transport.base import TransportConnection, VideoReceipt


class MemoryConnection(TransportConnection):
    def __init__(self, peer_key: bytes) -> None:
        self._peer_key = peer_key
        self._in_control: asyncio.Queue[bytes] = asyncio.Queue()
        self._in_bulk: asyncio.Queue[bytes] = asyncio.Queue()
        self._in_video: deque[tuple[int, bytes]] = deque(maxlen=4)
        self._video_seq = 0
        self._video_last_delivered: int | None = None
        self._video_available = asyncio.Event()
        self._out_control: asyncio.Queue[bytes] | None = None
        self._out_bulk: asyncio.Queue[bytes] | None = None
        self._out_video: "MemoryConnection | None" = None
        self._closed = False

    def link(self, other: "MemoryConnection") -> None:
        self._out_control = other._in_control
        self._out_bulk = other._in_bulk
        self._out_video = other

    @property
    def peer_public_key(self) -> bytes:
        return self._peer_key

    @property
    def is_connected(self) -> bool:
        return not self._closed

    async def send_control(self, data: bytes) -> None:
        self._out_control.put_nowait(bytes(data))

    async def recv_control(self) -> bytes:
        return await self._in_control.get()

    async def send_bulk(self, data: bytes) -> None:
        self._out_bulk.put_nowait(bytes(data))

    async def recv_bulk(self) -> bytes:
        return await self._in_bulk.get()

    async def send_video(self, data: bytes) -> None:
        # drop-oldest with sequence numbers, mirroring the real transport
        peer = self._out_video
        peer._in_video.append((peer._video_seq, bytes(data)))
        peer._video_seq += 1
        peer._video_available.set()

    async def recv_video(self) -> VideoReceipt:
        while True:
            if self._in_video:
                seq, body = self._in_video.popleft()
                baseline = -1 if self._video_last_delivered is None else self._video_last_delivered
                dropped = seq - baseline - 1
                self._video_last_delivered = seq
                return VideoReceipt(data=body, dropped=dropped)
            self._video_available.clear()
            await self._video_available.wait()

    async def close(self) -> None:
        self._closed = True


def make_memory_pair(key_a: bytes = b"\x01" * 32, key_b: bytes = b"\x02" * 32):
    a = MemoryConnection(key_b)
    b = MemoryConnection(key_a)
    a.link(b)
    b.link(a)
    return a, b
