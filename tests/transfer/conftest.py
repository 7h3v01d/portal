# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""An in-memory TransportConnection pair, so the transfer engine can be tested
without real sockets while still honouring the exact interface contract."""

from __future__ import annotations

import asyncio
from collections import deque

from portal.transport.base import TransportConnection


class MemoryConnection(TransportConnection):
    def __init__(self, peer_key: bytes) -> None:
        self._peer_key = peer_key
        self._in_control: asyncio.Queue[bytes] = asyncio.Queue()
        self._in_bulk: asyncio.Queue[bytes] = asyncio.Queue()
        self._in_video: deque[bytes] = deque(maxlen=4)
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
        # drop-oldest, never blocks (mirrors the real transport contract)
        self._out_video._in_video.append(bytes(data))
        self._out_video._video_available.set()

    async def recv_video(self) -> bytes:
        while True:
            if self._in_video:
                return self._in_video.popleft()
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
