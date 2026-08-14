# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Transport interfaces.

A transport moves bytes between two authenticated endpoints. It grants no
authority — being connected lets a peer send messages, not perform actions.
Authority lives entirely in the capability layer above.

Three shapes, because the original single `send/recv` couldn't express the
architecture:

  TransportProvider  — dial out (`connect`) or listen (`listen`). Dad's PC needs
                       the listen side; the old interface only had connect.
  TransportListener  — `accept()` incoming connections.
  TransportConnection— a live link exposing SEPARATE logical channels, because
                       control and bulk traffic have incompatible contracts:

       control channel : small, structured, strict-codec, <= 64 KiB per message
       bulk channel    : file chunks, binary, streamed/back-pressured, 256 KiB
       media channel   : video frames (added in the video phases)

A single `send(bytes)` could not honour both the 64 KiB control ceiling and the
256 KiB chunk size at once. Splitting them now — while nothing depends on the
transport yet — avoids cutting the architecture open during Phase 3.

Concrete transports planned behind these interfaces:
  - TLS-over-TCP (Phase 3): control + bulk over one TLS connection, framed.
  - aiortc/WebRTC (Phase 6+): control -> reliable DataChannel, bulk -> a second
    DataChannel, media -> a media track. The channel split is exactly what makes
    WebRTC a clean swap.

**Authentication invariant.** A returned TransportConnection is authenticated
BY CONSTRUCTION: `connect()` and `accept()` complete the peer's Ed25519
authentication or they raise/reject — no half-authenticated connection reaches
the application. So `peer_public_key` is always exactly 32 bytes, never None.
That authenticated key is still NOT authority: the session layer must compare it
for full equality against a pinned trusted record (security.identity.verify_pinned)
before granting any capability. Authenticated identity != trust != authority.

**Allocation limits.** Framing must enforce a length ceiling BEFORE allocating
or buffering a frame, or a header claiming gigabytes kills the process before the
codec ever runs. `recv_control` frames must be <= MAX_CONTROL_MESSAGE_BYTES and
`recv_bulk` frames <= MAX_BULK_FRAME_BYTES, checked against the declared length
prior to allocation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..common.constants import (  # noqa: F401  (referenced by the contract)
    MAX_BULK_FRAME_BYTES,
    MAX_CONTROL_MESSAGE_BYTES,
)


@dataclass(frozen=True)
class VideoReceipt:
    """A received video frame plus how many frames the transport dropped (drop-
    oldest) immediately before it. `dropped > 0` means the encoded stream has a
    gap — H.264 packets are interdependent, so the consumer must resync (reset the
    decoder and request a keyframe) rather than feed the decoder a broken chain."""

    data: bytes
    dropped: int


class TransportConnection(ABC):
    """A live, authenticated link with separate control and bulk channels."""

    @property
    @abstractmethod
    def peer_public_key(self) -> bytes:
        """The raw 32-byte Ed25519 public key this channel authenticated. Always
        present — a connection that reaches the application is authenticated by
        construction. Authorisation compares this (full-key, constant-time)
        against a pinned trusted record; it is never authority on its own."""

    @abstractmethod
    async def send_control(self, data: bytes) -> None:
        """Send one codec-validated control message (<= 64 KiB)."""

    @abstractmethod
    async def recv_control(self) -> bytes:
        """Receive one raw control message (the caller passes it to the codec).
        MUST reject a declared frame length > MAX_CONTROL_MESSAGE_BYTES before
        allocating for it."""

    @abstractmethod
    async def send_bulk(self, data: bytes) -> None:
        """Send one bulk frame (e.g. a file chunk). Back-pressured by the impl.
        Bulk is RELIABLE — never dropped — so it is used for file data that must
        arrive intact."""

    @abstractmethod
    async def recv_bulk(self) -> bytes:
        """Receive one bulk frame. MUST reject a declared frame length >
        MAX_BULK_FRAME_BYTES before allocating for it."""

    @abstractmethod
    async def send_video(self, data: bytes) -> None:
        """Send one video frame. The video channel is LOSSY by contract: the
        receiver keeps only the most recent frames (drop-oldest) and the reader
        NEVER blocks on it. This prevents *application-queue* starvation — a slow
        video consumer cannot suspend control-plane demultiplexing at the queue
        layer (A4a). NOTE: a single TCP stream still permits unavoidable
        *wire-level* head-of-line delay — video bytes already serialised ahead of
        a control frame cannot be leapfrogged (tracked under A4c); that is a
        transport-architecture limit, not something this buffer can solve."""

    @abstractmethod
    async def recv_video(self) -> "VideoReceipt":
        """Receive the next available video frame as a VideoReceipt (data +
        dropped count). Because video is drop-oldest, `dropped` reports how many
        frames were discarded before this one — a non-zero value means the
        H.264 chain has a gap and the consumer must resync. MUST reject a declared
        length > MAX_BULK_FRAME_BYTES before allocating."""

    @abstractmethod
    async def close(self) -> None:
        """Tear down. Safe to call more than once."""

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        ...


class TransportListener(ABC):
    @abstractmethod
    async def accept(self) -> TransportConnection:
        """Block until an incoming connection is established and authenticated."""

    @abstractmethod
    async def close(self) -> None:
        ...


class TransportProvider(ABC):
    @abstractmethod
    async def connect(self, endpoint: str) -> TransportConnection:
        """Dial `endpoint` and return an authenticated connection."""

    @abstractmethod
    async def listen(self, endpoint: str) -> TransportListener:
        """Begin listening on `endpoint` for incoming connections."""
