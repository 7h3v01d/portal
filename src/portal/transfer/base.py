# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""File-transfer interface.

The transfer engine is transport-agnostic: built and hardened over the LAN
transport in Phase 3, then moved onto a WebRTC data channel in Phase 12 with no
redesign — only the transport under it changes.

The receiver contract (enforced by the Phase 3 implementation):
  - ask the local user to approve every offer (unless auto-accept is on);
  - validate the filename with security.validation before touching disk;
  - write to <name>.part, tracking confirmed offsets for resume;
  - verify the SHA-256 before accepting the file;
  - atomically rename into place only after verification.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel, ConfigDict, Field

from ..common.constants import MAX_FILENAME_LEN

_WIRE = ConfigDict(extra="forbid", strict=True, frozen=True)


class FileOffer(BaseModel):
    """An offered file, validated the same strict way as any wire message. No
    loose primitives: the hash is exactly 64 hex chars, the id is a constrained
    opaque token, size is bounded, and time is integer nanoseconds — no float
    timestamps on the protocol after all the work spent removing numeric
    coercion elsewhere."""

    model_config = _WIRE

    transfer_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    filename: str = Field(min_length=1, max_length=MAX_FILENAME_LEN)
    size: int = Field(ge=0, le=1 << 44)  # up to ~16 TiB; bounded, non-negative
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    mtime_ns: int = Field(ge=0)


class TransferBackend(ABC):
    @abstractmethod
    async def offer(self, path: str) -> str:
        """Offer a local file to the peer. Returns a transfer id."""

    @abstractmethod
    async def accept(self, transfer_id: str) -> None:
        """Accept an incoming offer and begin receiving."""

    @abstractmethod
    async def reject(self, transfer_id: str) -> None:
        ...

    @abstractmethod
    async def cancel(self, transfer_id: str) -> None:
        """Cancel an in-flight transfer in either direction."""
