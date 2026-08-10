# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The permission gate. Every privileged host action passes through here first.

    gate.require(Capability.INPUT_INJECT_MOUSE)   # raises if not granted
    windows_input.move_mouse(...)                 # only reached when allowed

The gate reads through a capability source that exposes `has()` — normally a
SessionAuthority, so a revoke on the authority is seen by the very next
`require`/`check`. For work that outlives a single call (file transfer, queued
input), the caller additionally holds a capability-bound token from
`SessionAuthority.authorize(...)` and checks `token.valid` mid-flight."""

from __future__ import annotations

from typing import Protocol

from ..common.errors import PermissionDeniedError
from ..protocol.capabilities import Capability


class SupportsHas(Protocol):
    def has(self, capability: Capability) -> bool: ...


class PermissionGate:
    __slots__ = ("_source",)

    def __init__(self, source: SupportsHas) -> None:
        # A SessionAuthority or a CapabilitySet — anything exposing has(). The
        # gate never receives a way to *mutate* authority, only to read it.
        self._source = source

    def check(self, capability: Capability) -> bool:
        return self._source.has(capability)

    def require(self, capability: Capability) -> None:
        if not self._source.has(capability):
            raise PermissionDeniedError(f"missing capability: {capability}")
