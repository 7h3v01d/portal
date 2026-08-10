# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Capabilities — the unit of authority in Portal.

The whole security model rests on one rule: a live connection grants *nothing*.
Every distinct thing a peer may do is a named capability that must be explicitly
granted and can be independently revoked.

Names describe the **protected local operation**, not the remote party's intent,
because "send" and "receive" are ambiguous once two machines are involved — does
`file.send` granted to Leon mean "Leon may send Dad a file" or "Leon may cause
Dad to send a file"? Naming after the local operation removes the guess:

    file.write.inbound   -> the peer may write a file ONTO this machine
    file.read.outbound   -> the peer may read a file FROM this machine

This matters more once host/controller roles start switching.
"""

from __future__ import annotations

from enum import Enum


class Capability(str, Enum):
    """The complete set of things a session may be permitted to do, each named
    for the local operation it authorises."""

    SCREEN_PUBLISH = "screen.publish"          # allow this screen to be captured & streamed to the peer
    INPUT_INJECT_MOUSE = "input.inject.mouse"  # allow mouse events to be injected locally
    INPUT_INJECT_KEYBOARD = "input.inject.keyboard"
    FILE_WRITE_INBOUND = "file.write.inbound"  # allow the peer to write a file onto this machine
    FILE_READ_OUTBOUND = "file.read.outbound"  # allow the peer to read a file from this machine
    CLIPBOARD_READ_LOCAL = "clipboard.read.local"   # allow the peer to read this machine's clipboard
    CLIPBOARD_WRITE_LOCAL = "clipboard.write.local"  # allow the peer to write this machine's clipboard

    def __str__(self) -> str:
        return self.value


class CapabilitySet:
    """A mutable, deny-first collection of granted capabilities.

    Starts empty. `has()` is the single question every privileged action asks.
    Grants and revokes are explicit; there is deliberately no "grant all"."""

    __slots__ = ("_granted",)

    def __init__(self) -> None:
        self._granted: set[Capability] = set()

    def grant(self, capability: Capability) -> None:
        if not isinstance(capability, Capability):
            raise TypeError(f"not a Capability: {capability!r}")
        self._granted.add(capability)

    def revoke(self, capability: Capability) -> None:
        # Revoking something not granted is a no-op, not an error — revocation
        # should always succeed at reaching the closed state.
        self._granted.discard(capability)

    def revoke_all(self) -> None:
        self._granted.clear()

    def has(self, capability: Capability) -> bool:
        return capability in self._granted

    def granted(self) -> frozenset[Capability]:
        return frozenset(self._granted)

    def __contains__(self, capability: object) -> bool:
        return capability in self._granted

    def __iter__(self):
        return iter(sorted(self._granted, key=lambda c: c.value))

    def __repr__(self) -> str:
        inside = ", ".join(c.value for c in self)
        return f"CapabilitySet({{{inside}}})"
