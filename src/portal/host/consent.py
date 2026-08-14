# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Host-side consent — the human gate that makes 'trusted' distinct from
'authorised'.

Trust (a pinned key) only says *who* the peer is. It does NOT grant authority: a
trusted peer still cannot see the screen or write a file until the human at the
host approves THIS operation, right now. This protocol is that approval, and the
pairing SAS ceremony. The real implementation is a UI dialog; tests provide fakes.

The distinction is load-bearing: without it, pairing once with Dad's machine would
be a standing grant to view or control it forever. With it, every session is an
explicit, revocable act of consent."""

from __future__ import annotations

from typing import Protocol

from ..security.identity import DeviceIdentity
from ..security.pairing import PairingConfirmation


class HostConsent(Protocol):
    async def confirm_pairing(self, confirmation: PairingConfirmation) -> bool:
        """The SAS ceremony: shown the SAS to compare out-of-band against the
        other machine; returns True only if the human confirms they match."""
        ...

    async def confirm_operation(self, peer: DeviceIdentity, operation: str) -> bool:
        """Approve a specific operation (e.g. 'screen', 'file-receive') from an
        already-trusted peer. Returns True only on explicit human approval."""
        ...

    async def notify_pairing_code(self, code: str) -> None:
        """Surface the one-time pairing code so the human can read it to the other
        party out-of-band. The code is a secret the peer must present; without
        this the coordinator would generate a code no human could see."""
        ...


class DenyAllConsent:
    """A consent provider that refuses everything — the safe default and a useful
    test fixture for the 'trusted but no consent' path."""

    async def confirm_pairing(self, confirmation: PairingConfirmation) -> bool:
        return False

    async def confirm_operation(self, peer: DeviceIdentity, operation: str) -> bool:
        return False

    async def notify_pairing_code(self, code: str) -> None:
        return None
