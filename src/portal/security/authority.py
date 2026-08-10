# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Session authority and cancellation.

Point-in-time capability checks are enough for a single input event; the next
event sees the revocation. They are NOT enough for a long-running operation — a
5 GB transfer authorised under `file.write.inbound` keeps running if that
capability is revoked mid-flight, because nothing re-checks. So "revocation is
instant" is made an enforceable property:

  - the authority holds a monotonically increasing *generation*;
  - any revoke bumps the generation, invalidating every token issued before it;
  - a long-running op takes a **capability-bound** token when it starts and
    checks `token.valid` at each step, aborting the moment it goes stale.

A capability-bound token is valid iff BOTH the generation is unchanged AND the
specific capability it was issued for is still granted — stronger than a generic
cancellation token.

**No mutable capability set is exposed.** The only way to change authority is
through `grant`/`revoke`/`revoke_all` on the authority itself, so a revoke can
never happen without bumping the generation. Reading is via `has`/`granted`
(a frozenset copy), never the live set.

**Concurrency contract.** A SessionAuthority is owned by a single event loop /
thread and is NOT internally synchronised: `revoke` then `generation += 1` is
two operations, and a reader on another thread could observe the gap. Mutate and
read it from the one owning context; cross-thread hand-offs must marshal onto it.
"""

from __future__ import annotations

from ..common.errors import PermissionDeniedError
from ..protocol.capabilities import Capability, CapabilitySet


class CancellationToken:
    """A capability-bound snapshot. Invalid the instant a revoke bumps the
    generation past it, the bound capability is dropped, or it is cancelled."""

    __slots__ = ("_authority", "_capability", "_generation", "_cancelled")

    def __init__(self, authority: "SessionAuthority", capability: Capability, generation: int) -> None:
        self._authority = authority
        self._capability = capability
        self._generation = generation
        self._cancelled = False

    @property
    def capability(self) -> Capability:
        return self._capability

    @property
    def valid(self) -> bool:
        return (
            not self._cancelled
            and self._authority.generation == self._generation
            and self._authority.has(self._capability)
        )

    def cancel(self) -> None:
        self._cancelled = True


class SessionAuthority:
    """Owns the live capabilities plus the generation counter. The mutable set is
    private; callers mutate only through this object's methods."""

    __slots__ = ("_caps", "_generation")

    def __init__(self) -> None:
        self._caps = CapabilitySet()
        self._generation = 0

    @property
    def generation(self) -> int:
        return self._generation

    # --- reads (never the mutable set) ---
    def has(self, capability: Capability) -> bool:
        return self._caps.has(capability)

    def granted(self) -> frozenset[Capability]:
        return self._caps.granted()

    # --- mutations (revocation always bumps the generation) ---
    def grant(self, capability: Capability) -> None:
        self._caps.grant(capability)  # widening authority does not invalidate tokens

    def revoke(self, capability: Capability) -> None:
        self._caps.revoke(capability)
        self._generation += 1

    def revoke_all(self) -> None:
        self._caps.revoke_all()
        self._generation += 1

    # --- capability-bound authorization for long-running work ---
    def authorize(self, capability: Capability) -> CancellationToken:
        """Verify the capability is granted right now and return a token bound to
        it. Raises if not granted, so an unauthorised long op never starts."""
        if not self._caps.has(capability):
            raise PermissionDeniedError(f"missing capability: {capability}")
        return CancellationToken(self, capability, self._generation)
