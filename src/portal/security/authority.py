# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Session authority and cancellation.

Point-in-time capability checks are enough for a single input event; the next
event sees the revocation. They are NOT enough for a long-running operation — a
5 GB transfer authorised under `file.write.inbound` keeps running if that
capability is revoked mid-flight, because nothing re-checks. So "revocation is
instant" is made an enforceable property with **independent** cancellation
domains:

  - each capability has its own generation counter;
  - `revoke(C)` bumps only C's generation — a running mouse session is not
    aborted because a file capability was revoked, and vice versa;
  - `revoke_all()` bumps every capability's generation (the emergency kill);
  - a long-running op takes a **capability-bound** token when it starts and
    checks `token.valid` at each step, aborting the moment its own capability's
    generation moves or the capability is dropped.

This matches the constitutional claim that capabilities are *independently*
revocable — their cancellation domains are now independent, not just their
membership.

**No mutable capability set is exposed.** The only way to change authority is
through `grant`/`revoke`/`revoke_all` here, so a revoke can never happen without
bumping the relevant generation. Reading is via `has`/`granted` (a frozenset
copy), never the live set.

**Concurrency contract (B4).** A SessionAuthority instance is owned by exactly
one session on exactly one event loop, and is NOT internally synchronised: `grant`
/`revoke`/`revoke_all`/`authorize` and every token `.valid` read must happen on
that owning loop. `revoke` then bumping a generation is two operations; a reader
on another thread could observe the gap and act on stale authority. Do not share
one authority across sessions or threads. When session handling becomes multi-
threaded, either confine all authority mutation to the owning loop via
`call_soon_threadsafe`-style marshalling, or introduce explicit locking — this is
a tracked blocking condition (B5/B4 in the roadmap) before any such use, and in
particular before input injection reads authority on a hot path."""

from __future__ import annotations

from ..common.errors import PermissionDeniedError
from ..protocol.capabilities import Capability, CapabilitySet


class CancellationToken:
    """A capability-bound snapshot. Invalid the instant its own capability's
    generation moves (a revoke of that capability or revoke_all), the capability
    is dropped, or it is cancelled.

    Cancellation-aware: `wait_invalid()` completes promptly when the token becomes
    invalid, so a long-running op can *race* a blocking await against revocation
    instead of only discovering it on the next poll — which, combined with a
    re-check after every await and before the privileged side effect, is what
    makes 'instant revocation' actually hold across `await` boundaries."""

    __slots__ = ("_authority", "_capability", "_generation", "_cancelled", "_event", "_cancel_event")

    def __init__(
        self,
        authority: "SessionAuthority",
        capability: Capability,
        generation: int,
        event: "object | None" = None,
    ) -> None:
        self._authority = authority
        self._capability = capability
        self._generation = generation
        self._cancelled = False
        self._event = event  # shared asyncio.Event fired when this capability is revoked
        self._cancel_event = None  # token-local, created lazily on first wait/cancel

    @property
    def capability(self) -> Capability:
        return self._capability

    @property
    def valid(self) -> bool:
        return (
            not self._cancelled
            and self._authority.generation_of(self._capability) == self._generation
            and self._authority.has(self._capability)
        )

    def _local_cancel_event(self):
        import asyncio

        if self._cancel_event is None:
            self._cancel_event = asyncio.Event()
        return self._cancel_event

    def cancel(self) -> None:
        self._cancelled = True
        # Wake this token's own waiter — NOT the shared capability event, which
        # other tokens for the same capability depend on.
        if self._cancel_event is not None:
            self._cancel_event.set()

    async def wait_invalid(self) -> None:
        """Return as soon as this token is no longer valid. Used to race a
        long-running await (a frame wait, a network read) against revocation."""
        import asyncio

        if not self.valid:
            return
        local = self._local_cancel_event()
        if self._event is None:
            # No capability event wired: race only the local cancel event with a
            # short poll so a generation move is still noticed.
            while self.valid:
                try:
                    await asyncio.wait_for(local.wait(), timeout=0.05)
                except asyncio.TimeoutError:
                    pass
            return
        # Race the shared capability-revoke event AND the token-local cancel event;
        # a poll-timeout still catches a generation move we got no event for.
        while self.valid:
            cap_wait = asyncio.ensure_future(self._event.wait())
            local_wait = asyncio.ensure_future(local.wait())
            try:
                await asyncio.wait(
                    {cap_wait, local_wait}, timeout=0.5, return_when=asyncio.FIRST_COMPLETED
                )
            finally:
                for t in (cap_wait, local_wait):
                    if not t.done():
                        t.cancel()


class SessionAuthority:
    """Owns the live capabilities plus a per-capability generation counter. The
    mutable set is private; callers mutate only through this object's methods."""

    __slots__ = ("_caps", "_generations", "_events")

    def __init__(self) -> None:
        self._caps = CapabilitySet()
        self._generations: dict[Capability, int] = {}
        self._events: dict[Capability, object] = {}  # asyncio.Event per capability

    def _event_for(self, capability: Capability):
        import asyncio

        ev = self._events.get(capability)
        if ev is None:
            ev = asyncio.Event()
            self._events[capability] = ev
        return ev

    def _fire(self, capability: Capability) -> None:
        # Wake anything waiting on this capability, then install a fresh event so
        # future grants of the same capability start un-fired.
        import asyncio

        ev = self._events.get(capability)
        if ev is not None:
            ev.set()
        self._events[capability] = asyncio.Event()

    def generation_of(self, capability: Capability) -> int:
        return self._generations.get(capability, 0)

    # --- reads (never the mutable set) ---
    def has(self, capability: Capability) -> bool:
        return self._caps.has(capability)

    def granted(self) -> frozenset[Capability]:
        return self._caps.granted()

    # --- mutations (revocation bumps the relevant generation) ---
    def grant(self, capability: Capability) -> None:
        self._caps.grant(capability)  # widening authority does not invalidate tokens

    def revoke(self, capability: Capability) -> None:
        self._caps.revoke(capability)
        self._generations[capability] = self.generation_of(capability) + 1
        self._fire(capability)  # wake any waiter racing this capability

    def revoke_all(self) -> None:
        # Emergency kill: bump every capability's generation so no outstanding
        # token of any kind survives, then drop all grants.
        for capability in Capability:
            self._generations[capability] = self.generation_of(capability) + 1
            self._fire(capability)
        self._caps.revoke_all()

    # --- capability-bound authorization for long-running work ---
    def authorize(self, capability: Capability) -> CancellationToken:
        """Verify the capability is granted right now and return a token bound to
        it and to its current generation. Raises if not granted."""
        if not self._caps.has(capability):
            raise PermissionDeniedError(f"missing capability: {capability}")
        return CancellationToken(
            self, capability, self.generation_of(capability), event=self._event_for(capability)
        )
