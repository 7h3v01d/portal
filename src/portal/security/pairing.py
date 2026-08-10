# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Pairing: how two machines that have never met establish mutual trust.

The design rests on four properties, in priority order:

  1. **Key-bound, not code-bound.** The peer's identity is the public key the
     transport already authenticated — NEVER a key or id the peer asserts in the
     payload. The one-time code proves the *human* on the other end is the
     intended person; the pinned key is the durable identity (TOFU).
  2. **Single-use.** A code is consumed the moment it is correctly redeemed (and
     also the moment it is exhausted by wrong guesses), so it can't be replayed.
  3. **Expiring + rate-limited.** Short TTL plus a hard cap on wrong attempts
     bounds brute force to a handful of guesses inside a small window — which is
     what actually protects a short, human-typeable code, not its entropy alone.
  4. **Attended.** Trust is pinned only after an explicit local confirmation of
     the peer's fingerprint. No confirmation, no trust, no silent pairing.

The code is never stored in plaintext — only its SHA-256 — and comparison is
constant-time.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from ..common.constants import MAX_DEVICE_NAME_LEN
from ..common.logging import get_logger, redact
from .identity import DeviceIdentity, IdentityStore
from .validation import ensure_display_text

_log = get_logger("security.pairing")

# Crockford-style alphabet: no I, L, O, 0, 1 — unambiguous read-aloud/type.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
DEFAULT_TTL_SECONDS = 180.0
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_CODE_GROUPS = 2  # 2 groups of 4 = 8 chars ~ 40 bits


class PairingOutcome(Enum):
    ACCEPTED = "accepted"
    NO_ACTIVE_PAIRING = "no_active_pairing"
    BAD_CODE = "bad_code"
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"
    ALREADY_TRUSTED = "already_trusted"
    DENIED_BY_USER = "denied_by_user"


@dataclass(frozen=True)
class PairingResult:
    outcome: PairingOutcome
    peer: DeviceIdentity | None = None

    @property
    def ok(self) -> bool:
        return self.outcome in (PairingOutcome.ACCEPTED, PairingOutcome.ALREADY_TRUSTED)


@dataclass
class _PendingPairing:
    code_hash: bytes
    created_at: float
    ttl: float
    max_attempts: int
    attempts: int = 0

    def expired(self, now: float) -> bool:
        return now >= self.created_at + self.ttl


def generate_code(groups: int = DEFAULT_CODE_GROUPS, group_len: int = 4) -> str:
    """A one-time code from a CSPRNG, grouped for readability (e.g. AB2C-9KMN)."""
    chunks = [
        "".join(secrets.choice(_CODE_ALPHABET) for _ in range(group_len))
        for _ in range(groups)
    ]
    return "-".join(chunks)


def _hash_code(code: str) -> bytes:
    return hashlib.sha256(code.encode("utf-8")).digest()


class PairingManager:
    """Host-side pairing state. One pending pairing at a time by design — the
    owner deliberately enters pairing mode, a code is shown, one peer redeems it.

    Concurrency: like SessionAuthority, this is owned by a single event loop /
    thread and is not internally synchronised."""

    def __init__(
        self,
        store: IdentityStore,
        *,
        clock: Callable[[], float] = time.time,
        ttl: float = DEFAULT_TTL_SECONDS,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    ) -> None:
        self._store = store
        self._clock = clock
        self._ttl = ttl
        self._max_attempts = max_attempts
        self._pending: _PendingPairing | None = None

    @property
    def pairing_active(self) -> bool:
        if self._pending is None:
            return False
        if self._pending.expired(self._clock()):
            self._pending = None
            return False
        return True

    def begin_pairing(self) -> str:
        """Enter pairing mode. Returns the plaintext code to display to the owner
        exactly once; only its hash is retained."""
        code = generate_code()
        self._pending = _PendingPairing(
            code_hash=_hash_code(code),
            created_at=self._clock(),
            ttl=self._ttl,
            max_attempts=self._max_attempts,
        )
        return code

    def cancel(self) -> None:
        self._pending = None

    def handle_request(
        self,
        peer_public_key: bytes,
        code: str,
        device_name_hint: str,
        confirm: Callable[[DeviceIdentity], bool],
    ) -> PairingResult:
        """Process an incoming pairing request.

        `peer_public_key` MUST be the key the transport authenticated — not a
        value from the request payload. `confirm` is the attended step: it is
        shown the peer's fingerprint and returns True only if the local owner
        approves. Trust is pinned only on approval."""
        now = self._clock()

        pending = self._pending
        if pending is None:
            return PairingResult(PairingOutcome.NO_ACTIVE_PAIRING)

        if pending.expired(now):
            self._pending = None
            return PairingResult(PairingOutcome.EXPIRED)

        # Attempt accounting happens before the compare so a flood of guesses is
        # bounded regardless of correctness.
        pending.attempts += 1
        code_ok = hmac.compare_digest(pending.code_hash, _hash_code(code))

        if not code_ok:
            if pending.attempts >= pending.max_attempts:
                self._pending = None  # burn the code: too many wrong guesses
                _log.warning("pairing code exhausted by failed attempts")
                return PairingResult(PairingOutcome.EXHAUSTED)
            return PairingResult(PairingOutcome.BAD_CODE)

        # Correct code -> single-use: consume it now, before anything else can go
        # wrong, so it can never be redeemed twice.
        self._pending = None

        # Identity is derived from the AUTHENTICATED key; the name is a sanitised,
        # untrusted hint.
        safe_name = ensure_display_text(device_name_hint)[:MAX_DEVICE_NAME_LEN]
        peer = DeviceIdentity.from_public_key(peer_public_key, safe_name)

        # If this exact key is already trusted, pairing is idempotent.
        if self._store.is_trusted(peer):
            return PairingResult(PairingOutcome.ALREADY_TRUSTED, peer)

        # Attended confirmation of the fingerprint — the one human gate.
        if not confirm(peer):
            _log.info("pairing declined by local user for %s", redact(peer.device_id))
            return PairingResult(PairingOutcome.DENIED_BY_USER, peer)

        self._store.trust(peer)
        _log.info("paired and pinned new device %s", redact(peer.device_id))
        return PairingResult(PairingOutcome.ACCEPTED, peer)
