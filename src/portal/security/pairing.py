# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Pairing: how two machines that have never met establish MUTUAL trust.

The design rests on five properties, in priority order:

  1. **Key-bound, not code-bound.** A peer's identity is the public key the
     transport already authenticated — NEVER a key or id asserted in a payload.
  2. **SAS-authenticated first contact.** Cryptographic channel authentication
     only proves "the peer owns this key", not "this key is Dad's computer".
     Before pinning, BOTH machines display the same Short Authentication String,
     derived from BOTH public keys, and a human confirms they match out of band.
     Under an active MITM (a terminating attacker with its own key on each leg)
     the two machines derive DIFFERENT strings, so the comparison fails. This is
     what makes pairing authenticated rather than TOFU-with-a-button. See the
     invariant below — it is non-negotiable, especially for the internet phases.
  3. **Single-use.** A code is consumed the moment it is correctly redeemed (and
     when it is exhausted by wrong guesses), so it can't be replayed.
  4. **Expiring + rate-limited.** Short TTL (on a *monotonic* clock, so a wall-
     clock step-back can't extend validity) plus a hard cap on wrong attempts
     bounds brute force to a handful of guesses in a small window.
  5. **Mutual.** The host trusts the controller (handle_request) and the
     controller trusts the host (ControllerPairing.handle_accept). Both sides
     pin the other's authenticated key, each after its own SAS confirmation.

============================ SECURITY INVARIANT =============================
Pairing approval MUST mean: "the SAS shown on THIS machine was compared, out of
band, against the SAS shown on the OTHER physical machine, and they matched."
It must NOT mean "a dialog said a name and a fingerprint; the user clicked OK".
The `confirm` callback is that ceremony; the UI that implements it is bound by
this invariant and must be tested at the session/UI boundary.
============================================================================

The code is never stored in plaintext — only its SHA-256 — and compared in
constant time.
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
SAS_DIGITS = 6


class PairingOutcome(Enum):
    ACCEPTED = "accepted"
    NO_ACTIVE_PAIRING = "no_active_pairing"
    BAD_CODE = "bad_code"
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"
    ALREADY_TRUSTED = "already_trusted"
    DENIED_BY_USER = "denied_by_user"
    DENIED_BY_PEER = "denied_by_peer"


@dataclass(frozen=True)
class PairingConfirmation:
    """What the human is asked to approve. `sas` is the string to compare against
    the OTHER machine; approval means the two matched out of band."""

    peer: DeviceIdentity
    sas: str
    fingerprint: str


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


def compute_sas(key_a: bytes, key_b: bytes, digits: int = SAS_DIGITS) -> str:
    """Short Authentication String derived from BOTH public keys. Order-
    independent (the keys are sorted first) so both endpoints compute the same
    value from the same pair of keys — and a DIFFERENT value if either key
    differs, which is exactly the MITM-detection property. Rendered as grouped
    decimal digits for easy read-aloud comparison."""
    lo, hi = sorted((bytes(key_a), bytes(key_b)))
    digest = hashlib.sha256(b"portal-sas-v1" + lo + hi).digest()
    value = int.from_bytes(digest[:8], "big") % (10 ** digits)
    s = str(value).zfill(digits)
    return f"{s[:3]}-{s[3:]}" if digits == 6 else s


class PairingManager:
    """Host-side pairing state. One pending pairing at a time by design — the
    owner deliberately enters pairing mode, a code is shown, one peer redeems it.

    Concurrency: owned by a single event loop / thread; not internally
    synchronised."""

    def __init__(
        self,
        store: IdentityStore,
        own_public_key: bytes,
        *,
        clock: Callable[[], float] = time.monotonic,
        ttl: float = DEFAULT_TTL_SECONDS,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    ) -> None:
        self._store = store
        self._own_key = bytes(own_public_key)
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
        confirm: Callable[[PairingConfirmation], bool],
    ) -> PairingResult:
        """Process an incoming pairing request.

        `peer_public_key` MUST be the key the transport authenticated — not a
        value from the request payload. `confirm` is the SAS ceremony (see the
        module invariant): it is shown the SAS to compare against the other
        machine and returns True only if they matched. Trust is pinned only then."""
        now = self._clock()

        pending = self._pending
        if pending is None:
            return PairingResult(PairingOutcome.NO_ACTIVE_PAIRING)

        if pending.expired(now):
            self._pending = None
            return PairingResult(PairingOutcome.EXPIRED)

        # Count the attempt before comparing, so a flood is bounded regardless.
        pending.attempts += 1
        code_ok = hmac.compare_digest(pending.code_hash, _hash_code(code))

        if not code_ok:
            if pending.attempts >= pending.max_attempts:
                self._pending = None
                _log.warning("pairing code exhausted by failed attempts")
                return PairingResult(PairingOutcome.EXHAUSTED)
            return PairingResult(PairingOutcome.BAD_CODE)

        # Correct code -> single-use: consume now so it can never be redeemed twice.
        self._pending = None

        try:
            safe_name = ensure_display_text(device_name_hint)[:MAX_DEVICE_NAME_LEN]
            peer = DeviceIdentity.from_public_key(peer_public_key, safe_name)
        except Exception:
            # Malformed key or unsafe name: refuse, do not trust.
            _log.warning("pairing request had invalid peer identity")
            return PairingResult(PairingOutcome.DENIED_BY_USER)

        if self._store.is_trusted(peer):
            return PairingResult(PairingOutcome.ALREADY_TRUSTED, peer)

        confirmation = PairingConfirmation(
            peer=peer,
            sas=compute_sas(self._own_key, peer.public_key),
            fingerprint=peer.fingerprint(),
        )
        if not confirm(confirmation):
            _log.info("pairing declined at SAS ceremony for %s", redact(peer.device_id))
            return PairingResult(PairingOutcome.DENIED_BY_USER, peer)

        self._store.trust(peer)
        _log.info("paired and pinned new device %s", redact(peer.device_id))
        return PairingResult(PairingOutcome.ACCEPTED, peer)


class ControllerPairing:
    """Controller-side pairing. The controller has typed the code and connected;
    the transport has authenticated the host's key. It sends PAIR_REQUEST and,
    on PAIR_ACCEPT, pins the HOST's key after its own SAS confirmation — so both
    sides end up trusting each other (mutual pairing)."""

    def __init__(self, store: IdentityStore, own_public_key: bytes, host_public_key: bytes) -> None:
        self._store = store
        self._own_key = bytes(own_public_key)
        self._host = DeviceIdentity.from_public_key(host_public_key, device_name="")

    def sas(self) -> str:
        """The SAS this side displays — same value as the host for the same key
        pair, different under a MITM."""
        return compute_sas(self._own_key, self._host.public_key)

    def handle_accept(
        self,
        host_name_hint: str,
        confirm: Callable[[PairingConfirmation], bool],
    ) -> PairingResult:
        """Called when PAIR_ACCEPT arrives. Pins the host key after SAS confirm."""
        try:
            safe_name = ensure_display_text(host_name_hint)[:MAX_DEVICE_NAME_LEN]
        except Exception:
            safe_name = ""
        host = DeviceIdentity.from_public_key(self._host.public_key, safe_name)

        if self._store.is_trusted(host):
            return PairingResult(PairingOutcome.ALREADY_TRUSTED, host)

        confirmation = PairingConfirmation(
            peer=host, sas=self.sas(), fingerprint=host.fingerprint()
        )
        if not confirm(confirmation):
            return PairingResult(PairingOutcome.DENIED_BY_USER, host)

        self._store.trust(host)
        _log.info("controller pinned host %s", redact(host.device_id))
        return PairingResult(PairingOutcome.ACCEPTED, host)

    def handle_deny(self) -> PairingResult:
        return PairingResult(PairingOutcome.DENIED_BY_PEER, self._host)
