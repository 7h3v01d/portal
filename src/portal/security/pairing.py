# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Pairing: how two machines that have never met establish MUTUAL trust.

The design rests on six properties, in priority order:

  1. **Key-bound, not code-bound.** A peer's identity is the public key the
     transport already authenticated — NEVER a key or id asserted in a payload.

  2. **Grind-resistant SAS-authenticated first contact.** Channel authentication
     only proves "the peer owns this key", not "this key is Dad's computer".
     Before pinning, BOTH machines display the same Short Authentication String,
     derived from BOTH public keys, and a human confirms they match out of band.

     The threat is an active MITM that presents its OWN key on each leg and tries
     to make both legs show the same SAS. Crucially it chooses BOTH keys, so this
     is a two-sided claw/collision search, not a one-sided preimage: the generic
     work factor is ~n/2 for an n-bit SAS (birthday bound), NOT n. A 6-digit
     (~20-bit) SAS collides in ~2**10 work; even an 80-bit SAS only gives ~2**40
     collision resistance, which is feasible offline because a bare-hash SAS
     carries no fresh session secret. So the SAS output is **160 bits**, giving
     ~2**80 generic collision resistance. This is a usable-but-long string; the
     proper long-term fix (and the internet-phase plan) is an established PAKE
     (SPAKE2+/OPAQUE) with commitment, so a short SAS becomes safe again and the
     one-time code becomes a real secret rather than plaintext in transit. We do
     not invent that ourselves.

  3. **Single-use.** A code is consumed the moment it is correctly redeemed (and
     when it is exhausted by wrong guesses), so it can't be replayed.

  4. **Expiring + rate-limited.** Short TTL on a *monotonic* clock plus a hard cap
     on wrong attempts bounds brute force to a handful of guesses in a small
     window.

  5. **Mutual, with explicit commit.** Trust is not persisted the instant a SAS is
     confirmed. The host holds a PENDING commit after its SAS confirmation and
     durably trusts the controller only on an explicit PAIR_CONFIRM carrying the
     transaction nonce. The controller — the less dangerous side — commits first;
     the host — which will grant control of the machine — commits last, so a
     dropped/declined final step leaves the *host* under-trusting, never over-
     trusting. Full distributed atomicity is impossible; this makes the residual
     asymmetry fail safe.

  6. **Nonce-correlated.** Each pairing carries a random transaction nonce so the
     accept/confirm steps are bound to the exchange that started them.

============================ SECURITY INVARIANT =============================
Pairing approval MUST mean: "the SAS shown on THIS machine was compared, out of
band, against the SAS shown on the OTHER physical machine, and they matched."
Not "a dialog said a name; the user clicked OK". The `confirm` callback is that
ceremony; the UI that implements it is bound by this invariant.
============================================================================
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
from ..common.errors import PairingError
from ..common.logging import get_logger, redact
from .identity import DeviceIdentity, IdentityStore
from .validation import ensure_display_text

_log = get_logger("security.pairing")

# Crockford-style alphabet: no I, L, O, 0, 1 — unambiguous read-aloud/type.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
DEFAULT_TTL_SECONDS = 180.0
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_CODE_GROUPS = 2      # 2 groups of 4 = 8 chars ~ 40 bits
SAS_BYTES = 20             # 160-bit output -> ~80-bit generic collision resistance (n/2)


class PairingOutcome(Enum):
    PENDING_COMMIT = "pending_commit"   # host: SAS confirmed, awaiting PAIR_CONFIRM
    ACCEPTED = "accepted"               # durably trusted
    NO_ACTIVE_PAIRING = "no_active_pairing"
    NO_PENDING_COMMIT = "no_pending_commit"
    BAD_CODE = "bad_code"
    SOURCE_THROTTLED = "source_throttled"  # this source used its guess budget
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"             # global backstop tripped — code burned
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
    nonce: str | None = None  # host surfaces this so the caller can send PAIR_ACCEPT

    @property
    def ok(self) -> bool:
        return self.outcome in (PairingOutcome.ACCEPTED, PairingOutcome.ALREADY_TRUSTED)


@dataclass
class PairingChallenge:
    """Result of stage-1 validate_request. `ok` is True only when the code was
    correct and a SAS challenge is ready; then `.confirmation` holds the SAS to
    show the human and stage-2 confirm_request applies their decision. When `ok`
    is False, `.result` carries the failing outcome (bad code, throttled, etc.)
    and no human prompt should be shown."""

    result: PairingResult
    confirmation: "PairingConfirmation | None" = None
    _nonce: str | None = None
    _peer: DeviceIdentity | None = None

    @property
    def ok(self) -> bool:
        return (
            self.result.outcome is PairingOutcome.PENDING_COMMIT
            and self.confirmation is not None
        )


@dataclass
class _PendingPairing:
    code_hash: bytes
    nonce: str
    created_at: float
    ttl: float
    per_source_max: int
    global_max: int
    global_attempts: int = 0
    source_attempts: dict = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.source_attempts is None:
            self.source_attempts = {}

    def expired(self, now: float) -> bool:
        return now >= self.created_at + self.ttl


@dataclass
class _PendingCommit:
    peer: DeviceIdentity
    nonce: str
    created_at: float
    ttl: float

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


def compute_sas(key_a: bytes, key_b: bytes, sas_bytes: int = SAS_BYTES) -> str:
    """Short Authentication String from BOTH public keys. Order-independent (keys
    are sorted first) so both endpoints derive the same value from the same pair,
    and a different value if either key differs — the MITM-detection property.

    80 bits by default so an attacker who chooses the keys it presents cannot
    grind them to force the two legs to a matching SAS. Rendered as grouped
    uppercase hex for read-aloud comparison."""
    lo, hi = sorted((bytes(key_a), bytes(key_b)))
    digest = hashlib.sha256(b"portal-sas-v1" + lo + hi).digest()
    hexs = digest[:sas_bytes].hex().upper()
    return "-".join(hexs[i : i + 4] for i in range(0, len(hexs), 4))


class PairingManager:
    """Host-side pairing state. One pending pairing at a time by design.

    Concurrency: owned by a single event loop / thread; not internally
    synchronised."""

    def __init__(
        self,
        store: IdentityStore,
        own_public_key: bytes,
        *,
        clock: Callable[[], float] = time.monotonic,
        ttl: float = DEFAULT_TTL_SECONDS,
        per_source_attempts: int = DEFAULT_MAX_ATTEMPTS,
        global_attempts: int | None = None,
    ) -> None:
        from ..common.constants import PAIR_ATTEMPTS_GLOBAL_MAX

        self._store = store
        self._own_key = bytes(own_public_key)
        self._clock = clock
        self._ttl = ttl
        self._per_source_max = per_source_attempts
        self._global_max = global_attempts if global_attempts is not None else PAIR_ATTEMPTS_GLOBAL_MAX
        self._pending: _PendingPairing | None = None
        self._pending_commit: _PendingCommit | None = None

    @property
    def pairing_active(self) -> bool:
        if self._pending is None:
            return False
        if self._pending.expired(self._clock()):
            self._pending = None
            return False
        return True

    @property
    def awaiting_commit(self) -> bool:
        if self._pending_commit is None:
            return False
        if self._pending_commit.expired(self._clock()):
            self._pending_commit = None
            return False
        return True

    def begin_pairing(self) -> str:
        """Enter pairing mode. Returns the plaintext code to display exactly once;
        only its hash is retained. A transaction nonce is generated internally.

        Refuses if a previous pairing is still awaiting its final commit — the
        state machine holds at most one transaction, and transitions out of a
        pending commit must be explicit (commit / cancel / expire)."""
        if self.awaiting_commit:
            raise PairingError("a pairing is awaiting commit; commit or cancel first")
        code = generate_code()
        self._pending = _PendingPairing(
            code_hash=_hash_code(code),
            nonce=secrets.token_hex(16),
            created_at=self._clock(),
            ttl=self._ttl,
            per_source_max=self._per_source_max,
            global_max=self._global_max,
        )
        return code

    def cancel(self) -> None:
        self._pending = None
        self._pending_commit = None

    def handle_request(
        self,
        peer_public_key: bytes,
        code: str,
        device_name_hint: str,
        confirm: Callable[[PairingConfirmation], bool],
        source: str = "local",
    ) -> PairingResult:
        """Back-compat one-shot: validate the code, and only if it is correct run
        the SAS `confirm` callback. Prefer the two-stage validate_request /
        confirm_request API when consent is async, so the human is never prompted
        before the pairing secret is proven."""
        challenge = self.validate_request(peer_public_key, code, device_name_hint, source=source)
        if not challenge.ok:
            return challenge.result
        if challenge.result.outcome is PairingOutcome.ALREADY_TRUSTED:
            return challenge.result
        approved = confirm(challenge.confirmation)
        return self.confirm_request(challenge, approved)

    def validate_request(
        self,
        peer_public_key: bytes,
        code: str,
        device_name_hint: str,
        source: str = "local",
    ) -> "PairingChallenge":
        """Stage 1: validate the pairing code and charge the guess budget BEFORE
        any human interaction. A wrong code is rejected here — the host never
        shows a SAS prompt to a peer that hasn't proven knowledge of the secret.
        Returns a challenge whose `.confirmation` carries the SAS to show the
        human, or `.ok is False` with the failing result."""
        now = self._clock()
        pending = self._pending
        if pending is None:
            return PairingChallenge(result=PairingResult(PairingOutcome.NO_ACTIVE_PAIRING))
        if pending.expired(now):
            self._pending = None
            return PairingChallenge(result=PairingResult(PairingOutcome.EXPIRED))

        if pending.source_attempts.get(source, 0) >= pending.per_source_max:
            return PairingChallenge(result=PairingResult(PairingOutcome.SOURCE_THROTTLED))

        code_ok = hmac.compare_digest(pending.code_hash, _hash_code(code))
        if not code_ok:
            pending.source_attempts[source] = pending.source_attempts.get(source, 0) + 1
            pending.global_attempts += 1
            if pending.global_attempts >= pending.global_max:
                self._pending = None
                _log.warning("pairing code exhausted (global attempt cap)")
                return PairingChallenge(result=PairingResult(PairingOutcome.EXHAUSTED))
            if pending.source_attempts[source] >= pending.per_source_max:
                _log.info("pairing source throttled after failed attempts")
                return PairingChallenge(result=PairingResult(PairingOutcome.SOURCE_THROTTLED))
            return PairingChallenge(result=PairingResult(PairingOutcome.BAD_CODE))

        # Code is correct — consume it (single-use) and prepare the SAS challenge.
        nonce = pending.nonce
        self._pending = None

        try:
            safe_name = ensure_display_text(device_name_hint)[:MAX_DEVICE_NAME_LEN]
            peer = DeviceIdentity.from_public_key(peer_public_key, safe_name)
        except Exception:  # noqa: BLE001
            _log.warning("pairing request had invalid peer identity")
            return PairingChallenge(result=PairingResult(PairingOutcome.DENIED_BY_USER))

        if self._store.is_trusted(peer):
            return PairingChallenge(result=PairingResult(PairingOutcome.ALREADY_TRUSTED, peer))

        confirmation = PairingConfirmation(
            peer=peer, sas=compute_sas(self._own_key, peer.public_key), fingerprint=peer.fingerprint()
        )
        return PairingChallenge(
            result=PairingResult(PairingOutcome.PENDING_COMMIT, peer, nonce=nonce),
            confirmation=confirmation,
            _nonce=nonce,
            _peer=peer,
        )

    def confirm_request(self, challenge: "PairingChallenge", approved: bool) -> PairingResult:
        """Stage 2: apply the human SAS decision for a validated challenge. Only
        reachable once the code was proven correct in validate_request."""
        if not challenge.ok:
            return challenge.result
        peer = challenge._peer
        if not approved:
            _log.info("pairing declined at SAS ceremony for %s", redact(peer.device_id))
            return PairingResult(PairingOutcome.DENIED_BY_USER, peer)
        self._pending_commit = _PendingCommit(
            peer=peer, nonce=challenge._nonce, created_at=self._clock(), ttl=self._ttl
        )
        return PairingResult(PairingOutcome.PENDING_COMMIT, peer, nonce=challenge._nonce)

    def commit(self, peer_public_key: bytes, nonce: str) -> PairingResult:
        """Finalise durable trust on receipt of PAIR_CONFIRM. Requires BOTH the
        transaction nonce AND the same transport-authenticated peer key that the
        pending commit was created for — so, like every other authority decision
        in Portal, this is bound to the authenticated key, not to nonce
        possession alone. The host commits last so a lost/declined confirm leaves
        it under-trusting, never over-trusting."""
        pc = self._pending_commit
        if pc is None or pc.expired(self._clock()):
            self._pending_commit = None
            return PairingResult(PairingOutcome.NO_PENDING_COMMIT)
        nonce_ok = hmac.compare_digest(pc.nonce, nonce)
        key_ok = (
            isinstance(peer_public_key, (bytes, bytearray))
            and hmac.compare_digest(bytes(peer_public_key), pc.peer.public_key)
        )
        if not (nonce_ok and key_ok):
            return PairingResult(PairingOutcome.NO_PENDING_COMMIT)
        self._pending_commit = None
        self._store.trust(pc.peer)
        _log.info("paired and pinned new device %s", redact(pc.peer.device_id))
        return PairingResult(PairingOutcome.ACCEPTED, pc.peer)


class ControllerPairing:
    """Controller-side pairing. The controller has typed the code and connected;
    the transport authenticated the host's key. On PAIR_ACCEPT it pins the host
    after its own SAS confirmation (committing first), then emits PAIR_CONFIRM."""

    def __init__(self, store: IdentityStore, own_public_key: bytes, host_public_key: bytes) -> None:
        self._store = store
        self._own_key = bytes(own_public_key)
        self._host = DeviceIdentity.from_public_key(host_public_key, device_name="")

    def sas(self) -> str:
        return compute_sas(self._own_key, self._host.public_key)

    def handle_accept(
        self,
        host_name_hint: str,
        confirm: Callable[[PairingConfirmation], bool],
    ) -> PairingResult:
        """Pin the host after SAS confirm. The caller then sends PAIR_CONFIRM with
        the nonce it received in PAIR_ACCEPT."""
        try:
            safe_name = ensure_display_text(host_name_hint)[:MAX_DEVICE_NAME_LEN]
        except Exception:
            safe_name = ""
        host = DeviceIdentity.from_public_key(self._host.public_key, safe_name)

        if self._store.is_trusted(host):
            return PairingResult(PairingOutcome.ALREADY_TRUSTED, host)

        confirmation = PairingConfirmation(peer=host, sas=self.sas(), fingerprint=host.fingerprint())
        if not confirm(confirmation):
            return PairingResult(PairingOutcome.DENIED_BY_USER, host)

        self._store.trust(host)
        _log.info("controller pinned host %s", redact(host.device_id))
        return PairingResult(PairingOutcome.ACCEPTED, host)

    def handle_deny(self) -> PairingResult:
        return PairingResult(PairingOutcome.DENIED_BY_PEER, self._host)
