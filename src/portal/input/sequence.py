# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Session sequence guard — INV-12, the FIRST stage of the input intake pipeline.

Independent of the transport/A6 channel binding, the input layer enforces its own
per-session replay defence: a host-generated random 128-bit nonce plus a strictly
increasing uint64 input_seq. The defining property is CONSUME-ON-SEEN: the sequence
number is consumed the moment a session-bound frame is seen (correct nonce, next
expected seq), BEFORE any authority / view / rate / pause policy runs. That ordering
is itself a safety property — if the sequence were consumed only on *accepted*
events, a frame dropped by a later policy (e.g. rate limit) could be resent under
the same seq and executed, violating "rate exceeded -> drop forever".

Rules:
  * wrong nonce                      -> reject (WRONG_SESSION)
  * seq <= last_seen (replay/stale)  -> reject (STALE_SEQ)   [does NOT advance]
  * seq >  last_seen + 1 (gap)       -> reject (SEQ_GAP)     [ordered transport]
  * seq == last_seen + 1             -> ACCEPT, advance last_seen immediately

A new session (new nonce) resets the expected sequence. The guard is the sole owner
of last_seen; nothing downstream may advance or roll it back.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import Enum

from .model import SessionRef


class SeqVerdict(str, Enum):
    ACCEPT = "accept"
    WRONG_SESSION = "wrong_session"
    STALE_SEQ = "stale_seq"       # replay or out-of-order-old — the key replay guard
    SEQ_GAP = "seq_gap"           # skipped ahead; ordered/reliable transport forbids


@dataclass(frozen=True)
class SeqResult:
    verdict: SeqVerdict

    @property
    def accepted(self) -> bool:
        return self.verdict is SeqVerdict.ACCEPT


class SessionSequenceGuard:
    """Owns the per-session nonce and the monotonic last_seen sequence. Single
    instance per host-side input session; a new input session installs a fresh
    guard (new nonce). Not internally locked — the intake pipeline calls it from a
    single consumer; if that ever changes, wrap calls in the pipeline's lock."""

    def __init__(self, nonce: bytes) -> None:
        if len(nonce) != 16:
            raise ValueError("session nonce must be 16 bytes (128 bits)")
        self._nonce = nonce
        self._last_seen = -1  # no frame seen yet; first valid seq is 0

    @property
    def last_seen(self) -> int:
        return self._last_seen

    def attributes_to_session(self, session: SessionRef) -> bool:
        """True if this frame is cryptographically attributable to THIS session
        (nonce matches). Checked BEFORE consuming the sequence so a wrong-session
        frame never touches sequence state. Constant-time to avoid a nonce-probing
        timing oracle."""
        return hmac.compare_digest(session.input_session_nonce, self._nonce)

    def check(self, session: SessionRef) -> SeqResult:
        """Consume-on-seen. Advances last_seen iff the frame is attributable to this
        session AND is the next expected sequence. A stale/replayed seq (<=
        last_seen) is rejected and does NOT roll the counter back or advance it.

        IMPORTANT ordering property (see pipeline): the caller MUST have already
        established that the frame is well-formed (shape) and attributable to this
        session. Consumption means \"a valid, session-owned frame at this sequence
        was seen\" — NOT \"any bytes claiming this seq were seen\". A malformed or
        wrong-session frame must never consume a sequence a legitimate retransmit
        needs."""
        # Constant-time nonce comparison so a probing attacker can't learn the nonce
        # by timing. A wrong nonce never touches the sequence state.
        if not hmac.compare_digest(session.input_session_nonce, self._nonce):
            return SeqResult(SeqVerdict.WRONG_SESSION)

        seq = session.input_seq
        if seq <= self._last_seen:
            # Replay or stale/out-of-order-old. Firmly rejected; counter unchanged.
            return SeqResult(SeqVerdict.STALE_SEQ)
        if seq > self._last_seen + 1:
            # Gap: ordered, reliable transport must deliver seq == last_seen + 1.
            # A gap means loss/tampering; reject without advancing (the missing
            # frame can't be "filled" later — that would be a stale seq then).
            return SeqResult(SeqVerdict.SEQ_GAP)

        # seq == last_seen + 1: the next expected frame. Consume it NOW, before any
        # downstream policy can drop it.
        self._last_seen = seq
        return SeqResult(SeqVerdict.ACCEPT)
