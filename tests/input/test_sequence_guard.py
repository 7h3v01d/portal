# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""INV-12 — session sequence guard: consume-on-seen and replay rejection."""

from __future__ import annotations

from portal.input.model import SessionRef, new_session_nonce
from portal.input.sequence import SessionSequenceGuard, SeqVerdict

N = new_session_nonce()


def _s(seq, nonce=N):
    return SessionRef(nonce, seq)


def test_in_order_accepted_and_advances():
    g = SessionSequenceGuard(N)
    assert g.check(_s(0)).accepted
    assert g.check(_s(1)).accepted
    assert g.check(_s(2)).accepted
    assert g.last_seen == 2


def test_replay_same_seq_rejected():
    g = SessionSequenceGuard(N)
    assert g.check(_s(0)).accepted
    # Replaying seq 0 must be rejected as stale, and must not roll back last_seen.
    r = g.check(_s(0))
    assert r.verdict is SeqVerdict.STALE_SEQ
    assert g.last_seen == 0


def test_lower_seq_replay_rejected():
    g = SessionSequenceGuard(N)
    for i in range(5):
        assert g.check(_s(i)).accepted
    # An old, lower seq (replay) is firmly rejected.
    assert g.check(_s(2)).verdict is SeqVerdict.STALE_SEQ
    assert g.last_seen == 4


def test_gap_rejected_without_advancing():
    g = SessionSequenceGuard(N)
    assert g.check(_s(0)).accepted
    # Skipping ahead (ordered transport should never do this) is rejected and does
    # NOT advance — so the skipped seq can't later sneak in as "next".
    assert g.check(_s(5)).verdict is SeqVerdict.SEQ_GAP
    assert g.last_seen == 0
    # The true next frame still works.
    assert g.check(_s(1)).accepted


def test_wrong_nonce_rejected_and_no_state_change():
    g = SessionSequenceGuard(N)
    assert g.check(_s(0)).accepted
    other = new_session_nonce()
    assert g.check(_s(1, nonce=other)).verdict is SeqVerdict.WRONG_SESSION
    # Wrong-session frame must not have advanced our sequence.
    assert g.last_seen == 0
    assert g.check(_s(1)).accepted


def test_consumed_seq_cannot_be_reused_after_drop():
    # The core replay property: once a seq is SEEN it is consumed, even if the
    # caller would later drop the event. Re-presenting the same seq is stale.
    g = SessionSequenceGuard(N)
    assert g.check(_s(0)).accepted   # seen+consumed (imagine a later policy drops it)
    assert g.check(_s(0)).verdict is SeqVerdict.STALE_SEQ  # can't replay it
