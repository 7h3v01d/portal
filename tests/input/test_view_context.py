# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""INV-10 — view-context registry: host-authoritative freshness, epoch invalidation."""

from __future__ import annotations

from portal.input.model import ViewRef
from portal.input.viewctx import ViewContextRegistry, ViewVerdict


class Clock:
    def __init__(self): self.t = 500.0
    def __call__(self): return self.t
    def advance(self, dt): self.t += dt


def test_fresh_frame_accepted():
    c = Clock()
    reg = ViewContextRegistry(max_age_s=0.5, clock=c)
    v = reg.register_frame()
    assert reg.check(v).accepted


def test_old_frame_rejected_by_host_clock():
    c = Clock()
    reg = ViewContextRegistry(max_age_s=0.5, clock=c)
    v = reg.register_frame()
    c.advance(0.6)  # host's own clock says it's stale
    assert reg.check(v).verdict is ViewVerdict.TOO_OLD


def test_controller_cannot_forge_freshness():
    # The controller only echoes (epoch, frame_seq) — it supplies NO timestamp.
    # Age is computed from the host's capture time, so a stale frame_seq is stale
    # no matter what; there is no field for the controller to lie in.
    c = Clock()
    reg = ViewContextRegistry(max_age_s=0.5, clock=c)
    v = reg.register_frame()
    c.advance(10.0)
    forged = ViewRef(view_epoch=v.view_epoch, frame_seq=v.frame_seq)  # same ref, no age
    assert reg.check(forged).verdict is ViewVerdict.TOO_OLD


def test_epoch_bump_invalidates_prior_frames():
    c = Clock()
    reg = ViewContextRegistry(max_age_s=10.0, clock=c)
    v = reg.register_frame()
    reg.bump_epoch()  # topology/geometry/focus changed
    assert reg.check(v).verdict is ViewVerdict.STALE_EPOCH
    # A fresh frame in the new epoch works.
    v2 = reg.register_frame()
    assert reg.check(v2).accepted


def test_unknown_frame_rejected():
    c = Clock()
    reg = ViewContextRegistry(clock=c)
    reg.register_frame()
    assert reg.check(ViewRef(view_epoch=0, frame_seq=999)).verdict is ViewVerdict.UNKNOWN_FRAME


def test_frame_table_bounded():
    c = Clock()
    reg = ViewContextRegistry(max_age_s=1e9, clock=c)
    for _ in range(400):
        reg.register_frame()
    # Only the most recent frames are retained (bounded memory).
    assert len(reg._frames) <= 256
