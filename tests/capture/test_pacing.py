# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""FPS pacing logic, tested with an injected clock (no real time)."""

from __future__ import annotations

import pytest

from portal.capture.pacing import FrameClock


class FakeClock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def test_interval_from_fps():
    fc = FrameClock(30, clock=FakeClock())
    assert abs(fc.interval - 1 / 30) < 1e-9


def test_not_due_until_interval_elapses():
    clk = FakeClock()
    fc = FrameClock(10, clock=clk)  # 0.1s interval
    assert fc.due()  # first frame due immediately
    fc.mark_emitted()
    assert not fc.due()
    clk.advance(0.05)
    assert not fc.due()
    clk.advance(0.05)
    assert fc.due()


def test_time_until_next():
    clk = FakeClock()
    fc = FrameClock(10, clock=clk)
    fc.mark_emitted()
    clk.advance(0.03)
    assert abs(fc.time_until_next() - 0.07) < 1e-9


def test_falling_behind_resyncs_no_burst():
    clk = FakeClock()
    fc = FrameClock(30, clock=clk)
    fc.mark_emitted()
    # Jump far ahead (e.g. process stalled 5s). The next deadline should resync
    # to ~now, not schedule a burst of ~150 backlogged frames.
    clk.advance(5.0)
    fc.mark_emitted()
    assert fc.time_until_next() <= fc.interval + 1e-9


def test_positive_fps_required():
    with pytest.raises(ValueError):
        FrameClock(0)
