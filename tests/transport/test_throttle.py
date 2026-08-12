# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Connection throttle policy, tested with an injected clock (Gate 3.1)."""

from __future__ import annotations

from portal.transport.throttle import (
    ConcurrencyLimiter,
    ConnectionThrottle,
    SlidingWindowRateLimiter,
)


class FakeClock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def test_rate_limiter_allows_up_to_max_then_denies():
    clk = FakeClock()
    rl = SlidingWindowRateLimiter(3, 10.0, clock=clk)
    assert rl.allow("a") and rl.allow("a") and rl.allow("a")
    assert not rl.allow("a")  # 4th within window denied


def test_rate_limiter_window_slides():
    clk = FakeClock()
    rl = SlidingWindowRateLimiter(2, 10.0, clock=clk)
    assert rl.allow("a") and rl.allow("a")
    assert not rl.allow("a")
    clk.advance(11)  # window passed
    assert rl.allow("a")


def test_rate_limiter_is_per_key():
    rl = SlidingWindowRateLimiter(1, 10.0, clock=FakeClock())
    assert rl.allow("a")
    assert rl.allow("b")  # different source unaffected
    assert not rl.allow("a")


def test_concurrency_per_key_and_global():
    cl = ConcurrencyLimiter(per_key_max=2, global_max=3)
    assert cl.acquire("a") and cl.acquire("a")
    assert not cl.acquire("a")     # per-key cap
    assert cl.acquire("b")         # global still has room
    assert not cl.acquire("c")     # global cap (3) reached
    cl.release("a")
    assert cl.acquire("c")         # room freed


def test_throttle_admit_and_release():
    clk = FakeClock()
    t = ConnectionThrottle(
        per_source_rate=100, window_seconds=10, per_source_concurrent=2,
        global_in_flight=10, clock=clk,
    )
    a1 = t.admit("1.1.1.1")
    a2 = t.admit("1.1.1.1")
    assert a1 and a2
    assert t.admit("1.1.1.1") is None   # per-source concurrent cap
    assert t.in_flight == 2
    a1.release()
    assert t.admit("1.1.1.1") is not None
    a1.release()  # idempotent


def test_throttle_rate_blocks_flood():
    clk = FakeClock()
    t = ConnectionThrottle(
        per_source_rate=5, window_seconds=10, per_source_concurrent=100,
        global_in_flight=1000, clock=clk,
    )
    admitted = 0
    for _ in range(50):
        adm = t.admit("attacker")
        if adm:
            admitted += 1
            adm.release()  # release so concurrency isn't the limiter — rate is
    assert admitted == 5  # only the rate budget within the window
