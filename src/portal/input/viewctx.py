# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""View-context registry — INV-10, the view-freshness stage of intake.

An injected event must land on a view the controller actually saw, recently. The
HOST is authoritative about the view: it stamps every displayed frame with a
monotonic view_epoch (display topology + geometry + foreground window + input
desktop) and a monotonic frame_seq, and remembers each frame_seq's capture time.
An input event echoes the (view_epoch, frame_seq) it was made against; the host
looks up the capture time ITSELF — the controller never supplies the age (a lying
controller could otherwise claim any event was fresh).

Verdicts:
  * epoch != current               -> reject (STALE_EPOCH): topology/focus changed
  * frame_seq unknown              -> reject (UNKNOWN_FRAME)
  * now - captured_at > max_age     -> reject (TOO_OLD)
  * otherwise                      -> accept

Identity-context transitions (lock / user switch) are handled a level up by
REVOKING the session (INV-10 requires revoke, not mere suspend, because the person
at the machine may have changed). Ordinary transitions bump the epoch, which makes
in-flight events for the old epoch fail STALE_EPOCH until the controller re-syncs.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from .model import ViewRef

# Bound the remembered frames so an attacker can't grow host memory by forcing
# frame churn; old frames age out naturally (and would fail TOO_OLD anyway).
_MAX_TRACKED_FRAMES = 256


class ViewVerdict(str, Enum):
    ACCEPT = "accept"
    STALE_EPOCH = "stale_epoch"
    UNKNOWN_FRAME = "unknown_frame"
    TOO_OLD = "too_old"


@dataclass(frozen=True)
class ViewResult:
    verdict: ViewVerdict

    @property
    def accepted(self) -> bool:
        return self.verdict is ViewVerdict.ACCEPT


class ViewContextRegistry:
    """Host-authoritative record of displayed frames and the current view epoch.

    `clock` is injectable (monotonic seconds) for deterministic tests. `max_age_s`
    is the oldest view an input may reference — tuned small so a click can't act on
    a stale screen."""

    def __init__(self, max_age_s: float = 0.5, clock: Callable[[], float] | None = None) -> None:
        import time
        self._clock = clock or time.monotonic
        self._max_age = max_age_s
        self._epoch = 0
        self._frames: "OrderedDict[int, float]" = OrderedDict()  # frame_seq -> captured_at
        self._next_frame_seq = 0

    @property
    def current_epoch(self) -> int:
        return self._epoch

    def bump_epoch(self) -> int:
        """Called when the view context changes (geometry/topology/foreground). In-
        flight events referencing the previous epoch now fail STALE_EPOCH until the
        controller re-syncs to a frame in the new epoch. Old frames are cleared so a
        frame_seq can't be reused across epochs."""
        self._epoch += 1
        self._frames.clear()
        return self._epoch

    def register_frame(self, captured_at: float | None = None) -> ViewRef:
        """Stamp a newly displayed frame with the current epoch and a fresh
        frame_seq, recording its CAPTURE time. `captured_at` is the monotonic
        timestamp from the capture pipeline (when the pixels were grabbed) — NOT
        when this registry happened to see the frame, which could be seconds later
        behind an encode/network backlog (INV-10). Falls back to now() only when a
        capture time isn't supplied (e.g. synthetic frames in tests)."""
        seq = self._next_frame_seq
        self._next_frame_seq += 1
        now = self._clock()
        cap_t = captured_at if captured_at is not None else now
        self._frames[seq] = cap_t
        # Evict by AGE first: any frame older than max_age can never pass check()
        # anyway (TOO_OLD), so dropping it loses nothing. This ensures a still-valid
        # (within max_age) recent frame is NEVER evicted just to satisfy the count
        # cap — the count cap is only a backstop against unbounded growth if frames
        # are somehow all young (e.g. an absurd frame rate).
        cutoff = now - self._max_age
        stale = [s for s, t in self._frames.items() if t < cutoff]
        for s in stale:
            del self._frames[s]
        # Backstop hard cap (evict oldest) only if age-eviction wasn't enough.
        while len(self._frames) > _MAX_TRACKED_FRAMES:
            self._frames.popitem(last=False)
        return ViewRef(view_epoch=self._epoch, frame_seq=seq)

    def check(self, view: ViewRef) -> ViewResult:
        """Validate an input's claimed view against host-authoritative state. The
        age is computed from the host's own capture timestamp, never from anything
        the controller supplied."""
        if view.view_epoch != self._epoch:
            return ViewResult(ViewVerdict.STALE_EPOCH)
        captured_at = self._frames.get(view.frame_seq)
        if captured_at is None:
            return ViewResult(ViewVerdict.UNKNOWN_FRAME)
        if self._clock() - captured_at > self._max_age:
            return ViewResult(ViewVerdict.TOO_OLD)
        return ViewResult(ViewVerdict.ACCEPT)
