# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""A1 / Gate 3.1: admission must happen BEFORE the TLS handshake.

The defect: with ssl= passed to start_server, asyncio performs the full TLS
handshake before the stream callback runs, so ConnectionThrottle.admit() executes
only AFTER TLS. A raw TCP peer that sends a valid-looking TLS record header and
then goes silent stalls inside asyncio's handshake for up to ssl_handshake_timeout
and the throttle NEVER SEES IT — so per-source/global admission limits do not
govern raw-TCP floods at all.

The measurable invariant: throttle.admit() is called for a raw connection BEFORE
any TLS handshake work. These tests spy on admit and prove it runs promptly even
for a no-ClientHello peer. They FAIL against post-TLS admission (admit never runs
for a stalled handshake) and PASS once admission is raw-socket-first."""

from __future__ import annotations

import asyncio

import pytest

import portal.transport.tls as tlsmod
from portal.security.identity import Ed25519Identity
from portal.transport.tls import TlsTransport


@pytest.mark.asyncio
async def test_admit_runs_before_tls_for_silent_peer(monkeypatch):
    calls = []
    orig = tlsmod.ConnectionThrottle.admit

    def spy(self, source):
        calls.append(source)
        return orig(self, source)

    monkeypatch.setattr(tlsmod.ConnectionThrottle, "admit", spy)

    host = Ed25519Identity.generate("Dad")
    listener = await TlsTransport(host).listen("127.0.0.1:0")
    port = listener.sockname[1]
    try:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        # A TLS handshake record header claiming more bytes than we will send,
        # then silence — this stalls asyncio's TLS handshake if TLS runs first.
        w.write(b"\x16\x03\x01\x00\x50")
        await w.drain()

        # admit() must have been called promptly — BEFORE the (stalled) TLS work.
        for _ in range(40):
            if calls:
                break
            await asyncio.sleep(0.05)
        assert calls, "throttle.admit() did not run before TLS — post-TLS admission (A1)"
        w.close()
    finally:
        await listener.close()


@pytest.mark.asyncio
async def test_raw_flood_is_counted_by_throttle(monkeypatch):
    # Every raw TCP connection from a source must be admitted (counted), so a flood
    # of silent raw sockets is governed by the same per-source/global limits — not
    # invisible to the throttle because they never finished TLS.
    admit_sources = []
    orig = tlsmod.ConnectionThrottle.admit

    def spy(self, source):
        admit_sources.append(source)
        return orig(self, source)

    monkeypatch.setattr(tlsmod.ConnectionThrottle, "admit", spy)

    host = Ed25519Identity.generate("Dad")
    listener = await TlsTransport(host).listen("127.0.0.1:0")
    port = listener.sockname[1]
    writers = []
    try:
        for _ in range(5):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"\x16\x03\x01\x00\x50")  # stall mid-handshake
            await w.drain()
            writers.append(w)
        # Give admission a moment.
        for _ in range(40):
            if len(admit_sources) >= 5:
                break
            await asyncio.sleep(0.05)
        assert len(admit_sources) >= 5, (
            f"only {len(admit_sources)} of 5 raw connections were admitted — "
            "raw-TCP floods bypass the throttle (A1)"
        )
    finally:
        for w in writers:
            try:
                w.close()
            except Exception:
                pass
        await listener.close()


@pytest.mark.asyncio
async def test_raw_flood_beyond_concurrency_cap_is_rejected(monkeypatch):
    # With the per-source concurrency cap forced to 2, opening 5 stalled raw
    # sockets from one source must yield exactly 2 admissions and 3 rejections —
    # proving excess raw connections are DENIED before TLS, not merely observed.
    import portal.common.constants as C
    monkeypatch.setattr(C, "CONN_CONCURRENT_PER_SOURCE", 2)
    # tls.py imports the value by name, so patch it where it's used too.
    monkeypatch.setattr(tlsmod, "CONN_CONCURRENT_PER_SOURCE", 2, raising=False)

    decisions = []
    orig = tlsmod.ConnectionThrottle.admit

    def spy(self, source):
        d = orig(self, source)
        decisions.append(d is not None)
        return d

    monkeypatch.setattr(tlsmod.ConnectionThrottle, "admit", spy)

    host = Ed25519Identity.generate("Dad")
    listener = await TlsTransport(host).listen("127.0.0.1:0")
    port = listener.sockname[1]
    writers = []
    try:
        for _ in range(5):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"\x16\x03\x01\x00\x50")  # stall mid-handshake, hold the slot
            await w.drain()
            writers.append(w)
        for _ in range(40):
            if len(decisions) >= 5:
                break
            await asyncio.sleep(0.05)
        granted = sum(1 for d in decisions if d)
        denied = sum(1 for d in decisions if not d)
        assert granted == 2, f"expected 2 admissions under the cap, got {granted}"
        assert denied == 3, f"expected 3 rejections over the cap, got {denied}"
    finally:
        for w in writers:
            try:
                w.close()
            except Exception:
                pass
        await listener.close()


@pytest.mark.asyncio
async def test_close_cancels_inflight_handshakes():
    # Listener shutdown must own the full lifecycle: a peer stalled mid-handshake
    # must have its in-flight task cancelled by close(), not left lingering until
    # the handshake timeout.
    host = Ed25519Identity.generate("Dad")
    listener = await TlsTransport(host).listen("127.0.0.1:0")
    port = listener.sockname[1]
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"\x16\x03\x01\x00\x50")  # start a TLS record, then stall
    await w.drain()
    # Let the handshake task spin up.
    for _ in range(40):
        if listener._inflight:
            break
        await asyncio.sleep(0.02)
    assert listener._inflight, "no in-flight handshake task registered"
    tasks = list(listener._inflight)

    await listener.close()  # must cancel the in-flight task(s)
    assert all(t.done() for t in tasks), "close() left an in-flight handshake running"
    try:
        w.close()
    except Exception:
        pass
