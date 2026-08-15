# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""LIVE transport smoke test — exercises the real socket/TLS/admission stack.

Unlike smoke_native.py (which only imports), this opens real loopback sockets and
drives the actual `TlsTransport` end to end, so it validates the A1 pre-TLS
admission path (`sock_accept` -> throttle -> `connect_accepted_socket`) on the
platform it runs on. This matters because `connect_accepted_socket` and asyncio
socket handling behave differently across OSes, and the LAN MVP targets Windows
10/11 + Python 3.11.x — a green run HERE is the definitive answer, not CI on Linux.

    python scripts/smoke_transport.py

Each check runs in its OWN SUBPROCESS with its own timeout. That isolation is
deliberate: an earlier version ran all checks in one event loop with shared
module-level state (a class-level monkeypatch on ConnectionThrottle.admit), and
cross-check contamination made results flap between machines — a validation tool
that flaps is worse than none. With subprocess isolation each check has a clean
interpreter, fresh event loop, and no shared state, so a result is deterministic
and a hang in one check cannot affect another.

Exit code 0 = all checks passed; non-zero = a check failed or errored.
Requires only the core deps (cryptography, pydantic).
"""

from __future__ import annotations

import argparse
import asyncio
import platform
import subprocess
import sys
import time

CHECK_TIMEOUT_SECONDS = 25.0


async def check_roundtrip() -> tuple[bool, str]:
    """A legitimate client pairs over real TLS; control/bulk/video all flow."""
    from portal.security.identity import Ed25519Identity
    from portal.transport.tls import TlsTransport

    host = Ed25519Identity.generate("SmokeHost")
    ctrl = Ed25519Identity.generate("SmokeCtrl")
    listener = await TlsTransport(host).listen("127.0.0.1:0")
    port = listener.sockname[1]
    try:
        client = await asyncio.wait_for(TlsTransport(ctrl).connect(f"127.0.0.1:{port}"), timeout=10)
        server = await asyncio.wait_for(listener.accept(), timeout=10)

        await client.send_control(b"ping-control")
        c = await asyncio.wait_for(server.recv_control(), timeout=5)
        if c != b"ping-control":
            return False, f"control mismatch: {c!r}"

        await client.send_bulk(b"bulk-payload")
        b = await asyncio.wait_for(server.recv_bulk(), timeout=5)
        if b != b"bulk-payload":
            return False, f"bulk mismatch: {b!r}"

        await client.send_video(b"frame-0")
        v = await asyncio.wait_for(server.recv_video(), timeout=5)
        if v.data != b"frame-0" or v.dropped != 0:
            return False, f"video mismatch: data={v.data!r} dropped={v.dropped}"

        if client.peer_public_key != host.identity.public_key or \
                server.peer_public_key != ctrl.identity.public_key:
            return False, "channel-bound auth peer-key mismatch"

        await client.close()
        await server.close()
        return True, "control+bulk+video+auth ok"
    finally:
        await listener.close()


async def check_pre_tls_admission() -> tuple[bool, str]:
    """A raw/no-ClientHello peer is admitted (counted) BEFORE TLS.

    Runs in its own subprocess, so the class-level spy here cannot leak into any
    other check. We still restore it in finally for cleanliness."""
    import portal.transport.tls as tlsmod
    from portal.security.identity import Ed25519Identity
    from portal.transport.tls import TlsTransport

    calls: list[str] = []
    orig = tlsmod.ConnectionThrottle.admit

    def spy(self, source):
        calls.append(source)
        return orig(self, source)

    tlsmod.ConnectionThrottle.admit = spy
    try:
        host = Ed25519Identity.generate("SmokeHost")
        listener = await TlsTransport(host).listen("127.0.0.1:0")
        port = listener.sockname[1]
        try:
            _r, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"\x16\x03\x01\x00\x50")  # TLS record header, then silence
            await writer.drain()
            t0 = time.monotonic()
            deadline = t0 + 10.0
            while not calls and time.monotonic() < deadline:
                await asyncio.sleep(0.02)
            dt = (time.monotonic() - t0) * 1000
            writer.close()
            if not calls:
                return False, f"admit() never observed within {dt:.0f}ms"
            return True, f"admit() observed in {dt:.0f}ms"
        finally:
            await listener.close()
    finally:
        tlsmod.ConnectionThrottle.admit = orig


async def check_listener_shutdown() -> tuple[bool, str]:
    """close() cancels an in-flight stalled handshake (owns its lifecycle)."""
    from portal.security.identity import Ed25519Identity
    from portal.transport.tls import TlsTransport

    host = Ed25519Identity.generate("SmokeHost")
    listener = await TlsTransport(host).listen("127.0.0.1:0")
    port = listener.sockname[1]
    _r, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"\x16\x03\x01\x00\x50")
    await writer.drain()
    deadline = time.monotonic() + 10.0
    while not listener._inflight and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    tasks = list(listener._inflight)
    if not tasks:
        await listener.close()
        return False, "no in-flight handshake task registered"
    if not all(not t.done() for t in tasks):
        await listener.close()
        return False, "handshake finished on its own — cannot observe cancellation"
    await listener.close()
    if not all(t.cancelled() for t in tasks):
        return False, "close() did not cancel the in-flight handshake"
    return True, "in-flight handshake cancelled by close()"


CHECKS = {
    "roundtrip": ("control/bulk/video roundtrip + channel-bound auth", check_roundtrip),
    "admission": ("admit() runs before TLS for silent peer", check_pre_tls_admission),
    "shutdown": ("close() cancels in-flight handshake", check_listener_shutdown),
}


def _run_single_check(name: str) -> int:
    """Child mode: run ONE check in a fresh event loop, print a result marker."""
    _label, coro = CHECKS[name]
    try:
        ok, detail = asyncio.run(coro())
    except Exception as exc:  # noqa: BLE001
        print(f"RESULT {name} FAIL {type(exc).__name__}: {exc}")
        return 1
    print(f"RESULT {name} {'PASS' if ok else 'FAIL'} {detail}")
    return 0 if ok else 1


def _orchestrate() -> int:
    """Parent mode: spawn a subprocess per check, isolated and time-bounded."""
    print("Portal live transport smoke test (isolated subprocess per check)")
    print(f"  Python {platform.python_version()} on {platform.system()} {platform.release()}\n")

    passed = 0
    for name, (label, _coro) in CHECKS.items():
        try:
            proc = subprocess.run(
                [sys.executable, __file__, "--check", name],
                capture_output=True, text=True, timeout=CHECK_TIMEOUT_SECONDS,
            )
            marker = next((ln for ln in proc.stdout.splitlines()
                           if ln.startswith(f"RESULT {name} ")), None)
            if marker is None:
                ok, detail = False, "no result marker (child crashed)"
                if proc.stderr.strip():
                    detail += f": {proc.stderr.strip().splitlines()[-1]}"
            else:
                parts = marker.split(" ", 3)
                ok = parts[2] == "PASS"
                detail = parts[3] if len(parts) > 3 else ""
        except subprocess.TimeoutExpired:
            ok, detail = False, f"timed out after {CHECK_TIMEOUT_SECONDS:.0f}s"

        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {label}" + (f" — {detail}" if detail else ""))
        passed += 1 if ok else 0

    total = len(CHECKS)
    print(f"\n{passed}/{total} checks passed")
    return 0 if passed == total else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Portal live transport smoke test")
    parser.add_argument("--check", choices=list(CHECKS), help=argparse.SUPPRESS)
    args = parser.parse_args()

    try:
        import cryptography  # noqa: F401
        import pydantic  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        print(f"core deps missing: {exc}")
        return 2

    if args.check:
        return _run_single_check(args.check)
    return _orchestrate()


if __name__ == "__main__":
    raise SystemExit(main())
