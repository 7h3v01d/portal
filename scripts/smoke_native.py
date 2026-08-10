# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Phase-aware native-stack smoke test.

Dependencies are staged into extras, so a correctly set-up early-phase venv does
NOT have the capture/webrtc/server/ui stacks installed. This test only fails on
the scope you ask for; optional deps outside that scope are reported as "not
installed", never as a failure.

    python scripts/smoke_native.py            # core only (default) — Phase 0-2
    python scripts/smoke_native.py --capture  # + dxcam, PyAV       — Phase 4+
    python scripts/smoke_native.py --webrtc   # + aiortc            — Phase 6+
    python scripts/smoke_native.py --server   # + fastapi, uvicorn
    python scripts/smoke_native.py --ui       # + PyQt6
    python scripts/smoke_native.py --full     # everything

Imports only — captures nothing, opens no socket.
"""

from __future__ import annotations

import argparse
import platform
import sys

SCOPES: dict[str, list[tuple[str, str, bool]]] = {
    "core": [
        ("cryptography", "cryptography", False),
        ("pydantic", "pydantic", False),
    ],
    "ui": [("PyQt6.QtCore", "PyQt6", False)],
    "capture": [("dxcam", "DXcam", True), ("av", "PyAV (av)", False)],
    "webrtc": [("aiortc", "aiortc", False)],
    "server": [("fastapi", "FastAPI", False), ("uvicorn", "uvicorn", False)],
}


def _version(module) -> str:
    for attr in ("__version__", "version", "PYQT_VERSION_STR"):
        v = getattr(module, attr, None)
        if isinstance(v, str):
            return v
    return "(no version attr)"


def _check(import_name: str, label: str, windows_only: bool, required: bool) -> bool:
    if windows_only and sys.platform != "win32":
        print(f"  SKIP  {label:<16} (Windows-only)")
        return True
    try:
        module = __import__(import_name, fromlist=["_"])
        print(f"  OK    {label:<16} {_version(module)}")
        return True
    except Exception as exc:  # noqa: BLE001
        if required:
            print(f"  FAIL  {label:<16} {type(exc).__name__}: {exc}")
            return False
        print(f"  ----  {label:<16} not installed (optional for this scope)")
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Portal native smoke test")
    for extra in ("ui", "capture", "webrtc", "server"):
        parser.add_argument(f"--{extra}", action="store_true", help=f"require the {extra} extra")
    parser.add_argument("--full", action="store_true", help="require every extra")
    args = parser.parse_args()

    required_scopes = {"core"}
    for extra in ("ui", "capture", "webrtc", "server"):
        if getattr(args, extra) or args.full:
            required_scopes.add(extra)

    print(f"Portal native smoke test — Python {platform.python_version()} on {sys.platform}")
    print(f"required scopes: {', '.join(sorted(required_scopes))}\n")

    failures = 0
    for scope, deps in SCOPES.items():
        required = scope in required_scopes
        for import_name, label, windows_only in deps:
            if not _check(import_name, label, windows_only, required):
                failures += 1

    print()
    if failures:
        print(f"{failures} required dependency import(s) failed — resolve before building.")
        return 1
    print("All required dependencies for the selected scope imported cleanly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
