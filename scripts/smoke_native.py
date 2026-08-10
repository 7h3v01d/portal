# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Native-stack smoke test. Run this FIRST on the target rig, before building on
the dependency set:

    .venv\\Scripts\\python scripts\\smoke_native.py

It only imports each dependency and reports its version — it captures no screen,
opens no socket, injects no input. The point is to catch a wheel/build problem
(the kind of thing that bit libtorrent on 3.14) at the cheapest possible moment,
not after you've written a phase against it.

`dxcam` is Windows-only; on other platforms it is reported as skipped, not
failed."""

from __future__ import annotations

import platform
import sys

# (import name, human label, windows_only)
CHECKS = [
    ("PyQt6.QtCore", "PyQt6", False),
    ("aiortc", "aiortc", False),
    ("av", "PyAV (av)", False),
    ("cryptography", "cryptography", False),
    ("fastapi", "FastAPI", False),
    ("uvicorn", "uvicorn", False),
    ("pydantic", "pydantic", False),
    ("dxcam", "DXcam", True),
]


def _version(module) -> str:
    for attr in ("__version__", "version", "PYQT_VERSION_STR"):
        v = getattr(module, attr, None)
        if isinstance(v, str):
            return v
    return "(no version attr)"


def main() -> int:
    is_windows = sys.platform == "win32"
    print(f"Portal native smoke test — Python {platform.python_version()} on {sys.platform}\n")

    failures = 0
    for import_name, label, windows_only in CHECKS:
        if windows_only and not is_windows:
            print(f"  SKIP  {label:<16} (Windows-only)")
            continue
        try:
            module = __import__(import_name, fromlist=["_"])
            print(f"  OK    {label:<16} {_version(module)}")
        except Exception as exc:  # noqa: BLE001 — report every failure, keep going
            print(f"  FAIL  {label:<16} {type(exc).__name__}: {exc}")
            failures += 1

    print()
    if failures:
        print(f"{failures} dependency import(s) failed — resolve before building further.")
        return 1
    print("All required dependencies imported cleanly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
