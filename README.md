# Portal

Secure, self-hosted **Windows remote-assistance and file-transfer** tool.
Not a TeamViewer clone — a private, trusted-user remote-support tool you run
yourself.

*Working name; may change before any public release.*

## Status

**Phase 0 + 0.1 — Foundation, adversarially hardened (0.0.1).** Architecture,
protocol core, security model, and the five replaceable interfaces are in place,
through Phase 2 (identity + pairing), with two adversarial passes folded in.
117 tests green. Gate 1 + Gate 2 closed. No screen capture, no networking, no input injection yet — see
[`docs/ROADMAP.md`](docs/ROADMAP.md).

## Design principle

> **Transport connectivity grants zero authority.**

Being connected lets a peer send messages; it never lets them *do* anything.
Every action — publish the screen, inject a mouse event, write an inbound file — is a named
capability that must be explicitly granted and can be independently revoked.
Attended access by default; unattended access is deliberately deferred to very
late in the plan.

## Layout

```
src/portal/
  common/      config, logging, errors, constants
  protocol/    message types, validated envelope, codec, capabilities, versioning
  security/    identity, store, pairing, authority, permission gate, validation
  transport/   Transport interface        (LAN TLS → WebRTC later)
  capture/     CaptureBackend interface    (DXcam later)
  input/       InputBackend interface      (Windows SendInput later)
  transfer/    TransferBackend interface   (LAN chunked → WebRTC data channel)
  host/        host agent + session        (later phases)
  controller/  controller client + session (later phases)
  ui/          PyQt6 UI                     (later phases)
scripts/       smoke_native.py — native dependency check, run first
tests/         protocol/ + security/ suites (Gate 1 + deny-first model)
docs/          ROADMAP.md
```

## Getting started

```bat
setup_venv.bat
.venv\Scripts\python scripts\smoke_native.py
run_tests.bat
```

`setup_venv.bat` creates `.venv` and installs the core + dev extras. Heavier
dependencies are opt-in extras (`ui`, `capture`, `webrtc`, `server`, `full`) so
the foundation stays light.
`smoke_native.py` confirms the native stack (DXcam, PyAV, aiortc, …) imports on
your rig before you build on it. `run_tests.bat` runs the suite.

## Stack

PyQt6 · aiortc (WebRTC, later) · PyAV (FFmpeg) · DXcam (Windows capture) ·
cryptography (Ed25519) · FastAPI (signalling, later) · pydantic.

## Licence

Apache 2.0 © 2026 Leon Priest ([github.com/7h3v01d](https://github.com/7h3v01d)).
See [`docs/LICENSING.md`](docs/LICENSING.md) for the PyQt6/Apache dependency note.
