# Portal — MVP Roadmap

*Working name: Portal. Windows-first, PyQt6, Apache 2.0.*

This is the **near-term** roadmap: the arc from empty repo to a genuinely useful
LAN remote-support tool. The full 20-phase plan (internet rendezvous, TURN,
unattended access, Windows service, UAC/secure-desktop) is real and still the
destination — but it's deliberately out of scope here so the first milestone
stays tight enough to build, test, and adversarially harden.

## The one architectural rule

**Transport connectivity grants zero authority.** Being connected lets a peer
send messages; it never lets them *do* anything. Every action is gated on an
explicitly granted, independently revocable capability. Everything below serves
that rule.

## Key refinement over the original plan

The original roadmap coupled the first usable milestone (LAN file transfer) to
WebRTC. Portal decouples them: the MVP rides on a **simple TLS-over-TCP LAN
transport** behind the `Transport` interface, so file transfer and screen view
ship without aiortc even installed. WebRTC becomes a later *swap* behind the same
interface, not a prerequisite. This removes the single biggest early risk.

## The five interfaces

Defined in Phase 0 so no application code ever touches a concrete backend:

| Interface | MVP backend | Later backend |
|---|---|---|
| `Transport` | TLS-over-TCP (LAN) | aiortc / WebRTC |
| `CaptureBackend` | DXcam | native (Rust/C++) |
| `InputBackend` | Windows SendInput | — |
| `IdentityStore` | encrypted on-disk | — |
| `TransferBackend` | LAN chunked | WebRTC data channel |

If profiling later says capture/encode/transport needs native code, only that
one class changes. Python does not become a prison.

## Phases and gates

### Phase 0 — Foundation *(this build, 0.0.1)*
Repo layout, the five interfaces as abstract bases, the protocol message set and
validated envelope, the capability model, path-containment validation, the
Ed25519 identity primitive, and a native-stack smoke test. Conventions baked in:
`.venv`/`.bat` (fail-closed), Apache 2.0 headers, deny-first config defaults,
staged dependency extras.

### Phase 0.1 — Adversarial hardening *(0.0.1)*
Corrections from the first adversarial pass, made at the seams while nothing
depends on them yet:
- Codec returns a **typed, validated** payload — the raw dict never crosses the
  trust boundary. Wire models are **strict** (no int/float/bool/str coercion,
  no inf/nan, duplicate JSON keys rejected).
- **Fail-closed on message type:** a known-but-unimplemented type is rejected;
  registering a payload schema is required to activate an operation.
- **Transport** split into provider / listener / connection with separate
  **control and bulk channels** and an authenticated `peer_public_key`.
- **Trust pinned to the full public key** (constant-time), never the 64-bit
  display id; `verify_pinned` is the authorisation primitive.
- Capabilities **renamed to the protected local operation** (`screen.publish`,
  `input.inject.mouse`, `file.write.inbound`, …) to remove send/receive
  direction ambiguity.
- **Enforceable revocation:** a `SessionAuthority` generation + cancellation
  tokens so long-running work aborts the instant a capability is revoked.

### Phase 0.2 — Second adversarial pass *(0.0.1)*
Local invariant leaks sealed (architecture validated, no redesign):
- Codec: non-string/unhashable `type` and deep-nesting bombs now raise a
  **ProtocolError**, never an escaping TypeError/RecursionError — every decode
  exit is a clean rejection. Depth capped before parsing.
- Codec is symmetric: `build`/`encode` refuse to emit any message the decoder
  would reject (wrong payload type, unimplemented type, junk raw envelope).
- Authority: the mutable capability set is no longer exposed, so revocation
  can't happen without bumping the generation; tokens are **capability-bound**.
- Config: strict validation (a typo can't flip a security flag on); the global
  `auto_grant_capabilities` switch removed as contrary to explicit consent.
- Wire text: `session_id`/`error.code` charset-constrained; peer device names
  rejected for control/bidi characters; `redact`/`safe_line` can't be used to
  inject a log line.
- Transport: authenticated peer key is non-optional (authenticated by
  construction); allocation ceilings written into the recv contract.
- HELLO no longer trusts a peer-supplied `device_id` (derived from the key).
- Input targets a stable `display_id`; `Frame` has a buffer-lifetime contract;
  `FileOffer` is a strict model (64-hex SHA-256, integer-ns time).

### Phase 1 — Protocol core *(0.0.1)*
Message envelope + type registry + codec. **Gate 1 — CLOSED:** malformed,
non-string-type, deeply-nested, unknown, unimplemented, unsupported/newer,
oversized, extra-key, coercion, non-finite, and duplicate-key messages all
rejected with a specific ProtocolError before anything acts on them.

### Phase 2 — Identity & pairing *(0.0.2 — this build)*
On-disk `FileIdentityStore` (atomic writes; private key passphrase-encryptable,
owner-only otherwise; trust keyed on the full public key). `PairingManager` with
one-time codes that are **single-use, expiring, and rate-limited**, binding trust
to the transport-**authenticated** key rather than any peer-asserted identity,
and pinning (TOFU) only after **explicit local fingerprint confirmation**. The
`PAIR_REQUEST/ACCEPT/DENY` message types are now registered and active. **Gate 2:**
attended-only, explicit local approval, no silent connection — a burned/expired/
exhausted code cannot pair, and an imposter forging a trusted device's display id
with a different key is not trusted.

### Phase 3 — LAN file transfer *(0.1.0 — first shippable)*
The first genuinely useful build. TLS-over-TCP transport + chunked transfer:
offer → accept → chunk → verify. Write to `<name>.part`, verify SHA-256,
atomically rename. Destination locked under `Downloads/Remote Transfers` via the
Phase 0 lexical-containment gate, plus **race-safe** filesystem containment at
the actual file-open (refuse to follow reparse points; confirm the opened handle
resolves inside the root). **Gate 3:** 1 KB / 10 MB / multi-GB files, cancel,
disconnect, duplicate name, hash mismatch, resume, malicious filenames, disk
full.

### Phase 4 — Screen capture *(0.2.0)*
DXcam behind `CaptureBackend`: display enumeration, selection, frame timestamps,
FPS limiting, pause. Local display of captured frames only — **no network**.
**Gate 4:** monitor switch, resolution change, sleep/wake all survive.

### Phase 5 — Video pipeline *(0.2.0)*
PyAV encode. First target 1280×720@15, then 1080p@30. Measure capture/encode/
network/decode/render latency. **Gate 5:** 30-min session, bounded RAM, no
growing frame queue, graceful drop, encoder-failure handling.

### Phase 6 — LAN screen viewer *(0.3.0)*
Wire the video track through the transport to a PyQt6 viewer (dark-industrial).
**Gate 6:** viewing *only* — no input path exists yet. The separation is
intentional.

### Phase 7 — Remote mouse *(0.4.0 — MVP complete)*
Control events over the data channel using normalised 0.0–1.0 coordinates. Every
event passes the `PermissionGate` (`input.inject.mouse`) before reaching
SendInput.
Emergency host-side kill (Ctrl+Alt+Shift+F12) revokes all capabilities
instantly. **Gate 7:** scaling, multi-resolution, multi-monitor, and — the ones
that matter — disconnect and revocation stop input *immediately*.

## MVP definition

> Two Windows PCs securely pair on a LAN, explicitly approve a session, transfer
> files with integrity verification, stream one desktop at usable latency, and
> permit revocable mouse control — with no remote shell and no unattended access.

When that passes its gates, Portal is a real remote-support tool, not a tech
demo — and internet rendezvous becomes an extension rather than a gamble.

## Deferred (post-MVP, the back half of the full plan)

Remote keyboard hardening · capability adversarial pass · signalling server ·
internet P2P · TURN fallback · integrated WebRTC file transfer · clipboard ·
production UI · failure engineering · trusted devices · unattended access ·
Windows service · reboot/reconnect · UAC/secure desktop (v1.0+ territory).

## Testing posture

pytest + pytest-asyncio. High test density on `protocol/`, `security/`,
`transfer/`, `session/`. Revert-proven regression tests are non-negotiable:
every bug gets a failing test first. Run on the real Windows 11 / Python 3.11.5
rig; the native smoke test (`scripts/smoke_native.py`) runs before each new phase
that adds a native dependency.
