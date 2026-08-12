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

### Phase 2 — Identity & pairing *(0.0.2 — hardened through 2.3)*
On-disk `FileIdentityStore` (atomic writes, in-process lock so a concurrent
revoke can't be lost, private key passphrase-encryptable; public key is
authoritative and the id is re-derived on load; malformed keys refused).
`PairingManager` (host) + `ControllerPairing` (controller) implement **mutual**
pairing: one-time codes that are **single-use, expiring (monotonic clock), and
rate-limited**, binding trust to the transport-**authenticated** key, pinned only
after a **Short Authentication String** ceremony.

**Gate 2A — host trust establishment: CLOSED.** **Gate 2B — mutual end-to-end
pairing: CLOSED** (PAIR_REQUEST → PAIR_ACCEPT → PAIR_CONFIRM through the codec).

The SAS is **160 bits** (grouped hex). The threat is an active MITM that presents
its own key on each leg; because it chooses BOTH keys, forging a matching SAS is a
two-sided birthday/claw search at ~n/2, not an n-bit preimage — so 160 bits gives
~2**80 generic collision resistance (an 80-bit SAS would give only ~2**40, which
is feasible offline against long-lived keys). Trust is committed with explicit
**pending → commit** semantics bound by a transaction nonce AND the authenticated
peer key: the controller commits first; the host — the side that will grant
control of the machine — commits only on the final PAIR_CONFIRM (matching nonce
and same authenticated key), so a dropped/declined last step leaves the host
*under*-trusting, never over-trusting. The 160-bit hex string is long to compare
aloud; a PGP-style word encoding of those bits is the planned UX follow-up so the
ceremony stays usable. The real long-term fix is an established PAKE (see below).

**Known LAN limitation (documented, revisited in Phase 3):** a single global
attempt counter means an untrusted peer can force EXHAUSTED and annoy a
legitimate pairing attempt — a nuisance DoS, not a trust compromise (posture
stays fail-closed). When the real listener lands in Phase 3, add source/connection
throttling and pairing-mode DoS handling.

**SAS invariant (non-negotiable, esp. for the internet phases):** pairing
approval means the SAS shown on this machine was compared *out of band* against
the SAS on the other physical machine and matched. The `confirm` callback is that
ceremony; the UI is bound by this invariant. For internet pairing, use an
established PAKE (SPAKE2+/OPAQUE) so the one-time code becomes a real secret
rather than plaintext in transit — not a home-grown protocol.

### Phase 3 — LAN file transfer *(0.1.0 — this build, first shippable)*
The first genuinely useful build: an authenticated TLS-over-TCP transport and a
verified file transfer.

**Transport** (`transport/tls.py`) implements the provider/listener/connection
interfaces. TLS (self-signed ephemeral certs) gives confidentiality; the real
Ed25519 identity is authenticated *above* TLS (`security/handshake.py`) and
**bound to the TLS channel** via `tls-unique`. This is what makes the pairing SAS
meaningful: an active relaying MITM terminating both TLS legs cannot forward the
real parties' authentication, because a signature made over one leg's binding
fails on the other — verified end-to-end against a real relaying attacker. So the
MITM is forced to present its own key, which the SAS then catches. Framing is
`tag||length||body` with the length checked against the per-channel ceiling
before the body is read. `security/session.py` classifies the authenticated key
against the trust store (trusted → session; unknown → pairing only).

**Transfer** (`transfer/lan.py`): offer → attended approve → validate filename →
race-safe `<name>.part` open (nofollow + exclusive, under the fixed transfer root)
→ verify SHA-256 → atomic rename. The receiver chooses the destination; a hash
mismatch, oversize, decline, disconnect, or capability revocation discards the
partial file and nothing unverified ever appears under the final name.

**Gate 3 — covered by tests:** verified happy path (incl. 1 MiB over real TLS),
hash-mismatch discard, malicious/traversal filename refusal, containment, size
overflow, decline, and mid-stream revocation abort.
**Deferred to hardware validation / follow-up:** multi-GB streaming and memory
bound, resume after disconnect, disk-full handling, and pairing-mode connection
throttling (the real listener now exists, so source/rate throttling is the next
DoS item).

### Phase 4 — Screen capture *(0.2.0 — this build)*
Screen capture split into backend-agnostic runtime (tested on any OS) and a thin
Windows adapter (validated on the rig). `CaptureSession` owns pacing (FPS limit
via a pure, clock-injected `FrameClock`), pause/resume, resolution/monitor-change
detection (`on_display_change`), device-loss recovery (restart on a backend error
from sleep/wake or monitor switch), frame timestamping, and a **bounded
drop-oldest queue** so a slow consumer can't grow memory (ahead of Phase 5's
gate). `SyntheticCaptureBackend` generates frames in memory so this pipeline —
and the Phase 5 encoder and Phase 6 viewer — can be built without Windows.
`DxcamCaptureBackend` is the real Desktop Duplication adapter (BGRA, Windows-only,
`capture` extra). **Local frames only — no network.**

**Gate 4 — covered by tests (synthetic backend):** enumeration, pause, resolution
change fires the callback, device-loss recovery, frame timestamps, bounded queue,
full paced loop.
**Deferred to hardware validation:** real DXcam grab on the rig, actual
monitor-switch / sleep-wake device-loss, and true multi-monitor geometry.

### Phase 4.1 — Seam hardening *(0.2.0)*
Fixes from the adversarial pass, all at module seams:
- **Transfer authority (was fail-open):** capability tokens are now mandatory AND
  capability-specific — `receive_file` requires `file.write.inbound`,
  `send_file` requires `file.read.outbound`. A token for an unrelated capability
  (e.g. `screen.publish`) is refused before any I/O. This is the authority
  wrapper the model depends on.
- **Transport resource bounds:** control/bulk/accept queues are bounded (control
  overflow closes the connection; bulk applies TCP backpressure), and the auth
  handshake has a timeout — an authenticated-but-untrusted peer can no longer
  flood memory or tie up the listener.
- **Disconnect discards pending work:** on connection death the queues are
  cleared and waiters raise immediately, rather than draining a backlog of
  now-stale (soon: privileged) commands — important before input injection.
- **Capture recovery is genuinely bounded:** consecutive failures are counted and
  reset only by a *successful frame*, with backoff/yield, so a backend that fails
  every grab terminates instead of spinning the event loop; the session has a
  terminal state so `get()` raises instead of hanging.
- **Transfer control on the strict codec:** FILE_OFFER/ACCEPT/REJECT are real
  Portal messages now, not ad-hoc JSON — no coercion, no extra fields.
- **No silent overwrite:** an existing destination is preserved; the incoming
  file lands as `name (1).ext`.

### Gate 3.1 — Listener & pairing DoS throttling *(blocking, near-term)*
The real TLS listener now exists (Phase 3), so unauthenticated/untrusted inbound
connection abuse is a live risk, not a future one. Before Phase 6 exposes a
long-lived listening session, this gate must close:
- per-source connection rate limiting (cap concurrent + new-per-window by peer IP);
- a global cap on in-flight (pre-accept) handshakes beyond the existing accept
  queue bound;
- pairing-mode hardening: a single global attempt counter currently lets an
  untrusted peer force EXHAUSTED and grief a legitimate pairing — scope attempts
  per source and rate-limit `begin_pairing`/inbound pair requests.
The rate-limiter logic is pure and unit-testable now; the socket wiring lands
with the listener work.

### Gate 3.1 — Listener & pairing DoS throttling *(CLOSED)*
The live-since-Phase-3 exposure, now closed:
- **Connection admission throttle** (`transport/throttle.py`, pure + clock-injected):
  per-source sliding-window rate limit, per-source concurrent-handshake cap, and a
  global in-flight cap. Wired into the TLS listener keyed by peer IP; a slot is
  held only for the handshake window, and a flood is dropped before a handshake is
  spent on it (verified: 12 rapid connections from one source admit only the rate
  budget).
- **Pairing attempts scoped per source:** a source spends only its own small
  wrong-guess budget (throttled after that) while the code stays alive for others;
  a global backstop still burns the code under a distributed attempt. This closes
  the grief-DoS where one bad source could exhaust a legitimate user's pairing
  (verified: attacker from one IP throttled, real user from another still pairs).
The socket wiring passes the remote IP through as the throttle/attempt key; the
rate-limiter and attempt logic are unit-tested independently.

### Phase 5 — Video pipeline *(0.2.0)*
PyAV encode. First target 1280×720@15, then 1080p@30. Measure capture/encode/
network/decode/render latency. **Gate 5:** 30-min session, bounded RAM, no
growing frame queue, graceful drop, encoder-failure handling.

### Phase 6 — LAN screen viewer *(0.3.0)*
Wire the video track through the transport to a PyQt6 viewer (dark-industrial).
**Gate 6:** viewing *only* — no input path exists yet. The separation is
intentional.

### Phase 7 — Remote mouse *(0.4.0 — MVP complete)*
Control events over the data channel using normalised 0.0–1.0 coordinates.

**Blocking precondition — input-injection design review (do BEFORE writing any
SendInput code):**
- capability is re-checked **per event**, not once per session — a mid-stream
  revoke must stop the very next event (the authority generation/token model
  already supports this; the input path must actually use it);
- coordinate mapping is DPI-aware and correct across multi-monitor virtual-desktop
  geometry, so a normalised point can't land on the wrong screen or off-target;
- the emergency kill (Ctrl+Alt+Shift+F12 → `revoke_all`) must be reachable even
  while remote input is active, and its limitations on the secure desktop / UAC
  prompts documented — the operator must never be locked out of their own machine.

**Blocking precondition — Windows-native containment (carried from Phase 3):**
before input injection or unattended file writes, the receiver's file-open must be
reparse-point-proof on Windows (native handle validation, not just lexical
containment + `O_EXCL`, which is all POSIX `O_NOFOLLOW` gives and is a no-op on
Windows). Symlink/junction redirection of a received file is not acceptable once
the tool can also drive the machine.

Every event passes the `PermissionGate` (`input.inject.mouse`) before reaching
SendInput. **Gate 7:** scaling, multi-resolution, multi-monitor, and — the ones
that matter — disconnect and revocation stop input *immediately*.

## MVP definition

> Two Windows PCs securely pair on a LAN, explicitly approve a session, transfer
> files with integrity verification, stream one desktop at usable latency, and
> permit revocable mouse control — with no remote shell and no unattended access.

When that passes its gates, Portal is a real remote-support tool, not a tech
demo — and internet rendezvous becomes an extension rather than a gamble.

## Blocking gate conditions (carried risks that must not slip)

These are known-deferred risks promoted to explicit blockers, each pinned to the
phase that may not ship without it. They are tracked here, in one place, precisely
so schedule pressure can't quietly downgrade them to "later".

| # | Condition | Blocks | Status |
|---|-----------|--------|--------|
| B1 | **Windows-native reparse-point-proof file-open** (not just lexical + `O_EXCL`; `O_NOFOLLOW` is a no-op on Windows) | Phase 7 (input/unattended writes) | open, Windows-only |
| B2 | **Listener & pairing DoS throttling** — per-source connection + pair-request rate limiting; scope pairing attempts per source | Phase 6 (long-lived listener) | **CLOSED (Gate 3.1)** |
| B3 | **Private key at rest** — OS-native protection (Windows DPAPI / keyring), not plaintext-with-warning | any "install and forget" / unattended UX | open, Windows-only |
| B4 | **Concurrency ownership** for `SessionAuthority` / trust store — documented single-owner model or explicit synchronisation before multi-session/threaded use | multi-session work | store lock done in-process; authority ownership to document |
| B5 | **Input-injection design review** — per-event capability re-check, DPI/multi-monitor coordinate correctness, kill-switch reachable on secure desktop | Phase 7 (before any SendInput) | required precondition |

None of these is a current defect (the Phase 4.1 pass closed the live bugs); they
are forward risks whose cost rises the later they are addressed. B1, B3, and B5
are Windows-runtime concerns validated on the rig; B2's rate-limiter and B4's
ownership contract are testable now.

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
