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

### Phase 5 — Video pipeline *(0.2.0 — this build)*
H.264 encode pipeline turning captured BGRA frames into a network-ready packet
stream. `encode/pyav_backend.py` is a real libx264 encoder tuned zero-latency
(no B-frames/lookahead → one frame in, one packet out) — and because PyAV bundles
FFmpeg, it is genuinely tested here (encode + FFmpeg decode round-trip), not just
on the rig. `encode/pipeline.py` owns the long-session concerns: a bounded
drop-oldest output queue that never drops a keyframe (RAM can't grow with session
length), encoder reopen + forced keyframe on resolution change, bounded
encoder-failure recovery (consecutive failures reset by a good packet), and a
terminal signal so `get()` can't hang. `encode/synthetic.py` fakes the encoder so
the pipeline logic is testable without FFmpeg.

**Gate 5 — covered by tests:** real encode→decode round-trip, keyframe forcing,
resolution-change reopen, transient-failure recovery, permanent-failure bounded
termination, source-termination propagation, keyframe-preserving bounded queue,
and capture→encode composed end-to-end. Sustained-run RAM shown bounded (both
queues stay at their caps under a slow consumer).
**Deferred to hardware validation:** encode latency/throughput on the rig with
real DXcam frames; hardware encoders (NVENC/QSV) as future backends.

### Phase 6 — LAN screen viewer *(0.3.0 — this build)*
Closes the loop: capture → encode → **transport → decode → display**. The host's
`stream/publish.py` ties CaptureSession → EncodePipeline → the bulk channel, gated
by the `screen.publish` capability (checked before start AND per packet, so a
revoke stops the stream on the next frame). The controller's `stream/viewer.py`
requests the stream (STREAM_START), reads geometry (STREAM_PARAMS), and pulls
packets off bulk → `decode/pyav_decoder.py` (real FFmpeg H.264) → displayable
RGB24 frames, requesting a keyframe to (re)sync. Video rides a compact binary
header on the bulk channel (`encode/wire.py`); control (start/stop/keyframe/params)
rides the strict codec. `ui/viewer_widget.py` is a thin PyQt6 blit surface,
validated on the rig; all the real logic is in ScreenViewer and tested here.

**Gate 6 — covered by tests:** full loop over REAL TLS (synthetic capture → real
libx264 → TLS → real decode → RGB frames), wire-codec round-trip + bad-magic/short
rejection, decoder waits-for-keyframe resync, publish requires `screen.publish`
(wrong capability denied), and **instant revocation stops the stream**.
**Gate 6 — REOPENED (Phase 6.1 hardening in progress).** The full loop works and
is tested, but an adversarial pass found the "instant revocation" claim was a
TOCTOU (a frame could ship after revoke landed during a pending `await`). Fixed
in A2 with this invariant: *authority is re-checked after any suspension point
that precedes an authority-sensitive side effect, and long-running waits are
raced against revocation where prompt termination is required.* `CancellationToken`
is now cancellation-aware (`wait_invalid()`, plus a token-local cancel event), and
both screen publish and file receive race their blocking awaits against it, so a
revoke both prevents the side effect AND terminates the operation without the peer
having to cooperate. Regression tests are write-spy / event-synchronised and
revert-proven (they fail against the pre-fix code) for both paths. Gate 6 stays
open until the rest of the 6.1 pass (A1 pre-TLS admission, A3 composed authority
path, A5 decode ceilings) closes.

**A1 — pre-TLS admission: CLOSED (Gate 3.1 re-closed).** The listener manages its
own listening socket: it accepts the RAW socket with `loop.sock_accept`, runs
`throttle.admit(source)` FIRST, and hands only admitted sockets to asyncio with SSL
via `loop.connect_accepted_socket(..., ssl=ctx, ssl_handshake_timeout=...)`. So a
raw / no-ClientHello flooder is counted and dropped by the per-source/global limits
before any TLS work. (A first attempt used `loop.start_tls` + manual StreamWriter
reconstruction; that tangled stream ownership and dropped ordinary traffic after a
successful handshake in a TIMING-DEPENDENT way — it passed locally but failed under
different scheduling. `connect_accepted_socket` avoids the STARTTLS conversion
entirely and is stable across repeated runs.) Client `connect()` now also passes
`ssl_handshake_timeout` for symmetry. Proven: silent peer → admit runs in <1s
(revert-proven vs the old ~60s stall); a deterministic cap test shows 5 stalled raw
sockets from one source → exactly 2 admitted / 3 denied (revert-proven that the cap
patch is load-bearing).

Pairing-window hardening (Gate 3.1 companion): pairing no longer auto-opens on an
unknown connection — the host opens a window deliberately (`open_pairing()`), and a
SINGLE host-owned `PairingManager` governs the window so guess budgets persist
across reconnects. With no window open, unknown peers are refused outright. A burned
transaction (exhausted/expired) is detected so `open_pairing()` re-issues a FRESH
transaction instead of a dead code, and the window closes on terminal outcomes.
Tests: closed-window refusal, budget persistence, burned-window reopen, and a
correct-code→SAS-denied test (this last replaced a false green — dangling code that
used a WRONG code so it never reached the SAS ceremony it claimed to test). All
revert-proven.

Post-sign-off lifecycle fixes: (a) `_pairing_burned()` now uses the manager's
public `pairing_active`/`awaiting_commit` (which evaluate TTL lazily) instead of a
private `_pending` peek, so an IDLE-EXPIRED window is correctly detected and
re-opened with a fresh code rather than handing out a dead one (clock-injected
regression, revert-proven). (b) `TlsListener.close()` now owns the full lifecycle:
it stops the accept loop, CANCELS in-flight handshake tasks (a stalled peer no
longer lingers to its handshake timeout), closes any authenticated-but-unaccepted
queued connections, and shuts the listening socket — so after close() the listener
holds no live connection (revert-proven).

**A4 — control-plane starvation: PARTIAL.**
- *A4a (video app-queue starvation) — FIXED.* Video moved to a dedicated LOSSY
  channel (`send_video`/`recv_video`): a bounded drop-oldest buffer the reader
  never blocks on, so a slow/absent video consumer can't suspend the reader.
  Revert-proven (flood video, urgent control still arrives; times out on the old
  path).
- *A4d (encoded-loss recovery) — FIXED.* Dropped video frames are no longer
  silent: `recv_video()` returns a `VideoReceipt` with a drop count (sequence-gap
  detected), and the viewer resyncs on any loss — reset the decoder, request a
  keyframe, discard until the next IDR. Recovery is BOUNDED: if the recovery IDR
  is itself dropped in the same congestion, the viewer re-requests on a rate-limited
  timer (RESYNC_RETRY_SECONDS) rather than waiting forever; every drop is counted. Regression uses the
  REAL encoder+decoder (drop the IDR, prove recovery) and is revert-proven against
  the silent-drop version.
- *A4b (reliable file bulk can still block control) — OPEN.* `await bulk.put()`
  still backpressures the reader, so a saturating file transfer can delay control.
  The interim fix is session policy: a coordinator must make interactive input and
  file transfer mutually exclusive on one connection (belongs in A3), or file gets
  its own connection. Not an assumption in a comment — an enforced invariant.
- *A4c (TCP head-of-line) — OPEN / architectural.* One TLS/TCP stream serialises
  all tags, so video bytes already on the wire physically precede a later control
  frame; a receive-side drop buffer cannot leapfrog them. True fix is separate
  transports (or QUIC/WebRTC streams) per channel — the internet-transport phase.

**A3 — composed authority path: HOST SIDE CLOSED; controller side PARTIAL.**
Independently confirmed by reproducing each vulnerability on the prior build and
defeating it on this one: session-authority isolation (per-session SessionContext,
no coordinator-global state), pre-consent pairing-code validation (two-stage
validate_request/confirm_request — a wrong code never prompts the human), and
awaited connection close on teardown (serve() returns only once authority is gone
AND the transport is closed). Still open: the controller-side coordinator and the
full pairing round-trip driven through it.

Note (belongs with Gate 3.1, not A3): pairing still auto-opens on any unknown
connection, so a remote unknown peer can cause a pairing CODE to be displayed
(never a SAS prompt — that needs the code). And because PairingManager is created
per connection, its source/global guess budgets do not persist across reconnects.
The fix is a single host-owned pairing WINDOW (host enables pairing → one manager,
one code, persistent budgets → window closes → unknown rejected), tracked under
Gate 3.1 with A1. The previous "CLOSED (core)" was premature — the reviewer showed
the "unknown peers can only pair" guarantee was enforced only incidentally (by a
re-classify that a refactor could remove) and my headline test passed for the
wrong reason (it used pair-consent=NO, so pairing never happened). Corrected:
- Session entry is now a SINGLE unconditional gate, `_may_open_session(conn)` =
  "is this key pinned in the store?", checked for every path into the session
  loop. The trust store is the one source of truth; scattered pairing return
  values can no longer let a peer fall through. Deterministically unit-tested and
  **revert-proven** (weakening the gate to always-allow fails the tests) — no
  transport-timing dependence.
- `_run_pairing` returns an explicit status enum (PAIRED only on a completed
  commit); pairing has a 60s timeout (M3) so an unknown peer can't park a
  coordinator forever.
- Real over-the-transport attack tests added: unknown streams before pairing;
  unknown knows the code, gets PAIR_ACCEPT, then skips commit and streams; wrong
  SAS then streams — all blocked, none pinned.
- M1 fixed (active-operation cleared on revoke / emergency-stop / crash), M2 fixed
  (the `assert self._authority` is now a real `-O`-safe guard).
Still open: the controller-side coordinator and the full pairing round-trip
*driven through* the coordinator remain to be built; this pass hardened and proved
the host enforcement, which is the security-critical side.

**Process note.** This is the ~fourth time a green test passed because the attack
wasn't actually attempted. The durable fix applied here: test the security
INVARIANT at a single deterministic seam and revert-prove it, rather than assert
on end-to-end side effects whose timing can mask the hole.

**A4b — reliable-bulk control starvation: mutual-exclusion SCAFFOLD in place (per-session, single active operation); full cross-operation enforcement (screen/file/input) awaits the file+input coordinator paths, so not yet provable end-to-end.**
The coordinator refuses a second operation while one is active (verified: refused
before consent is even asked), so interactive control and file transfer cannot run
concurrently on one connection — the exclusion the previous review demanded is now
enforced policy, not a comment. The deeper transport fix (separate control
transport / QUIC) remains B6/A4c for the internet phase.

**A5 — decode resource ceilings: CLOSED.** Layered, lowest to highest:
1. `StreamParamsPayload` bounds negotiated geometry (each side ≤ 3840, product ≤
   8.3M — both 4K orientations allowed, extreme ratios rejected).
2. libavcodec `max_pixels` is installed on the decoder context via the AVOption
   route and **fails closed**: the decoder opens the codec, and if `max_pixels`
   was not consumed by `avcodec_open2` (still present on `ctx.options`) or the
   open fails, it raises rather than decoding with no native guard. So a hostile
   oversized SPS is refused inside FFmpeg at `avcodec_send_packet`, before the
   full native decode/allocation.
3. Python post-decode checks independently bound the returned geometry AND the RGB
   byte count BEFORE `reformat()` materialises the buffer, and require the frame
   match the expected geometry.
Legitimate resolution changes (Gate 5) are preserved via keyframe-bound, honest-
header, in-ceiling transitions; the viewer's advertised width/height now follows a
validated resize (Gate-7 input-mapping readiness).

Tests are genuinely layer-isolating (this took two iterations — the first native
test was a false green because the Python precheck rejected the declared geometry
before FFmpeg ran): `test_native_max_pixels_is_installed` proves the AVOption was
consumed; `test_native_ceiling_rejects_lying_oversized_bitstream` lies in the wire
header so the oversized bitstream reaches FFmpeg and asserts the NATIVE "decode
failed" rejection (revert-proven: removing max_pixels makes it fall through to the
Python ceiling — a different message — and the test fails). No-PyAV reformat-spy
tests keep the Python invariant in the core suite; fail-closed and viewer-resize
have their own regressions. All revert-proven.

**A6 — TLS 1.3 channel-binding construction: OPEN (cryptographic design review
required).** Auth still uses `get_channel_binding("tls-unique")`, which RFC 9266
does not define for TLS 1.3 (tls-exporter is the standardised replacement). Works
in current CPython/OpenSSL and the relay tests pass, but the construction isn't
standards-aligned and must not be treated as frozen. (Restored to the ledger — it
should not have dropped off.)

**Transport wire-version note.** `_TAG_VIDEO=2` is a transport-framing change
below the JSON envelope version, so `PROTOCOL_VERSION` can't detect a mismatch —
an old build closes on "unknown channel tag 2". Before mixed family builds run,
add a transport version / channel-capability handshake.

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
| B6 | **Control-plane priority under load** — file bulk backpressure (A4b) + TCP head-of-line (A4c); enforce input/file mutual exclusion or separate transports | Phase 7 (input under load) | open |
| B7 | **TLS 1.3 channel binding** — move tls-unique -> RFC 9266 tls-exporter (A6) | before freezing the handshake | open |

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


## On-rig validation (LAN MVP release candidate)

A1–A5 are closed and revert-proven in CI (Linux). Before trusting the LAN MVP on
the target hardware, run BOTH smoke tests on the Windows 10/11 + Python 3.11.x rig:

    python scripts/smoke_native.py --capture   # dependency/stack check (imports)
    python scripts/smoke_transport.py          # LIVE socket/TLS/admission check

smoke_transport.py opens real loopback sockets and drives the actual TlsTransport
end to end — control/bulk/video roundtrip, channel-bound auth, pre-TLS admission
timing, and listener-shutdown cancellation. Each check runs in its OWN SUBPROCESS
with its own timeout, so results are deterministic and a harness artifact in one
check cannot masquerade as a transport failure in another. This is the definitive
check that loop.connect_accepted_socket behaves on Windows (it differs across
OSes); a green run on the rig is what CI-on-Linux cannot prove. Exit code 0 = all
checks passed, non-zero = a check failed (usable in rig automation).
