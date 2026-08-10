# Licensing

Portal's own source is **Apache-2.0** (© 2026 Leon Priest). This note records
the one dependency-licence decision that needs to be conscious rather than
accidental. *Not legal advice — just the dependency reality laid out so the
choice is deliberate.*

## The PyQt6 / Apache-2.0 tension

The GUI (later phases) uses **PyQt6**. Riverbank's free PyQt6 is **GPLv3**.
Apache-2.0 source is compatible with being combined into a GPLv3 *distributed
work*, but the combined binary you ship is then effectively governed by GPLv3 —
which is a stronger copyleft than Apache-2.0 implies on its own. So "Apache-2.0
project that ships a PyQt6 binary" is, unqualified, slightly self-contradictory.

Three honest resolutions:

1. **Keep PyQt6, be explicit about distribution (current choice).** The Portal
   *source* stays Apache-2.0. Any distributed binary bundling PyQt6 is provided
   under GPLv3. This keeps estate consistency — the whole estate is PyQt6 — at
   the cost of the stronger copyleft on shipped binaries. Any eventual binary
   sharing is something whose applicable licence obligations should be checked at
   release time; the point is that the dependency is isolated and replaceable.

2. **Switch to PySide6 (LGPLv3).** Qt's official binding is LGPLv3, which sits
   more comfortably under an Apache-2.0 application and imposes lighter
   obligations on distribution. Cost: it breaks the estate's PyQt6 muscle memory
   and design-system reflexes. This was the stack originally discussed.

3. **Commercial PyQt licence.** Removes the GPL obligation entirely; a paid path.

**Decision:** option 1 for now — PyQt6 is not even a core dependency (it lives in
the `ui` extra), so the foundation and its tests carry no GPL surface at all. The
question only becomes live when UI code and distributable binaries appear, at
which point option 2 remains open with no architectural cost, because all UI
sits behind the app's own interfaces.

## Dependency licences (foundation)

| Dependency | Licence |
|---|---|
| cryptography | Apache-2.0 / BSD |
| pydantic | MIT |
| PyQt6 *(extra: ui)* | GPLv3 / commercial |
| dxcam *(extra: capture)* | MIT |
| PyAV *(extra: capture)* | BSD |
| aiortc *(extra: webrtc)* | BSD |
| FastAPI / uvicorn *(extra: server)* | MIT / BSD |
