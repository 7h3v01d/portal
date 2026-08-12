# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Filename and destination validation for incoming files.

A remote-control app is authorised spyware when it works and malware when its
controls fail. The single nastiest failure is letting a peer choose *where* a
received file lands. This module is the gate that stops that.

Scope note: what lives here is **lexical / path containment** — it rejects
dangerous *names and paths* before they reach the filesystem. It is not, on its
own, race-safe filesystem containment: a symlink/reparse-point could still be
swapped between validation and open (a TOCTOU gap). That second guarantee
belongs to the actual Windows file-open in the Phase 3 transfer engine (open the
final handle, then confirm it resolves inside the transfer root, refusing to
follow reparse points). Keeping the two claims distinct so neither is oversold.

Policy for a received filename:
  - reject empty / whitespace-only names
  - reject any path separator (no subdirectories chosen by the sender)
  - reject drive-absolute (C:\\...) and UNC (\\\\server\\share) forms
  - reject '.' and '..' components
  - reject Windows reserved device names (CON, NUL, COM1, ...)
  - reject NTFS alternate-data-stream syntax (name:stream)
  - reject control characters and the characters Windows forbids in names

`resolve_within` is the containment check for the final path: after joining the
sanitised name to the transfer root, the resolved path must still be inside that
root, or we refuse.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePath

from ..common.constants import MAX_FILENAME_LEN
from ..common.errors import UnsafePathError

# Names Windows reserves regardless of extension.
_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

# Characters Windows forbids in a filename, plus the ADS separator ':'.
_FORBIDDEN_CHARS = set('<>:"/\\|?*')


def sanitize_filename(name: str) -> str:
    """Return `name` unchanged if it is a safe *bare* filename, else raise
    UnsafePathError. We do not silently rewrite hostile input into something
    'close' — a suspicious name is rejected so the operator sees it."""
    if not isinstance(name, str):
        raise UnsafePathError(f"filename must be str, got {type(name).__name__}")

    # Validate the RAW name — never normalise first. Stripping before checking
    # would mask a trailing-space/dot attack, which is precisely the thing
    # Windows silently drops.
    if not name or not name.strip():
        raise UnsafePathError("empty filename")

    if len(name) > MAX_FILENAME_LEN:
        raise UnsafePathError(f"filename exceeds {MAX_FILENAME_LEN} characters")

    # Reject any leading/trailing whitespace outright rather than trimming it.
    if name != name.strip():
        raise UnsafePathError("filename has leading or trailing whitespace")

    # No control characters.
    if any(ord(ch) < 32 for ch in name):
        raise UnsafePathError("filename contains control characters")

    # No path separators or Windows-forbidden characters (this also catches
    # absolute paths, UNC prefixes, and ADS ':' in one shot).
    if any(ch in _FORBIDDEN_CHARS for ch in name):
        raise UnsafePathError(f"filename contains a forbidden character: {name!r}")

    # No traversal components.
    if name in (".", ".."):
        raise UnsafePathError("filename is a path component")

    # A bare name should not differ from its own basename.
    if PurePath(name).name != name:
        raise UnsafePathError(f"filename is not a bare name: {name!r}")

    # Reserved device names, with or without extension (CON, CON.txt).
    stem = name.split(".", 1)[0].upper()
    if stem in _RESERVED:
        raise UnsafePathError(f"reserved device name: {name!r}")

    # Trailing dot is stripped by Windows and can mask an extension. (Trailing
    # space is already excluded by the whitespace check above.)
    if name.endswith("."):
        raise UnsafePathError("filename ends with a dot")

    return name


def resolve_within(root: Path, name: str) -> Path:
    """Sanitise `name`, join it under `root`, and confirm the result stays
    inside `root`. Returns the safe absolute destination or raises."""
    safe_name = sanitize_filename(name)
    root_resolved = Path(root).resolve()
    candidate = (root_resolved / safe_name).resolve()

    # Containment: candidate must be root itself or a descendant of it.
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise UnsafePathError(f"destination escapes transfer root: {name!r}") from exc

    # Belt and braces against symlinked roots resolving oddly.
    if os.path.commonpath([str(root_resolved), str(candidate)]) != str(root_resolved):
        raise UnsafePathError(f"destination not contained by root: {name!r}")

    return candidate


# Unicode bidirectional-control characters — an RLO/LRO in a device name can make
# "evil.txt" render as "txt.live" and a name look like a trusted one.
_BIDI_CONTROLS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # LRE RLE PDF LRO RLO
    "\u2066", "\u2067", "\u2068", "\u2069",            # LRI RLI FSI PDI
    "\u200e", "\u200f",                                 # LRM RLM
}


def ensure_display_text(value: str) -> str:
    """Validate a peer-supplied human string (e.g. a device name) that may reach
    a log line or the UI. Rejects C0/C1 control characters (including CR/LF, so a
    value can't inject a second log line) and Unicode bidi controls. Returns the
    value unchanged if safe, else raises UnsafePathError."""
    if not isinstance(value, str):
        raise UnsafePathError(f"display text must be str, got {type(value).__name__}")
    for ch in value:
        code = ord(ch)
        if code < 0x20 or 0x7F <= code <= 0x9F:  # C0 and C1 controls
            raise UnsafePathError("display text contains control characters")
        if ch in _BIDI_CONTROLS:
            raise UnsafePathError("display text contains bidirectional-control characters")
    return value

