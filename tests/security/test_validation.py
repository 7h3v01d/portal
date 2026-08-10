# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Containment tests. These are the roadmap's Phase 3 attack strings, locked
down now so the transfer engine inherits a proven gate rather than a promise."""

from __future__ import annotations

from pathlib import Path

import pytest

from portal.common.errors import UnsafePathError
from portal.security.validation import resolve_within, sanitize_filename

MALICIOUS = [
    r"..\..\Windows\System32\evil.exe",
    r"C:\Windows\evil.exe",
    r"\\server\share\evil.exe",
    "CON",
    "NUL",
    "COM1",
    "CON.txt",
    "file.exe:alternate_stream",
    "../etc/passwd",
    "/etc/passwd",
    "",
    "   ",
    ".",
    "..",
    "name\x00.exe",
    "trailingdot.",
    "trailingspace ",
    "sub/dir/name.txt",
    "a" * 256 + ".txt",  # exceeds MAX_FILENAME_LEN
]


@pytest.mark.parametrize("name", MALICIOUS)
def test_malicious_names_rejected(name):
    with pytest.raises(UnsafePathError):
        sanitize_filename(name)


@pytest.mark.parametrize(
    "name",
    ["family_photo.jpg", "report.pdf", "firefox_manager.zip", "notes 2026.txt", "a.b.c.tar.gz"],
)
def test_ordinary_names_pass(name):
    assert sanitize_filename(name) == name.strip()


def test_resolve_within_keeps_files_inside_root(tmp_path: Path):
    root = tmp_path / "Remote Transfers"
    root.mkdir()
    dest = resolve_within(root, "photo.jpg")
    assert dest.parent == root.resolve()
    assert dest.name == "photo.jpg"


def test_resolve_within_rejects_escape(tmp_path: Path):
    root = tmp_path / "Remote Transfers"
    root.mkdir()
    with pytest.raises(UnsafePathError):
        resolve_within(root, r"..\..\evil.exe")


# --- Display-text safety (log/UI injection) -------------------------------
from portal.common.logging import redact, safe_line  # noqa: E402
from portal.security.validation import ensure_display_text  # noqa: E402


@pytest.mark.parametrize("bad", [
    "Dad-PC\nTRUSTED",       # newline / log injection
    "Dad-PC\rmore",          # carriage return
    "Dad\u202ePC",           # bidi right-to-left override
    "tab\there",             # C0 control
    "c1\x85control",         # C1 control (NEL)
])
def test_ensure_display_text_rejects_unsafe(bad):
    with pytest.raises(UnsafePathError):
        ensure_display_text(bad)


def test_ensure_display_text_allows_normal():
    assert ensure_display_text("Dad's Laptop (office)") == "Dad's Laptop (office)"


def test_redact_cannot_inject_newline():
    out = redact("abc\nFORGED LOG LINE")
    assert "\n" not in out


def test_safe_line_collapses_controls():
    out = safe_line("line1\nline2\tend")
    assert "\n" not in out and "\t" not in out
