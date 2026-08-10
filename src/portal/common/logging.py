# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Logging. The audit rules (Phase 15) forbid ever logging keystrokes,
screenshots, clipboard contents, passwords, or private keys. This module gives
every part of the app a logger and a `redact()` helper so that rule is easy to
honour and hard to break by accident.

Security-relevant *events* (session start/end, permissions granted, file hashes,
auth failures) are logged. Their *contents* are not.
"""

from __future__ import annotations

import logging

from .constants import APP_NAME

_CONFIGURED = False


def configure_logging(level: int = logging.INFO) -> None:
    """Idempotent root configuration. Call once at process start."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root = logging.getLogger(APP_NAME.lower())
    root.setLevel(level)
    root.addHandler(handler)
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger (e.g. 'portal.protocol.codec')."""
    return logging.getLogger(f"{APP_NAME.lower()}.{name}")


def _one_line(text: str) -> str:
    """Collapse to a single physical line with control characters escaped, so an
    untrusted string can never inject a fake log line."""
    return "".join(
        ch if (ch.isprintable() and ch not in "\r\n") else f"\\x{ord(ch):02x}"
        for ch in text
    )


def safe_line(text: object) -> str:
    """Render untrusted text for logging: one line, control characters escaped.
    Use this for any peer-supplied string (device names, error details)."""
    return _one_line(str(text))


def redact(value: object, keep: int = 4) -> str:
    """Render an identifying-but-not-secret value (device/session id) for logging
    without exposing it — and without letting embedded control characters inject
    a log line. Never pass a private key or clipboard content here."""
    s = _one_line(str(value))
    if len(s) <= keep:
        return "*" * len(s)
    return s[:keep] + "…" + "*" * min(6, len(s) - keep)
