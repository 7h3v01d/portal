# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Protocol version negotiation.

Deny-first: we decode a message only if its declared version is in
`SUPPORTED_VERSIONS`. Anything else is rejected — including *newer* versions, so
a downgrade/upgrade probe can't slip past by claiming an unexpected number."""

from __future__ import annotations

from ..common.constants import PROTOCOL_VERSION

# The explicit allow-list of versions this build will decode. Never inferred.
SUPPORTED_VERSIONS: frozenset[int] = frozenset({PROTOCOL_VERSION})


def is_supported(version: object) -> bool:
    """True only for an int that is in the allow-list. Non-ints are False, not
    an error — the codec turns that into a clean rejection."""
    return isinstance(version, int) and not isinstance(version, bool) and version in SUPPORTED_VERSIONS
