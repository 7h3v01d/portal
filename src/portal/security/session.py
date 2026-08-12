# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The transport ↔ trust bridge.

A freshly established TransportConnection carries an *authenticated* peer key
(the handshake proved it, bound to the channel). Authentication is not authority:
before anything is allowed, the session layer classifies that key against the
trust store — TRUSTED peers proceed to a session; UNKNOWN peers may only enter
pairing. This is the one place "TLS connected" is turned into a trust decision,
and it is done by full-key comparison, never by any peer-asserted identity."""

from __future__ import annotations

from enum import Enum

from .identity import DeviceIdentity, IdentityStore
from ..transport.base import TransportConnection


class TrustStatus(Enum):
    TRUSTED = "trusted"    # a pinned, trusted device — a session may proceed
    UNKNOWN = "unknown"    # authenticated but not trusted — pairing only


def classify_peer(store: IdentityStore, connection: TransportConnection) -> TrustStatus:
    """Classify a connection's authenticated peer against the trust store."""
    peer = DeviceIdentity.from_public_key(connection.peer_public_key, device_name="")
    return TrustStatus.TRUSTED if store.is_trusted(peer) else TrustStatus.UNKNOWN


def authenticated_peer(connection: TransportConnection) -> DeviceIdentity:
    """The authenticated peer identity for a connection (id derived from the key)."""
    return DeviceIdentity.from_public_key(connection.peer_public_key, device_name="")
