# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Channel-bound mutual authentication.

This is what turns an encrypted-but-anonymous TLS channel into an *authenticated*
one, and — critically — makes it relay-resistant so the pairing SAS ceremony
actually means something.

The problem: TLS with self-signed ephemeral certs gives confidentiality but does
not prove *who* the peer is. A naive "send your Ed25519 key + a signature over a
nonce" is relayable: an active MITM terminating TLS on each leg can forward the
real parties' signed messages between the two legs, so both ends authenticate the
real peer key while the MITM sits in the middle decrypting everything — and the
SAS (derived from both real keys) would MATCH on both sides, defeating it.

The fix: bind the identity signature to THIS TLS channel. Both ends observe the
same per-connection channel-binding value (TLS `tls-unique`); the two legs of a
MITM have *different* binding values. Each side signs

    "portal-auth-v1" || role || channel_binding || its_own_public_key

The peer verifies that signature against the presented key using ITS OWN copy of
the channel binding. A relayed signature was made over the other leg's binding,
so it fails here. The MITM cannot re-sign (it lacks the private keys). Therefore
the MITM is forced to present its OWN keys on each leg — which is exactly the case
the SAS ceremony detects (different key pairs -> different SAS).

`role` (client vs server) prevents an attacker reflecting a message back to its
sender. This module is pure and socket-free so the relay attack can be unit
tested directly by handing the two sides mismatched binding values.
"""

from __future__ import annotations

import hashlib

from ..common.errors import IdentityError
from .identity import DeviceIdentity, Ed25519Identity

_DOMAIN = b"portal-auth-v1"
ROLE_CLIENT = b"client"
ROLE_SERVER = b"server"
_ED25519_PUBLIC_LEN = 32


def _transcript(role: bytes, channel_binding: bytes, public_key: bytes) -> bytes:
    # Length-prefixed so no two distinct (role, cb, key) triples can collide into
    # the same signed bytes.
    def framed(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b

    return hashlib.sha256(
        _DOMAIN + framed(role) + framed(channel_binding) + framed(public_key)
    ).digest()


def build_auth(identity: Ed25519Identity, role: bytes, channel_binding: bytes) -> dict:
    """Produce this side's authentication message. `role` is ROLE_CLIENT or
    ROLE_SERVER (whichever this endpoint is); `channel_binding` is the local
    TLS `tls-unique` value."""
    if role not in (ROLE_CLIENT, ROLE_SERVER):
        raise IdentityError(f"invalid role: {role!r}")
    public_key = identity.identity.public_key
    signature = identity.sign(_transcript(role, channel_binding, public_key))
    return {"public_key": public_key.hex(), "signature": signature.hex()}


def verify_auth(message: dict, peer_role: bytes, channel_binding: bytes) -> DeviceIdentity:
    """Verify the peer's authentication message and return its authenticated
    identity, or raise IdentityError.

    `peer_role` is the role the *peer* should have used (the opposite of ours);
    `channel_binding` is OUR local binding value. A relayed message — signed over
    the other leg's binding — fails here."""
    if not isinstance(message, dict):
        raise IdentityError("auth message must be an object")
    try:
        public_key = bytes.fromhex(message["public_key"])
        signature = bytes.fromhex(message["signature"])
    except (KeyError, ValueError, TypeError) as exc:
        raise IdentityError("malformed auth message") from exc

    if len(public_key) != _ED25519_PUBLIC_LEN:
        raise IdentityError("peer key is not canonical Ed25519 material")

    transcript = _transcript(peer_role, channel_binding, public_key)
    if not Ed25519Identity.verify(public_key, transcript, signature):
        # Either a forgery, a relayed message (binding mismatch), or a reflected
        # message (role mismatch). All fail here — do not say which.
        raise IdentityError("peer authentication failed")

    # Deriving the id from the authenticated key (never peer-asserted).
    return DeviceIdentity.from_public_key(public_key, device_name="")
