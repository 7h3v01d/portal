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
same per-connection channel-binding value; the two legs of a MITM have *different*
binding values. Each side signs

    "portal-auth-v1" || role || binding_type || channel_binding || its_own_public_key

The peer verifies that signature against the presented key using ITS OWN copy of
the channel binding. A relayed signature was made over the other leg's binding,
so it fails here. The MITM cannot re-sign (it lacks the private keys). Therefore
the MITM is forced to present its OWN keys on each leg — which is exactly the case
the SAS ceremony detects (different key pairs -> different SAS).

`binding_type` names the channel-binding construction (RFC 9266 `tls-exporter`
when the runtime can produce it, else `tls-unique`) and is part of the signed
transcript, so the construction is explicit and upgradeable rather than frozen: a
peer using a different construction fails verification, and moving the runtime to
one that offers tls-exporter upgrades both ends automatically.

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


def _transcript(role: bytes, binding_type: bytes, channel_binding: bytes, public_key: bytes) -> bytes:
    # Length-prefixed so no two distinct (role, type, cb, key) tuples can collide
    # into the same signed bytes. The binding TYPE is included so the specific
    # channel-binding construction in use (tls-exporter vs tls-unique) is part of
    # what's signed — a peer using a different construction fails verification,
    # and the wire is explicit about the binding rather than silently frozen.
    def framed(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b

    return hashlib.sha256(
        _DOMAIN + framed(role) + framed(binding_type) + framed(channel_binding) + framed(public_key)
    ).digest()


def build_auth(identity: Ed25519Identity, role: bytes, binding_type: str, channel_binding: bytes) -> dict:
    """Produce this side's authentication message. `role` is ROLE_CLIENT or
    ROLE_SERVER (whichever this endpoint is); `binding_type` is the channel-binding
    construction used (e.g. 'tls-exporter' or 'tls-unique'); `channel_binding` is
    the local binding value of that type."""
    if role not in (ROLE_CLIENT, ROLE_SERVER):
        raise IdentityError(f"invalid role: {role!r}")
    public_key = identity.identity.public_key
    bt = binding_type.encode("ascii")
    signature = identity.sign(_transcript(role, bt, channel_binding, public_key))
    return {
        "public_key": public_key.hex(),
        "signature": signature.hex(),
        "binding": binding_type,
    }


def verify_auth(
    message: dict, peer_role: bytes, binding_type: str, channel_binding: bytes
) -> DeviceIdentity:
    """Verify the peer's authentication message and return its authenticated
    identity, or raise IdentityError.

    `peer_role` is the role the *peer* should have used (the opposite of ours);
    `binding_type` and `channel_binding` are OURS. The peer must have used the same
    binding type (both ends run identical selection over the same TLS connection),
    and a relayed message — signed over the other leg's binding — fails here."""
    if not isinstance(message, dict):
        raise IdentityError("auth message must be an object")
    try:
        public_key = bytes.fromhex(message["public_key"])
        signature = bytes.fromhex(message["signature"])
    except (KeyError, ValueError, TypeError) as exc:
        raise IdentityError("malformed auth message") from exc

    # The peer must declare (and therefore have signed with) the SAME binding type
    # we used. A mismatch is a downgrade/confusion attempt or version skew — reject.
    peer_binding = message.get("binding")
    if peer_binding != binding_type:
        raise IdentityError("peer used a different channel-binding type")

    if len(public_key) != _ED25519_PUBLIC_LEN:
        raise IdentityError("peer key is not canonical Ed25519 material")

    transcript = _transcript(peer_role, binding_type.encode("ascii"), channel_binding, public_key)
    if not Ed25519Identity.verify(public_key, transcript, signature):
        # Forgery, relay (binding mismatch), or reflection (role mismatch) — all
        # fail here; do not say which.
        raise IdentityError("peer authentication failed")

    return DeviceIdentity.from_public_key(public_key, device_name="")
