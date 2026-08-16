# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The channel-bound handshake must authenticate the peer key AND resist an
active relaying MITM (the thing that would otherwise defeat the SAS)."""

from __future__ import annotations

import secrets

BT = "tls-exporter"  # binding type under test

import pytest

from portal.common.errors import IdentityError
from portal.security.handshake import (
    ROLE_CLIENT,
    ROLE_SERVER,
    build_auth,
    verify_auth,
)
from portal.security.identity import Ed25519Identity


def test_happy_path_authenticates_peer_key():
    cb = secrets.token_bytes(48)
    client = Ed25519Identity.generate("Leon")
    server = Ed25519Identity.generate("Dad")

    # Same channel binding on both ends (one honest connection).
    client_msg = build_auth(client, ROLE_CLIENT, BT, cb)
    server_msg = build_auth(server, ROLE_SERVER, BT, cb)

    # Server verifies the client; client verifies the server.
    peer_at_server = verify_auth(client_msg, ROLE_CLIENT, BT, cb)
    peer_at_client = verify_auth(server_msg, ROLE_SERVER, BT, cb)

    assert peer_at_server.public_key == client.identity.public_key
    assert peer_at_client.public_key == server.identity.public_key


def test_relay_across_different_channels_fails():
    # Active MITM: two TLS legs with DIFFERENT bindings. The MITM relays the real
    # parties' messages. Verification uses each leg's own binding, so a message
    # signed over leg-1's binding fails on leg-2.
    cb_leg1 = secrets.token_bytes(48)
    cb_leg2 = secrets.token_bytes(48)
    client = Ed25519Identity.generate("Leon")

    client_msg = build_auth(client, ROLE_CLIENT, BT, cb_leg1)  # made on leg 1
    with pytest.raises(IdentityError):
        verify_auth(client_msg, ROLE_CLIENT, BT, cb_leg2)  # replayed onto leg 2


def test_reflection_back_to_sender_fails():
    # Reflecting a client's message back to the client (as if it were the server)
    # must fail: the roles differ in the signed transcript.
    cb = secrets.token_bytes(48)
    client = Ed25519Identity.generate("Leon")
    client_msg = build_auth(client, ROLE_CLIENT, BT, cb)
    with pytest.raises(IdentityError):
        verify_auth(client_msg, ROLE_SERVER, BT, cb)  # expected a server-role message


def test_tampered_signature_fails():
    cb = secrets.token_bytes(48)
    client = Ed25519Identity.generate("Leon")
    msg = build_auth(client, ROLE_CLIENT, BT, cb)
    sig = bytearray.fromhex(msg["signature"])
    sig[0] ^= 0x01
    msg["signature"] = bytes(sig).hex()
    with pytest.raises(IdentityError):
        verify_auth(msg, ROLE_CLIENT, BT, cb)


def test_swapped_key_fails():
    # Claiming someone else's key without their private key fails.
    cb = secrets.token_bytes(48)
    client = Ed25519Identity.generate("Leon")
    other = Ed25519Identity.generate("Someone")
    msg = build_auth(client, ROLE_CLIENT, BT, cb)
    msg["public_key"] = other.identity.public_key.hex()  # lie about the key
    with pytest.raises(IdentityError):
        verify_auth(msg, ROLE_CLIENT, BT, cb)


@pytest.mark.parametrize("bad", [{}, {"public_key": "zz"}, {"public_key": "00", "signature": "00"}, "notadict"])
def test_malformed_messages_rejected(bad):
    with pytest.raises(IdentityError):
        verify_auth(bad, ROLE_CLIENT, BT, secrets.token_bytes(48))


def test_binding_type_mismatch_rejected():
    # A peer that used a DIFFERENT channel-binding type than us must be rejected —
    # even with a valid signature over its own type — since both ends of one TLS
    # connection derive the same type. This detects downgrade/confusion.
    cb = secrets.token_bytes(48)
    client = Ed25519Identity.generate("Leon")
    msg = build_auth(client, ROLE_CLIENT, "tls-unique", cb)  # peer used tls-unique
    with pytest.raises(IdentityError):
        verify_auth(msg, ROLE_CLIENT, "tls-exporter", cb)   # we used tls-exporter
