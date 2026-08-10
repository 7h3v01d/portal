# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Identity primitive: a stable id derived from the key, a working signature, and
rejection of tampered data and forged signatures."""

from __future__ import annotations

import pytest

from portal.common.errors import IdentityError
from portal.security.identity import Ed25519Identity


def test_device_id_is_deterministic_for_a_key():
    ident = Ed25519Identity.generate("Dad-PC")
    # Rebuilding the wrapper from the same private key yields the same id.
    rebuilt = Ed25519Identity(ident._private, "Dad-PC")  # noqa: SLF001 (test introspection)
    assert ident.identity.device_id == rebuilt.identity.device_id


def test_device_id_format():
    ident = Ed25519Identity.generate("Dad-PC")
    did = ident.identity.device_id
    assert len(did) == 19  # 16 hex chars + 3 separators
    assert did.count("-") == 3
    assert did.replace("-", "").isupper()


def test_sign_and_verify_roundtrip():
    ident = Ed25519Identity.generate("Leon-PC")
    data = b"session-request:abc123"
    sig = ident.sign(data)
    assert Ed25519Identity.verify(ident.identity.public_key, data, sig) is True


def test_tampered_data_fails_verification():
    ident = Ed25519Identity.generate("Leon-PC")
    sig = ident.sign(b"original")
    assert Ed25519Identity.verify(ident.identity.public_key, b"tampered", sig) is False


def test_wrong_key_fails_verification():
    a = Ed25519Identity.generate("A")
    b = Ed25519Identity.generate("B")
    sig = a.sign(b"data")
    assert Ed25519Identity.verify(b.identity.public_key, b"data", sig) is False


def test_malformed_public_key_raises():
    ident = Ed25519Identity.generate("A")
    sig = ident.sign(b"data")
    with pytest.raises(IdentityError):
        Ed25519Identity.verify(b"too-short", b"data", sig)
