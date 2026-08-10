# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Trust is pinned to the full public key, never the 64-bit display id."""

from __future__ import annotations

from portal.security.identity import DeviceIdentity, Ed25519Identity, verify_pinned


def test_verify_pinned_matches_same_key():
    ident = Ed25519Identity.generate("Dad-PC").identity
    assert verify_pinned(ident.public_key, ident) is True


def test_verify_pinned_rejects_different_key():
    a = Ed25519Identity.generate("A").identity
    b = Ed25519Identity.generate("B").identity
    # Even if an attacker's record claimed A's display id, the key won't match.
    forged = DeviceIdentity(device_id=a.device_id, device_name=a.device_name, public_key=b.public_key)
    assert verify_pinned(a.public_key, forged) is False


def test_verify_pinned_rejects_none_and_wrong_length():
    ident = Ed25519Identity.generate("A").identity
    assert verify_pinned(None, ident) is False
    assert verify_pinned(b"too-short", ident) is False


def test_short_id_can_collide_but_key_cannot():
    # The point of the redesign: authorising on the short id would be unsafe;
    # authorising on the full key is not. Construct two records sharing a display
    # id and confirm the key comparison still separates them.
    real = Ed25519Identity.generate("Dad-PC").identity
    attacker_key = Ed25519Identity.generate("attacker").identity.public_key
    spoof = DeviceIdentity(device_id=real.device_id, device_name="Dad-PC", public_key=attacker_key)
    assert real.device_id == spoof.device_id  # ids equal by construction
    assert verify_pinned(attacker_key, real) is False  # keys are not
