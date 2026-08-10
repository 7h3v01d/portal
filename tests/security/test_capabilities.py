# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Authority model: deny-first, no mutable-set bypass, capability-bound tokens
with INDEPENDENT per-capability cancellation domains."""

from __future__ import annotations

import pytest

from portal.common.errors import PermissionDeniedError
from portal.protocol.capabilities import Capability, CapabilitySet
from portal.security.authority import SessionAuthority
from portal.security.permissions import PermissionGate


def test_new_authority_grants_nothing():
    auth = SessionAuthority()
    assert all(not auth.has(c) for c in Capability)


def test_no_mutable_capability_set_exposed():
    auth = SessionAuthority()
    assert not hasattr(auth, "capabilities")
    assert isinstance(auth.granted(), frozenset)


def test_token_valid_until_its_capability_revoked():
    auth = SessionAuthority()
    auth.grant(Capability.FILE_WRITE_INBOUND)
    token = auth.authorize(Capability.FILE_WRITE_INBOUND)
    assert token.valid
    auth.revoke(Capability.FILE_WRITE_INBOUND)
    assert not token.valid


def test_revocation_domains_are_independent():
    # The Phase 2.1 fix: revoking a DIFFERENT capability must NOT abort an
    # in-flight operation bound to this one.
    auth = SessionAuthority()
    auth.grant(Capability.FILE_WRITE_INBOUND)
    auth.grant(Capability.INPUT_INJECT_MOUSE)
    file_token = auth.authorize(Capability.FILE_WRITE_INBOUND)
    auth.revoke(Capability.INPUT_INJECT_MOUSE)
    assert file_token.valid  # file transfer survives a mouse revoke


def test_revoke_all_invalidates_every_token():
    auth = SessionAuthority()
    auth.grant(Capability.FILE_WRITE_INBOUND)
    auth.grant(Capability.SCREEN_PUBLISH)
    t1 = auth.authorize(Capability.FILE_WRITE_INBOUND)
    t2 = auth.authorize(Capability.SCREEN_PUBLISH)
    auth.revoke_all()
    assert not t1.valid and not t2.valid


def test_authorize_refuses_ungranted():
    auth = SessionAuthority()
    with pytest.raises(PermissionDeniedError):
        auth.authorize(Capability.FILE_WRITE_INBOUND)


def test_grant_does_not_invalidate_tokens():
    auth = SessionAuthority()
    auth.grant(Capability.SCREEN_PUBLISH)
    token = auth.authorize(Capability.SCREEN_PUBLISH)
    auth.grant(Capability.INPUT_INJECT_MOUSE)
    assert token.valid


def test_explicit_cancel():
    auth = SessionAuthority()
    auth.grant(Capability.SCREEN_PUBLISH)
    token = auth.authorize(Capability.SCREEN_PUBLISH)
    token.cancel()
    assert not token.valid


def test_gate_over_authority_and_bare_set():
    auth = SessionAuthority()
    auth.grant(Capability.INPUT_INJECT_MOUSE)
    gate = PermissionGate(auth)
    assert gate.check(Capability.INPUT_INJECT_MOUSE)
    auth.revoke(Capability.INPUT_INJECT_MOUSE)
    with pytest.raises(PermissionDeniedError):
        gate.require(Capability.INPUT_INJECT_MOUSE)

    caps = CapabilitySet()
    caps.grant(Capability.CLIPBOARD_READ_LOCAL)
    PermissionGate(caps).require(Capability.CLIPBOARD_READ_LOCAL)
