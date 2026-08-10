# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Authority model: deny-first, no mutable-set bypass, capability-bound tokens."""

from __future__ import annotations

import pytest

from portal.common.errors import PermissionDeniedError
from portal.protocol.capabilities import Capability, CapabilitySet
from portal.security.authority import SessionAuthority
from portal.security.permissions import PermissionGate


def test_new_set_grants_nothing():
    caps = CapabilitySet()
    assert all(not caps.has(c) for c in Capability)


def test_authority_deny_first_and_grant_isolated():
    auth = SessionAuthority()
    assert not auth.has(Capability.SCREEN_PUBLISH)
    auth.grant(Capability.SCREEN_PUBLISH)
    assert auth.has(Capability.SCREEN_PUBLISH)
    assert not auth.has(Capability.INPUT_INJECT_MOUSE)


def test_no_mutable_capability_set_exposed():
    # The Phase 0.2 bypass: there must be no public mutable capabilities handle.
    auth = SessionAuthority()
    assert not hasattr(auth, "capabilities")
    assert isinstance(auth.granted(), frozenset)


def test_authorize_token_valid_until_capability_revoked():
    auth = SessionAuthority()
    auth.grant(Capability.FILE_WRITE_INBOUND)
    token = auth.authorize(Capability.FILE_WRITE_INBOUND)
    assert token.valid
    auth.revoke(Capability.FILE_WRITE_INBOUND)
    assert not token.valid


def test_authorize_refuses_ungranted_capability():
    auth = SessionAuthority()
    with pytest.raises(PermissionDeniedError):
        auth.authorize(Capability.FILE_WRITE_INBOUND)


def test_revoke_all_invalidates_tokens():
    auth = SessionAuthority()
    auth.grant(Capability.SCREEN_PUBLISH)
    token = auth.authorize(Capability.SCREEN_PUBLISH)
    auth.revoke_all()
    assert not token.valid


def test_grant_does_not_invalidate_tokens():
    auth = SessionAuthority()
    auth.grant(Capability.SCREEN_PUBLISH)
    token = auth.authorize(Capability.SCREEN_PUBLISH)
    auth.grant(Capability.INPUT_INJECT_MOUSE)  # widening is safe
    assert token.valid


def test_revoking_other_capability_still_invalidates_via_generation():
    # Any revoke bumps the generation, so an in-flight token is conservatively
    # invalidated even if a *different* capability was the one revoked.
    auth = SessionAuthority()
    auth.grant(Capability.SCREEN_PUBLISH)
    auth.grant(Capability.INPUT_INJECT_MOUSE)
    token = auth.authorize(Capability.SCREEN_PUBLISH)
    auth.revoke(Capability.INPUT_INJECT_MOUSE)
    assert not token.valid


def test_explicit_cancel():
    auth = SessionAuthority()
    auth.grant(Capability.SCREEN_PUBLISH)
    token = auth.authorize(Capability.SCREEN_PUBLISH)
    token.cancel()
    assert not token.valid


def test_gate_over_authority_sees_live_revocation():
    auth = SessionAuthority()
    auth.grant(Capability.INPUT_INJECT_MOUSE)
    gate = PermissionGate(auth)
    assert gate.check(Capability.INPUT_INJECT_MOUSE)
    auth.revoke(Capability.INPUT_INJECT_MOUSE)
    with pytest.raises(PermissionDeniedError):
        gate.require(Capability.INPUT_INJECT_MOUSE)


def test_gate_also_works_over_bare_capability_set():
    caps = CapabilitySet()
    caps.grant(Capability.CLIPBOARD_READ_LOCAL)
    gate = PermissionGate(caps)
    gate.require(Capability.CLIPBOARD_READ_LOCAL)
