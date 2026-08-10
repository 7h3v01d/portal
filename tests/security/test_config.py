# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Config must be strict on security-widening fields — a typo fails startup
rather than reinterpreting itself into an open posture."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from portal.common.config import PortalConfig


def test_defaults_are_closed():
    cfg = PortalConfig()
    assert cfg.allow_unattended is False
    assert cfg.auto_accept_transfers is False
    assert cfg.listen_host == "127.0.0.1"


def test_no_global_auto_grant_field():
    # The dangerous blanket auto-grant switch was removed entirely.
    assert "auto_grant_capabilities" not in PortalConfig.model_fields


@pytest.mark.parametrize("value", ["true", "yes", 1, "1"])
def test_string_or_int_not_coerced_into_true(value):
    with pytest.raises(ValidationError):
        PortalConfig(allow_unattended=value)


def test_port_string_not_coerced():
    with pytest.raises(ValidationError):
        PortalConfig(listen_port="443")


def test_unknown_field_rejected():
    with pytest.raises(ValidationError):
        PortalConfig(enable_god_mode=True)


def test_proper_types_accepted():
    cfg = PortalConfig(allow_unattended=True, listen_port=8080)
    assert cfg.allow_unattended is True
    assert cfg.listen_port == 8080
