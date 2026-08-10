# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Application configuration with deny-first defaults and strict validation.

Every field that widens what the app will do defaults to the closed position.
The model is **strict**: a typo like `allow_unattended = "true"` in a config file
must fail startup, not silently reinterpret itself into True. A config loader may
deliberately convert human textual formats into these canonical types; the model
itself does not coerce.

There is deliberately no global `auto_grant_capabilities` switch — a blanket
auto-grant contradicts Portal's central principle of explicit, per-capability
consent. When unattended access arrives (very late), it will be a per-device,
per-capability policy (allow / ask / deny), never one global boolean."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .constants import MAX_DEVICE_NAME_LEN


class PortalConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    device_name: str = Field(default="Portal Host", max_length=MAX_DEVICE_NAME_LEN)

    # LAN listener (Phase 3). Loopback by default — nothing exposed until the
    # owner chooses a bind address.
    listen_host: str = Field(default="127.0.0.1")
    listen_port: int = Field(default=0, ge=0, le=65535)  # 0 = OS-assigned

    # Security posture — all closed.
    allow_unattended: bool = Field(default=False)
    auto_accept_transfers: bool = Field(default=False)

    log_level: str = Field(default="INFO")
