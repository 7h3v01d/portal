# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Message types, strict wire schemas, and the typed decoded message.

Two hardening rules run through this module:

1. **Strict, no coercion.** Wire models use `strict=True` and reject inf/nan. On
   a security-sensitive protocol, "1", 1, 1.0 and true must not all quietly mean
   the same thing. Application config can coerce; the wire cannot.

2. **Fail-closed on type.** The enum lists the *complete* future message set, but
   only types with an entry in `PAYLOAD_SCHEMAS` are accepted. A reserved/future
   type is rejected until its contract is deliberately registered — so adding a
   handler for INPUT_INJECT_MOUSE is not enough to activate it; its schema must
   also be registered. That is the deny-first property applied to the protocol
   surface itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..common.constants import (
    MAX_CAPABILITY_LIST_LEN,
    MAX_DEVICE_NAME_LEN,
    MAX_ERROR_CODE_LEN,
    MAX_ERROR_DETAIL_LEN,
    MAX_SEQUENCE,
    MAX_SESSION_ID_LEN,
)
from .capabilities import Capability

# Shared strict config for every wire model.
_WIRE = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False, frozen=True, validate_default=True)

# Enum-by-value is legitimate wire deserialization, not the dangerous scalar
# coercion strict mode exists to block. These annotated aliases accept the value
# string ("hello", "screen.publish") while still rejecting unknown values and
# leaving int/float/bool/str coercion on every other field disabled.
_WireMessageType = Annotated["MessageType", Field(strict=False)]
_WireCapability = Annotated[Capability, Field(strict=False)]


class MessageType(str, Enum):
    """The complete, closed set of Portal message types. Presence here makes a
    type *known*; presence in PAYLOAD_SCHEMAS makes it *accepted*."""

    # Handshake
    HELLO = "hello"
    HELLO_ACK = "hello_ack"

    # Pairing (Phase 2)
    PAIR_REQUEST = "pair_request"
    PAIR_ACCEPT = "pair_accept"
    PAIR_DENY = "pair_deny"
    PAIR_CONFIRM = "pair_confirm"

    # Session lifecycle
    SESSION_REQUEST = "session_request"
    SESSION_ACCEPT = "session_accept"
    SESSION_END = "session_end"

    # Capabilities
    CAPABILITY_REQUEST = "capability_request"
    CAPABILITY_GRANT = "capability_grant"
    CAPABILITY_REVOKE = "capability_revoke"

    # Input (Phase 7/8)
    INPUT_MOUSE = "input_mouse"
    INPUT_KEYBOARD = "input_keyboard"

    # File transfer (Phase 3/12)
    FILE_OFFER = "file_offer"
    FILE_ACCEPT = "file_accept"
    FILE_REJECT = "file_reject"
    FILE_CHUNK = "file_chunk"
    FILE_COMPLETE = "file_complete"
    FILE_CANCEL = "file_cancel"

    # Clipboard (Phase 13)
    CLIPBOARD_UPDATE = "clipboard_update"

    # Liveness / errors
    PING = "ping"
    PONG = "pong"
    ERROR = "error"

    def __str__(self) -> str:
        return self.value


# --- Framing --------------------------------------------------------------
class Envelope(BaseModel):
    """Strict framing wrapper. `payload` is validated separately against the
    per-type schema by the codec; the codec never lets the raw dict escape."""

    model_config = _WIRE

    version: int = Field(ge=1, le=MAX_SEQUENCE)
    type: _WireMessageType
    sequence: int = Field(ge=0, le=MAX_SEQUENCE)
    timestamp: int = Field(ge=0, le=MAX_SEQUENCE)  # epoch milliseconds; int, not float
    session_id: str | None = Field(
        default=None, max_length=MAX_SESSION_ID_LEN, pattern=r"^[A-Za-z0-9_-]+$"
    )
    payload: dict = Field(default_factory=dict)


# --- Payload schemas (only implemented types are registered) --------------
class EmptyPayload(BaseModel):
    model_config = _WIRE


class HelloPayload(BaseModel):
    model_config = _WIRE
    # No protocol_version: the envelope's `version` is the single source of truth.
    # No device_id: it is derived locally from the authenticated public key, so a
    # peer-supplied id is worthless and only invites impersonation of a trusted
    # device's displayed id. device_name is an UNTRUSTED display hint, sanitised
    # against control/bidi injection before it can reach a log or the UI.
    device_name: str = Field(min_length=1, max_length=MAX_DEVICE_NAME_LEN)

    @field_validator("device_name")
    @classmethod
    def _safe_name(cls, v: str) -> str:
        from ..security.validation import ensure_display_text
        from ..common.errors import UnsafePathError

        try:
            return ensure_display_text(v)
        except UnsafePathError as exc:
            raise ValueError(str(exc)) from exc


class SessionRequestPayload(BaseModel):
    model_config = _WIRE
    requested: list[_WireCapability] = Field(default_factory=list, max_length=MAX_CAPABILITY_LIST_LEN)


class PairRequestPayload(BaseModel):
    model_config = _WIRE
    # The peer's public key is NOT here — it is taken from the authenticated
    # channel, never self-asserted. This payload only carries the one-time code
    # and an untrusted display-name hint. The pairing manager derives the id from
    # the channel key.
    code: str = Field(min_length=4, max_length=64, pattern=r"^[A-Z2-9-]+$")
    device_name: str = Field(min_length=1, max_length=MAX_DEVICE_NAME_LEN)

    @field_validator("device_name")
    @classmethod
    def _safe_name(cls, v: str) -> str:
        from ..common.errors import UnsafePathError
        from ..security.validation import ensure_display_text

        try:
            return ensure_display_text(v)
        except UnsafePathError as exc:
            raise ValueError(str(exc)) from exc


class PairAcceptPayload(BaseModel):
    model_config = _WIRE
    device_name: str = Field(min_length=1, max_length=MAX_DEVICE_NAME_LEN)
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")  # transaction nonce to echo in PAIR_CONFIRM

    @field_validator("device_name")
    @classmethod
    def _safe_name(cls, v: str) -> str:
        from ..common.errors import UnsafePathError
        from ..security.validation import ensure_display_text

        try:
            return ensure_display_text(v)
        except UnsafePathError as exc:
            raise ValueError(str(exc)) from exc


class PairConfirmPayload(BaseModel):
    model_config = _WIRE
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")


class PairDenyPayload(BaseModel):
    model_config = _WIRE
    reason: str = Field(default="DENIED", max_length=MAX_ERROR_CODE_LEN, pattern=r"^[A-Z0-9_.-]+$")


class CapabilityChangePayload(BaseModel):
    model_config = _WIRE
    capabilities: list[_WireCapability] = Field(default_factory=list, max_length=MAX_CAPABILITY_LIST_LEN)


class ErrorPayload(BaseModel):
    model_config = _WIRE
    code: str = Field(min_length=1, max_length=MAX_ERROR_CODE_LEN, pattern=r"^[A-Z0-9_.-]+$")
    detail: str = Field(default="", max_length=MAX_ERROR_DETAIL_LEN)


# Registry of type -> payload model. A type absent here is KNOWN but NOT
# ACCEPTED — the codec rejects it as unimplemented. Extend as phases land.
PAYLOAD_SCHEMAS: dict[MessageType, type[BaseModel]] = {
    MessageType.HELLO: HelloPayload,
    MessageType.HELLO_ACK: HelloPayload,
    MessageType.PAIR_REQUEST: PairRequestPayload,
    MessageType.PAIR_ACCEPT: PairAcceptPayload,
    MessageType.PAIR_DENY: PairDenyPayload,
    MessageType.PAIR_CONFIRM: PairConfirmPayload,
    MessageType.SESSION_REQUEST: SessionRequestPayload,
    MessageType.CAPABILITY_REQUEST: CapabilityChangePayload,
    MessageType.CAPABILITY_GRANT: CapabilityChangePayload,
    MessageType.CAPABILITY_REVOKE: CapabilityChangePayload,
    MessageType.PING: EmptyPayload,
    MessageType.PONG: EmptyPayload,
    MessageType.ERROR: ErrorPayload,
}


@dataclass(frozen=True)
class Message:
    """A fully validated message with a **typed** payload. This is what crosses
    the trust boundary out of the codec — never the raw dict."""

    version: int
    type: _WireMessageType
    sequence: int
    timestamp: int
    session_id: str | None
    payload: BaseModel
