# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The wire codec — the one place untrusted bytes become a trusted, typed
Message, and the one place we build outbound messages.

Two symmetric guarantees:
  - decode(): hostile input becomes a specific ProtocolError, never an uncaught
    TypeError/RecursionError that walks around a caller's `except ProtocolError`.
  - encode()/build(): Portal never emits a message its own decoder would reject.

decode() rejection order (hand-written so the adversarial pass can read it):

    1. size ceiling      -> MessageTooLargeError            (before parse)
    2. nesting depth     -> DecodeError                     (before parse)
    3. strict JSON parse -> DecodeError                     (dup keys, inf/nan, recursion)
    4. must be object    -> DecodeError
    5. version known     -> UnsupportedVersionError
    6. type is a string  -> UnknownMessageTypeError         (guards unhashable type)
    7. type known        -> UnknownMessageTypeError
    8. type implemented  -> UnimplementedMessageTypeError   (fail-closed)
    9. envelope shape    -> DecodeError                     (strict, extra forbidden)
   10. payload shape     -> DecodeError                     (strict, per-type schema)

The returned Message carries a typed, validated payload; the raw dict never
escapes. JSON on the wire — never pickle, never eval.
"""

from __future__ import annotations

import json
import time

from pydantic import BaseModel, ValidationError

from ..common.constants import MAX_CONTROL_MESSAGE_BYTES, MAX_JSON_DEPTH, PROTOCOL_VERSION
from ..common.errors import (
    DecodeError,
    MessageTooLargeError,
    ProtocolError,
    UnimplementedMessageTypeError,
    UnknownMessageTypeError,
    UnsupportedVersionError,
)
from .messages import PAYLOAD_SCHEMAS, Envelope, Message, MessageType
from .versioning import is_supported

_VALID_TYPE_VALUES = frozenset(t.value for t in MessageType)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    """object_pairs_hook: refuse any JSON object with a repeated key — a Rust/Go/
    JS peer must not be able to smuggle a second `type` past us."""
    seen: set[str] = set()
    out: dict = {}
    for key, value in pairs:
        if key in seen:
            raise DecodeError(f"duplicate JSON key: {key!r}")
        seen.add(key)
        out[key] = value
    return out


def _reject_constant(token: str) -> object:
    """parse_constant hook: Infinity / -Infinity / NaN are not valid on our wire."""
    raise DecodeError(f"non-finite JSON constant not allowed: {token}")


def _exceeds_depth(raw: bytes, limit: int) -> bool:
    """Cheap structural pre-scan: True if bracket/brace nesting exceeds `limit`.
    Respects JSON string literals and escapes so `{` inside a string doesn't
    count. Runs before json.loads so a nesting bomb never reaches the recursive
    parser."""
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        ch = chr(byte)
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            if depth > limit:
                return True
        elif ch in "}]":
            depth -= 1
    return False


def now_ms() -> int:
    """Current time as epoch milliseconds — the wire timestamp unit."""
    return int(time.time() * 1000)


def build(
    message_type: MessageType,
    payload: BaseModel,
    *,
    sequence: int,
    session_id: str | None = None,
    version: int | None = None,
) -> Envelope:
    """Construct an Envelope from a typed payload, refusing to build anything the
    decoder would reject: the type must be implemented and the payload must be an
    instance of that type's registered schema."""
    schema = PAYLOAD_SCHEMAS.get(message_type)
    if schema is None:
        raise UnimplementedMessageTypeError(
            f"cannot build reserved/unimplemented type: {message_type}"
        )
    if not isinstance(payload, schema):
        raise ProtocolError(
            f"{message_type} requires {schema.__name__}, got {type(payload).__name__}"
        )
    return Envelope(
        version=PROTOCOL_VERSION if version is None else version,
        type=message_type,
        sequence=sequence,
        timestamp=now_ms(),
        session_id=session_id,
        payload=payload.model_dump(),
    )


def encode(envelope: Envelope) -> bytes:
    """Serialise a validated Envelope to UTF-8 JSON bytes. Symmetric with decode:
    the payload is validated against its registered schema and the type must be
    implemented, so a raw Envelope built with a junk payload is refused here
    rather than emitted for a peer to reject."""
    schema = PAYLOAD_SCHEMAS.get(envelope.type)
    if schema is None:
        raise UnimplementedMessageTypeError(
            f"cannot encode reserved/unimplemented type: {envelope.type}"
        )
    try:
        schema.model_validate(envelope.payload)
    except ValidationError as exc:
        raise DecodeError(f"outbound payload for {envelope.type} is invalid: {exc}") from exc

    raw = envelope.model_dump_json().encode("utf-8")
    if len(raw) > MAX_CONTROL_MESSAGE_BYTES:
        raise MessageTooLargeError(
            f"encoded message is {len(raw)} bytes (limit {MAX_CONTROL_MESSAGE_BYTES})"
        )
    return raw


def decode(raw: bytes) -> Message:
    """Turn raw bytes into a validated, typed Message, or raise a specific
    ProtocolError. This function is the trust boundary — every exit is a
    ProtocolError subclass, never a bare TypeError/RecursionError."""

    # 0. Input must be bytes-like. decode() is the trust boundary and promises
    #    every exit is a ProtocolError — so a non-bytes argument is a clean
    #    DecodeError, not an escaping TypeError.
    if not isinstance(raw, (bytes, bytearray)):
        raise DecodeError(f"decode expects bytes, got {type(raw).__name__}")
    raw = bytes(raw)

    # 1. Size ceiling — before parsing.
    if len(raw) > MAX_CONTROL_MESSAGE_BYTES:
        raise MessageTooLargeError(
            f"message is {len(raw)} bytes (limit {MAX_CONTROL_MESSAGE_BYTES})"
        )

    # 2. Nesting depth — before parsing, so a nesting bomb never recurses.
    if _exceeds_depth(raw, MAX_JSON_DEPTH):
        raise DecodeError(f"JSON nesting exceeds limit of {MAX_JSON_DEPTH}")

    # 3. Strict parse: reject duplicate keys and non-finite constants; treat a
    #    RecursionError as a rejection rather than a crash (belt for #2).
    try:
        obj = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except DecodeError:
        raise
    except RecursionError as exc:
        raise DecodeError("JSON nesting exceeds safe limit") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DecodeError(f"not valid JSON: {exc}") from exc

    # 4. Top level must be an object.
    if not isinstance(obj, dict):
        raise DecodeError(f"top-level JSON must be an object, got {type(obj).__name__}")

    # 5. Version in the allow-list.
    if not is_supported(obj.get("version")):
        raise UnsupportedVersionError(f"unsupported protocol version: {obj.get('version')!r}")

    # 6. Type must be a string BEFORE any set membership test — a list/dict as
    #    `type` would raise an unhashable TypeError that escapes ProtocolError.
    raw_type = obj.get("type")
    if not isinstance(raw_type, str):
        raise UnknownMessageTypeError(
            f"message type must be a string, got {type(raw_type).__name__}"
        )

    # 7. Type must be a known member.
    if raw_type not in _VALID_TYPE_VALUES:
        raise UnknownMessageTypeError(f"unknown message type: {raw_type!r}")

    message_type = MessageType(raw_type)

    # 8. Fail-closed: type must have an active payload schema.
    schema = PAYLOAD_SCHEMAS.get(message_type)
    if schema is None:
        raise UnimplementedMessageTypeError(
            f"message type is reserved/unimplemented: {message_type}"
        )

    # 9. Strict envelope validation.
    try:
        envelope = Envelope.model_validate(obj)
    except ValidationError as exc:
        raise DecodeError(f"envelope failed validation: {exc}") from exc

    # 10. Strict payload validation -> a typed model instance.
    try:
        typed_payload = schema.model_validate(envelope.payload)
    except ValidationError as exc:
        raise DecodeError(f"payload for {message_type} failed validation: {exc}") from exc

    return Message(
        version=envelope.version,
        type=envelope.type,
        sequence=envelope.sequence,
        timestamp=envelope.timestamp,
        session_id=envelope.session_id,
        payload=typed_payload,
    )
