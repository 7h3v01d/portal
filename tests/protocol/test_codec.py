# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Gate 1: every hostile input becomes a specific ProtocolError — no TypeError or
RecursionError escapes — and Portal never emits what its own decoder rejects."""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel

from portal.common.constants import MAX_CONTROL_MESSAGE_BYTES, MAX_JSON_DEPTH, PROTOCOL_VERSION
from portal.common.errors import (
    DecodeError,
    MessageTooLargeError,
    ProtocolError,
    UnimplementedMessageTypeError,
    UnknownMessageTypeError,
    UnsupportedVersionError,
)
from portal.protocol import codec
from portal.protocol.capabilities import Capability
from portal.protocol.codec import build, decode, encode
from portal.protocol.messages import (
    CapabilityChangePayload,
    EmptyPayload,
    Envelope,
    HelloPayload,
    MessageType,
)


def raw(**obj) -> bytes:
    base = {"version": PROTOCOL_VERSION, "type": "ping", "sequence": 1, "timestamp": 1000}
    base.update(obj)
    return json.dumps(base).encode()


# --- Happy path & typed payloads ------------------------------------------
def test_roundtrip_ping_typed():
    msg = decode(encode(build(MessageType.PING, EmptyPayload(), sequence=1)))
    assert msg.type is MessageType.PING
    assert isinstance(msg.payload, EmptyPayload)


def test_capability_payload_is_enum_not_string():
    env = build(
        MessageType.CAPABILITY_GRANT,
        CapabilityChangePayload(capabilities=[Capability.SCREEN_PUBLISH]),
        sequence=2,
    )
    msg = decode(encode(env))
    assert msg.payload.capabilities == [Capability.SCREEN_PUBLISH]
    assert all(isinstance(c, Capability) for c in msg.payload.capabilities)


# --- ProtocolError boundary: the reopened Gate 1 probes -------------------
@pytest.mark.parametrize("bad_type", ["[]", "{}", '["ping"]'])
def test_non_string_type_is_protocol_error_not_typeerror(bad_type):
    body = ('{"version":1,"type":%s,"sequence":1,"timestamp":1}' % bad_type).encode()
    with pytest.raises(ProtocolError):  # specifically NOT a bare TypeError
        decode(body)


def test_deeply_nested_json_rejected_cleanly():
    depth = MAX_JSON_DEPTH + 50
    body = ('{"version":1,"type":"ping","sequence":1,"timestamp":1,"payload":'
            + "[" * depth + "]" * depth + "}").encode()
    with pytest.raises(ProtocolError):  # DecodeError, not RecursionError
        decode(body)


def test_nesting_inside_string_does_not_falsely_trip_depth():
    # Braces inside a JSON string must not count toward structural depth.
    env = build(MessageType.HELLO, HelloPayload(device_name="{[{[{[" * 5), sequence=1)
    msg = decode(encode(env))
    assert "{[" in msg.payload.device_name


# --- Size / structure -----------------------------------------------------
def test_oversized_rejected_before_parse():
    with pytest.raises(MessageTooLargeError):
        decode(b"x" * (MAX_CONTROL_MESSAGE_BYTES + 1))


def test_malformed_json_rejected():
    with pytest.raises(DecodeError):
        decode(b"{not json")


def test_non_object_json_rejected():
    with pytest.raises(DecodeError):
        decode(b"[1, 2, 3]")


# --- Version --------------------------------------------------------------
def test_missing_version_rejected():
    with pytest.raises(UnsupportedVersionError):
        decode(json.dumps({"type": "ping", "sequence": 1, "timestamp": 1}).encode())


def test_newer_version_rejected():
    with pytest.raises(UnsupportedVersionError):
        decode(raw(version=PROTOCOL_VERSION + 1))


def test_bool_version_rejected():
    with pytest.raises(UnsupportedVersionError):
        decode(raw(version=True))


# --- Type -----------------------------------------------------------------
def test_unknown_type_rejected():
    with pytest.raises(UnknownMessageTypeError):
        decode(raw(type="run_shell"))


def test_known_but_unimplemented_type_rejected():
    with pytest.raises(UnimplementedMessageTypeError):
        decode(raw(type="input_mouse", payload={"anything": 1}))


def test_reserved_type_cannot_smuggle_payload():
    with pytest.raises(UnimplementedMessageTypeError):
        decode(raw(type="file_chunk", payload={"run_shell": "calc.exe"}))


# --- Strictness / coercion ------------------------------------------------
@pytest.mark.parametrize("field,value", [
    ("sequence", "1"), ("sequence", 1.0), ("sequence", True),
    ("timestamp", "1"),
])
def test_scalar_coercion_rejected(field, value):
    with pytest.raises(DecodeError):
        decode(raw(**{field: value}))


def test_infinity_rejected():
    with pytest.raises(DecodeError):
        decode(b'{"version": 1, "type": "ping", "sequence": 1, "timestamp": Infinity}')


def test_nan_rejected():
    with pytest.raises(DecodeError):
        decode(b'{"version": 1, "type": "ping", "sequence": 1, "timestamp": NaN}')


def test_duplicate_keys_rejected():
    with pytest.raises(DecodeError):
        decode(b'{"version":1,"type":"run_shell","type":"ping","sequence":1,"timestamp":1}')


# --- Envelope / payload shape ---------------------------------------------
def test_extra_top_level_key_rejected():
    with pytest.raises(DecodeError):
        decode(raw(smuggled="x"))


def test_negative_sequence_rejected():
    with pytest.raises(DecodeError):
        decode(raw(sequence=-1))


def test_unknown_capability_string_rejected():
    with pytest.raises(DecodeError):
        decode(raw(type="capability_grant", payload={"capabilities": ["screen.view"]}))


def test_session_id_with_newline_rejected():
    with pytest.raises(DecodeError):
        decode(raw(session_id="abc\nforged-log-line"))


def test_error_code_charset_enforced():
    with pytest.raises(DecodeError):
        decode(raw(type="error", payload={"code": "bad code!", "detail": ""}))


def test_hello_rejects_control_char_device_name():
    with pytest.raises(DecodeError):
        decode(raw(type="hello", payload={"device_name": "Dad-PC\nTRUSTED"}))


def test_hello_rejects_bidi_override_device_name():
    with pytest.raises(DecodeError):
        decode(raw(type="hello", payload={"device_name": "Dad\u202ePC"}))


def test_hello_rejects_legacy_device_id_field():
    # device_id was removed from HELLO; sending it is now an extra key.
    with pytest.raises(DecodeError):
        decode(raw(type="hello", payload={"device_id": "8F42", "device_name": "Dad-PC"}))


# --- Outbound symmetry: Portal never emits what it rejects ----------------
def test_build_rejects_wrong_payload_type():
    with pytest.raises(ProtocolError):
        build(MessageType.HELLO, EmptyPayload(), sequence=1)  # HELLO needs HelloPayload


def test_build_rejects_unimplemented_type():
    with pytest.raises(UnimplementedMessageTypeError):
        build(MessageType.INPUT_MOUSE, EmptyPayload(), sequence=1)


def test_encode_rejects_raw_envelope_with_junk_payload():
    env = Envelope(version=PROTOCOL_VERSION, type=MessageType.PING, sequence=1,
                   timestamp=1, payload={"junk": 1})
    with pytest.raises(ProtocolError):
        encode(env)
