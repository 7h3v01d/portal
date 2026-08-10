# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Gate 2B: the PAIR_REQUEST -> PAIR_ACCEPT/DENY transaction through the real
codec, ending in BOTH installations trusting each other. This is the mutual
end-to-end pairing the previous review found missing."""

from __future__ import annotations

from pathlib import Path

from portal.protocol.codec import build, decode, encode
from portal.protocol.messages import (
    MessageType,
    PairAcceptPayload,
    PairDenyPayload,
    PairRequestPayload,
)
from portal.security.identity import Ed25519Identity
from portal.security.pairing import ControllerPairing, PairingManager, PairingOutcome
from portal.security.store import FileIdentityStore

YES = lambda _c: True   # noqa: E731  (SAS matched out of band)


def test_mutual_pairing_over_the_codec(tmp_path: Path):
    # Two installations, each with its own identity.
    host_store = FileIdentityStore(tmp_path / "host")
    host_key = host_store.load_or_create("Dad-PC").identity.public_key
    ctrl_store = FileIdentityStore(tmp_path / "ctrl")
    ctrl_key = ctrl_store.load_or_create("Leon-PC").identity.public_key

    # Host enters pairing mode; the code is read out of band to the controller.
    host_mgr = PairingManager(host_store, host_key)
    code = host_mgr.begin_pairing()

    # Controller builds a real PAIR_REQUEST and puts it on the wire.
    req_bytes = encode(build(
        MessageType.PAIR_REQUEST,
        PairRequestPayload(code=code, device_name="Leon-PC"),
        sequence=1,
    ))

    # Host decodes it. The peer key comes from the AUTHENTICATED channel, not the
    # payload — the payload carries only the code + name hint.
    req = decode(req_bytes)
    assert req.type is MessageType.PAIR_REQUEST
    host_result = host_mgr.handle_request(
        peer_public_key=ctrl_key,           # from transport, not from req.payload
        code=req.payload.code,
        device_name_hint=req.payload.device_name,
        confirm=YES,
    )
    assert host_result.outcome is PairingOutcome.ACCEPTED
    assert host_store.is_trusted(host_result.peer)  # host now trusts controller

    # Host replies PAIR_ACCEPT over the wire.
    acc_bytes = encode(build(
        MessageType.PAIR_ACCEPT, PairAcceptPayload(device_name="Dad-PC"), sequence=2
    ))
    acc = decode(acc_bytes)
    assert acc.type is MessageType.PAIR_ACCEPT

    # Controller pins the host after its own SAS confirmation.
    cp = ControllerPairing(ctrl_store, ctrl_key, host_key)
    ctrl_result = cp.handle_accept(acc.payload.device_name, confirm=YES)
    assert ctrl_result.outcome is PairingOutcome.ACCEPTED
    assert ctrl_store.is_trusted(ctrl_result.peer)  # controller now trusts host

    # Mutual: each trusts the other's authenticated key.
    assert host_store.is_trusted(host_result.peer)
    assert ctrl_store.is_trusted(ctrl_result.peer)


def test_pair_deny_transaction(tmp_path: Path):
    ctrl_store = FileIdentityStore(tmp_path / "ctrl")
    ctrl_key = ctrl_store.load_or_create("Leon-PC").identity.public_key
    host_key = Ed25519Identity.generate("Dad-PC").identity.public_key

    deny_bytes = encode(build(MessageType.PAIR_DENY, PairDenyPayload(), sequence=1))
    deny = decode(deny_bytes)
    assert deny.type is MessageType.PAIR_DENY
    assert deny.payload.reason == "DENIED"  # default now satisfies its own pattern

    cp = ControllerPairing(ctrl_store, ctrl_key, host_key)
    result = cp.handle_deny()
    assert result.outcome is PairingOutcome.DENIED_BY_PEER
    assert ctrl_store.list_trusted() == []


def test_pair_request_roundtrips_through_codec():
    payload = PairRequestPayload(code="AB2C-9KMN", device_name="Leon-PC")
    msg = decode(encode(build(MessageType.PAIR_REQUEST, payload, sequence=1)))
    assert msg.payload.code == "AB2C-9KMN"
    assert msg.payload.device_name == "Leon-PC"
