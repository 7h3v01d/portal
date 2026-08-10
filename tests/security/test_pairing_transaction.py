# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Gate 2B: the PAIR_REQUEST -> PAIR_ACCEPT -> PAIR_CONFIRM transaction through
the real codec, ending in BOTH installations trusting each other — with the host
committing durable trust only on the final confirm."""

from __future__ import annotations

from pathlib import Path

from portal.protocol.codec import build, decode, encode
from portal.protocol.messages import (
    MessageType,
    PairAcceptPayload,
    PairConfirmPayload,
    PairDenyPayload,
    PairRequestPayload,
)
from portal.security.identity import Ed25519Identity
from portal.security.pairing import ControllerPairing, PairingManager, PairingOutcome
from portal.security.store import FileIdentityStore

YES = lambda _c: True  # noqa: E731  (SAS matched out of band)


def test_mutual_pairing_over_the_codec(tmp_path: Path):
    host_store = FileIdentityStore(tmp_path / "host")
    host_key = host_store.load_or_create("Dad-PC").identity.public_key
    ctrl_store = FileIdentityStore(tmp_path / "ctrl")
    ctrl_key = ctrl_store.load_or_create("Leon-PC").identity.public_key

    host_mgr = PairingManager(host_store, host_key)
    code = host_mgr.begin_pairing()

    # Controller -> PAIR_REQUEST
    req = decode(encode(build(
        MessageType.PAIR_REQUEST, PairRequestPayload(code=code, device_name="Leon-PC"), sequence=1
    )))

    # Host verifies; SAS confirmed -> PENDING (not trusted yet), returns nonce.
    host_result = host_mgr.handle_request(
        peer_public_key=ctrl_key, code=req.payload.code,
        device_name_hint=req.payload.device_name, confirm=YES,
    )
    assert host_result.outcome is PairingOutcome.PENDING_COMMIT
    assert not host_store.is_trusted(host_result.peer)  # NOT yet
    nonce = host_result.nonce

    # Host -> PAIR_ACCEPT (carries the nonce)
    acc = decode(encode(build(
        MessageType.PAIR_ACCEPT, PairAcceptPayload(device_name="Dad-PC", nonce=nonce), sequence=2
    )))

    # Controller pins the host (commits first) and echoes the nonce in PAIR_CONFIRM.
    cp = ControllerPairing(ctrl_store, ctrl_key, host_key)
    ctrl_result = cp.handle_accept(acc.payload.device_name, confirm=YES)
    assert ctrl_result.outcome is PairingOutcome.ACCEPTED
    assert ctrl_store.is_trusted(ctrl_result.peer)

    conf = decode(encode(build(
        MessageType.PAIR_CONFIRM, PairConfirmPayload(nonce=acc.payload.nonce), sequence=3
    )))

    # Host commits durable trust only now.
    committed = host_mgr.commit(conf.payload.nonce)
    assert committed.outcome is PairingOutcome.ACCEPTED
    assert host_store.is_trusted(committed.peer)

    # Mutual.
    assert host_store.is_trusted(ctrl_key_identity(ctrl_key))
    assert ctrl_store.is_trusted(host_key_identity(host_key))


def ctrl_key_identity(key):
    from portal.security.identity import DeviceIdentity
    return DeviceIdentity.from_public_key(key, "")


def host_key_identity(key):
    from portal.security.identity import DeviceIdentity
    return DeviceIdentity.from_public_key(key, "")


def test_host_does_not_trust_without_commit(tmp_path: Path):
    # If the controller declines / the confirm never arrives, the host — the
    # dangerous side — must NOT durably trust.
    host_store = FileIdentityStore(tmp_path / "host")
    host_key = host_store.load_or_create("Dad-PC").identity.public_key
    ctrl_key = Ed25519Identity.generate("Leon-PC").identity.public_key

    mgr = PairingManager(host_store, host_key)
    code = mgr.begin_pairing()
    r = mgr.handle_request(ctrl_key, code, "Leon-PC", confirm=YES)
    assert r.outcome is PairingOutcome.PENDING_COMMIT
    # No commit happens.
    assert not host_store.is_trusted(r.peer)


def test_commit_rejects_wrong_nonce(tmp_path: Path):
    host_store = FileIdentityStore(tmp_path / "host")
    host_key = host_store.load_or_create("Dad-PC").identity.public_key
    ctrl_key = Ed25519Identity.generate("Leon-PC").identity.public_key
    mgr = PairingManager(host_store, host_key)
    code = mgr.begin_pairing()
    r = mgr.handle_request(ctrl_key, code, "Leon-PC", confirm=YES)
    bad = mgr.commit("f" * 32)
    assert bad.outcome is PairingOutcome.NO_PENDING_COMMIT
    assert not host_store.is_trusted(r.peer)
    # The correct nonce still works afterwards.
    good = mgr.commit(r.nonce)
    assert good.outcome is PairingOutcome.ACCEPTED


def test_pair_deny_transaction(tmp_path: Path):
    ctrl_store = FileIdentityStore(tmp_path / "ctrl")
    ctrl_key = ctrl_store.load_or_create("Leon-PC").identity.public_key
    host_key = Ed25519Identity.generate("Dad-PC").identity.public_key

    deny = decode(encode(build(MessageType.PAIR_DENY, PairDenyPayload(), sequence=1)))
    assert deny.payload.reason == "DENIED"
    cp = ControllerPairing(ctrl_store, ctrl_key, host_key)
    assert cp.handle_deny().outcome is PairingOutcome.DENIED_BY_PEER
    assert ctrl_store.list_trusted() == []
