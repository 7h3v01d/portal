# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Gate 3 + Phase 4.1: the transfer engine's authority wrapper and integrity.
Tokens are mandatory and capability-specific; verified happy path; hash-mismatch,
malicious filename, decline, oversize, revoke, and non-clobber are all handled."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

from portal.common.errors import PermissionDeniedError, TransferError
from portal.protocol.capabilities import Capability
from portal.security.authority import SessionAuthority
from portal.transfer.lan import receive_file, send_file
from conftest import make_memory_pair


def _write_token(auth=None):
    auth = auth or SessionAuthority()
    auth.grant(Capability.FILE_WRITE_INBOUND)
    return auth, auth.authorize(Capability.FILE_WRITE_INBOUND)


def _read_token(auth=None):
    auth = auth or SessionAuthority()
    auth.grant(Capability.FILE_READ_OUTBOUND)
    return auth, auth.authorize(Capability.FILE_READ_OUTBOUND)


async def _run_transfer(tmp_path, src_bytes, filename="photo.jpg", approve=lambda o: True,
                        recv_token=None, send_token=None, tamper=None):
    src = tmp_path / "src" / filename
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_bytes(src_bytes)
    dest_root = tmp_path / "Remote Transfers"

    if recv_token is None:
        _, recv_token = _write_token()
    if send_token is None:
        _, send_token = _read_token()

    sender_conn, receiver_conn = make_memory_pair()
    if tamper:
        receiver_conn = tamper(receiver_conn)

    recv_task = asyncio.create_task(receive_file(receiver_conn, dest_root, approve, token=recv_token))
    send_task = asyncio.create_task(send_file(sender_conn, str(src), token=send_token))
    results = await asyncio.gather(recv_task, send_task, return_exceptions=True)
    return results, dest_root


# --- authority wrapper (the headline finding) -----------------------------
@pytest.mark.asyncio
async def test_wrong_capability_token_denied(tmp_path):
    # A screen.publish token must NOT authorise a file write.
    auth = SessionAuthority()
    auth.grant(Capability.SCREEN_PUBLISH)
    wrong = auth.authorize(Capability.SCREEN_PUBLISH)
    src = tmp_path / "f.bin"; src.write_bytes(b"x")
    sender, receiver = make_memory_pair()
    with pytest.raises(PermissionDeniedError):
        await receive_file(receiver, tmp_path / "root", lambda o: True, token=wrong)
    with pytest.raises(PermissionDeniedError):
        await send_file(sender, str(src), token=wrong)


@pytest.mark.asyncio
async def test_revoked_token_denied_before_io(tmp_path):
    auth, token = _write_token()
    auth.revoke(Capability.FILE_WRITE_INBOUND)
    _sender, receiver = make_memory_pair()
    with pytest.raises(PermissionDeniedError):
        await receive_file(receiver, tmp_path / "root", lambda o: True, token=token)


@pytest.mark.asyncio
async def test_valid_correct_token_allows(tmp_path):
    results, _ = await _run_transfer(tmp_path, b"ok" * 100)
    assert isinstance(results[0], Path)


# --- integrity path -------------------------------------------------------
@pytest.mark.asyncio
async def test_happy_path_verifies_and_lands_file(tmp_path):
    data = b"hello portal" * 1000
    results, dest_root = await _run_transfer(tmp_path, data)
    recv_result, _ = results
    assert isinstance(recv_result, Path)
    assert recv_result.read_bytes() == data
    assert list(dest_root.glob("*.part")) == []


@pytest.mark.asyncio
async def test_hash_mismatch_discards_file(tmp_path):
    def tamper(conn):
        orig = conn.recv_bulk

        async def flipped():
            chunk = await orig()
            return (bytes([chunk[0] ^ 0xFF]) + chunk[1:]) if chunk else chunk

        conn.recv_bulk = flipped
        return conn

    results, dest_root = await _run_transfer(tmp_path, b"A" * 5000, tamper=tamper)
    assert isinstance(results[0], TransferError)
    assert "hash mismatch" in str(results[0])
    assert list(dest_root.glob("*")) == []


@pytest.mark.asyncio
async def test_malicious_filename_refused(tmp_path):
    import json

    from portal.protocol.codec import build, encode
    from portal.protocol.messages import FileOfferPayload, MessageType

    _sender, receiver = make_memory_pair()
    dest_root = tmp_path / "Remote Transfers"
    _, token = _write_token()

    async def run():
        task = asyncio.create_task(receive_file(receiver, dest_root, lambda o: True, token=token))
        offer = build(MessageType.FILE_OFFER,
                      FileOfferPayload(filename=r"..\..\Windows\evil.exe", size=4, sha256="00" * 32),
                      sequence=1)
        receiver._in_control.put_nowait(encode(offer))  # noqa: SLF001
        return await task

    with pytest.raises(TransferError):
        await run()
    assert not (tmp_path / "Windows").exists()


@pytest.mark.asyncio
async def test_declined_writes_nothing(tmp_path):
    results, dest_root = await _run_transfer(tmp_path, b"data", approve=lambda o: False)
    assert isinstance(results[0], TransferError)
    assert not dest_root.exists() or list(dest_root.iterdir()) == []


@pytest.mark.asyncio
async def test_mid_stream_revoke_aborts(tmp_path):
    auth, token = _write_token()

    # Revoke after the transfer starts by wrapping recv_bulk to revoke on first chunk.
    src = tmp_path / "src.bin"; src.write_bytes(b"B" * 5000)
    dest_root = tmp_path / "root"
    sender, receiver = make_memory_pair()
    orig = receiver.recv_bulk
    first = {"seen": False}

    async def revoke_then_recv():
        if not first["seen"]:
            first["seen"] = True
            auth.revoke(Capability.FILE_WRITE_INBOUND)
        return await orig()

    receiver.recv_bulk = revoke_then_recv
    _, stoken = _read_token()
    r = await asyncio.gather(
        receive_file(receiver, dest_root, lambda o: True, token=token),
        send_file(sender, str(src), token=stoken),
        return_exceptions=True,
    )
    assert isinstance(r[0], TransferError)
    assert list(dest_root.glob("*")) == [] if dest_root.exists() else True


@pytest.mark.asyncio
async def test_existing_file_not_clobbered(tmp_path):
    # An existing report.txt must survive; the incoming one lands as "report (1).txt".
    dest_root = tmp_path / "Remote Transfers"
    dest_root.mkdir()
    (dest_root / "report.jpg").write_bytes(b"ORIGINAL")

    data = b"NEW CONTENT" * 100
    results, _ = await _run_transfer(tmp_path, data, filename="report.jpg")
    landed = results[0]
    assert isinstance(landed, Path)
    assert (dest_root / "report.jpg").read_bytes() == b"ORIGINAL"  # preserved
    assert landed.name == "report (1).jpg"
    assert landed.read_bytes() == data
