# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""The whole Phase 3 stack composed: a file transferred over the real TLS
transport with channel-bound authentication, verified end to end."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

from portal.protocol.capabilities import Capability
from portal.security.authority import SessionAuthority
from portal.security.identity import Ed25519Identity
from portal.transfer.lan import receive_file, send_file
from portal.transport.tls import TlsTransport


@pytest.mark.asyncio
async def test_file_transfer_over_tls(tmp_path):
    host = Ed25519Identity.generate("Dad")
    ctrl = Ed25519Identity.generate("Leon")

    listener = await TlsTransport(host).listen("127.0.0.1:0")
    port = listener._server.sockets[0].getsockname()[1]  # noqa: SLF001

    data = bytes(range(256)) * 4096  # 1 MiB, all byte values
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    dest_root = tmp_path / "Remote Transfers"

    accept_task = asyncio.create_task(listener.accept())
    client_conn = await TlsTransport(ctrl).connect(f"127.0.0.1:{port}")
    server_conn = await accept_task

    # Host is the receiver; controller sends. Each holds the right capability.
    rauth = SessionAuthority(); rauth.grant(Capability.FILE_WRITE_INBOUND)
    sauth = SessionAuthority(); sauth.grant(Capability.FILE_READ_OUTBOUND)
    recv_task = asyncio.create_task(
        receive_file(server_conn, dest_root, approve=lambda o: True,
                     token=rauth.authorize(Capability.FILE_WRITE_INBOUND))
    )
    send_task = asyncio.create_task(
        send_file(client_conn, str(src), token=sauth.authorize(Capability.FILE_READ_OUTBOUND))
    )

    landed, _ = await asyncio.gather(recv_task, send_task)
    try:
        assert isinstance(landed, Path)
        assert hashlib.sha256(landed.read_bytes()).hexdigest() == hashlib.sha256(data).hexdigest()
        assert landed.read_bytes() == data
    finally:
        await client_conn.close()
        await server_conn.close()
        await listener.close()
