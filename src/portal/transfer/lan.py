# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""LAN file transfer engine.

Sender: offer(path) -> stream chunks over the bulk channel -> end marker.
Receiver: validate the offer -> approve (attended) -> validate the filename ->
write to a race-safe <name>.part -> verify SHA-256 -> atomically rename into a
non-clobbering destination.

Authority: BOTH sides require a capability-bound token, and the RIGHT capability
— a token is not merely present-and-valid, it must be for the specific operation.
receive_file needs FILE_WRITE_INBOUND; send_file needs FILE_READ_OUTBOUND. This
is the authority wrapper the capability model depends on; without it a token for
an unrelated capability (e.g. screen.publish) could authorise a file write.

Wire: the offer/accept/reject cross the control channel as strict Portal codec
messages (FILE_OFFER / FILE_ACCEPT / FILE_REJECT), not ad-hoc JSON — same no-
coercion discipline as the rest of the protocol. Chunks are raw bytes on the bulk
channel; a zero-length bulk frame marks end-of-stream.

Containment: the receiver fixes the root and validates the bare filename
(lexical containment). The <name>.part is opened O_EXCL (+ O_NOFOLLOW where the
platform supports it) so a pre-planted symlink can't redirect the write and an
existing part is never clobbered. NOTE: on Windows, O_NOFOLLOW is a no-op; native
reparse-point-proof handle validation is a tracked follow-up, so the current
guarantee there is lexical containment + exclusive create, not reparse-proof.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Awaitable, Callable

from ..common.constants import DEFAULT_CHUNK_BYTES, PART_SUFFIX
from ..common.errors import PermissionDeniedError, TransferError, UnsafePathError
from ..common.logging import get_logger
from ..protocol.capabilities import Capability
from ..protocol.codec import build, decode, encode
from ..protocol.messages import EmptyPayload, FileOfferPayload, MessageType
from ..security.authority import CancellationToken
from ..security.validation import resolve_within, sanitize_filename
from ..transport.base import TransportConnection

_log = get_logger("transfer.lan")


def _require_capability(token: CancellationToken, expected: Capability) -> None:
    """Fail-closed authority gate: the token must be for exactly `expected` AND
    still valid. Checked before anything touches the network or disk."""
    if token.capability is not expected:
        raise PermissionDeniedError(
            f"transfer requires {expected}, got a token for {token.capability}"
        )
    if not token.valid:
        raise PermissionDeniedError(f"capability {expected} is not currently authorised")


async def _recv_bulk_or_revoked(conn: TransportConnection, token: CancellationToken) -> bytes | None:
    """await recv_bulk, but abort promptly if the token is revoked — so a revoke
    terminates the receive even if the (now-untrusted) peer sends nothing more.
    Returns the chunk, or None if revoked while waiting."""
    import asyncio

    recv = asyncio.ensure_future(conn.recv_bulk())
    rev = asyncio.ensure_future(token.wait_invalid())
    try:
        done, _pending = await asyncio.wait({recv, rev}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (recv, rev):
            if not t.done():
                t.cancel()
    if recv in done and token.valid:
        return recv.result()
    return None


def _hash_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(DEFAULT_CHUNK_BYTES)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


async def send_file(conn: TransportConnection, path: str, token: CancellationToken) -> None:
    """Sender side. Requires a FILE_READ_OUTBOUND token."""
    _require_capability(token, Capability.FILE_READ_OUTBOUND)

    p = Path(path)
    if not p.is_file():
        raise TransferError(f"not a file: {path}")
    sha256, size = _hash_file(p)

    offer = build(
        MessageType.FILE_OFFER,
        FileOfferPayload(filename=p.name, size=size, sha256=sha256),
        sequence=1,
    )
    await conn.send_control(encode(offer))

    decision = decode(await conn.recv_control())
    if decision.type is not MessageType.FILE_ACCEPT:
        raise TransferError("receiver rejected the transfer")

    with open(p, "rb") as fh:
        while True:
            if not token.valid:
                await conn.send_bulk(b"")  # terminate; receiver aborts
                raise TransferError("transfer authority revoked")
            chunk = fh.read(DEFAULT_CHUNK_BYTES)
            if not chunk:
                break
            await conn.send_bulk(chunk)
    await conn.send_bulk(b"")  # end-of-stream marker


ApproveFn = Callable[[FileOfferPayload], "bool | Awaitable[bool]"]


async def receive_file(
    conn: TransportConnection,
    transfer_root: str | Path,
    approve: ApproveFn,
    token: CancellationToken,
) -> Path:
    """Receiver side. Requires a FILE_WRITE_INBOUND token. Returns the final path."""
    _require_capability(token, Capability.FILE_WRITE_INBOUND)

    root = Path(transfer_root)
    root.mkdir(parents=True, exist_ok=True)

    msg = decode(await conn.recv_control())
    if msg.type is not MessageType.FILE_OFFER:
        raise TransferError(f"expected FILE_OFFER, got {msg.type}")
    offer: FileOfferPayload = msg.payload

    try:
        safe_name = sanitize_filename(offer.filename)
    except UnsafePathError as exc:
        await conn.send_control(encode(build(MessageType.FILE_REJECT, EmptyPayload(), sequence=1)))
        raise TransferError(f"unsafe filename: {exc}") from exc

    approved = approve(offer)
    if hasattr(approved, "__await__"):
        approved = await approved  # type: ignore[assignment]
    if not approved:
        await conn.send_control(encode(build(MessageType.FILE_REJECT, EmptyPayload(), sequence=1)))
        raise TransferError("transfer declined by receiver")

    # Non-clobbering destination: never silently replace an existing file.
    final_path = _unique_destination(resolve_within(root, safe_name))
    part_path = _unique_part(final_path.with_name(final_path.name + PART_SUFFIX))

    await conn.send_control(encode(build(MessageType.FILE_ACCEPT, EmptyPayload(), sequence=1)))

    h = hashlib.sha256()
    written = 0
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(part_path, flags, 0o600)
    except OSError as exc:
        raise TransferError(f"could not open destination: {exc}") from exc

    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                # Race the receive against revocation: a revoke both prevents the
                # write (side-effect safety) AND terminates the operation without
                # needing the untrusted peer to send anything (liveness).
                chunk = await _recv_bulk_or_revoked(conn, token)
                if chunk is None:
                    raise TransferError("transfer authority revoked")
                if chunk == b"":  # end-of-stream
                    break
                # Belt-and-braces: re-check before the privileged write in case the
                # race resolved to a chunk in the same tick a revoke landed.
                if not token.valid:
                    raise TransferError("transfer authority revoked")
                written += len(chunk)
                if written > offer.size:
                    raise TransferError("sender exceeded declared size")
                h.update(chunk)
                out.write(chunk)

        if written != offer.size:
            raise TransferError(f"size mismatch: got {written}, expected {offer.size}")
        if h.hexdigest() != offer.sha256:
            raise TransferError("hash mismatch — file discarded")

        os.replace(part_path, final_path)  # verified; atomic
        _log.info("received and verified %s (%d bytes)", final_path.name, written)
        return final_path
    except BaseException:
        try:
            os.unlink(part_path)
        except OSError:
            pass
        raise


def _unique_destination(final_path: Path) -> Path:
    """report.txt -> report (1).txt -> report (2).txt so an existing file is
    never silently overwritten. (Small TOCTOU between check and rename remains;
    atomic no-clobber rename is a tracked follow-up.)"""
    if not final_path.exists():
        return final_path
    stem, suffix = final_path.stem, final_path.suffix
    i = 1
    while True:
        cand = final_path.with_name(f"{stem} ({i}){suffix}")
        if not cand.exists():
            return cand
        i += 1


def _unique_part(part_path: Path) -> Path:
    if not part_path.exists():
        return part_path
    i = 1
    while True:
        cand = part_path.with_name(f"{part_path.name}.{i}")
        if not cand.exists():
            return cand
        i += 1
