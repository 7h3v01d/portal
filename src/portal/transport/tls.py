# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""TLS-over-TCP transport (LAN).

Implements the Phase 0.2 transport interfaces. TLS (self-signed ephemeral certs)
provides confidentiality; the real Ed25519 identity is authenticated ABOVE TLS by
security.handshake, bound to the TLS channel so an active MITM is forced to
present its own key (which the pairing SAS then catches). A returned connection is
authenticated by construction: `peer_public_key` is always the 32-byte key the
handshake proved, or the connect/accept call raised.

Framing: every frame is `tag(1) || length(4, big-endian) || body`. `tag`
distinguishes the control and bulk channels. The length is checked against the
per-channel ceiling BEFORE the body is read, so a header claiming gigabytes is
refused before any large allocation. A single reader task demultiplexes frames
into per-channel queues.
"""

from __future__ import annotations

import asyncio
import ssl

from ..common.constants import (
    ACCEPT_QUEUE_MAX,
    BULK_QUEUE_MAX,
    CONN_CONCURRENT_PER_SOURCE,
    CONN_INFLIGHT_GLOBAL_MAX,
    CONN_RATE_PER_SOURCE,
    CONN_RATE_WINDOW_SECONDS,
    CONTROL_QUEUE_MAX,
    HANDSHAKE_TIMEOUT_SECONDS,
    MAX_BULK_FRAME_BYTES,
    MAX_CONTROL_MESSAGE_BYTES,
)
from ..common.errors import TransportError
from ..common.logging import get_logger
from ..security.handshake import ROLE_CLIENT, ROLE_SERVER, build_auth, verify_auth
from ..security.identity import Ed25519Identity
from .base import TransportConnection, TransportListener, TransportProvider
from .throttle import ConnectionThrottle
from .tls_certs import make_ephemeral_cert_files

_log = get_logger("transport.tls")

_TAG_CONTROL = 0
_TAG_BULK = 1
_LEN_PREFIX = 4
_AUTH_FRAME_MAX = 4096  # the auth handshake message is tiny


def _limit_for(tag: int) -> int:
    return MAX_CONTROL_MESSAGE_BYTES if tag == _TAG_CONTROL else MAX_BULK_FRAME_BYTES


async def _read_exactly(reader: asyncio.StreamReader, n: int) -> bytes:
    try:
        return await reader.readexactly(n)
    except (asyncio.IncompleteReadError, ConnectionError) as exc:
        raise TransportError("connection closed") from exc


async def _read_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    header = await _read_exactly(reader, 1 + _LEN_PREFIX)
    tag = header[0]
    length = int.from_bytes(header[1 : 1 + _LEN_PREFIX], "big")
    if tag not in (_TAG_CONTROL, _TAG_BULK):
        raise TransportError(f"unknown channel tag {tag}")
    if length > _limit_for(tag):  # ceiling BEFORE allocating/reading the body
        raise TransportError(f"frame length {length} exceeds limit for channel {tag}")
    body = await _read_exactly(reader, length) if length else b""
    return tag, body


def _encode_frame(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + len(body).to_bytes(_LEN_PREFIX, "big") + body


class TlsConnection(TransportConnection):
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_public_key: bytes,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._peer_public_key = peer_public_key
        # Bounded: an authenticated-but-untrusted peer must not be able to flood
        # memory by sending frames faster than we consume them.
        self._control: asyncio.Queue[bytes] = asyncio.Queue(maxsize=CONTROL_QUEUE_MAX)
        self._bulk: asyncio.Queue[bytes] = asyncio.Queue(maxsize=BULK_QUEUE_MAX)
        self._closed = False
        self._error: Exception | None = None
        self._closed_event = asyncio.Event()
        self._pump = asyncio.create_task(self._read_loop())

    @property
    def peer_public_key(self) -> bytes:
        return self._peer_public_key

    @property
    def is_connected(self) -> bool:
        return not self._closed

    async def _read_loop(self) -> None:
        try:
            while True:
                tag, body = await _read_frame(self._reader)
                if tag == _TAG_CONTROL:
                    try:
                        self._control.put_nowait(body)  # control should not back up
                    except asyncio.QueueFull:
                        raise TransportError("control queue overflow — closing connection")
                else:
                    # Bulk applies backpressure: awaiting a full queue stops us
                    # reading the socket, throttling the sender at the TCP layer.
                    await self._bulk.put(body)
        except Exception as exc:  # noqa: BLE001
            self._error = exc
        finally:
            self._mark_closed()

    def _mark_closed(self) -> None:
        # Death discards pending work: clear the queues so a consumer never
        # drains a backlog of privileged commands after the peer is gone, and
        # wake any waiter so it raises promptly.
        self._closed = True
        _drain(self._control)
        _drain(self._bulk)
        self._closed_event.set()

    async def _send(self, tag: int, data: bytes) -> None:
        if self._closed:
            raise TransportError("connection is closed")
        if len(data) > _limit_for(tag):
            raise TransportError(f"outbound frame exceeds limit for channel {tag}")
        self._writer.write(_encode_frame(tag, data))
        await self._writer.drain()

    async def _recv(self, queue: "asyncio.Queue[bytes]") -> bytes:
        # Discard-on-death: if the connection is already closed, raise rather than
        # serve a stale queued item.
        if self._closed:
            raise TransportError(self._error and str(self._error) or "connection closed")
        get_task = asyncio.ensure_future(queue.get())
        closed_task = asyncio.ensure_future(self._closed_event.wait())
        try:
            done, _pending = await asyncio.wait(
                {get_task, closed_task}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            for t in (get_task, closed_task):
                if not t.done():
                    t.cancel()
        if self._closed:
            raise TransportError(self._error and str(self._error) or "connection closed")
        return get_task.result()

    async def send_control(self, data: bytes) -> None:
        await self._send(_TAG_CONTROL, data)

    async def recv_control(self) -> bytes:
        return await self._recv(self._control)

    async def send_bulk(self, data: bytes) -> None:
        await self._send(_TAG_BULK, data)

    async def recv_bulk(self) -> bytes:
        return await self._recv(self._bulk)

    async def close(self) -> None:
        self._mark_closed()
        self._pump.cancel()
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


def _drain(queue: "asyncio.Queue") -> None:
    try:
        while True:
            queue.get_nowait()
    except asyncio.QueueEmpty:
        pass


async def _authenticate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    identity: Ed25519Identity,
    own_role: bytes,
    peer_role: bytes,
) -> bytes:
    """Run the channel-bound identity handshake over the established TLS channel.
    Returns the authenticated peer public key or raises TransportError."""
    ssl_obj = writer.get_extra_info("ssl_object")
    if ssl_obj is None:
        raise TransportError("no TLS layer on connection")
    channel_binding = ssl_obj.get_channel_binding("tls-unique")
    if not channel_binding:
        raise TransportError("TLS channel binding unavailable")

    import json

    msg = build_auth(identity, own_role, channel_binding)
    raw = json.dumps(msg).encode("utf-8")
    writer.write(_encode_frame(_TAG_CONTROL, raw))
    await writer.drain()

    try:
        tag, body = await asyncio.wait_for(_read_frame(reader), timeout=HANDSHAKE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        raise TransportError("peer did not complete authentication in time") from exc
    if tag != _TAG_CONTROL or len(body) > _AUTH_FRAME_MAX:
        raise TransportError("unexpected auth frame")
    try:
        peer_msg = json.loads(body)
        peer = verify_auth(peer_msg, peer_role, channel_binding)
    except Exception as exc:  # noqa: BLE001
        raise TransportError("peer authentication failed") from exc
    return peer.public_key


class TlsListener(TransportListener):
    def __init__(self, server: asyncio.AbstractServer, identity: Ed25519Identity, queue: asyncio.Queue) -> None:
        self._server = server
        self._identity = identity
        self._queue = queue

    async def accept(self) -> TransportConnection:
        conn = await self._queue.get()
        if isinstance(conn, Exception):
            raise conn
        return conn

    async def close(self) -> None:
        self._server.close()
        try:
            await self._server.wait_closed()
        except Exception:  # noqa: BLE001
            pass


class TlsTransport(TransportProvider):
    """Provider for both dialling out and listening."""

    def __init__(self, identity: Ed25519Identity) -> None:
        self._identity = identity

    async def connect(self, endpoint: str) -> TransportConnection:
        host, port = _parse_endpoint(endpoint)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # identity is authenticated above TLS, not here
        try:
            reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
        except OSError as exc:
            raise TransportError(f"connect failed: {exc}") from exc
        peer_key = await _authenticate(reader, writer, self._identity, ROLE_CLIENT, ROLE_SERVER)
        return TlsConnection(reader, writer, peer_key)

    async def listen(self, endpoint: str) -> TransportListener:
        host, port = _parse_endpoint(endpoint)
        cert_path, key_path = make_ephemeral_cert_files()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        ctx.verify_mode = ssl.CERT_NONE

        queue: asyncio.Queue = asyncio.Queue(maxsize=ACCEPT_QUEUE_MAX)
        throttle = ConnectionThrottle(
            per_source_rate=CONN_RATE_PER_SOURCE,
            window_seconds=CONN_RATE_WINDOW_SECONDS,
            per_source_concurrent=CONN_CONCURRENT_PER_SOURCE,
            global_in_flight=CONN_INFLIGHT_GLOBAL_MAX,
        )

        async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peername = writer.get_extra_info("peername")
            source = peername[0] if peername else "unknown"
            # Admission throttling: drop a flooding source before spending a
            # handshake on it. The slot is held only for the handshake window.
            admission = throttle.admit(source)
            if admission is None:
                _log.info("connection from %s throttled", source)
                try:
                    writer.close()
                except Exception:  # noqa: BLE001
                    pass
                return
            try:
                peer_key = await asyncio.wait_for(
                    _authenticate(reader, writer, self._identity, ROLE_SERVER, ROLE_CLIENT),
                    timeout=HANDSHAKE_TIMEOUT_SECONDS,
                )
                try:
                    queue.put_nowait(TlsConnection(reader, writer, peer_key))
                except asyncio.QueueFull:
                    _log.warning("accept queue full — dropping inbound connection")
                    writer.close()
            except Exception:  # noqa: BLE001 — a failed/slow handshake drops the socket
                _log.info("inbound connection failed authentication")
                try:
                    writer.close()
                except Exception:  # noqa: BLE001
                    pass
            finally:
                admission.release()  # free the in-flight slot once handshaking ends

        server = await asyncio.start_server(on_client, host, port, ssl=ctx)
        return TlsListener(server, self._identity, queue)


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    if ":" not in endpoint:
        raise TransportError(f"endpoint must be host:port, got {endpoint!r}")
    host, _, port = endpoint.rpartition(":")
    try:
        return host, int(port)
    except ValueError as exc:
        raise TransportError(f"bad port in endpoint {endpoint!r}") from exc
