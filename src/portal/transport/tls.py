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
from collections import deque

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
    VIDEO_QUEUE_MAX,
)
from ..common.errors import TransportError
from ..common.logging import get_logger
from ..security.handshake import ROLE_CLIENT, ROLE_SERVER, build_auth, verify_auth
from ..security.identity import Ed25519Identity
from .base import TransportConnection, TransportListener, TransportProvider, VideoReceipt
from .throttle import ConnectionThrottle
from .tls_certs import make_ephemeral_cert_files

_log = get_logger("transport.tls")

_TAG_CONTROL = 0
_TAG_BULK = 1
_TAG_VIDEO = 2
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
    if tag not in (_TAG_CONTROL, _TAG_BULK, _TAG_VIDEO):
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
        # Video is LOSSY: a bounded drop-oldest buffer the reader never blocks on,
        # so a slow/absent video consumer can never starve the control plane (A4a).
        # Each frame carries a monotonic sequence assigned on receipt, so the
        # consumer can detect drop-oldest gaps (A4d) and resync the decoder.
        self._video: deque[tuple[int, bytes]] = deque(maxlen=VIDEO_QUEUE_MAX)
        self._video_seq = 0
        self._video_last_delivered: int | None = None
        self._video_available = asyncio.Event()
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
                elif tag == _TAG_VIDEO:
                    # Never block on video: drop-oldest. This is the A4a guarantee —
                    # a slow video consumer cannot suspend the reader and thereby
                    # starve control-plane frames. The sequence number lets the
                    # consumer detect any dropped frames and resync (A4d).
                    self._video.append((self._video_seq, body))
                    self._video_seq += 1
                    self._video_available.set()
                else:
                    # File bulk is reliable: backpressure the sender at the TCP
                    # layer by awaiting a full queue. (During screen sharing there
                    # is no concurrent file bulk, so the reader never blocks and
                    # control is never starved; concurrent saturating file + control
                    # is addressed by the future per-stream transport split.)
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
        self._video.clear()
        self._video_available.set()
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

    async def send_video(self, data: bytes) -> None:
        await self._send(_TAG_VIDEO, data)

    async def recv_video(self) -> "VideoReceipt":
        """Return the next available video frame plus how many frames were dropped
        (drop-oldest) before it, so the consumer can resync a broken H.264 chain."""
        while True:
            if self._closed:
                raise TransportError(self._error and str(self._error) or "connection closed")
            if self._video:
                seq, body = self._video.popleft()
                # Report any gap since the last delivered frame. For the very
                # first delivery, the baseline is "before frame 0", so frames the
                # buffer dropped before we started consuming are still counted —
                # nothing is silently lost from the accounting.
                baseline = -1 if self._video_last_delivered is None else self._video_last_delivered
                dropped = seq - baseline - 1
                self._video_last_delivered = seq
                return VideoReceipt(data=body, dropped=dropped)
            self._video_available.clear()
            wait_task = asyncio.ensure_future(self._video_available.wait())
            closed_task = asyncio.ensure_future(self._closed_event.wait())
            try:
                await asyncio.wait({wait_task, closed_task}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for t in (wait_task, closed_task):
                    if not t.done():
                        t.cancel()

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


def _select_channel_binding(ssl_obj) -> tuple[str, bytes]:
    """Choose the strongest available channel binding for THIS connection.

    RFC 9266 defines `tls-exporter` as the channel binding for TLS 1.3 and
    deprecates `tls-unique` there. We PREFER tls-exporter whenever the runtime can
    produce it (CPython 3.13+ exposes it via get_channel_binding); otherwise we
    fall back to tls-unique, which CPython still computes for TLS 1.3 as the
    Finished MAC — functional and unique per connection, but not standardised, so
    we log a warning. Binding the chosen TYPE into the signed transcript (see
    handshake.py) keeps the construction explicit and upgradeable rather than
    silently frozen: the day the rig moves to a runtime with tls-exporter, both
    peers negotiate to it with no wire change beyond the already-present type."""
    available = getattr(ssl, "CHANNEL_BINDING_TYPES", ("tls-unique",))
    if "tls-exporter" in available:
        value = ssl_obj.get_channel_binding("tls-exporter")
        if value:
            return "tls-exporter", value
    # Fallback.
    value = ssl_obj.get_channel_binding("tls-unique")
    if not value:
        raise TransportError("TLS channel binding unavailable")
    version = None
    try:
        version = ssl_obj.version()
    except Exception:  # noqa: BLE001
        pass
    if version == "TLSv1.3":
        _log.warning(
            "using non-standard tls-unique channel binding on TLS 1.3 "
            "(runtime lacks tls-exporter; RFC 9266 prefers tls-exporter) — "
            "functional but upgrade the runtime to freeze on the standard binding"
        )
    return "tls-unique", value


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
    binding_type, channel_binding = _select_channel_binding(ssl_obj)

    import json

    msg = build_auth(identity, own_role, binding_type, channel_binding)
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
        peer = verify_auth(peer_msg, peer_role, binding_type, channel_binding)
    except Exception as exc:  # noqa: BLE001
        raise TransportError("peer authentication failed") from exc
    return peer.public_key


class TlsListener(TransportListener):
    def __init__(self, lsock, accept_task, inflight, identity: Ed25519Identity, queue: asyncio.Queue) -> None:
        self._lsock = lsock
        self._accept_task = accept_task
        self._inflight = inflight
        self._identity = identity
        self._queue = queue
        self._closed = False

    @property
    def sockname(self):
        """The bound (host, port) — tests read the ephemeral port from here."""
        return self._lsock.getsockname()

    async def accept(self) -> TransportConnection:
        conn = await self._queue.get()
        if isinstance(conn, Exception):
            raise conn
        return conn

    async def close(self) -> None:
        # Own the full lifecycle: after close() returns, this listener holds no
        # live connection — the accept loop is stopped, in-flight handshakes are
        # cancelled, queued-but-unaccepted connections are closed, and the
        # listening socket is shut.
        self._closed = True
        self._accept_task.cancel()
        try:
            await self._accept_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        # Cancel in-flight handshake tasks (a stalled TLS peer would otherwise
        # linger until its handshake timeout).
        for t in list(self._inflight):
            t.cancel()
        for t in list(self._inflight):
            try:
                await t
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        # Close any authenticated connections that reached the queue but were
        # never accept()ed by the application.
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if not isinstance(item, Exception):
                try:
                    await item.close()
                except Exception:  # noqa: BLE001
                    pass
        try:
            self._lsock.close()
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
            reader, writer = await asyncio.open_connection(
                host, port, ssl=ctx, ssl_handshake_timeout=HANDSHAKE_TIMEOUT_SECONDS
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise TransportError(f"connect failed: {exc}") from exc
        peer_key = await _authenticate(reader, writer, self._identity, ROLE_CLIENT, ROLE_SERVER)
        return TlsConnection(reader, writer, peer_key)

    async def listen(self, endpoint: str) -> TransportListener:
        import socket

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
        loop = asyncio.get_event_loop()
        inflight: set[asyncio.Task] = set()

        # Manage the listening socket ourselves so we can admit a RAW accepted
        # socket BEFORE any TLS work, then hand only admitted sockets to asyncio
        # with SSL via connect_accepted_socket. This avoids a STARTTLS-style
        # upgrade entirely (no start_tls / manual StreamWriter reconstruction,
        # which tangled stream ownership and dropped connections), and is the
        # implementation that behaves predictably on the Python 3.11 target.
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((host or "0.0.0.0", port))
        lsock.listen(ACCEPT_QUEUE_MAX)
        lsock.setblocking(False)

        async def handle(raw_sock, source, admission) -> None:
            try:
                reader = asyncio.StreamReader(loop=loop)
                protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
                # connect_accepted_socket performs the TLS handshake on the already
                # accepted socket, bounded by ssl_handshake_timeout, and yields a
                # clean transport/protocol pair we wrap into stream reader/writer.
                transport, _ = await loop.connect_accepted_socket(
                    lambda: protocol, raw_sock, ssl=ctx,
                    ssl_handshake_timeout=HANDSHAKE_TIMEOUT_SECONDS,
                )
                writer = asyncio.StreamWriter(transport, protocol, reader, loop)
                peer_key = await asyncio.wait_for(
                    _authenticate(reader, writer, self._identity, ROLE_SERVER, ROLE_CLIENT),
                    timeout=HANDSHAKE_TIMEOUT_SECONDS,
                )
                try:
                    queue.put_nowait(TlsConnection(reader, writer, peer_key))
                except asyncio.QueueFull:
                    _log.warning("accept queue full — dropping inbound connection")
                    _hard_close(writer)
            except Exception:  # noqa: BLE001 — failed/slow TLS or auth drops the socket
                _log.info("inbound connection failed TLS/authentication")
                try:
                    raw_sock.close()
                except Exception:  # noqa: BLE001
                    pass
            finally:
                admission.release()

        async def accept_loop() -> None:
            while True:
                try:
                    raw_sock, addr = await loop.sock_accept(lsock)
                except (asyncio.CancelledError, OSError):
                    return
                source = addr[0] if addr else "unknown"
                raw_sock.setblocking(False)
                # ADMIT BEFORE TLS. A raw / no-ClientHello flooder is counted and
                # dropped here, never occupying a TLS handshake slot.
                admission = throttle.admit(source)
                if admission is None:
                    _log.info("connection from %s throttled (pre-TLS)", source)
                    try:
                        raw_sock.close()
                    except Exception:  # noqa: BLE001
                        pass
                    continue
                t = asyncio.create_task(handle(raw_sock, source, admission))
                inflight.add(t)
                t.add_done_callback(inflight.discard)

        accept_task = asyncio.create_task(accept_loop())
        return TlsListener(lsock, accept_task, inflight, self._identity, queue)


def _hard_close(writer) -> None:
    """Close a writer/transport, ignoring errors. Safe to call more than once."""
    try:
        writer.close()
    except Exception:  # noqa: BLE001
        pass


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    if ":" not in endpoint:
        raise TransportError(f"endpoint must be host:port, got {endpoint!r}")
    host, _, port = endpoint.rpartition(":")
    try:
        return host, int(port)
    except ValueError as exc:
        raise TransportError(f"bad port in endpoint {endpoint!r}") from exc
