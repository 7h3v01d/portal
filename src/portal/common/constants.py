# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Shared constants. Anything a security gate depends on lives here so the limits
are auditable in one place rather than scattered as magic numbers."""

from __future__ import annotations

APP_NAME = "Portal"
ORG_NAME = "Leon Priest"

# --- Protocol -------------------------------------------------------------
PROTOCOL_VERSION = 1

# Hard ceiling on a single decoded control message. Control messages are small
# by design; anything larger is rejected before parsing. File *payloads* never
# ride inside a control envelope — they go through the bulk channel as chunks.
MAX_CONTROL_MESSAGE_BYTES = 64 * 1024  # 64 KiB

# Maximum structural nesting depth we will decode. Portal messages are shallow
# (envelope -> payload -> a list of scalars = depth 3); a deeply nested blob is a
# cheap crash primitive (RecursionError), so we reject before parsing.
MAX_JSON_DEPTH = 16

# Transport resource bounds. Individual frames are size-capped, but the *number*
# of buffered frames must be bounded too, or an authenticated-but-untrusted peer
# can flood memory before any trust check runs.
CONTROL_QUEUE_MAX = 64        # control frames buffered; overflow = violation -> close
BULK_QUEUE_MAX = 8            # bulk frames buffered; overflow applies backpressure
ACCEPT_QUEUE_MAX = 16         # pending authenticated connections awaiting accept()
HANDSHAKE_TIMEOUT_SECONDS = 10.0  # a peer must complete the auth handshake within this

# Connection admission throttling (Gate 3.1). Defaults tuned for a LAN family
# tool: generous for a real user, tight enough to blunt a flood.
CONN_RATE_PER_SOURCE = 20        # new connections per source per window
CONN_RATE_WINDOW_SECONDS = 10.0
CONN_CONCURRENT_PER_SOURCE = 5   # simultaneous in-handshake connections per source
CONN_INFLIGHT_GLOBAL_MAX = 64    # global cap on connections currently handshaking

# Pairing attempt scoping (Gate 3.1). A single source gets a small budget of wrong
# guesses; a global backstop bounds a distributed attempt. Neither lets one source
# burn a legitimate pairing.
PAIR_ATTEMPTS_PER_SOURCE = 5
PAIR_ATTEMPTS_GLOBAL_MAX = 50

# Per-field wire limits. The 64 KiB envelope ceiling is not enough on its own —
# a hostile peer could still send one field that is 60 KiB of garbage. These cap
# the individual fields a strict model can't otherwise bound.
MAX_SEQUENCE = 2**53 - 1  # stays exact through any JSON double, for other clients
MAX_SESSION_ID_LEN = 128
MAX_DEVICE_NAME_LEN = 64
MAX_DEVICE_ID_LEN = 128
MAX_CAPABILITY_LIST_LEN = 16
MAX_ERROR_CODE_LEN = 64
MAX_ERROR_DETAIL_LEN = 512

# --- File transfer --------------------------------------------------------
DEFAULT_CHUNK_BYTES = 256 * 1024  # 256 KiB per file chunk (rides the bulk channel)
# Hard ceiling a bulk-channel frame may be before the transport allocates for it.
# One chunk plus framing overhead — a length header claiming gigabytes must be
# refused before any buffer is allocated.
MAX_BULK_FRAME_BYTES = DEFAULT_CHUNK_BYTES + 4 * 1024
DEFAULT_TRANSFER_SUBDIR = "Remote Transfers"
PART_SUFFIX = ".part"

# Windows MAX_PATH component limit is 255; keep received names comfortably under.
MAX_FILENAME_LEN = 255
