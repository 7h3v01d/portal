# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Error hierarchy. A single root (`PortalError`) so callers can catch broadly at
boundaries, with specific subclasses so the protocol/security layers can be
precise about *why* they rejected something — which matters for the audit log
and for the Phase 17 adversarial pass."""

from __future__ import annotations


class PortalError(Exception):
    """Root of every deliberate error Portal raises."""


# --- Protocol / wire ------------------------------------------------------
class ProtocolError(PortalError):
    """Base for anything wrong with a message on the wire."""


class MessageTooLargeError(ProtocolError):
    """Raw message exceeded the size ceiling; rejected before parsing."""


class DecodeError(ProtocolError):
    """Message could not be parsed or failed structural validation."""


class UnknownMessageTypeError(ProtocolError):
    """Message declared a type that is not in the known MessageType set."""


class UnimplementedMessageTypeError(ProtocolError):
    """Message declared a type that exists in the enum but has no active payload
    schema registered. Fail-closed: a future/reserved operation is rejected until
    its contract is deliberately registered — knowing the enum member exists is
    not enough to let it cross the trust boundary."""


class UnsupportedVersionError(ProtocolError):
    """Message declared a protocol version we will not decode."""


# --- Security -------------------------------------------------------------
class SecurityError(PortalError):
    """Base for authority / identity / validation failures."""


class PermissionDeniedError(SecurityError):
    """An action was attempted without the required capability granted."""


class IdentityError(SecurityError):
    """Key generation, signing, or verification failed."""


class UnsafePathError(SecurityError):
    """A filename or destination failed containment validation."""


# --- Subsystems -----------------------------------------------------------
class TransportError(PortalError):
    """Connection-layer failure (connect/send/recv/close)."""


class TransferError(PortalError):
    """File-transfer state-machine failure."""


class CaptureError(PortalError):
    """Screen-capture backend failure."""


class InputError(PortalError):
    """Input-injection backend failure."""
