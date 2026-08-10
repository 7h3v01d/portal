# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Device identity and trust.

Each installation has one long-term Ed25519 keypair. The **public key is the
identity**; the short device id is a human-facing label derived from it and is
NEVER the basis for an authorisation decision. Trust is pinned to the full key.

The short id keeps 64 bits of the key hash — lovely for a UI ("is this 8F42-…?")
but far too little to authorise against. So the trust API takes a full
DeviceIdentity and compares public keys with a constant-time check; you cannot
ask "do I trust this id string?" and have it mean anything security-relevant."""

from __future__ import annotations

import hashlib
import hmac
from abc import ABC, abstractmethod
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..common.errors import IdentityError

_ED25519_PUBLIC_LEN = 32


def _device_id_from_public_key(public_raw: bytes) -> str:
    """A stable, human-readable *label* from the public key: first 8 bytes of its
    SHA-256, hex, upper-cased, in 4-char groups (e.g. 8F42-A71E-...). For display
    and lookup only — never for authorisation."""
    digest = hashlib.sha256(public_raw).hexdigest().upper()
    head = digest[:16]
    return "-".join(head[i : i + 4] for i in range(0, 16, 4))


def device_id_for(public_key: bytes) -> str:
    """Public wrapper: the canonical display id for a public key. Always derive a
    peer's id from its authenticated key with this — never trust a peer-supplied
    id string."""
    return _device_id_from_public_key(public_key)


@dataclass(frozen=True)
class DeviceIdentity:
    """The public half of a device's identity — safe to share and display.

    The public key is authoritative and is validated as canonical 32-byte
    Ed25519 material at construction, so no path (pairing, store load, wire) can
    ever produce or persist an identity backed by a malformed key."""

    device_id: str
    device_name: str
    public_key: bytes  # raw 32-byte Ed25519 public key — the authoritative identity

    def __post_init__(self) -> None:
        if not isinstance(self.public_key, (bytes, bytearray)):
            raise IdentityError(
                f"public_key must be bytes, got {type(self.public_key).__name__}"
            )
        if len(self.public_key) != _ED25519_PUBLIC_LEN:
            raise IdentityError(
                f"public_key must be {_ED25519_PUBLIC_LEN} bytes, got {len(self.public_key)}"
            )

    def fingerprint(self) -> str:
        """Full SHA-256 of the public key, for the 'is this really Dad's PC?'
        confirmation during pairing."""
        return hashlib.sha256(self.public_key).hexdigest().upper()

    @classmethod
    def from_public_key(cls, public_key: bytes, device_name: str) -> "DeviceIdentity":
        """Build a peer identity from its authenticated public key, deriving the
        id locally. Rejects anything that is not a 32-byte key (via __post_init__).
        The name is an untrusted display hint supplied by the peer."""
        if not isinstance(public_key, (bytes, bytearray)):
            raise IdentityError(
                f"public_key must be bytes, got {type(public_key).__name__}"
            )
        return cls(
            device_id=_device_id_from_public_key(bytes(public_key)),
            device_name=device_name,
            public_key=bytes(public_key),
        )


def verify_pinned(peer_public_key: bytes | None, trusted: DeviceIdentity) -> bool:
    """The authorisation primitive: True iff the key the transport actually
    authenticated equals the pinned trusted key, byte-for-byte, in constant time.

    This is the invariant that keeps 'TLS connected' from ever meaning 'trusted
    Portal device'. No capability is granted unless this returns True."""
    if not isinstance(peer_public_key, (bytes, bytearray)):
        return False
    if len(peer_public_key) != _ED25519_PUBLIC_LEN:
        return False
    return hmac.compare_digest(bytes(peer_public_key), trusted.public_key)


class Ed25519Identity:
    """Wraps a private key with generate / sign / verify."""

    __slots__ = ("_private", "identity")

    def __init__(self, private_key: Ed25519PrivateKey, device_name: str) -> None:
        self._private = private_key
        public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.identity = DeviceIdentity(
            device_id=_device_id_from_public_key(public_raw),
            device_name=device_name,
            public_key=public_raw,
        )

    @classmethod
    def generate(cls, device_name: str) -> "Ed25519Identity":
        return cls(Ed25519PrivateKey.generate(), device_name)

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    @staticmethod
    def verify(public_key: bytes, data: bytes, signature: bytes) -> bool:
        """True iff `signature` is valid for `data` under `public_key`. False on
        a bad signature; IdentityError on malformed key material."""
        try:
            key = Ed25519PublicKey.from_public_bytes(public_key)
        except Exception as exc:
            raise IdentityError(f"invalid public key: {exc}") from exc
        try:
            key.verify(signature, data)
            return True
        except InvalidSignature:
            return False


class IdentityStore(ABC):
    """Persistence for this device's own identity and the set of trusted peers.

    Trust is keyed on the full public key. `is_trusted` and `get_trusted_peer`
    take/return full DeviceIdentity records; there is deliberately no
    `is_trusted(device_id: str)` that would authorise on the 64-bit label.

    Concrete on-disk implementation (encrypted store, trust list, revocation) is
    Phase 2; the interface is fixed now so nothing depends on a concrete store."""

    @abstractmethod
    def load_or_create(self, device_name: str) -> Ed25519Identity:
        """Return this installation's identity, creating it on first run."""

    @abstractmethod
    def trust(self, peer: DeviceIdentity) -> None:
        """Record a peer as trusted, after the user confirms its fingerprint."""

    @abstractmethod
    def revoke(self, public_key: bytes) -> None:
        """Remove a peer from the trusted set, by full public key."""

    @abstractmethod
    def is_trusted(self, peer: DeviceIdentity) -> bool:
        """True iff a trusted record exists whose public key equals peer's."""

    @abstractmethod
    def get_trusted_peer(self, device_id: str) -> DeviceIdentity | None:
        """Look up a trusted record by its display id. The caller must still
        confirm the full key (verify_pinned) before authorising — this is a
        lookup convenience, not an authorisation."""

    @abstractmethod
    def list_trusted(self) -> list[DeviceIdentity]:
        ...
