# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""On-disk IdentityStore.

Persists this installation's Ed25519 identity and the set of trusted peers.
Trust is keyed on the **full public key**, never the short display id.

Files under `base_dir`:
  identity.pem   — this device's private key (PKCS8 PEM; passphrase-encrypted if
                   a passphrase is supplied, else written owner-only in plaintext
                   with a logged warning)
  device.json    — this device's chosen display name
  trusted.json   — trusted peers: device_id, name, public_key(hex), added_at

At-rest hardening notes (tracked follow-ups, not silently assumed):
  - Passphrase encryption is the real protection for the private key. When absent
    we fall back to a 0o600 file and a warning; OS-native protection (Windows
    DPAPI / a keyring) is the intended next step.
  - chmod(0o600) is best-effort; on Windows it does not fully restrict ACLs. A
    proper Windows ACL lockdown is a follow-up.

All writes are atomic (write temp, fsync, os.replace) so a crash mid-write can
never leave a half-written key or trust file.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..common.errors import IdentityError
from ..common.logging import get_logger
from .identity import DeviceIdentity, Ed25519Identity, IdentityStore, verify_pinned

_log = get_logger("security.store")

# Locks are shared by RESOLVED storage directory, not by store instance — two
# FileIdentityStore objects pointing at the same directory in one process must
# serialise against each other, or a concurrent trust()/revoke() can resurrect
# revoked trust. (Cross-process locking via a filesystem lock is a documented
# follow-up for when Portal runs as a service.)
_DIR_LOCKS_GUARD = threading.Lock()
_DIR_LOCKS: dict[str, threading.RLock] = {}


def _lock_for(resolved_dir: str) -> threading.RLock:
    with _DIR_LOCKS_GUARD:
        lock = _DIR_LOCKS.get(resolved_dir)
        if lock is None:
            lock = threading.RLock()
            _DIR_LOCKS[resolved_dir] = lock
        return lock


def _atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    # Unique temp file in the same directory, then atomic replace. A unique name
    # (not a fixed .tmp) is safe even if multiple writers ever coexist.
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, mode)  # best-effort; limited on Windows
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class FileIdentityStore(IdentityStore):
    def __init__(self, base_dir: str | Path, passphrase: str | None = None) -> None:
        self._dir = Path(base_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._passphrase = passphrase.encode() if passphrase else None
        self._key_path = self._dir / "identity.pem"
        self._device_path = self._dir / "device.json"
        self._trusted_path = self._dir / "trusted.json"
        # Shared by resolved directory so all instances for the same store
        # serialise their read-modify-write against each other.
        self._lock = _lock_for(str(self._dir.resolve()))

    # --- this device's identity ------------------------------------------
    def load_or_create(self, device_name: str) -> Ed25519Identity:
        with self._lock:
            if self._key_path.exists():
                private = self._load_private_key()
                name = self._load_device_name(default=device_name)
                return Ed25519Identity(private, name)

            identity = Ed25519Identity.generate(device_name)
            self._save_private_key(identity)
            self._save_device_name(device_name)
            if self._passphrase is None:
                _log.warning(
                    "device private key written without a passphrase; enable "
                    "passphrase or OS-native protection before real deployment"
                )
            return identity

    def _load_private_key(self) -> Ed25519PrivateKey:
        data = self._key_path.read_bytes()
        try:
            key = serialization.load_pem_private_key(data, password=self._passphrase)
        except (ValueError, TypeError) as exc:
            # Wrong/missing passphrase or corrupt file — do not leak which.
            raise IdentityError("could not load device private key") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise IdentityError("stored key is not an Ed25519 private key")
        return key

    def _save_private_key(self, identity: Ed25519Identity) -> None:
        encryption = (
            serialization.BestAvailableEncryption(self._passphrase)
            if self._passphrase
            else serialization.NoEncryption()
        )
        pem = identity._private.private_bytes(  # noqa: SLF001 (owner of the key)
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        _atomic_write_bytes(self._key_path, pem, mode=0o600)

    def _load_device_name(self, default: str) -> str:
        try:
            doc = json.loads(self._device_path.read_text("utf-8"))
        except (OSError, ValueError):
            return default
        # Must be an object with a string device_name that passes the display-text
        # gate; anything else (corruption/tampering) falls back to the default.
        if not isinstance(doc, dict):
            return default
        name = doc.get("device_name")
        if not isinstance(name, str) or not name:
            return default
        try:
            from .validation import ensure_display_text

            return ensure_display_text(name)[:64]
        except Exception:
            return default

    def _save_device_name(self, device_name: str) -> None:
        _atomic_write_bytes(
            self._device_path,
            json.dumps({"device_name": device_name}).encode("utf-8"),
            mode=0o600,
        )

    # --- trusted peers (keyed on full public key) ------------------------
    def _load_trusted(self) -> list[DeviceIdentity]:
        try:
            rows = json.loads(self._trusted_path.read_text("utf-8"))
        except (OSError, ValueError):
            return []
        # Fail closed: a corrupted/tampered trust database means trust nobody,
        # not raise. Valid JSON that isn't a list (123, null, true, "x") is
        # exactly such corruption.
        if not isinstance(rows, list):
            _log.warning("trusted.json is not a list; treating as empty (trust nobody)")
            return []
        out: list[DeviceIdentity] = []
        for row in rows:
            try:
                public_key = bytes.fromhex(row["public_key"])
                # Public key is authoritative: derive the id from it rather than
                # trusting the stored device_id, and reject any row whose key is
                # not canonical 32-byte material (DeviceIdentity validates length).
                out.append(
                    DeviceIdentity.from_public_key(
                        public_key, device_name=str(row.get("device_name", ""))
                    )
                )
            except (KeyError, ValueError, TypeError, IdentityError):
                continue  # skip malformed rows rather than trusting them
        return out

    def _save_trusted(self, peers: list[DeviceIdentity]) -> None:
        rows = [
            {
                "device_id": p.device_id,
                "device_name": p.device_name,
                "public_key": p.public_key.hex(),
                "added_at": int(time.time()),
            }
            for p in sorted(peers, key=lambda p: p.public_key.hex())
        ]
        _atomic_write_bytes(
            self._trusted_path, json.dumps(rows, indent=2).encode("utf-8"), mode=0o600
        )

    def trust(self, peer: DeviceIdentity) -> None:
        with self._lock:
            peers = self._load_trusted()
            if any(verify_pinned(peer.public_key, existing) for existing in peers):
                return  # already trusted (idempotent, keyed on full key)
            peers.append(peer)
            self._save_trusted(peers)

    def revoke(self, public_key: bytes) -> None:
        with self._lock:
            peers = [p for p in self._load_trusted() if not verify_pinned(public_key, p)]
            self._save_trusted(peers)

    def is_trusted(self, peer: DeviceIdentity) -> bool:
        return any(verify_pinned(peer.public_key, existing) for existing in self._load_trusted())

    def get_trusted_peer(self, device_id: str) -> DeviceIdentity | None:
        for p in self._load_trusted():
            if p.device_id == device_id:
                return p
        return None

    def list_trusted(self) -> list[DeviceIdentity]:
        return self._load_trusted()
