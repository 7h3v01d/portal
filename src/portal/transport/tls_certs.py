# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""Ephemeral self-signed certificates for the TLS transport.

These certs exist ONLY to stand up an encrypted TLS channel — they are throwaway
and per-process, NOT the device identity. Authentication of the real Ed25519
identity happens above TLS in security.handshake, bound to the TLS channel. So
these certs are deliberately not the identity key and are never pinned."""

from __future__ import annotations

import datetime
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID


def make_ephemeral_cert_files() -> tuple[str, str]:
    """Generate a throwaway Ed25519 self-signed cert + key, write them to temp
    PEM files, and return (cert_path, key_path). Used only to satisfy the TLS
    layer's need for a certificate."""
    from cryptography.hazmat.primitives import serialization

    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "portal-ephemeral")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, None)  # Ed25519 signs without a separate hash
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    cert_file = tempfile.NamedTemporaryFile(prefix="portal-", suffix=".crt", delete=False)
    key_file = tempfile.NamedTemporaryFile(prefix="portal-", suffix=".key", delete=False)
    cert_file.write(cert_pem)
    cert_file.close()
    key_file.write(key_pem)
    key_file.close()
    return cert_file.name, key_file.name
