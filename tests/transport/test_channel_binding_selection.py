# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (github.com/7h3v01d)
"""A6: channel-binding selection — prefer tls-exporter (RFC 9266) when the runtime
can produce it, else fall back to tls-unique. The runtime here can't produce
tls-exporter, so we drive the selector with fakes to prove BOTH paths."""

from __future__ import annotations

import pytest

import portal.transport.tls as tlsmod
from portal.common.errors import TransportError


class FakeSSL:
    def __init__(self, available, values, version="TLSv1.3"):
        self._available = available
        self._values = values
        self._version = version

    def get_channel_binding(self, cb_type):
        return self._values.get(cb_type)

    def version(self):
        return self._version


def test_prefers_tls_exporter_when_available(monkeypatch):
    monkeypatch.setattr(tlsmod.ssl, "CHANNEL_BINDING_TYPES",
                        ["tls-unique", "tls-exporter"], raising=False)
    ssl_obj = FakeSSL(
        available=["tls-unique", "tls-exporter"],
        values={"tls-exporter": b"E" * 32, "tls-unique": b"U" * 48},
    )
    bt, val = tlsmod._select_channel_binding(ssl_obj)
    assert bt == "tls-exporter"
    assert val == b"E" * 32


def test_falls_back_to_tls_unique(monkeypatch):
    monkeypatch.setattr(tlsmod.ssl, "CHANNEL_BINDING_TYPES", ["tls-unique"], raising=False)
    ssl_obj = FakeSSL(available=["tls-unique"], values={"tls-unique": b"U" * 48})
    bt, val = tlsmod._select_channel_binding(ssl_obj)
    assert bt == "tls-unique"
    assert val == b"U" * 48


def test_no_binding_available_raises(monkeypatch):
    monkeypatch.setattr(tlsmod.ssl, "CHANNEL_BINDING_TYPES", ["tls-unique"], raising=False)
    ssl_obj = FakeSSL(available=["tls-unique"], values={"tls-unique": None})
    with pytest.raises(TransportError):
        tlsmod._select_channel_binding(ssl_obj)


def test_tls_unique_on_13_warns(monkeypatch, caplog):
    import logging
    monkeypatch.setattr(tlsmod.ssl, "CHANNEL_BINDING_TYPES", ["tls-unique"], raising=False)
    ssl_obj = FakeSSL(available=["tls-unique"], values={"tls-unique": b"U" * 48},
                      version="TLSv1.3")
    with caplog.at_level(logging.WARNING):
        bt, _ = tlsmod._select_channel_binding(ssl_obj)
    assert bt == "tls-unique"
    assert any("tls-unique" in r.message and "1.3" in r.message for r in caplog.records)
