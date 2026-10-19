#!/usr/bin/env python3
"""test_tls_check_stage_reclassify.py — check_tls separates connect from handshake.

WHY THIS EXISTS (2026-10-18). check_tls used to run socket.create_connection()
and ssl.wrap_socket() inside ONE try block, so a ConnectionResetError raised
mid-handshake was fed into tls_check_is_degraded(), whose isinstance check maps
ConnectionResetError to network_unreachable BEFORE its ssl/handshake branch.
Two real hosts (ftp.unimacgraphics.com, ftp.commandmi.com) accept the TCP
connect on 443 and then RST our modern ClientHello (their floor is legacy
TLS 1.0/1.1 + 3DES / RSA-SHA1 vs Python's OpenSSL SECLEVEL-2 context) — so they
were logged "unreachable" when they are, in fact, reachable and refusing our
TLS. The stage split routes connect failures to network_unreachable (honest)
and handshake failures to tls_handshake_failed (honest).
"""
from __future__ import annotations

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_light as L  # noqa: E402


class _Sock:
    """Minimal context-manager stand-in for a connected TCP socket."""
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False
    def close(self):
        pass


def _sslctx(raise_exc=None, cert=None, version="TLSv1.3"):
    """A fake ssl.create_default_context() result. wrap_socket() returns a
    context manager that either raises (handshake-stage failure) or yields an
    object exposing getpeercert()/version() like a real SSLSocket."""

    class _SSock:
        def __init__(self, sock):
            self.sock = sock
        def __enter__(self):
            if raise_exc is not None:
                raise raise_exc
            return self
        def __exit__(self, *exc):
            return False
        def getpeercert(self, binary_form=False):
            if cert is None:
                return None
            return b"DER" if binary_form else dict(cert)
        def version(self):
            return version

    ctx = types.SimpleNamespace()
    ctx.wrap_socket = lambda sock, server_hostname=None: _SSock(sock)
    return ctx


def _ctx():
    return types.SimpleNamespace(
        hostname="host.example",
        tools_run=[],
        tool_status={},
        artifacts=[],
        findings=[],
    )


def _raise(exc):
    def _boom(*a, **k):
        raise exc
    return _boom


def test_connect_reset_is_network_unreachable(monkeypatch):
    """A reset during the TCP connect is transport — we never reached it."""
    ctx = _ctx()
    monkeypatch.setattr(
        L.socket, "create_connection",
        _raise(ConnectionResetError("Connection reset by peer")))
    monkeypatch.setattr(L.ssl, "create_default_context", lambda: _sslctx())
    L.check_tls(ctx)
    assert ctx.tool_status["tls_check"] == {"degraded": "network_unreachable"}
    assert ctx.artifacts == []


def test_connect_refused_is_network_unreachable(monkeypatch):
    ctx = _ctx()
    monkeypatch.setattr(
        L.socket, "create_connection",
        _raise(ConnectionRefusedError("Connection refused")))
    monkeypatch.setattr(L.ssl, "create_default_context", lambda: _sslctx())
    L.check_tls(ctx)
    assert ctx.tool_status["tls_check"] == {"degraded": "network_unreachable"}


def test_handshake_reset_is_tls_handshake_failed(monkeypatch):
    """The 2026-10-18 bug: connect succeeds, then wrap_socket resets. That is a
    handshake rejection, NOT an unreachable host."""
    ctx = _ctx()
    monkeypatch.setattr(L.socket, "create_connection", lambda *a, **k: _Sock())
    monkeypatch.setattr(
        L.ssl, "create_default_context",
        lambda: _sslctx(raise_exc=ConnectionResetError("Connection reset by peer")))
    L.check_tls(ctx)
    assert ctx.tool_status["tls_check"] == {"degraded": "tls_handshake_failed"}
    assert ctx.artifacts == []


def test_handshake_sslerror_is_tls_handshake_failed(monkeypatch):
    ctx = _ctx()
    monkeypatch.setattr(L.socket, "create_connection", lambda *a, **k: _Sock())
    monkeypatch.setattr(
        L.ssl, "create_default_context",
        lambda: _sslctx(raise_exc=L.ssl.SSLError("unsupported protocol")))
    L.check_tls(ctx)
    assert ctx.tool_status["tls_check"] == {"degraded": "tls_handshake_failed"}


def test_handshake_timeout_is_tls_handshake_failed(monkeypatch):
    """Ruling: a stall once connected is still a handshake failure — one label."""
    ctx = _ctx()
    monkeypatch.setattr(L.socket, "create_connection", lambda *a, **k: _Sock())
    monkeypatch.setattr(
        L.ssl, "create_default_context",
        lambda: _sslctx(raise_exc=TimeoutError("timed out")))
    L.check_tls(ctx)
    assert ctx.tool_status["tls_check"] == {"degraded": "tls_handshake_failed"}


def test_successful_handshake_still_marks_ok(monkeypatch):
    """The stage split must not break the healthy path."""
    ctx = _ctx()
    monkeypatch.setattr(L.socket, "create_connection", lambda *a, **k: _Sock())
    monkeypatch.setattr(
        L.ssl, "create_default_context",
        lambda: _sslctx(cert={
            "subject": ((("commonName", "host.example"),),),
            "issuer": ((("commonName", "CA"),),),
            "notBefore": "Jan  1 00:00:00 2025 GMT",
            "notAfter": "Jan  1 00:00:00 2035 GMT",
            "subjectAltName": (("DNS", "host.example"),),
        }))
    L.check_tls(ctx)
    assert ctx.tool_status["tls_check"] == {"ok": True}
    assert any(a[0] == "tls_check" for a in ctx.artifacts)


def test_unknown_exception_falls_back_to_unknown_exception():
    assert L.tls_handshake_stage_reason(RuntimeError("boom")) == "unknown_exception"