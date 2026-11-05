"""KB 12 job 4y (2026-11-05): Sentry names what each device is — the clue collector.

Howie, 2026-11-04 19:10: "I'd really love to get something in terms of a deeper scan or a
better recognition of what these security devices are." Trial 4w (Howie's Mac, 2026-11-05
08:33 ET, bar met) proved these requests and this reading; device_clues.py is its program
as one scan step. Plan: KB wrap-up 2026-11-05 0845 (4y), v2.

Pinned here, against fake servers on this machine (the trial's way) and pure functions:
  * exactly the trial's requests: four handshakes that send nothing, GET /, at most one
    same-host https redirect, GET /favicon.ico; plain GETs, never a Cookie header;
  * what is kept and what never is (page text, the generator tag, cookie values,
    parameter values);
  * no answer carries no clues, and landing_paths is null then (the classifier's
    "did not look");
  * the same make and set-up key (no certificate in it);
  * the history rows: only a change, only between two answering artifacts, own savepoint;
  * the light and deep scans call it as an observation, not a credited tool.
"""
from __future__ import annotations

import functools
import hashlib
import inspect
import json
import os
import random
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import device_clues as dc  # noqa: E402

ICON = bytes(random.Random(7).randrange(256) for _ in range(1150))
PORTAL = (b"<html><head><title>Fake &amp; Portal</title><meta name=\"generator\" content=\"FakeGen 1.2\">"
          b"</head><body>secret page text SECRETBODY</body></html>")
SECRETS = ("SECRETBODY", "SECRET123", "SECRET456", "QVAL777", "QVAL888", "QVAL999", "FakeGen")


# ── fake servers (the trial's, on 127.0.0.1, one port each) ───────────────────

def _mkcert(work, tag, subj, san):
    c, k = os.path.join(work, tag + ".pem"), os.path.join(work, tag + ".key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", k, "-out", c,
                    "-days", "30", "-subj", subj, "-addext", "subjectAltName=" + san],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return c, k


class Fake:
    """mode: portal | other | loop | eft | plain | tls12"""

    def __init__(self, mode, cert):
        self.mode = mode
        self.conns = []
        self.lock = threading.Lock()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(32)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(*cert)
        self.ctx.set_ciphers("ALL:@SECLEVEL=0")
        if mode == "tls12":
            self.ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.set_alpn_protocols(["http/1.1"])
        self._last_sni = None
        self.ctx.sni_callback = lambda s, name, c: setattr(self, "_last_sni", name)
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        rec = {"sni": None, "sent": b""}
        try:
            c.settimeout(3)
            s = self.ctx.wrap_socket(c, server_side=True)
            rec["sni"] = self._last_sni
            data = b""
            while b"\r\n\r\n" not in data:
                try:
                    d = s.recv(4096)
                except (socket.timeout, ssl.SSLError, OSError):
                    break
                if not d:
                    break
                data += d
            rec["sent"] = data
            if data:
                s.sendall(self.answer(data))
            try:
                s.close()
            except OSError:
                pass
        except (ssl.SSLError, OSError) as e:
            rec["error"] = type(e).__name__
        with self.lock:
            self.conns.append(rec)

    def answer(self, req):
        path = req.split(b" ")[1].decode()
        m = self.mode
        if path == "/favicon.ico":
            if m in ("portal", "eft", "tls12"):
                return b"HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\nContent-Length: %d\r\n\r\n" % len(ICON) + ICON
            return b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        if m == "portal":
            if path == "/":
                return (b"HTTP/1.1 302 Found\r\nServer: FakeServer/9\r\nSet-Cookie: ASPSESSIONIDABCDEFGH=SECRET123; path=/\r\n"
                        b"Location: /PortalSite?Brand=QVAL777&x=QVAL888\r\nContent-Length: 0\r\n\r\n")
            if path.startswith("/PortalSite"):
                return (b"HTTP/1.1 200 OK\r\nX-Powered-By: FakeStack\r\nContent-Type: text/html\r\n"
                        b"Set-Cookie: csrftoken=SECRET456; Secure\r\nContent-Length: %d\r\n\r\n" % len(PORTAL) + PORTAL)
        if m == "eft":
            if path == "/":
                return b"HTTP/1.1 302 Found\r\nLocation: /Web/Account/Login.htm\r\nSet-Cookie: savedpath=x\r\nContent-Length: 0\r\n\r\n"
            if path == "/Web/Account/Login.htm":
                body = b"<title>Command Companies Secure File Transfer</title>"
                return b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n" % len(body) + body
        if m == "other" and path == "/":
            return b"HTTP/1.1 301 Moved\r\nLocation: https://elsewhere.example/login?u=QVAL999\r\nContent-Length: 0\r\n\r\n"
        if m == "loop":
            if path == "/":
                return b"HTTP/1.1 302 Found\r\nLocation: /a\r\nContent-Length: 0\r\n\r\n"
            if path == "/a":
                return b"HTTP/1.1 302 Found\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n"
        return b"HTTP/1.1 200 OK\r\nServer: Plain\r\nContent-Type: text/html\r\nContent-Length: 20\r\n\r\n<title>Plain</title>"

    def close(self):
        self.sock.close()


@pytest.fixture(scope="module")
def certs():
    if not shutil.which("openssl"):
        pytest.skip("openssl is needed to make the fake servers' certificates")
    work = tempfile.mkdtemp(prefix="t4y.")
    yield {"a": _mkcert(work, "a", "/C=US/O=Fake Co, Inc./CN=*.sciimage.test",
                        "DNS:*.sciimage.test,DNS:sciimage.test,IP:127.0.0.1"),
           "b": _mkcert(work, "b", "/CN=other.test", "DNS:other.test")}
    shutil.rmtree(work, ignore_errors=True)


def _collect(server, host, *, sleeps=None):
    """collect() against one fake server, nothing else reachable, no real sleeping."""
    slept = sleeps if sleeps is not None else []
    art, sent = dc.collect(
        host, "light",
        resolve=lambda h, **k: ["127.0.0.1"],
        shake=functools.partial(dc.handshake, port=server.port),
        get=functools.partial(dc.http_get, port=server.port),
        sleep=slept.append)
    time.sleep(0.2)          # let the server threads record the last connection
    return art, sent


def _wait(server, n):
    for _ in range(50):
        with server.lock:
            if len(server.conns) >= n:
                return
        time.sleep(0.05)


# ── the requests ───────────────────────────────────────────────────────────────

def test_exactly_the_trials_requests_and_never_a_cookie(certs):
    s = Fake("portal", certs["a"])
    try:
        sleeps = []
        art, sent = _collect(s, "insite.sciimage.test", sleeps=sleeps)
        _wait(s, 7)
        assert sent == 7                                   # 4 handshakes + / + one redirect + icon
        hs = [c for c in s.conns if not c["sent"]]
        gets = [c["sent"] for c in s.conns if c["sent"]]
        assert len(hs) == 4, "handshake-only connections send nothing after the handshake"
        assert len(gets) == 3 and all(g.startswith(b"GET ") for g in gets)
        paths = sorted(g.split(b" ")[1].decode() for g in gets)
        assert paths == ["/", "/PortalSite?Brand=QVAL777&x=QVAL888", "/favicon.ico"]
        assert all(b"\ncookie:" not in g.lower() for g in gets), "no cookie is ever sent"
        assert all(b"authorization" not in g.lower() and b"POST" not in g for g in gets)
        assert {c["sni"] for c in s.conns} == {"insite.sciimage.test"}
        assert sleeps == [dc.STEP_S] * 6, "two seconds between every connection"
    finally:
        s.close()


def test_one_redirect_at_most_and_never_to_another_host(certs):
    loop, other = Fake("loop", certs["a"]), Fake("other", certs["a"])
    try:
        art, sent = _collect(loop, "loop.test")
        _wait(loop, 7)
        paths = sorted(c["sent"].split(b" ")[1].decode() for c in loop.conns if c["sent"])
        assert paths == ["/", "/a", "/favicon.ico"], "the second redirect (/b) is never asked"
        assert art["addresses"]["127.0.0.1"]["landing_path"] == "/a"
        art2, sent2 = _collect(other, "o.test")
        _wait(other, 6)
        assert sent2 == 6
        assert sorted(c["sent"].split(b" ")[1].decode() for c in other.conns if c["sent"]) == ["/", "/favicon.ico"]
        a2 = art2["addresses"]["127.0.0.1"]
        assert a2["outcome"] == dc.ANSWERED and a2["landing_path"] is None   # sent elsewhere: not followed
        assert art2["landing_paths"] is None
    finally:
        loop.close()
        other.close()


def test_by_address_sends_no_name(certs):
    s = Fake("plain", certs["a"])
    try:
        art, _ = dc.collect("127.0.0.1", "heavy", shake=functools.partial(dc.handshake, port=s.port),
                            get=functools.partial(dc.http_get, port=s.port), sleep=lambda x: None)
        _wait(s, 6)
        assert {c["sni"] for c in s.conns} == {None}
        assert all(b"Host: 127.0.0.1\r\n" in c["sent"] for c in s.conns if c["sent"])
        assert art["tier"] == "heavy" and art["addresses"]["127.0.0.1"]["landing_path"] == "/"
    finally:
        s.close()


# ── what is kept ───────────────────────────────────────────────────────────────

def test_kept_and_never_kept(certs):
    s = Fake("portal", certs["a"])
    try:
        art, _ = _collect(s, "insite.sciimage.test")
        text = json.dumps(art)
        for secret in SECRETS:
            assert secret not in text, secret
        a = art["addresses"]["127.0.0.1"]
        assert a["landing_path"] == "/PortalSite" and a["landing_param_names"] == ["Brand", "x"]
        assert a["title"] == "Fake & Portal"
        assert a["set_cookie_names"] == ["ASPSESSIONIDABCDEFGH", "csrftoken"]
        assert a["server"] == "FakeServer/9" and a["header_names"][0] == "Server"
        assert a["icon"] == {"status": 200, "mmh3": dc.icon_hash(ICON), "sha256": hashlib.sha256(ICON).hexdigest()}
        assert [t["probe"] for t in a["tls"]] == list(dc.PROBES)
        assert a["cert"]["subject"] == "C=US, O=Fake Co, Inc., CN=*.sciimage.test"
        assert a["cert"]["names"] == ["*.sciimage.test", "sciimage.test", "IP 127.0.0.1"]
        assert set(a) <= {"outcome", "tls", "cert", "landing_path", "landing_param_names", "title",
                          "set_cookie_names", "header_names", "server", "x_powered_by", "icon", "group_key"}
        assert art["landing_paths"] == ["/PortalSite"]
        assert art["cert_subject"] == a["cert"]["subject"]
        assert art["set_cookie_names"] == ["ASPSESSIONIDABCDEFGH", "csrftoken"]
    finally:
        s.close()


def test_the_eft_login_lands_where_the_classifier_looks(certs):
    s = Fake("eft", certs["a"])
    try:
        art, _ = _collect(s, "ftp.sciimage.test")
        assert art["landing_paths"] == ["/Web/Account/Login.htm"]
        assert art["addresses"]["127.0.0.1"]["title"] == "Command Companies Secure File Transfer"
    finally:
        s.close()


def test_no_answer_carries_no_clues_and_landing_paths_is_null():
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port = free.getsockname()[1]
    free.close()                                          # nothing listens: refused
    art, sent = dc.collect("gone.test", "light", resolve=lambda h, **k: ["127.0.0.1"],
                           shake=functools.partial(dc.handshake, port=port),
                           get=functools.partial(dc.http_get, port=port), sleep=lambda x: None)
    assert art["addresses"] == {"127.0.0.1": {"outcome": dc.NO_ANSWER}}
    assert art["landing_paths"] is None and art["cert_subject"] is None and art["set_cookie_names"] == []
    assert sent == 6                                       # 4 handshakes + / + icon; nothing followed


def test_a_name_that_points_nowhere_writes_an_empty_artifact():
    art, sent = dc.collect("nowhere.test", "light", resolve=lambda h, **k: [], sleep=lambda x: None)
    assert sent == 0 and art["addresses"] == {} and art["landing_paths"] is None


# ── pure pieces ───────────────────────────────────────────────────────────────

def test_murmur3_published_value():
    assert dc.mmh3_32(b"hello") == 613153351
    assert dc.mmh3_32(b"") == 0


def test_same_host_location_keeps_names_never_values():
    assert dc.same_host_location("/PortalSite?Brand=panel&x=1", "h") == ("/PortalSite", ["Brand", "x"], "/PortalSite?Brand=panel&x=1")
    assert dc.same_host_location("https://h/Web/Account/Login.htm", "h")[0] == "/Web/Account/Login.htm"
    assert dc.same_host_location("https://other/x", "h") == (None, None, None)
    assert dc.same_host_location("http://h/x", "h") == (None, None, None)      # not https
    assert dc.same_host_location("https://h:8443/x", "h") == (None, None, None)
    assert dc.same_host_location(None, "h") == (None, None, None)


def _tls(*versions):
    return [{"probe": p, "ok": v is not None, "version": v, "cipher": "C" if v else None, "alpn": None}
            for p, v in zip(dc.PROBES, versions)]


def test_the_set_up_key_ignores_the_certificate_and_sees_header_order():
    a = dc.address_record(_tls("TLSv1.3", "TLSv1.2", "TLSv1.2", "TLSv1.2"), {"sha256": "1" * 64},
                          {"status": 200, "headers": [("Server", "X"), ("Date", "d")], "body": b"", "host": "h"},
                          None, {"status": 404, "headers": [], "body": b""})
    b = dc.address_record(_tls("TLSv1.3", "TLSv1.2", "TLSv1.2", "TLSv1.2"), {"sha256": "2" * 64},
                          {"status": 200, "headers": [("Server", "X"), ("Date", "d")], "body": b"", "host": "h"},
                          None, {"status": 404, "headers": [], "body": b""})
    c = dc.address_record(_tls("TLSv1.3", "TLSv1.2", "TLSv1.2", "TLSv1.2"), {"sha256": "1" * 64},
                          {"status": 200, "headers": [("Date", "d"), ("Server", "X")], "body": b"", "host": "h"},
                          None, {"status": 404, "headers": [], "body": b""})
    assert a["group_key"] == b["group_key"], "a certificate is installed, not built in"
    assert a["group_key"] != c["group_key"]


def test_two_addresses_both_feed_landing_paths():
    one = {"outcome": dc.ANSWERED, "landing_path": "/Web/Account/Login.htm", "cert": {"subject": "CN=b"}}
    two = {"outcome": dc.ANSWERED, "landing_path": "/", "cert": {"subject": "CN=a"}}
    art = dc.artifact("h", "light", {"10.0.0.2": one, "10.0.0.1": two, "10.0.0.3": {"outcome": dc.NO_ANSWER}})
    assert art["landing_paths"] == ["/", "/Web/Account/Login.htm"]
    assert art["cert_subject"] == "CN=a"                  # the first answering address, by address


def test_each_connection_gets_only_what_is_left_and_none_starts_after():
    """Code review 2026-11-05, must-fix 1. A fake clock that moves 100 s per connection:
    the first two connections run, each told how much is left; the third is never started;
    the address keeps no clues (cut short); the second address is never touched."""
    now = [0.0]
    budgets = []

    def shake(ip, sni, p, budget_s=None):
        budgets.append((ip, budget_s))
        now[0] += 100.0
        return {"probe": p, "ok": True, "version": "TLSv1.3", "cipher": "C", "alpn": None}, None

    art, sent = dc.collect("h", "light", resolve=lambda h, **k: ["10.0.0.1", "10.0.0.2"], shake=shake,
                           get=lambda *a, **k: (200, [], b"", None), sleep=lambda x: None, clock=lambda: now[0])
    assert budgets == [("10.0.0.1", dc.BUDGET_S), ("10.0.0.1", dc.BUDGET_S - 100.0)]
    assert sent == 2 and art["addresses"] == {"10.0.0.1": {"outcome": dc.CUT_SHORT}}
    assert art["landing_paths"] is None, "a cut-short address is 'did not look'"


def test_a_name_lookup_that_hangs_counts_as_no_address(monkeypatch):
    """The system lookup has no timeout of its own: resolve_v4 gives it `timeout` seconds."""
    monkeypatch.setattr(dc.socket, "getaddrinfo", lambda *a, **k: time.sleep(5) or [])
    t0 = time.monotonic()
    assert dc.resolve_v4("hangs.test", timeout=0.5) == []
    assert time.monotonic() - t0 < 2.0


def test_the_name_lookup_gets_only_its_share():
    seen = []
    dc.collect("h", "light", resolve=lambda h, timeout=None: seen.append(timeout) or [], sleep=lambda x: None)
    assert seen == [dc.RESOLVE_S]


class _Slow:
    """A TLS server that answers a GET one byte at a time, forever (trickle), or a TCP
    server that accepts and never says anything (silent)."""

    def __init__(self, mode, cert):
        self.mode, self.stop = mode, False
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(32)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(*cert)
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        try:
            if self.mode == "silent":
                while not self.stop:
                    time.sleep(0.2)
                return
            s = self.ctx.wrap_socket(c, server_side=True)
            s.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data:
                d = s.recv(4096)
                if not d:
                    return
                data += d
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
            while not self.stop:
                s.sendall(b"x")
                time.sleep(0.2)
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def close(self):
        self.stop = True
        self.sock.close()


def _timed_collect(server, budget, monkeypatch):
    monkeypatch.setattr(dc, "BUDGET_S", budget)
    box = {}

    def go():
        box["out"] = dc.collect("slow.test", "light", resolve=lambda h, **k: ["127.0.0.1"],
                                shake=functools.partial(dc.handshake, port=server.port),
                                get=functools.partial(dc.http_get, port=server.port), sleep=lambda x: None)
    t0 = time.monotonic()
    th = threading.Thread(target=go, daemon=True)
    th.start()
    th.join(budget + 6)
    return th.is_alive(), time.monotonic() - t0, box.get("out")


def test_a_trickling_server_cannot_hold_the_host_past_its_limit(certs, monkeypatch):
    s = _Slow("trickle", certs["a"])
    try:
        alive, took, out = _timed_collect(s, 3.0, monkeypatch)
        assert not alive, "a byte every 0.2 s kept the reading going past the host's limit"
        assert took < 3.0 + 2.0, took
        art, sent = out
        assert art["addresses"]["127.0.0.1"] == {"outcome": dc.CUT_SHORT}
    finally:
        s.close()


def test_a_silent_server_cannot_hold_the_host_past_its_limit(certs, monkeypatch):
    s = _Slow("silent", certs["a"])
    try:
        alive, took, out = _timed_collect(s, 2.0, monkeypatch)
        assert not alive, "a server that never finishes the handshake held the host"
        assert took < 2.0 + 2.0, took
    finally:
        s.close()


# ── history ────────────────────────────────────────────────────────────────────

def _addr(g="g1", path="/Web/Account/Login.htm", cert="c1", outcome=dc.ANSWERED):
    return {"outcome": outcome, "group_key": g, "landing_path": path, "cert": {"sha256": cert}}


def test_history_writes_only_a_change_between_two_answers():
    prev = {"addresses": {"10.0.0.1": _addr(), "10.0.0.2": _addr()}}
    same = {"addresses": {"10.0.0.1": _addr(), "10.0.0.2": _addr()}}
    assert dc.plan_history_rows(prev, same) == []
    assert dc.plan_history_rows(None, same) == [], "a first artifact writes nothing"
    moved = {"addresses": {"10.0.0.1": _addr(g="g2"), "10.0.0.2": _addr(cert="c2", path="/"),
                           "10.0.0.9": _addr(g="new")}}
    rows = dc.plan_history_rows(prev, moved)
    assert [r["item_key"] for r in rows] == ["10.0.0.1", "10.0.0.2"], "a new address is the DNS job's, not this"
    assert rows[0]["new_value"]["changed"] == ["group_key"]
    assert rows[1]["new_value"]["changed"] == ["landing_path", "cert_sha256"]
    gone = {"addresses": {"10.0.0.1": _addr(g="g9", outcome=dc.NO_ANSWER)}}
    assert dc.plan_history_rows(prev, gone) == [], "no answer is not a change"


class _Cur:
    def __init__(self, prev=None, fail_on=None):
        self.prev, self.fail_on, self.sql = prev, fail_on, []

    def execute(self, sql, params=None):
        self.sql.append((" ".join(sql.split()), params))
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError("boom")

    def fetchone(self):
        return {"blob": json.dumps(self.prev)} if self.prev is not None else None


class _Ctx:
    def __init__(self, art):
        self.asset_id, self.scan_run_id = "ftp.sciimage.com", "run-2"
        self.artifacts = [("headers_check", "json", "{}")] + (
            [(dc.TOOL_NAME, "json", json.dumps(art))] if art is not None else [])


def test_history_rows_are_written_in_their_own_savepoint():
    prev = {"addresses": {"10.0.0.1": _addr()}}
    cur = _Cur(prev)
    n = dc.record_from_ctx(cur, _Ctx({"addresses": {"10.0.0.1": _addr(g="g2")}}), "light", lambda v: v)
    assert n == 1
    kinds = [s.split()[0] + " " + s.split()[1] for s, _ in cur.sql]
    assert kinds[0] == "SAVEPOINT device_clues_history" and kinds[-1] == "RELEASE SAVEPOINT"
    ins = [p for s, p in cur.sql if s.startswith("INSERT INTO public.asset_tech_history")]
    assert len(ins) == 1 and ins[0]["change_type"] == "attribute_changed" and ins[0]["category"] == "device_clues"
    assert ins[0]["source"] == "light" and ins[0]["item_key"] == "10.0.0.1"
    sel_sql, sel = [(s, p) for s, p in cur.sql if s.startswith("SELECT a.content_jsonb")][0]
    assert sel["scan_run_id"] == "run-2", "this run's own artifact is never its own baseline"
    assert "r.scan_run_id::text <> %(scan_run_id)s" in sel_sql and "a.tool_name = %(tool)s" in sel_sql


def test_a_failed_history_write_rolls_back_alone():
    cur = _Cur({"addresses": {"10.0.0.1": _addr()}}, fail_on="INSERT INTO")
    assert dc.record_from_ctx(cur, _Ctx({"addresses": {"10.0.0.1": _addr(g="g2")}}), "heavy", lambda v: v) == -1
    assert cur.sql[-1][0] == "ROLLBACK TO SAVEPOINT device_clues_history"


def test_a_savepoint_that_cannot_be_made_is_a_failed_write_not_an_exception():
    """Code review 2026-11-05, minor 3."""
    cur = _Cur({"addresses": {"10.0.0.1": _addr()}}, fail_on="SAVEPOINT device_clues_history")
    assert dc.record_from_ctx(cur, _Ctx({"addresses": {"10.0.0.1": _addr(g="g2")}}), "light", lambda v: v) == -1
    assert [x for x, _ in cur.sql] == ["SAVEPOINT device_clues_history"], "no rollback to a savepoint never made"


def test_no_clues_this_run_touches_nothing():
    cur = _Cur()
    assert dc.record_from_ctx(cur, _Ctx(None), "light", lambda v: v) == 0
    assert cur.sql == []


def test_history_uses_attribute_changed_which_the_table_allows():
    """STORAGE ONLY (code review 2026-11-05, minor 5: this cannot see the portal). The rows
    use attribute_changed, which the table's CHECK allows. That the live asset page leaves
    it out of "Recent stack changes" is the portal's own fact (TechHistoryPanel, read
    2026-11-05; receipt in the 4y build folder); the portal push pins it in its own tests."""
    assert dc.HISTORY_CHANGE == "attribute_changed"
    root = os.path.dirname(os.path.dirname(HERE))
    mig = open(os.path.join(root, "scripts", "db", "migrations", "20260522d_asset_tech_profile.sql")).read()
    assert "'attribute_changed'" in mig


# ── wiring ─────────────────────────────────────────────────────────────────────

def test_the_light_scan_calls_it_as_an_observation_after_the_vpn_checks():
    import run_light
    src = inspect.getsource(run_light.run)
    i, j = src.index("check_stack_fingerprint(ctx)"), src.index("check_device_clues(ctx)")
    assert i < j < src.index("check_behavioral_probes(ctx)")
    body = inspect.getsource(run_light.check_device_clues)
    code = body.split('"""')[-1]                       # the code, not the docstring that explains it
    assert "tools_run" not in code and "mark_tool" not in code, "not a credited tool"
    assert 'device_clues.collect(ctx.hostname, "light"' in body
    from types import SimpleNamespace
    steps = run_light.build_light_planned_steps(SimpleNamespace(open_ports={443}, asset_kind=None))
    assert "device_clues" not in steps, "no planned step: the progress count is unchanged"
    writer = inspect.getsource(run_light)
    assert 'device_clues.record_from_ctx(cur, ctx, "light", Json, log=log)' in writer


def test_the_deep_scan_calls_it_beside_the_passive_collector():
    import run_heavy
    src = inspect.getsource(run_heavy.run)
    p, d, c = (src.index("run_stack_id_passive_phase(ctx, work_dir)"), src.index("run_device_clues_phase(ctx)"),
               src.index("phases_for_tier(TIER_HEAVY)"))
    assert p < d < c, "quiet requests, before anything that could earn a ban"
    body = inspect.getsource(run_heavy.run_device_clues_phase)
    code = body.split('"""')[-1]
    assert "tools_run" not in code and "tool_status" not in code and "credit" not in code
    assert 'device_clues.collect(ctx.hostname, "heavy"' in body
    w = inspect.getsource(run_heavy)
    assert 'device_clues.record_from_ctx(cur, ctx, "heavy", Json, log=log)' in w
    i = w.index('device_clues.record_from_ctx(cur, ctx, "heavy"')
    assert "if write_artifacts:" in w[i - 400:i], "history only when this run's artifacts are kept"
