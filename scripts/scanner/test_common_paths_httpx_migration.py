"""test_common_paths_httpx_migration.py — ㊴ probe 2, curl -> httpx -irrb.

WHY THIS EXISTS (2026-09-09). `_probe_path_body` was the last curl call in
common_paths. It returns (status, body, content_type) and ALL THREE are
load-bearing:

  * status  -> `code not in (200, 204, 206)` decides whether a path is even
               considered exposed.
  * body    -> _body_sha() feeds the catch-all baseline AND
               verify_secret_content() gates HIGH findings.
  * ctype   -> _is_known_secret_ctype() annotates HIGH findings.

🔴 THE SHAPE WAS CAPTURED BEFORE THIS PARSER WAS WRITTEN, and the first
capture attempt FAILED in a way that would have shipped a silent disaster.

Inventory run #7 (2026-09-09), using `-irr`:

    jq: parse error: Invalid string: control characters from U+0000
    through U+001F must be escaped at line 3, column 5707

httpx embeds the raw response with literal CR/LF inside a JSON string,
unescaped. json.loads rejects it too (strict=True). A parser written from a
guess would have thrown on every asset -- or worse, returned an empty body,
which makes EVERY catch-all hash identical, which makes EVERY host look like
a catch-all, which SUPPRESSES real /.env findings while every phase still
reports ok. Fewer findings, silently, fleet-wide.

Run #8 with `-irrb` captured the real shape:
    body [string, base64]  raw_header [string]  request [string]
    status_code [NUMBER]   content_type [string]   header [object]

`body` is its OWN key -- distinct from raw_header and request -- so hashing
it is body-only and free of Date/Set-Cookie. That is why the catch-all
baseline is still sound after the migration.
"""
import base64
import json

import pytest

import run_light
from run_light import _decode_httpx_body, _probe_path_body


def _rec(**over) -> dict:
    """A minimal but REAL-SHAPED -irrb record (keys verbatim from run #8)."""
    body = over.pop("_body", "<!DOCTYPE html><html><body>hello</body></html>")
    rec = {
        "host": "example.test",
        "input": "https://example.test/",
        "url": "https://example.test/",
        "status_code": 200,
        "content_type": "text/html",
        "content_length": len(body),
        "failed": False,
        "request": base64.b64encode(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n").decode(),
        "raw_header": base64.b64encode(
            b"HTTP/1.1 200 OK\r\ndate: Tue, 09 Sep 2026 12:00:00 GMT\r\n").decode(),
        "body": base64.b64encode(body.encode()).decode(),
        "header": {"content_type": "text/html", "server": "nginx"},
    }
    rec.update(over)
    return rec


def _stub(monkeypatch, rec, rc=0):
    monkeypatch.setattr(run_light, "run_cmd",
                        lambda *a, **k: (rc, json.dumps(rec) + "\n", ""))
    monkeypatch.setattr(run_light, "log", lambda *a, **k: None)

    class _Ctx:
        hostname = "example.test"
    return _Ctx()


# ── the happy path ────────────────────────────────────────────────────

def test_returns_status_body_and_ctype(monkeypatch):
    ctx = _stub(monkeypatch, _rec())
    code, body, ctype = _probe_path_body(ctx, "/.env")
    assert code == 200
    assert "hello" in body
    assert ctype == "text/html"


def test_body_is_base64_decoded_not_raw(monkeypatch):
    """⚠ If the base64 were passed through undecoded, _body_sha would still
    produce a stable hash and catch-all detection would still 'work' -- but
    verify_secret_content() would never match a marker, so a real /.env
    would be downgraded instead of emitted. Silent, and in the dangerous
    direction."""
    secret = "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE"
    ctx = _stub(monkeypatch, _rec(_body=secret))
    _code, body, _ct = _probe_path_body(ctx, "/.env")
    assert body == secret, "body was not base64-decoded"
    assert "AWS_SECRET" in body


# ── 🔴 the silent-failure guards ──────────────────────────────────────

def test_string_status_code_is_refused(monkeypatch):
    """status_code was captured as a NUMBER on the pinned v1.10.0.

    If a toolchain bump ever makes it a string, `code not in (200,204,206)`
    never matches, NO path is ever considered exposed, and common_paths goes
    silently blind while still reporting ok. Refuse loudly instead.
    """
    ctx = _stub(monkeypatch, _rec(status_code="200"))
    assert _probe_path_body(ctx, "/.env") == (0, "", None)


def test_httpx_failed_verdict_is_honoured(monkeypatch):
    """httpx reports reachability itself. Use its verdict rather than
    guessing from an exit code -- the whole point of ㊴."""
    ctx = _stub(monkeypatch, _rec(failed=True))
    assert _probe_path_body(ctx, "/.env") == (0, "", None)


def test_unparseable_output_does_not_raise(monkeypatch):
    """The -irr failure mode. If output is ever not valid JSON, fail as a
    failed probe -- never propagate an exception out of one path probe and
    kill the remaining 19."""
    monkeypatch.setattr(run_light, "run_cmd",
                        lambda *a, **k: (0, '{"body": "unterminated', ""))
    monkeypatch.setattr(run_light, "log", lambda *a, **k: None)

    class _Ctx:
        hostname = "example.test"
    assert _probe_path_body(_Ctx(), "/.env") == (0, "", None)


def test_empty_stdout_is_a_failed_probe(monkeypatch):
    ctx = _stub(monkeypatch, _rec())
    monkeypatch.setattr(run_light, "run_cmd", lambda *a, **k: (0, "", ""))
    assert _probe_path_body(ctx, "/.env") == (0, "", None)


# ── the decoder itself ────────────────────────────────────────────────

def test_decoder_returns_empty_on_garbage():
    assert _decode_httpx_body(None) == ""
    assert _decode_httpx_body("") == ""
    assert _decode_httpx_body(12345) == ""


def test_decoder_handles_non_utf8_bytes():
    """A binary secret file (keystore, .p12) must not explode the probe."""
    raw = base64.b64encode(b"\xff\xfe\x00binary").decode()
    out = _decode_httpx_body(raw)
    assert isinstance(out, str) and "binary" in out


def test_body_excludes_headers_so_the_hash_is_stable(monkeypatch):
    """🔴 THE CATCH-ALL INVARIANT.

    `body` must not contain the volatile response headers that live in
    `raw_header` (Date, Set-Cookie). If it did, two probes of the SAME url
    would hash differently, _is_catchall() would never see equal hashes,
    catch-all detection would silently switch off, and suppression would
    stop. Two independent records with different Date headers must still
    produce the same body hash.
    """
    r1 = _rec()
    r2 = _rec()
    r2["raw_header"] = base64.b64encode(
        b"HTTP/1.1 200 OK\r\ndate: Tue, 09 Sep 2026 23:59:59 GMT\r\n").decode()

    ctx1 = _stub(monkeypatch, r1)
    _c, b1, _t = _probe_path_body(ctx1, "/a")
    ctx2 = _stub(monkeypatch, r2)
    _c, b2, _t = _probe_path_body(ctx2, "/b")

    assert run_light._body_sha(b1) == run_light._body_sha(b2), (
        "body hash changed when only a response header changed -- the body "
        "field is carrying headers and the catch-all baseline is broken"
    )


def test_content_type_falls_back_to_header_map(monkeypatch):
    """Top-level content_type is captured, but the header map also carries
    it. Tolerate the top-level being absent without losing the ctype gate."""
    rec = _rec()
    del rec["content_type"]
    ctx = _stub(monkeypatch, rec)
    _code, _body, ctype = _probe_path_body(ctx, "/.env")
    assert ctype == "text/html"


def test_no_curl_remains_in_probe_path_body():
    """㊴ probe 2 is complete only when the curl call is GONE.

    ⚠ ast on the actual call, not a grep -- this module's own docstring
    discusses curl at length, and a text pin would match prose. That mistake
    has now shipped four times in this repo.
    """
    import ast
    from pathlib import Path

    tree = ast.parse(Path(run_light.__file__).read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_probe_path_body")
    argv0 = [
        el.value
        for node in ast.walk(fn) if isinstance(node, ast.Call)
        for a in node.args if isinstance(a, ast.List) and a.elts
        for el in a.elts[:1] if isinstance(el, ast.Constant)
    ]
    assert argv0, "no argv list found -- test would pass by examining nothing"
    assert "curl" not in argv0, f"_probe_path_body still shells out to curl: {argv0}"
    assert "httpx" in argv0, f"expected httpx as argv[0], got {argv0}"
