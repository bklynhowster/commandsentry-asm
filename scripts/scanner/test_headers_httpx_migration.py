"""test_headers_httpx_migration.py — ㊴, the curl -> httpx header migration.

WHY THIS EXISTS (2026-09-08). 4.7 ruling ㊴: light's probes move to the Go
stack because curl's UNMAPPED exit codes were being recorded as facts about
the target. Measured over 90 days: 158 `curl_failed` runs on headers_check
where the Go stack reached the same host IN THE SAME RUN 94% of the time.

⚠ THE MIGRATION HAS ONE SHARP EDGE AND IT IS SILENT.

httpx does NOT return wire-format header names in its -json `header` object.
Captured from the live pinned v1.10.0 build (toolchain-inventory run #6,
2026-09-08, against www.prodexlabs.com):

    "header": {"cache_control": ..., "content_type": ..., "x_powered_by": ...}

Lowercase, hyphens replaced by UNDERSCORES. The curl implementation looked
up `header_name.lower()` -> "strict-transport-security", which matches
NOTHING in that dict.

A naive swap therefore reports EVERY security header missing on EVERY asset
— seven fabricated findings per host, fleet-wide, each of which looks
exactly like a real finding. Nothing in the old test suite would have caught
it, because the failure produces MORE findings rather than fewer, and every
phase still reports ok.

So the load-bearing test here is `test_present_headers_are_not_reported_missing`.
The absent-header tests are the easy half.
"""
import json
from pathlib import Path

import pytest

import run_light
from run_light import (
    SECURITY_HEADERS,
    headers_check_is_degraded,
    httpx_header_key,
)


# A real httpx -json -irh record, trimmed. Keys and casing are VERBATIM from
# the live run — do not "tidy" them into wire format, that is the bug.
_LIVE_SHAPE = {
    "timestamp": "2026-09-08T12:00:00Z",
    "host": "www.prodexlabs.com",
    "url": "https://www.prodexlabs.com",
    "method": "GET",
    "status_code": 200,
    "failed": False,
    "webserver": "Vercel",
    "header": {
        "alt_svc": 'h3=":443"',
        "cache_control": "public, max-age=0, must-revalidate",
        "content_type": "text/html; charset=utf-8",
        "date": "Mon, 08 Sep 2026 12:00:00 GMT",
        "etag": '"abc123"',
        "server": "Vercel",
        "strict_transport_security": "max-age=63072000",
        "x_content_type_options": "nosniff",
        "x_powered_by": "Next.js",
    },
}


def _line(rec: dict) -> str:
    return json.dumps(rec) + "\n"


# ── The key translation itself ────────────────────────────────────────

def test_httpx_header_key_converts_hyphens_to_underscores():
    """The exact transform httpx applies. This is the whole hazard."""
    assert httpx_header_key("Strict-Transport-Security") == "strict_transport_security"
    assert httpx_header_key("X-Content-Type-Options") == "x_content_type_options"
    assert httpx_header_key("Content-Security-Policy") == "content_security_policy"
    # already-normalised input must be idempotent
    assert httpx_header_key("server") == "server"


def test_every_security_header_maps_to_a_legal_httpx_key():
    """No SECURITY_HEADERS entry may translate to something httpx could
    never emit — a stray hyphen or uppercase char means a permanent miss,
    i.e. a permanent false 'missing header' finding for that entry."""
    for name, _sev, _why in SECURITY_HEADERS:
        k = httpx_header_key(name)
        assert k == k.lower(), f"{name} -> {k} is not lowercase"
        assert "-" not in k, f"{name} -> {k} still contains a hyphen"
        assert k.replace("_", "").isalnum(), f"{name} -> {k} has unexpected chars"


# ── 🔴 THE LOAD-BEARING TEST ──────────────────────────────────────────

def test_present_headers_are_not_reported_missing(monkeypatch):
    """A header that IS present must not produce a finding.

    This is the test that catches the underscore bug. Under the naive
    `.lower()` lookup it FAILS with two fabricated findings
    (strict-transport-security and x-content-type-options), both of which
    are present in the response.

    ⚠ Test the case the check should PASS, not only the case it should
    catch — the ㉟ gate lesson, applied.
    """
    ctx = _ctx(monkeypatch, _LIVE_SHAPE)
    run_light.check_headers(ctx)

    emitted = {f.check_name for f in ctx.findings}
    assert "missing-header-strict-transport-security" not in emitted, (
        "STS is present in the response but was reported missing — the httpx "
        "key translation is broken (hyphen vs underscore)."
    )
    assert "missing-header-x-content-type-options" not in emitted, (
        "X-Content-Type-Options is present but was reported missing."
    )


def test_genuinely_absent_headers_are_still_reported(monkeypatch):
    """The other half: absence must still be detected. A translation bug
    that silenced EVERYTHING would pass the test above."""
    ctx = _ctx(monkeypatch, _LIVE_SHAPE)
    run_light.check_headers(ctx)
    emitted = {f.check_name for f in ctx.findings}
    # CSP and X-Frame-Options are genuinely absent from _LIVE_SHAPE.
    assert "missing-header-content-security-policy" in emitted
    assert "missing-header-x-frame-options" in emitted


def test_all_headers_present_yields_zero_findings(monkeypatch):
    """Floor: a fully-hardened host must produce NO header findings. If the
    translation is broken this emits all seven."""
    rec = json.loads(json.dumps(_LIVE_SHAPE))
    rec["header"] = {httpx_header_key(n): "x" for n, _, _ in SECURITY_HEADERS}
    ctx = _ctx(monkeypatch, rec)
    run_light.check_headers(ctx)
    assert [f.check_name for f in ctx.findings] == [], (
        "a host with every security header set still produced findings"
    )


# ── Degradation: the reason ㊴ exists ─────────────────────────────────

def test_unreachable_host_degrades_on_httpx_own_verdict():
    """httpx reports `failed: true` — a structured verdict, not an exit code
    we have to interpret. The old path guessed from curl's rc and produced
    `curl_failed` for every unmapped code."""
    rec = json.loads(json.dumps(_LIVE_SHAPE))
    rec["failed"] = True
    degraded, reason = headers_check_is_degraded(0, _line(rec), "")
    assert degraded and reason == "host_unreachable"


def test_missing_header_map_degrades_rather_than_emitting_findings():
    """⚠ If -irh is accepted but no header map comes back, that is a TOOL
    fault. Treating it as 'no headers present' would emit seven fabricated
    findings — the same fleet-wide false positive the key translation
    guards against, reached by a different route."""
    rec = json.loads(json.dumps(_LIVE_SHAPE))
    del rec["header"]
    degraded, reason = headers_check_is_degraded(0, _line(rec), "")
    assert degraded and reason == "no_header_map"


def test_healthy_record_is_not_degraded():
    degraded, _ = headers_check_is_degraded(0, _line(_LIVE_SHAPE), "")
    assert not degraded


def test_no_curl_failed_reason_survives_the_migration():
    """The whole point of ㊴: no unmapped catch-all remains that could be
    recorded as a fact about the target.

    ⚠ Asserts on RETURNED VALUES via ast, not on source text. The first cut
    of this test grepped the function body and failed against its own
    DOCSTRING, which explains the `curl_failed` history. That is the third
    time in one day a source pin matched prose instead of code
    (feedback_source_pins_must_strip_comments). ast can't make that mistake:
    a docstring is not a return value.
    """
    import ast

    tree = ast.parse(Path(run_light.__file__).read_text())
    fn = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "headers_check_is_degraded"
    )
    returned = {
        c.value
        for node in ast.walk(fn)
        if isinstance(node, ast.Return)
        for c in ast.walk(node.value or ast.Constant(value=None))
        if isinstance(c, ast.Constant) and isinstance(c.value, str)
    }
    assert "curl_failed" not in returned, (
        f"headers_check_is_degraded can still RETURN 'curl_failed' — the "
        f"unmapped curl exit code is exactly the false reachability verdict "
        f"㊴ removes. Returns: {sorted(returned)}"
    )
    # Floor: if this found no reasons at all it would pass vacuously.
    assert len(returned) >= 3, (
        f"only {len(returned)} return-string(s) found — the function shape "
        f"changed and this check would pass by examining nothing: {returned}"
    )


# ── harness ───────────────────────────────────────────────────────────

def _ctx(monkeypatch, rec: dict):
    """Minimal ScanContext + a run_cmd stub returning the given httpx record.

    ⚠ Calls the SHIPPED check_headers, never a mirror of it — the
    pure-function-test lesson. If the real function stops parsing `header`,
    these tests fail.
    """
    class _Ctx:
        hostname = "www.prodexlabs.com"
        def __init__(self):
            self.tools_run, self.findings, self.artifacts = [], [], []
            self.tool_status = {}

    ctx = _Ctx()
    monkeypatch.setattr(run_light, "run_cmd",
                        lambda *a, **k: (0, _line(rec), ""))
    monkeypatch.setattr(run_light, "log", lambda *a, **k: None)
    monkeypatch.setattr(run_light, "mark_tool_ok", lambda *a, **k: None)
    monkeypatch.setattr(run_light, "mark_tool_degraded", lambda *a, **k: None)
    return ctx
