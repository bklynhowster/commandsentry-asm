#!/usr/bin/env python3
"""(C) refusal capture + (A) the one malformed GET. Relay 295 — Howie's R30 ruling.

⛔ WHY THE PAIR EXISTS. `is_armor_block` — 400 plus Google's "malformed or illegal
request" — has been in the tree since the Cloud Armor spec and has never fired, because
NOTHING RECORDED A REFUSAL BODY. Measured 2026-09-18 across both estates: 2419 Prodex
artifacts carry zero Armor bodies and zero 400s of any kind, and ~900 common_paths
probes produced 200/404/301/504/302/403 and not one 400. Armor refuses MALFORMED
requests; every request this scanner sent was well-formed. A predicate with no
collector cannot be wrong and cannot be right.

⚠ NO VENDOR SIGNATURE IS ASSERTED HERE. The bodies do not exist yet. Capture ships
first and the fixtures come from the first light scans that carry it — 4.7's sequence,
and the rule that a fixture a human composed is not the bytes a tool emits.
"""
from __future__ import annotations

import json
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_light as L  # noqa: E402


def _ctx():
    return types.SimpleNamespace(hostname="x.example", artifacts=[], findings=[])


def _arts(ctx, name="refusal_response"):
    return [json.loads(a[2]) for a in ctx.artifacts if a[0] == name]


def test_a_400_is_captured_with_its_body():
    ctx = _ctx()
    assert L.record_refusal(ctx, "common_paths", "/x", 400, "blocked: reason here") is True
    (art,) = _arts(ctx)
    assert art["status"] == 400 and art["source"] == "common_paths" and art["path"] == "/x"
    assert art["body_snippet"] == "blocked: reason here"
    assert art["truncated"] is False and art["body_bytes"] == 20


def test_anything_that_is_not_a_refusal_status_records_nothing():
    """⚠ The capture is scoped to the status that carries the tell. Widening it is a
    ruling, not a convenience — every recorded body is data we now hold."""
    ctx = _ctx()
    for code in (200, 301, 403, 404, 500, 504, 0):
        assert L.record_refusal(ctx, "common_paths", "/x", code, "body") is False
    assert _arts(ctx) == []


def test_the_body_is_bounded_and_the_truncation_is_declared():
    ctx = _ctx()
    L.record_refusal(ctx, "common_paths", "/x", 400, "A" * (L.REFUSAL_BODY_MAX + 500))
    (art,) = _arts(ctx)
    assert len(art["body_snippet"]) == L.REFUSAL_BODY_MAX
    assert art["truncated"] is True
    assert art["body_bytes"] == L.REFUSAL_BODY_MAX + 500      # the REAL size, not the stored one


def test_the_body_is_stored_raw_not_normalised():
    """⚠ THE ANSI LESSON. Store what arrived; read a normalised copy. A signature we
    have not written yet may depend on case or on whitespace."""
    ctx = _ctx()
    body = "  Your client has issued a MALFORMED or illegal request.  \n"
    L.record_refusal(ctx, "refusal_probe", "/%zz", 400, body)
    (art,) = _arts(ctx)
    assert art["body_snippet"] == body        # byte for byte, no strip, no lower


def test_an_empty_body_still_records_the_refusal():
    """A 400 with no body is still a refusal — and 'we saw nothing' must be
    distinguishable from 'we never asked', which is why the artifact exists at all."""
    ctx = _ctx()
    assert L.record_refusal(ctx, "common_paths", "/x", 400, None) is True
    (art,) = _arts(ctx)
    assert art["body_snippet"] == "" and art["body_bytes"] == 0


def test_the_probe_sends_exactly_one_request_and_never_retries(monkeypatch):
    calls = []

    def fake(ctx, path):
        calls.append(path)
        return 400, "refused", None

    monkeypatch.setattr(L, "_probe_path_body", fake)
    ctx = _ctx()
    L.probe_refusal_signature(ctx)
    assert calls == [L.REFUSAL_PROBE_PATH], f"expected ONE request, got {calls}"
    assert len(_arts(ctx)) == 1


def test_a_transport_failure_is_not_retried_and_records_nothing(monkeypatch):
    """⛔ ONE REQUEST MEANS ONE. A retry on failure would double the estate-wide
    request budget for the case where the host is least able to answer."""
    calls = []
    monkeypatch.setattr(L, "_probe_path_body",
                        lambda ctx, path: (calls.append(path), (0, "", None))[1])
    ctx = _ctx()
    L.probe_refusal_signature(ctx)
    assert calls == [L.REFUSAL_PROBE_PATH] and _arts(ctx) == []


def test_a_host_that_answers_the_malformed_path_normally_records_nothing(monkeypatch):
    """Not every front end refuses. A 404 to /%zz is an answer, not a refusal."""
    monkeypatch.setattr(L, "_probe_path_body", lambda ctx, path: (404, "not found", None))
    ctx = _ctx()
    L.probe_refusal_signature(ctx)
    assert _arts(ctx) == []


def test_the_probe_path_is_malformed_not_sensitive():
    """⚠ THE ROE SHAPE OF THE REQUEST. It must be malformed at the URL layer and must
    not ask for anything: no traversal, no payload, no admin path, no secret file."""
    p = L.REFUSAL_PROBE_PATH
    assert p.startswith("/") and len(p) <= 8
    assert "%" in p and ".." not in p and "/." not in p
    for word in ("admin", "env", "git", "config", "wp-", "etc", "passwd", "sql", "script"):
        assert word not in p.lower()


def test_the_probe_runs_before_the_path_enumeration_and_only_in_the_https_suite():
    """⛔ ORDERING. Light has no passive collector — that is heavy-only — so the
    collector-first rule maps to: after the quiet checks, before the first enumeration.
    Asked of the source order, because the ordering IS the rule."""
    import inspect
    src = inspect.getsource(L)
    i_probe = src.index("probe_refusal_signature(ctx)\n", src.index("→ HTTPS suite"))
    i_paths = src.index("check_common_paths(ctx)\n", src.index("→ HTTPS suite"))
    i_tls = src.index("check_tls(ctx)\n", src.index("→ HTTPS suite"))
    assert i_tls < i_probe < i_paths, "the refusal probe is out of order"


def test_capture_is_wired_into_the_shared_path_helper_not_copied_per_caller():
    """One reader, one writer: every path probe in this file goes through
    `_probe_path_body`, so the capture is called where the body already is."""
    import inspect
    src = inspect.getsource(L.check_common_paths)
    assert "record_refusal(ctx, \"common_paths\"" in src


def test_no_vendor_signature_is_asserted_anywhere_yet():
    """⛔ THE POINT OF SHIPPING CAPTURE ALONE. Until a real refusal body exists in the
    DB, any signature here would be a string someone typed — the exact mistake that made
    a hand-written `ftp.sciimage.com` fixture disagree with production.

    ⚠ MY FIRST VERSION OF THIS TEST FAILED ON ITS OWN SUBJECT MATTER. It searched the
    module TEXT, and the module's comments EXPLAIN the Armor signature in order to say
    why capture must ship first — so the guard flagged the explanation as the offence.
    Ninth prose-vs-checker in this codebase and the rule is settled: **a text check over
    a region that contains prose asks the wrong question.** This one walks the AST and
    looks only at STRING LITERALS THE CODE EVALUATES, with docstrings excluded — a
    signature is a thing you compare against, not a thing you write about."""
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(L))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None) or []
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))
    literals = [n.value.lower() for n in ast.walk(tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and id(n) not in docstrings]
    for invented in ("malformed or illegal", "attention required", "cloudflare ray",
                     "fortiweb", "blocked by"):
        hits = [lit for lit in literals if invented in lit]
        assert not hits, f"a vendor signature is EVALUATED in run_light: {hits[:2]}"


# ══ THE ROE INVENTORY ════════════════════════════════════════════════════════

def test_the_probe_is_declared_in_the_ROE_inventory_and_they_agree():
    """⛔ 4.7's instruction: "the ROE gate must know it exists — do not smuggle it into
    common_paths." Declared in one list, and PINNED to the probe: change the path in
    one place and the build fails rather than the inventory going quietly stale."""
    import roe_gate
    probes = [p for p in roe_gate.DELIBERATE_REFUSAL_PROBES if p["name"] == "refusal_probe"]
    assert len(probes) == 1, "the refusal probe is not declared exactly once"
    (p,) = probes
    assert p["path"] == L.REFUSAL_PROBE_PATH, \
        f"inventory says {p['path']!r}, run_light sends {L.REFUSAL_PROBE_PATH!r}"
    assert p["tier"] == "light" and p["method"] == "GET"
    assert p["requests_per_host_per_scan"] == 1 and p["retries"] == 0
    assert p["escalates"] is False
    assert p["authorised_by"].startswith("Howie"), "a refused-by-design request needs its ruling"


def test_the_inventory_holds_exactly_one_entry():
    """⚠ The value of this list is that it is short. A second entry is a decision, and
    this test is where someone has to notice they are making one."""
    import roe_gate
    assert len(roe_gate.DELIBERATE_REFUSAL_PROBES) == 1


def test_the_budget_is_stated_as_a_number_not_a_paragraph():
    import roe_gate
    assert roe_gate.deliberate_refusal_budget(0) == 0
    assert roe_gate.deliberate_refusal_budget(78) == 78          # Command: 78 live assets
    assert roe_gate.deliberate_refusal_budget(78, scans_per_day=4) == 312


# ══ T4 = A — the landing page is the verdict (relay 152 / 303 / 304) ═════════

def test_followup_severity_reads_only_what_was_observed():
    """⛔ HOWIE'S RULING A. 152 asked for "200 with Swagger UI content"; no swagger
    landing body exists in either estate (7768 Command artifacts, relay 302), so the
    content test would be a signature typed from memory. Status and content-type are
    facts the server sent."""
    import run_medium as M
    assert M.followup_severity(200, "text/html", is_staging=False) == "MODERATE"
    assert M.followup_severity(200, "text/html; charset=utf-8", is_staging=True) == "LOW"
    assert M.followup_severity(200, "application/json", is_staging=False) == "LOW"
    for gated in (401, 403, 404, 500):
        assert M.followup_severity(gated, "text/html", is_staging=False) == "INFO"


def test_the_followup_never_leaves_the_host():
    """⛔ 152's gate: on-host, one hop. Enforced, not trusted."""
    import run_medium as M
    assert M._same_site("https://x.example/swagger/index.html", "x.example") is True
    assert M._same_site("https://a.x.example/s", "x.example") is True
    assert M._same_site("https://evil.example/x", "x.example") is False
    assert M._same_site("not a url", "x.example") is False


def test_only_the_path_exists_family_is_followed():
    import run_medium as M
    assert "swagger" in M._FOLLOWUP_WORDS and "admin" in M._FOLLOWUP_WORDS
    assert "wp-login" not in M._FOLLOWUP_WORDS and ".env" not in M._FOLLOWUP_WORDS


def test_the_followup_is_declared_in_the_request_inventory():
    """The same rule the refusal probe follows: what we send is one list, not a code read."""
    import roe_gate
    (p,) = [x for x in roe_gate.FOLLOWUP_PROBES if x["name"] == "path_followup"]
    assert p["hops"] == 1 and p["retries"] == 0 and p["same_site_only"] is True
    assert p["method"] == "GET"
    import run_medium as M
    assert set(p["words"]) == set(M._FOLLOWUP_WORDS), "the inventory and the code disagree"


# ══ 4.7's 306 hold — the CALLER's use of the guard, not just the guard ════════
# ⛔ `_same_site` was tested pure and its USE was not: inverting
# `if not _same_site(...)` to `if _same_site(...)` survived the whole suite. That is
# the mutant-D/L shape one more time — a safety decision reachable only when the code
# runs, while pure tests stay green — and it sits on the single line that keeps the
# one deliberate follow-up request on the host we were asked to scan.
#
# The assertion that matters is NOT "returns None". It is THAT NO REQUEST WAS SENT.
# A guard that returns None after firing the request has already broken the ROE.

def _followup_ctx(web_host="x.example"):
    return types.SimpleNamespace(web_host=web_host, hostname=web_host,
                                 artifacts=[], findings=[])


def _spy_run_cmd(calls, stdout=""):
    def fake(cmd, timeout=30, **kw):
        calls.append(cmd)
        return (0, stdout, "") if stdout else (1, "", "no such host")
    return fake


def test_an_offsite_redirect_sends_no_request_at_all(monkeypatch):
    """⛔ THE ROE LINE. An absolute off-host redirect target must be dropped BEFORE
    httpx runs — the skip is the point, the None is just how it is reported."""
    import run_medium as M
    calls = []
    monkeypatch.setattr(M, "run_cmd", _spy_run_cmd(calls, '{"status_code":200}'))
    ctx = _followup_ctx()
    out = M.follow_path_redirect(ctx, "swagger", "https://evil.example/swagger/", False)
    assert calls == [], "a request was sent to an off-host target"
    assert out is None
    assert [a for a in ctx.artifacts if a[0] == "path_followup"] == []


def test_an_onsite_redirect_proceeds_and_records_the_landing(monkeypatch):
    """The other half of the same mutation: inverting the guard skips the LEGITIMATE
    target, so this test dies too. One inversion, two failures."""
    import run_medium as M
    calls = []
    body = json.dumps({"status_code": 200, "content_type": "text/html",
                       "body": "<html>doc</html>"})
    monkeypatch.setattr(M, "run_cmd", _spy_run_cmd(calls, body))
    ctx = _followup_ctx()
    out = M.follow_path_redirect(ctx, "swagger", "/swagger/index.html", False)
    assert len(calls) == 1, "the on-host follow-up did not fire"
    assert out == (200, "text/html", "MODERATE")
    (art,) = [json.loads(a[2]) for a in ctx.artifacts if a[0] == "path_followup"]
    assert art["url"] == "https://x.example/swagger/index.html"
    assert art["body_snippet"] == "<html>doc</html>"


def test_the_request_target_is_the_one_the_guard_approved(monkeypatch):
    """A guard that checks one URL while the request fetches another is decoration.
    The URL httpx is handed must be the URL `_same_site` was asked about."""
    import run_medium as M
    calls = []
    monkeypatch.setattr(M, "run_cmd", _spy_run_cmd(calls, '{"status_code":404}'))
    seen = []
    real = M._same_site
    monkeypatch.setattr(M, "_same_site", lambda u, h: (seen.append(u), real(u, h))[1])
    M.follow_path_redirect(_followup_ctx(), "admin", "/admin/", False)
    (cmd,) = calls
    assert seen == [cmd[cmd.index("-u") + 1]]


def test_a_subdomain_redirect_is_on_host_and_a_lookalike_is_not(monkeypatch):
    """The two cases the caller actually meets in this estate, driven THROUGH the
    caller: www.x.example is ours, x.example.evil.test is not."""
    import run_medium as M
    for target, should_fire in (("https://www.x.example/admin/", True),
                                ("https://x.example.evil.test/admin/", False)):
        calls = []
        monkeypatch.setattr(M, "run_cmd", _spy_run_cmd(calls, '{"status_code":403}'))
        M.follow_path_redirect(_followup_ctx(), "admin", target, False)
        assert bool(calls) is should_fire, target


def test_a_204_is_not_scored_as_a_document(monkeypatch):
    """4.7's 306 nit, folded. 204 is DEFINED to have no body, so text/html on a 204
    is a header describing nothing — "something answered" (LOW), never MODERATE."""
    import run_medium as M
    assert M.followup_severity(204, "text/html", is_staging=False) == "LOW"
    assert M.followup_severity(206, "text/html", is_staging=False) == "LOW"
    assert M.followup_severity(200, "text/html", is_staging=False) == "MODERATE"
