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
