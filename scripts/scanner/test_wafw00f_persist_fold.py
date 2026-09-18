#!/usr/bin/env python3
"""The wafw00f parse and its persist are ONE operation — relay 216/217, 2026-09-16.

⛔ WHAT WAS BROKEN. `detect_waf()` parsed wafw00f and appended the RAW artifact.
`persist_stack_id_wafw00f()` — which writes the STRUCTURED verdict the classifier
actually reads — was a separate function, called from exactly one place: the line
after `detect_waf(ctx)` in run_medium.run()'s linear body.

`phase_registry.py:72` registers the FUNCTION `_medium.detect_waf`, not the pair.
When the heavy cutover (b51ef0c1 / 16d778e9, 2026-08-29) began dispatching phases
through `run_phases`, heavy inherited the parse and not the persist:

    heavy runs with a raw `wafw00f` artifact and no `stack_id_wafw00f`   18 of 18
    medium runs with both                                               22 of 22

Clean split on `scan_run.intensity`, 45-day window, Command. Prodex identical in
shape. So every heavy-derived WAF confirmation since 2026-08-29 was discarded:
wafw00f named FortiWeb on commandcommcentral.com on 2026-09-03 and the classifier
never heard it — the host then read as `waf/suspected` instead of `waf/confirmed`.

⭐ THE SHAPE IS `bump_alive_clock` / `resurrect_if_dark`: two operations that must
happen together, held together only by ADJACENCY IN ONE CALLER. They come apart
the moment a second caller appears. The registry was that second caller.

⚠ AND IT WAS ALREADY WRITTEN DOWN. test_corpus_prewarm.py names this exact
instance in a comment — "persist_stack_id_wafw00f lives in run_medium.run()'s
LINEAR BODY, so HEAVY ... never reaches it" — recorded while fixing its mirror
image (corpus_prewarm, registered-but-unreachable) and left unfixed. The comment
is now stale and has been corrected in place.

⛔ WHY THE FIX IS A FOLD AND NOT A REGISTERED PAIR (4.7 ruling 8): registering two
functions would preserve the two-ness that caused this. One function, one artifact
pair, every caller.

⚠ THE EARLY-RETURN TRAP. `detect_waf` had THREE `return`s — including the
named-vendor path, the one that matters. Appending the persist to the end of the
body would have been skipped on every successful detection: the same bug wearing a
fix's clothes. The parse moved to `_classify_wafw00f_output` (verbatim, returns
intact) so detect_waf's final persist is unconditional. This file pins that.
"""

from __future__ import annotations

import json
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_medium as m  # noqa: E402
import phase_registry  # noqa: E402

FORTIWEB = (
    "[*] Checking https://commandcommcentral.com/\n"
    "[+] The site https://commandcommcentral.com/ is behind FortiWeb (Fortinet) WAF.\n"
    "[~] Number of requests: 5\n"
)
GENERIC = "[*] The site seems to be behind a WAF or some sort of security solution\n"
NO_WAF = "[-] No WAF detected by the generic detection\n"


def _ctx():
    """Duck-typed, same spirit as test_stack_id_wafw00f.py's _ctx."""
    return types.SimpleNamespace(
        web_host="commandcommcentral.com", hostname="commandcommcentral.com",
        waf_detected=False, waf_kind=None,
        artifacts=[], tools_run=[], tool_status={},
        target_proven_reachable=False,
    )


def _fake_run_cmd(stdout, rc=0):
    return lambda *a, **k: (rc, stdout, "")


def _names(ctx):
    return [a[0] for a in ctx.artifacts]


def _verdict(ctx):
    blob = next(a[2] for a in ctx.artifacts if a[0] == "stack_id_wafw00f")
    return json.loads(blob)


# ---------------------------------------------------------------------------
# ⭐ THE PIN — both artifacts, on every exit path, via BOTH callers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("stdout,detected,kind", [
    (FORTIWEB, True, "fortiweb"),   # the named-vendor EARLY RETURN — the case that broke
    (GENERIC, True, "generic"),     # the generic EARLY RETURN
    (NO_WAF, False, None),          # the fall-through
])
def test_detect_waf_always_writes_both_artifacts(monkeypatch, stdout, detected, kind):
    """One call, both artifacts, whichever branch the parse takes.

    Parametrised over all three exit paths on purpose: the fix's whole risk is that
    a `return` skips the persist, and only the fall-through case would have caught
    a naive end-of-body append."""
    monkeypatch.setattr(m, "run_cmd", _fake_run_cmd(stdout))
    ctx = _ctx()
    m.detect_waf(ctx)
    assert "wafw00f" in _names(ctx), "the raw artifact must still be written"
    assert "stack_id_wafw00f" in _names(ctx), (
        "the structured verdict must be written by detect_waf itself — this is the "
        "defect: heavy reached the parse and never the persist")
    assert _verdict(ctx) == {
        "schema": 1, "wafw00f_detected": detected, "wafw00f_kind": kind}


def test_the_named_vendor_path_is_the_one_that_regressed(monkeypatch):
    """commandcommcentral.com, 2026-09-03, reproduced from the real output.

    Named FortiWeb -> `wafw00f_kind: 'fortiweb'`, which is the high-confidence
    signal carrying `waf/confirmed`. Losing THIS is what made a FortiGate-fronted
    host read as merely suspected."""
    monkeypatch.setattr(m, "run_cmd", _fake_run_cmd(FORTIWEB))
    ctx = _ctx()
    m.detect_waf(ctx)
    assert _verdict(ctx)["wafw00f_kind"] == "fortiweb"


def test_exactly_one_structured_verdict_per_call(monkeypatch):
    """The medium path used to call the persist separately. That call was DELETED,
    not moved — if it were left in place medium would write the artifact twice and
    the newest-wins read would be picking between duplicates."""
    monkeypatch.setattr(m, "run_cmd", _fake_run_cmd(FORTIWEB))
    ctx = _ctx()
    m.detect_waf(ctx)
    assert _names(ctx).count("stack_id_wafw00f") == 1
    assert _names(ctx).count("wafw00f") == 1


# ---------------------------------------------------------------------------
# the HEAVY path — through the registry, which is how this broke
# ---------------------------------------------------------------------------

def test_the_registry_phase_carries_both_halves(monkeypatch):
    """⛔ THE ACTUAL REGRESSION PATH. heavy never calls detect_waf by name; it
    dispatches `phase_registry`'s spec through run_phases. Resolve the registered
    callable and invoke it exactly as the registry would — if the persist is not
    inside the registered function, this fails."""
    monkeypatch.setattr(m, "run_cmd", _fake_run_cmd(FORTIWEB))
    spec = next((s for s in phase_registry.all_phases() if s.name == "wafw00f"), None) \
        if hasattr(phase_registry, "all_phases") else None
    if spec is None:                       # registry accessor differs — resolve by attribute
        fn = m.detect_waf
    else:
        fn = spec.fn
    ctx = _ctx()
    fn(ctx)
    assert "stack_id_wafw00f" in _names(ctx), (
        "the REGISTERED callable must write the structured verdict — registering "
        "detect_waf alone is exactly what lost 18 of 18 heavy verdicts")


def test_the_registered_callable_is_detect_waf_itself():
    """Guards the assumption the test above rests on. If the registry is ever
    pointed at a wrapper, the fold has to move with it."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "phase_registry.py"), encoding="utf-8").read()
    assert '_register("wafw00f", MEDIUM, _medium.detect_waf' in src, (
        "the registry no longer registers _medium.detect_waf — re-point this pin "
        "at whatever it registers now, and check the fold is inside THAT")


# ---------------------------------------------------------------------------
# structural: the pair cannot be separated again
# ---------------------------------------------------------------------------

def test_persist_is_called_from_inside_detect_waf_and_nowhere_else():
    """The structural half of the pin. A future edit that moves the persist back
    out to a call site — which is precisely how this happened — fails here even if
    every behavioural test above still passes on the medium path."""
    import ast
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "run_medium.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "detect_waf")
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and getattr(n.func, "id", "") == "persist_stack_id_wafw00f"]
    assert len(calls) == 1, (
        f"persist_stack_id_wafw00f is called {len(calls)}x — it must be called "
        f"exactly once, from inside detect_waf. Lines: {[c.lineno for c in calls]}")
    assert fn.lineno <= calls[0].lineno <= fn.end_lineno, (
        "the persist call is outside detect_waf again — that is the original defect")


def test_detect_waf_has_no_early_returns_before_the_persist():
    """The early-return trap, pinned. Three `return`s used to live in this function;
    they now live in `_classify_wafw00f_output`. If anyone puts a `return` back into
    detect_waf, the persist becomes conditional and the bug returns silently."""
    import ast
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "run_medium.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "detect_waf")
    rets = [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Return)]
    assert not rets, (
        f"detect_waf has return(s) at {rets}. The persist is its last statement, so "
        f"any early return skips it — put the branch in _classify_wafw00f_output")


# ══ VENDOR-AGNOSTIC STACK ID (relay 279/288) ═════════════════════════════════
# Howie, 2026-09-17: "the world is full of other web application firewalls other than
# FortiGate, for example Google Armor. I want our ability to detect to not be limited
# to just FortiGate. That could go in the garbage tomorrow."
#
# ⛔ THE BYTES, NOT OUR PROSE FOR THEM. Every string below is a production wafw00f line
# read from the two estates on 2026-09-18 — 55 Prodex artifacts say "Google Cloud App
# Armor", 1 says "Azure Front Door", 33 Command artifacts say "FortiWeb". The spec, the
# queue entry and my own first draft all said "Google Cloud ARMOR"; the tool says
# "Google Cloud APP Armor", and a hand-typed key would have matched nothing.

_PROD_LINES = {
    "[+] The site https://prodexlabs.com/ is behind Google Cloud App Armor (Google Cloud) WAF.":
        "google_cloud_app_armor",
    "[+] The site https://azure-demo.prodexlabs.com/ is behind Azure Front Door (Microsoft) WAF.":
        "azure_front_door",
    "[+] The site https://commandcommcentral.com/ is behind FortiWeb (Fortinet) WAF.":
        "fortiweb",
}


def _kind(line):
    ctx = types.SimpleNamespace(waf_detected=False, waf_kind=None, artifacts=[])
    saved = m.log
    m.log = lambda *a, **k: None
    try:
        m._classify_wafw00f_output(ctx, line, 0)
    finally:
        m.log = saved
    return ctx.waf_kind


def test_the_product_string_survives_the_parse_on_production_bytes():
    for line, want in _PROD_LINES.items():
        assert _kind(line) == want, f"{line!r} -> {_kind(line)!r}, wanted {want!r}"


def test_the_old_one_word_capture_would_have_lost_the_product():
    """What the defect cost, stated as a test rather than a story: two of the three
    production vendors collapsed to a hosting company's name."""
    import re
    old = lambda s: (re.search(r"is behind\s+([A-Za-z][A-Za-z0-9_\-]+)", s).group(1).lower())
    lines = list(_PROD_LINES)
    assert old(lines[0]) == "google" and _kind(lines[0]) == "google_cloud_app_armor"
    assert old(lines[1]) == "azure" and _kind(lines[1]) == "azure_front_door"
    assert old(lines[2]) == _kind(lines[2]) == "fortiweb"      # single token: unchanged


def test_a_vendor_nobody_has_written_code_for_still_gets_a_key():
    """The requirement, mechanised: the key is DERIVED, so a WAF the registry has never
    heard of is still identified the day wafw00f learns it. No hand-maintained list."""
    assert _kind("[+] The site https://x/ is behind Imperva SecureSphere WAF.") == "imperva_securesphere"
    assert _kind("[+] The site https://x/ is behind AWS Elastic Load Balancer (Amazon) WAF.") \
        == "aws_elastic_load_balancer"
    assert m.waf_kind_key("Barracuda Application Firewall") == "barracuda_application_firewall"


def test_the_widening_is_strict_no_detection_that_worked_can_stop_working():
    """⚠ A line with no ' WAF.' suffix falls back to the original single-token capture."""
    assert _kind("[+] The site https://x/ is behind Incapsula") == "incapsula"
    assert _kind("[*] The site https://x/ seems to be behind a WAF or some sort of "
                 "security solution") == "generic"
    assert _kind("[-] No WAF detected by the generic detection") is None


def test_waf_kind_key_is_pure_and_total():
    assert m.waf_kind_key(None) is None and m.waf_kind_key("") is None
    assert m.waf_kind_key("   ") is None
    assert m.waf_kind_key("FortiWeb") == m.waf_kind_key("  fortiweb  ") == "fortiweb"


def test_the_legacy_aliases_move_forward_only_and_cover_exactly_what_we_wrote():
    """⛔ ONE DIRECTION. The alias table exists to correct keys THIS PARSER wrote, and
    nothing else — 42 `google` + 1 `azure` rows on Prodex (relay 286). A canonical key
    maps to itself; an unknown key is left alone rather than guessed at."""
    assert m.canonical_waf_kind("google") == "google_cloud_app_armor"
    assert m.canonical_waf_kind("azure") == "azure_front_door"
    assert m.canonical_waf_kind("google_cloud_app_armor") == "google_cloud_app_armor"
    assert m.canonical_waf_kind("fortiweb") == "fortiweb"
    assert m.canonical_waf_kind("cloudflare") == "cloudflare"
    assert m.canonical_waf_kind(None) is None
    assert set(m.WAF_KIND_ALIASES) == {"google", "azure"}


def test_the_registry_can_now_reach_the_vendors_the_estates_actually_front():
    """⛔ THE GAP, MEASURED BEFORE AND AFTER. `wafw00f_high_confidence` matched only
    fortiweb|fortinet|cloudflare, so the 55 Prodex artifacts naming Google Cloud App
    Armor could never reach waf/confirmed on the wafw00f path — whatever the backfill
    wrote. The registry now carries both vendors on BOTH tiers (heavy + discovery)."""
    import yaml
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    fps = yaml.safe_load(open(os.path.join(root, "asm", "device_fingerprints.yaml")))
    subs = {}
    def walk(o):
        if isinstance(o, dict):
            if str(o.get("signal", "")).startswith("wafw00f"):
                subs.setdefault(o["signal"], []).extend(o["match_substrings"])
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(fps)
    for tier in ("wafw00f_high_confidence", "wafw00f_discovery_confidence"):
        flat = " ".join(subs[tier])
        for key in ("google_cloud_app_armor", "azure_front_door", "fortiweb", "cloudflare"):
            assert key in flat, f"{tier} cannot match {key}"
