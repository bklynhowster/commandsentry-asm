"""Anchor tests for the differential WAF-presence logic (4.7 Cloud Armor Q1/Q2/Q3).

The two headline fixtures are REAL data captured 2026-07-20 (see Obsidian 146):
  - NEGATIVE = demo.prodexlabs.com: benign + every attack class returned HTTP 200 at a
    byte-identical 2991 B -> nothing inspecting -> NOT a WAF (the true negative).
  - POSITIVE = commandcommcentral.com (FortiWeb): benign 200/39460 B, attack payloads
    500/39116 B (differ, generic edge error, no app context) -> a WAF is blocking.
These two are the guardrail 4.7 asked for against the single-class-shortcut risk.
"""
from waf_differential import classify_waf_differential, INDEPENDENT_CLASSES


# ── NEGATIVE: demo.prodexlabs.com — real all-pass (no WAF) ────────────────────
def test_demo_all_identical_is_not_a_waf():
    base = {"status": 200, "size": 2991, "tokens": {"demo_app_home"}, "headers": {"content-type"}}
    payloads = [{"cls": c, "status": 200, "size": 2991,
                 "tokens": {"demo_app_home"}, "headers": {"content-type"}}
                for c in INDEPENDENT_CLASSES]           # byte-identical to benign
    res = classify_waf_differential(base, payloads)
    assert res["waf_present"] is False
    assert res["blocked"] == []
    assert res["evidence_class"] == "presence_only"


# ── POSITIVE: ccc / FortiWeb — real differential block (WAF present) ───────────
def test_ccc_fortiweb_differential_is_a_waf():
    base = {"status": 200, "size": 39460,
            "tokens": {"ccc_app_page"}, "headers": {"cookiesession1", ".sci.session"}}
    # attack payloads short-circuited at the edge: 500 / 39116, generic, no app context.
    edge = lambda c: {"cls": c, "status": 500, "size": 39116, "tokens": {"edge_500"}, "headers": set()}
    res = classify_waf_differential(base, [edge("sqli"), edge("xss")])
    assert res["waf_present"] is True                    # >=2 independent classes blocked
    assert set(res["blocked"]) == {"sqli", "xss"}
    assert res["evidence_class"] == "presence_only"      # NEVER names FortiWeb here (Q3)


# ── Q1 tripwire: a SINGLE class blocking is NOT a WAF (app input-validator FP) ─
def test_single_class_block_is_not_asserted():
    base = {"status": 200, "size": 2991, "tokens": {"app"}, "headers": {"content-type"}}
    payloads = [
        {"cls": "sqli", "status": 403, "size": 90, "tokens": {"edge"}, "headers": set()},   # blocks
        {"cls": "xss",  "status": 200, "size": 2991, "tokens": {"app"}, "headers": {"content-type"}},  # passes
        {"cls": "lfi",  "status": 200, "size": 2991, "tokens": {"app"}, "headers": {"content-type"}},  # passes
    ]
    res = classify_waf_differential(base, payloads)
    assert res["waf_present"] is False                   # 1 class < the >=2 bar
    assert res["blocked"] == ["sqli"]


# ── Q2 gate 4/5: a deny that leaks the app's own context is the APP's 403, not edge ──
def test_app_context_leak_does_not_count_as_a_waf_block():
    base = {"status": 200, "size": 5000, "tokens": {"acme_portal"}, "headers": {"acme_session"}}
    # two payloads "differ" from baseline, but each leaks an app token / app header ->
    # gates 4/5 reject them -> NOT counted -> below the bar despite two differences.
    leaky = lambda c: {"cls": c, "status": 403, "size": 4800,
                       "tokens": {"acme_portal"}, "headers": {"acme_session"}}
    res = classify_waf_differential(base, [leaky("sqli"), leaky("xss")])
    assert res["waf_present"] is False
    assert res["blocked"] == []


# ── gate 1: a differential against a non-2xx baseline is undefined (e.g. dead origin) ─
def test_baseline_not_2xx_is_inconclusive():
    base = {"status": 504, "size": 1313, "tokens": set(), "headers": set()}
    payloads = [{"cls": c, "status": 504, "size": 1313, "tokens": set(), "headers": set()}
                for c in INDEPENDENT_CLASSES]
    res = classify_waf_differential(base, payloads)
    assert res["waf_present"] is False
    assert "baseline not 2xx" in res["reason"]


# ── two variations of the SAME class don't satisfy the >=2 INDEPENDENT-class bar ──
def test_two_same_class_variants_are_not_independent():
    base = {"status": 200, "size": 3000, "tokens": {"app"}, "headers": {"ct"}}
    # both are 'sqli' (union + boolean) -> the set collapses to one class.
    payloads = [{"cls": "sqli", "status": 403, "size": 80, "tokens": {"e"}, "headers": set()},
                {"cls": "sqli", "status": 403, "size": 80, "tokens": {"e"}, "headers": set()}]
    res = classify_waf_differential(base, payloads)
    assert res["waf_present"] is False
    assert res["blocked"] == ["sqli"]
