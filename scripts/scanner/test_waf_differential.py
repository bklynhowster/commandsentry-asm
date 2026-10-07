"""Anchor tests for the differential WAF-presence logic (4.7 Cloud Armor Q1/Q2/Q3).

The two headline fixtures are REAL data captured 2026-07-20 (see Obsidian 146):
  - NEGATIVE = demo.prodexlabs.com: benign + every attack class returned HTTP 200 at a
    byte-identical 2991 B -> nothing inspecting -> NOT a WAF (the true negative).
  - POSITIVE = commandcommcentral.com (FortiWeb): benign 200/39460 B, attack payloads
    500/39116 B (differ, generic edge error, no app context) -> a WAF is blocking.
These two are the guardrail 4.7 asked for against the single-class-shortcut risk.
"""
from waf_differential import (classify_waf_differential, INDEPENDENT_CLASSES,
                              _EDGE_STATUS, _SMALL_BODY, _payload_blocked)


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
def test_ccc_fortiweb_blocks_all_five_by_two_mechanisms():
    """⚠ FIXTURE CORRECTED THREE TIMES, and the last correction reversed the second.
    2026-07-20: the 500s were called edge blocks. relay 523/525: called app chokes and the
    500s were EXCLUDED. relay 528, measured in a browser: the 500 body reads "Web Page
    Blocked! / Attack ID: 20000008" — a FortiWeb block page served at HTTP 500. The original
    call was right for the wrong reason; the correction was wrong for a good one.

    Real coverage is 5 of 5 by TWO mechanisms, which is why status alone could never see it."""
    base = {"status": 200, "size": 39460,
            "tokens": {"ccc_app_page"}, "headers": {"cookiesession1", ".sci.session"}}
    page = lambda c, n: {"cls": c, "status": 500, "size": n, "tokens": {"t:blocked"},
                         "headers": set(), "block_tell": "FortiWeb"}
    terse = lambda c: {"cls": c, "status": 403, "size": 15, "tokens": set(),
                       "headers": set(), "block_tell": ""}
    res = classify_waf_differential(base, [
        page("sqli", 39121), page("xss", 39120), page("lfi", 39131),
        terse("log4shell-param"), terse("ssrf-metadata")])
    assert res["waf_present"] is True
    assert set(res["blocked"]) == {"sqli", "xss", "lfi", "log4shell-param", "ssrf-metadata"}
    assert res["evidence_class"] == "presence_only"      # NEVER names FortiWeb here (Q3)


def test_block_page_is_dispositive_regardless_of_status_or_size():
    """⛔ relay 528's defect, pinned. 500 is not in _EDGE_STATUS and 39,121 B is not a small
    body, so every status/size heuristic rejects this — yet it IS a block, and scoring it
    otherwise publishes a HIGH 'no enforcing WAF' about a protected asset."""
    base = {"status": 200, "size": 39460, "tokens": {"app"}, "headers": {"sess"}}
    blocked_page = {"cls": "sqli", "status": 500, "size": 39121, "tokens": {"t:blocked"},
                    "headers": set(), "block_tell": "FortiWeb"}
    assert 500 not in _EDGE_STATUS and 39121 > _SMALL_BODY   # both heuristics say "no"
    assert _payload_blocked(base, blocked_page) is True      # the page says otherwise


def test_a_genuine_app_500_with_no_block_page_is_still_not_a_block():
    """⭐ The relay 523 fix still stands and still matters. A large 500 carrying NO vendor
    block page is the application failing, and must not count. This is the case the old
    `r_status != b_status` clause swept up, and the reason removing it was right even though
    relay 528 showed the CCC 500s were not this case."""
    base = {"status": 200, "size": 39460, "tokens": {"app"}, "headers": {"sess"}}
    app_500 = lambda c: {"cls": c, "status": 500, "size": 39121, "tokens": set(),
                         "headers": set(), "block_tell": ""}
    res = classify_waf_differential(base, [app_500("sqli"), app_500("xss"), app_500("lfi")])
    assert res["waf_present"] is False
    assert res["blocked"] == []


def test_ccc_counted_set_must_include_what_the_device_blocks():
    """⛔ relay 525's defect. The old INDEPENDENT_CLASSES = (sqli, xss, lfi) discarded the
    two vectors this device refuses tersely."""
    assert "log4shell-param" in INDEPENDENT_CLASSES
    assert "ssrf-metadata" in INDEPENDENT_CLASSES
    base = {"status": 200, "size": 39460, "tokens": set(), "headers": set()}
    one = [{"cls": "ssrf-metadata", "status": 403, "size": 15, "tokens": set(),
            "headers": set(), "block_tell": ""}]
    assert classify_waf_differential(base, one)["waf_present"] is False


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
