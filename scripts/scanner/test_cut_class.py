"""test_cut_class.py — the bottleneck class behind a non-completion (4.7 ㉚).

WHY THIS EXISTS (2026-09-07). The critical/high coverage deficit was carried for
months as one number — "9%" — that turned out to be two failures with disjoint
bottlenecks: a ~78% TIME cut on non-WAF assets and a ~9% SIGNATURE BLOCK on
WAF-fronted ones. Extra wall clock fixes the first and is irrelevant to the
second. A distinction that isn't encoded in the data gets re-learned by accident,
expensively, every time someone looks.

⚠ The ruling's premise was that the two were already distinguishable as two
values of the same nuclei `reason`. Measured over 90 days, they are not:
`wall_clock_cut_400s` is the ONLY nuclei cut reason on record (13 occurrences),
and there is no signature-block reason on nuclei at all — the filter bottleneck
appears upstream as `tech_detect_blocked` on httpx. A WAF-fronted asset gets the
safe-only plan, which COMPLETES; you cannot be signature-blocked on templates you
were never offered. So the taxonomy spans four mechanisms, not two.
"""
import degradation as D


# ── Real production reasons, with counts, Command, 90 days to 2026-09-07 ────
# "Real data as test surface": a taxonomy validated only against reasons its
# author thought of is a taxonomy that classifies its author's imagination.
# Every string below was observed in scan_run.tool_status.
LIVE_REASONS: dict[str, tuple[str, int]] = {
    # reason:                        (expected class,     occurrences)
    "curl_failed":                   (D.CUT_TRANSPORT,    316),
    "homepage_fetch_failed":         (D.CUT_TRANSPORT,    265),
    "all_probes_failed":             (D.CUT_TRANSPORT,    240),
    "network_timeout":               (D.CUT_TRANSPORT,    161),
    "network_unreachable":           (D.CUT_TRANSPORT,     84),
    # Surfaced by the trimodality read 2026-09-07 — target_unreachable_after_run
    # returned `unclassified` on first contact, which is exactly what that value
    # is for. A default class would have mislabelled it silently.
    "target_unreachable_after_run":  (D.CUT_TRANSPORT,      1),
    "egress_unstable":               (D.CUT_TRANSPORT,      1),
    "nonzero_rc_no_reach_evidence:246": (D.CUT_TRANSPORT,  35),
    "empty_output":                  (D.CUT_TOOL,          87),
    "naabu_rc_1":                    (D.CUT_TOOL,          27),
    "catchall_calibration_failed":   (D.CUT_TOOL,          12),
    "no_status_recorded":            (D.CUT_TOOL,           7),
    "v1_p4_pending":                 (D.CUT_POLICY,        52),
    "auth_gated":                    (D.CUT_POLICY,         8),
    "tech_detect_blocked":           (D.CUT_FILTER,        23),
    # The other three tech-detect reasons. Only `blocked` is a filter;
    # all four shrink the plan, which is why the plan-shrink gate keys on
    # planned>actual rather than on cut_class.
    "tech_detect_no_signal":         (D.CUT_TOOL,           1),
    "tech_detect_no_output":         (D.CUT_TOOL,           1),
    "tech_detect_rc_1":              (D.CUT_TOOL,           1),
    "wall_clock_cut_400s":           (D.CUT_TIME,          13),
    "wall_timeout":                  (D.CUT_TIME,          11),
}


def test_every_reason_seen_in_production_classifies():
    """The floor. A classifier that returns `unclassified` for everything would
    pass every other test in this file — it would be internally consistent and
    completely useless."""
    unclassified = {
        r: D.classify_cut_reason(r)
        for r in LIVE_REASONS
        if D.classify_cut_reason(r) == D.CUT_UNCLASSIFIED
    }
    assert not unclassified, (
        f"reasons observed in production that do not classify: {unclassified}. "
        f"Add them to _CUT_CLASS_PREFIXES — an unclassified reason means the "
        f"population group-by silently under-counts a real class.")


def test_each_live_reason_lands_in_the_RIGHT_class():
    wrong = {
        r: (D.classify_cut_reason(r), want)
        for r, (want, _n) in LIVE_REASONS.items()
        if D.classify_cut_reason(r) != want
    }
    assert not wrong, f"misclassified (got, want): {wrong}"


def test_all_five_classes_are_actually_populated_by_live_data():
    """Guards a taxonomy that has grown a class nothing can reach — a category
    that never fires reads like coverage while providing none."""
    seen = {want for want, _n in LIVE_REASONS.values()}
    expected = {D.CUT_TIME, D.CUT_FILTER, D.CUT_TRANSPORT, D.CUT_POLICY, D.CUT_TOOL}
    assert seen == expected, (
        f"classes with no live example: {expected - seen}; "
        f"classes not in the taxonomy: {seen - expected}")


def test_transport_is_the_dominant_class_and_that_is_recorded():
    """Not a behavioural assertion — a documented FACT the numbers must keep
    supporting. ~1100 transport failures vs 24 time-cuts means the largest
    category of non-coverage on this fleet is 'we never reached the target',
    which was invisible before this field existed. If a future edit makes
    transport a minority, the fleet changed and the analysis needs redoing."""
    tally: dict[str, int] = {}
    for _r, (cls, n) in LIVE_REASONS.items():
        tally[cls] = tally.get(cls, 0) + n
    assert tally[D.CUT_TRANSPORT] > 10 * tally[D.CUT_TIME], (
        f"transport {tally[D.CUT_TRANSPORT]} vs time {tally[D.CUT_TIME]} — "
        f"the recorded distribution no longer holds; re-measure before relying "
        f"on the bimodal framing")


# ── absent evidence must never become a verdict ─────────────────────────────
def test_missing_reason_returns_None_not_a_class():
    """A phase with no reason has no cut to classify. Inventing one is the
    absent-evidence-becomes-a-verdict failure that has the device-class flip
    and cloud attribution both gated."""
    for empty in (None, "", "   ", 0, [], {}):
        assert D.classify_cut_reason(empty) is None, empty


def test_unknown_reason_is_UNCLASSIFIED_never_a_default_class():
    """A wrong class is worse than an admitted gap: it puts an asset in a
    population it does not belong to, and trustworthy populations are the
    entire point of the field."""
    for unknown in ("brand_new_failure_mode", "zzz", "cut"):
        assert D.classify_cut_reason(unknown) == D.CUT_UNCLASSIFIED, unknown


def test_prefix_matching_does_not_over_reach():
    """`ban` maps to filter, but a reason merely CONTAINING 'ban' must not."""
    assert D.classify_cut_reason("banned_by_waf") == D.CUT_FILTER
    assert D.classify_cut_reason("urban_myth") == D.CUT_UNCLASSIFIED


# ── phase_cut_reason: three producers, three keys ───────────────────────────
def test_reads_all_three_producer_keys():
    assert D.phase_cut_reason({"ok": False, "reason": "wall_clock_cut_400s"}) \
        == "wall_clock_cut_400s"
    assert D.phase_cut_reason({"degraded": "curl_failed"}) == "curl_failed"
    assert D.phase_cut_reason({"skipped": "auth_gated"}) == "auth_gated"


def test_a_clean_phase_has_no_cut_reason():
    assert D.phase_cut_reason({"ok": True}) is None
    assert D.phase_cut_reason({"ok": True, "evidence": {"total": 10}}) is None


def test_PARTIAL_OK_shape_is_not_read_as_clean():
    """🔴 The `"ok" in entry` bug, which has shipped in this repo before.
    PARTIAL_OK carries ok:false — key-membership reads a cut chunk as clean."""
    entry = {"ok": False, "reason": "wall_clock_cut_400s", "percent": 78}
    assert D.phase_cut_reason(entry) == "wall_clock_cut_400s"
    assert D.classify_cut_reason(D.phase_cut_reason(entry)) == D.CUT_TIME


def test_degraded_wins_even_when_ok_is_true():
    """An entry can carry ok:true AND a degraded key. Treating it as clean
    would hide the degradation behind a stale verdict."""
    assert D.phase_cut_reason({"ok": True, "degraded": "empty_output"}) == "empty_output"


# ── Completeness against DegradedRunError's own documented vocabulary ───────
# Those slugs are the authoritative list of things the runner can raise. A
# taxonomy that only covers what has happened to appear in the database is a
# taxonomy that under-counts every class until someone notices.
DOCUMENTED_SLUGS: dict[str, str] = {
    "rotation_exhausted":                          D.CUT_FILTER,
    "tool_status_invariant":                       D.CUT_TOOL,
    "target_unreachable_after_run":                D.CUT_TRANSPORT,
    "target_unreachable_pre_run":                  D.CUT_TRANSPORT,
    "output_stderr_contains_unreachable_pattern":  D.CUT_TRANSPORT,
    "tool_startup_failure":                        D.CUT_TOOL,
    "validate_mode_target_not_allowlisted":        D.CUT_POLICY,
    "vpn_bringup_failed":                          D.CUT_TRANSPORT,
    "asset_pre_flight_unreachable":                D.CUT_TRANSPORT,
}


def test_every_documented_DegradedRunError_slug_classifies():
    wrong = {
        s: (D.classify_cut_reason(s), want)
        for s, want in DOCUMENTED_SLUGS.items()
        if D.classify_cut_reason(s) != want
    }
    assert not wrong, (
        f"slugs documented in DegradedRunError but mis/unclassified "
        f"(got, want): {wrong}")


def test_the_documented_slug_list_matches_the_docstring():
    """Pins the two together. If a new slug is added to the docstring and not
    here, this fails and points at the gap — rather than the class silently
    reading `unclassified` in production for months."""
    doc = D.DegradedRunError.__doc__ or ""
    missing = [s for s in DOCUMENTED_SLUGS if f'"{s}"' not in doc]
    assert not missing, (
        f"listed here but no longer in the DegradedRunError docstring: {missing}")
    import re as _re
    in_doc = set(_re.findall(r'^\s*-\s*"([a-z_]+)"', doc, _re.M))
    unmapped = in_doc - set(DOCUMENTED_SLUGS)
    assert not unmapped, (
        f"documented in DegradedRunError but not mapped to a cut class: "
        f"{sorted(unmapped)} — add them to _CUT_CLASS_PREFIXES and here")
