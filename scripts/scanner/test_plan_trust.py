"""test_plan_trust.py — the ㉟ gate: may this plan be ordered or checkpointed?

WHY THIS EXISTS (2026-09-07). ㉛ (severity-first ordering) and ㉜ (resume cursor)
are only safe on a plan that is the plan the target should have had. Ordering a
truncated list optimises the wrong list; checkpointing one accumulates against a
moving denominator — a cursor that advances forever without converging, with the
non-advancement alarm satisfied the whole time.

🔴 THE GATE THAT WAS RATIFIED AND THEN REFUTED. `planned_chunks > actual_chunks`
was proposed (by me), ratified by 4.7, and killed by its own negative test the
same day. `24.157.51.84` is a Cisco ASA: tech-detect SUCCEEDED, none of the five
STACK_CHUNKS apply, planned=9 actual=4 — and 4 is the COMPLETE, CORRECT plan.
The count gate fires on it and would have excluded one of the only two eligible
assets on the fleet from the fix it qualifies for.

Two situations, identical arithmetic, opposite meaning:
    tech-detect succeeded, stacks don't apply  -> complete   -> ELIGIBLE
    tech-detect blocked, stack unknown         -> truncated  -> EXCLUDED
Missing APPLICABILITY vs missing INFORMATION. The count measures the delta; the
CAUSE is the question. Hence: allowlist on the reason.

Live values verified on the persisted record 2026-09-07:
    24.157.51.84 (Cisco ASA)      stack_not_applicable  httpx ok:true   ELIGIBLE
    24.157.51.86 (FortiWeb)       tech_detect_blocked   httpx degraded  EXCLUDED
    test.commandcommcentral.com   routed_safe_only      httpx ok:true   EXCLUDED
"""
import degradation as D


# ── the affirmative allow ───────────────────────────────────────────────────
def test_no_delta_reason_is_trustworthy():
    """Full plan, nothing omitted."""
    assert D.plan_is_trustworthy({"ok": True, "planned_chunks": 9, "actual_chunks": 9})


def test_stack_not_applicable_is_trustworthy_despite_planned_exceeding_actual():
    """🔴 THE CASE THE COUNT GATE GOT WRONG. This is the real 24.157.51.84 shape:
    a Cisco ASA where tech-detect succeeded and none of the five stacks apply."""
    entry = {"ok": False, "reason": "wall_clock_cut_400s",
             "plan_delta_reason": "stack_not_applicable",
             "planned_chunks": 9, "actual_chunks": 4}
    assert entry["planned_chunks"] > entry["actual_chunks"], "precondition"
    assert D.plan_is_trustworthy(entry), (
        "a complete plan for a target those stacks do not apply to MUST remain "
        "eligible — excluding it is the false positive that killed the count gate")


# ── the denials ─────────────────────────────────────────────────────────────
def test_every_tech_detect_reason_is_untrustworthy():
    """All four mean the stack is UNKNOWN, so the plan could not be built."""
    for r in ("tech_detect_blocked", "tech_detect_no_signal",
              "tech_detect_rc_1", "tech_detect_no_output",
              "tech_detect_no_stack_signal"):
        assert not D.plan_is_trustworthy({"plan_delta_reason": r}), r


def test_routed_safe_only_is_untrustworthy_even_though_tech_detect_SUCCEEDED():
    """The case that proves the gate must key on the REASON, not on whether
    tech-detect worked. On test.commandcommcentral.com httpx is ok:true — yet
    the plan was deliberately narrowed by routing before the scan began."""
    assert not D.plan_is_trustworthy({"plan_delta_reason": "routed_safe_only"})


def test_an_UNKNOWN_reason_is_denied_not_admitted():
    """The self-maintaining property. A plan_delta_reason added in future falls
    to the deny side automatically — the allowlist shape is what buys this, and
    it is the half the count gate got backwards."""
    for r in ("brand_new_shrink_cause", "", "   ", "STACK_NOT_APPLICABLE_TYPO"):
        assert not D.plan_is_trustworthy({"plan_delta_reason": r}), r


def test_unreadable_entry_denies_rather_than_raising():
    """An unreadable record is not evidence of a trustworthy plan."""
    for bad in (None, "string", 42, []):
        assert not D.plan_is_trustworthy(bad), bad


def test_allowlist_holds_exactly_one_reason():
    """A guard on scope creep. Every addition here admits a new plan shape into
    ㉛/㉜; each one needs its own affirmativeness argument, like the one that
    justifies stack_not_applicable (set only under
    tech_detection_meets_yield_floor, the same predicate behind httpx ok:true)."""
    assert D.TRUSTWORTHY_PLAN_DELTA_REASONS == frozenset({"stack_not_applicable"})


# ── whole-run verdict ───────────────────────────────────────────────────────
def _asa_run():
    """Real 24.157.51.84 shape: four nuclei chunks, all stack_not_applicable."""
    chunk = {"plan_delta_reason": "stack_not_applicable",
             "planned_chunks": 9, "actual_chunks": 4}
    return {
        "wafw00f": {"ok": True},
        "httpx[-td]": {"ok": True},
        "nuclei[critical,high]": {**chunk, "ok": False,
                                  "reason": "wall_clock_cut_400s"},
        "nuclei[medium:cve]": {**chunk, "ok": True},
        "nuclei[medium:exposure,config]": {**chunk, "ok": True},
        "nuclei[medium:tech]": {**chunk, "ok": True},
    }


def test_run_verdict_eligible_on_the_real_ASA_shape():
    assert D.run_plan_is_trustworthy(_asa_run())


def test_run_verdict_excluded_on_the_real_filter_blocked_shape():
    """24.157.51.86 — tech-detect blocked by a WAF."""
    ts = _asa_run()
    for k in [k for k in ts if k.startswith("nuclei")]:
        ts[k]["plan_delta_reason"] = "tech_detect_blocked"
    ts["httpx[-td]"] = {"degraded": "tech_detect_blocked"}
    assert not D.run_plan_is_trustworthy(ts)


def test_ONE_untrustworthy_chunk_disqualifies_the_whole_run():
    """The chunks share one plan, so a delta reason on one is a fact about all.
    Reading only the first would make the verdict depend on dict ordering."""
    ts = _asa_run()
    ts["nuclei[medium:tech]"]["plan_delta_reason"] = "tech_detect_blocked"
    assert not D.run_plan_is_trustworthy(ts)


def test_a_run_with_NO_nuclei_phase_is_not_vacuously_trustworthy():
    """`all()` over an empty list is True. A run with nothing to order or
    checkpoint must not pass the gate on that technicality — the
    checks-that-pass-by-never-running trap, in predicate form."""
    assert not D.run_plan_is_trustworthy({"wafw00f": {"ok": True}})
    assert not D.run_plan_is_trustworthy({})
    assert not D.run_plan_is_trustworthy(None)
