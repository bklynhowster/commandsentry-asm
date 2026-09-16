#!/usr/bin/env python3
"""Device-class phase 2b — preserve-prior + capability-aware downgrade streak.
Relay 153 (the ruling), 200 (the measurement), 201 (the rulings on it). 2026-09-16.

⛔ THE DEFECT THIS CLOSES, AND WHY THE MEASUREMENT CHANGED THE DESIGN.

`_fresh_scan_exists` asked "did ANY scan_run for this asset complete in the freshness
window" — no tier filter, no artifact filter. It fed `_collection_status`, which split
an empty read into `genuine_empty` (a scan ran and found nothing -> downgrade candidate)
vs `no_fresh_collection` (nothing to read -> preserve).

Measured on Command, 2026-09-16, 28 passes over 7 days:

    a LIGHT scan emits   common_paths · csp_nonce_check · dns_posture · headers_check
                         httpx_tech · naabu · tls_check
    the classifier reads fingerprint% · testssl% · stack_id_wafw00f · nuclei%
                         stack_id_passive · light_stack_passive

Not one name in common. So a light scan's empty evidence is absence of COLLECTION, not
absence of the thing — 169's principle exactly. `_fresh_scan_exists` counted it as
"collection happened", which made every light-scanned asset a downgrade candidate.

Scale: 27 of 51 fresh-scanned assets (53%) were light-only. The single asset that would
have downgraded in the window, mail.unimacgraphics.com, had a "streak" of
light(09-04) · light(09-11) · medium(09-15) — two observations that could never have
seen a WAF, and one that could. A counter in front of blind observations is still a
label from absent evidence.

⚠ THE TEST IS ARTIFACT-BASED, NOT TIER-BASED, AND THAT IS LOAD-BEARING. `intensity !=
'light'` would be wrong in fact as well as in principle: 2 of 225 light runs in the 30d
window DID emit light_stack_passive. Capability is a property of what a RUN produced.

⚠ FAILING-FIRST. test_light_only_collection_is_not_genuine_empty is written against the
PUBLIC helper both trees have (`_fresh_scan_exists`), not against a new symbol, so it
runs on the pre-fix tree and FAILS there on the assertion — a real red, not a collection
error. Recorded in the relay entry with both outputs.
"""

from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import device_class_runner as dcr  # noqa: E402


# ---------------------------------------------------------------------------
# a cursor fake that can tell the two probe shapes apart
# ---------------------------------------------------------------------------

class FakeCursor:
    """Answers the two queries this module issues, discriminating on whether the SQL
    joins scan_run_artifacts. That join IS the fix, so the fake can serve the old tree
    and the new one from the same fixture — which is what makes failing-first honest.

      any_scan_rows      -> what the OLD tier-blind probe would see
      capable_run_ids    -> runs that produced >=1 evidence artifact (the NEW probe)
      dryrun_rows        -> device_class_dryrun rows, newest first
    """

    def __init__(self, any_scan_rows=None, capable_run_ids=(), dryrun_rows=()):
        self._any = [{"?column?": 1}] if any_scan_rows is None else any_scan_rows
        self._capable = [{"scan_run_id": r, "completed_at": None} for r in capable_run_ids]
        self._dryrun = list(dryrun_rows)
        self._result = []
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        s = " ".join(sql.split())
        if "device_class_dryrun" in s:
            self._result = self._dryrun
        elif "scan_run_artifacts" in s:
            self._result = self._capable
        else:
            self._result = self._any

    def fetchall(self):
        return self._result

    def fetchone(self):
        return self._result[0] if self._result else None


def _dryrun_row(run_id, prior="waf", computed="unknown", event="TRANSITION_DOWNGRADE"):
    return {"scan_run_id": run_id, "device_class": computed, "event_type": event,
            "prior_state": {"device_class": prior, "confidence": "suspected"}}


# ---------------------------------------------------------------------------
# ⭐ THE FAILING-FIRST TEST — runs on BOTH trees, red on the old one
# ---------------------------------------------------------------------------

def test_light_only_collection_is_not_genuine_empty():
    """mail.unimacgraphics.com. Light scans completed inside the window, so the OLD
    probe says "collection happened" and the asset becomes a downgrade candidate. None
    of those runs produced an artifact the classifier reads, so the NEW probe says no
    collection happened and the prior is preserved.

    OLD TREE: _fresh_scan_exists -> True  (this assert FAILS — the red we want)
    NEW TREE: _fresh_scan_exists -> False"""
    cur = FakeCursor(any_scan_rows=[{"?column?": 1}], capable_run_ids=())
    assert dcr._fresh_scan_exists(cur, "mail.unimacgraphics.com", 30) is False


def test_a_run_that_produced_evidence_artifacts_does_count():
    """The other direction, so the fix cannot be 'return False' — a medium run that
    emitted wafw00f/nuclei IS collection, and its empty evidence IS genuine_empty."""
    cur = FakeCursor(any_scan_rows=[], capable_run_ids=("run-medium-1",))
    assert dcr._fresh_scan_exists(cur, "www.example.com", 30) is True


def test_capability_is_read_from_the_single_constant():
    """4.7 ruling 1: ONE source of truth. The probe must pass the shared constant as the
    pattern list — a second hand-written list is the drift that caused Q7."""
    cur = FakeCursor(capable_run_ids=("r1",))
    dcr._evidence_capable_scan_runs(cur, "a", 30)
    sql, params = cur.executed[-1]
    assert "scan_run_artifacts" in sql
    assert list(dcr.EVIDENCE_ARTIFACT_PATTERNS) in params, \
        "the probe must consume EVIDENCE_ARTIFACT_PATTERNS, not its own copy"


# ---------------------------------------------------------------------------
# the four-row matrix — one fire / no-fire pair per row
# ---------------------------------------------------------------------------

def test_row1_positive_prior_no_collection_preserves():
    assert dcr.apply_2b_matrix("waf", dcr._STATUS_NO_FRESH_COLLECTION, False) == "preserve"


def test_row1_pair_positive_prior_with_collection_does_not_take_the_preserve_path():
    assert dcr.apply_2b_matrix("waf", dcr._STATUS_GENUINE_EMPTY, True) == "write"


def test_row2_positive_prior_genuine_empty_preserves_until_the_streak():
    assert dcr.apply_2b_matrix("cdn", dcr._STATUS_GENUINE_EMPTY, False) == "preserve"


def test_row2_pair_streak_met_writes_the_downgrade():
    assert dcr.apply_2b_matrix("cdn", dcr._STATUS_GENUINE_EMPTY, True) == "write"


@pytest.mark.parametrize("status", [dcr._STATUS_NO_FRESH_COLLECTION,
                                    dcr._STATUS_GENUINE_EMPTY])
def test_rows3and4_unknown_prior_never_writes(status):
    """Q5b DROPPED. Measured 2026-09-16: writing `unreadable` here would have stamped
    ~365 of 416 Command assets — 88% of the fleet — from a coverage fact."""
    assert dcr.apply_2b_matrix("unknown", status, False) == "no_write"
    assert dcr.apply_2b_matrix("unknown", status, True) == "no_write", \
        "a streak must not manufacture a write where there is no positive prior to lose"


def test_nothing_in_the_matrix_ever_writes_unreadable():
    """`unreadable` stays in the taxonomy; 2b writes it nowhere."""
    seen = {dcr.apply_2b_matrix(p, s, k)
            for p in ("waf", "cdn", "origin_host", "unknown", "cloud_endpoint")
            for s in (dcr._STATUS_NO_FRESH_COLLECTION, dcr._STATUS_GENUINE_EMPTY,
                      dcr._STATUS_READS_OK)
            for k in (True, False)}
    assert "unreadable" not in seen
    assert seen <= {"write", "preserve", "no_write"}


# ---------------------------------------------------------------------------
# the streak — TRANSITION_DOWNGRADE rows on distinct evidence-capable runs
# ---------------------------------------------------------------------------

def test_three_distinct_capable_runs_meet_the_streak():
    caps = ("r1", "r2", "r3")
    cur = FakeCursor(capable_run_ids=caps,
                     dryrun_rows=[_dryrun_row("r3"), _dryrun_row("r2"), _dryrun_row("r1")])
    assert dcr._downgrade_streak_met(cur, "a", list(caps)) is True


def test_one_scan_re_read_four_times_is_one_observation():
    """The runner passes 4x/day (cron 15 */6) but scans land far less often. Four rows
    carrying the SAME scan_run_id are one observation, not a streak — this is why 4.7
    retired the '>2/day' bar as subsumed rather than replacing it with another knob.

    ⚠ capable MUST hold >= the requirement here. The first version passed
    capable=("r1",) and was satisfied by the len(capable) < required short-circuit, so
    the de-duplication rule it claims to test was never exercised — a mutant that
    counted the same run four times SURVIVED it. Three capable runs clear the
    short-circuit; only one of them has rows, so the dedupe is what decides."""
    cur = FakeCursor(capable_run_ids=("r1", "r2", "r3"),
                     dryrun_rows=[_dryrun_row("r1") for _ in range(4)])
    assert dcr._downgrade_streak_met(cur, "a", ["r1", "r2", "r3"]) is False


def test_a_stamp_row_does_not_count_toward_the_streak():
    """4.7 ruling 3: the EVENT TYPE is the test, not the class.

    ⚠ THIS TEST WAS VACUOUS IN ITS FIRST VERSION. It used STAMP rows with an `unknown`
    prior — the shape event_for() actually produces — and those are rejected by the
    POSITIVE-prior check, so it passed with the event_type rule deleted. The rows below
    are deliberately SYNTHETIC (positive prior + STAMP, which event_for cannot currently
    emit) because that is the only shape that isolates the event_type rule. It is a
    regression guard on the derivation: if event_for ever starts emitting STAMP over a
    positive prior, a class-keyed streak would silently start counting it."""
    cur = FakeCursor(capable_run_ids=("r1", "r2", "r3"),
                     dryrun_rows=[_dryrun_row("r1", prior="waf", event="STAMP"),
                                  _dryrun_row("r2", prior="waf", event="STAMP"),
                                  _dryrun_row("r3", prior="waf", event="STAMP")])
    assert dcr._downgrade_streak_met(cur, "a", ["r1", "r2", "r3"]) is False


def test_the_unknown_prior_stamp_shape_is_also_rejected():
    """The realistic shape, kept as its own case so the synthetic one above cannot be
    mistaken for the whole rule."""
    cur = FakeCursor(capable_run_ids=("r1", "r2", "r3"),
                     dryrun_rows=[_dryrun_row("r1", prior="unknown", event="STAMP"),
                                  _dryrun_row("r2", prior="unknown", event="STAMP"),
                                  _dryrun_row("r3", prior="unknown", event="STAMP")])
    assert dcr._downgrade_streak_met(cur, "a", ["r1", "r2", "r3"]) is False


def test_rows_from_runs_that_were_not_evidence_capable_do_not_count():
    """The mail.unimacgraphics.com light/light/medium shape. Three downgrade rows exist,
    but only one of the runs behind them could see — so the streak is 1, not 3.

    ⚠ capable holds THREE ids while the ROWS name two runs that are not among them. The
    first version passed capable=("r-medium",) and was satisfied by the short-circuit,
    so a mutant that dropped `sid in capable` SURVIVED. Here the short-circuit cannot
    fire, and the capability intersection is the only thing standing between these rows
    and a downgrade."""
    cur = FakeCursor(capable_run_ids=("r-medium", "r-medium-2", "r-medium-3"),
                     dryrun_rows=[_dryrun_row("r-medium"), _dryrun_row("r-light-2"),
                                  _dryrun_row("r-light-1")])
    assert dcr._downgrade_streak_met(
        cur, "mail.unimacgraphics.com",
        ["r-medium", "r-medium-2", "r-medium-3"]) is False


def test_a_downgrade_row_whose_prior_was_unknown_does_not_count():
    cur = FakeCursor(capable_run_ids=("r1", "r2", "r3"),
                     dryrun_rows=[_dryrun_row("r1", prior="unknown"),
                                  _dryrun_row("r2", prior="unknown"),
                                  _dryrun_row("r3", prior="unknown")])
    assert dcr._downgrade_streak_met(cur, "a", ["r1", "r2", "r3"]) is False


def test_streak_short_circuits_before_querying_when_capability_is_short():
    """Cost guard: fewer capable runs than the requirement cannot possibly meet it, so
    the dryrun read must not be issued at all inside a per-asset loop."""
    cur = FakeCursor(capable_run_ids=("r1", "r2"))
    assert dcr._downgrade_streak_met(cur, "a", ["r1", "r2"]) is False
    assert not any("device_class_dryrun" in s for s, _ in cur.executed)


# ---------------------------------------------------------------------------
# the pin — 4.7 ruling 1: the constant is the ONLY place these names appear
# ---------------------------------------------------------------------------

def test_the_artifact_names_appear_only_in_the_constant_block():
    """Two lists drift; that drift is invisible; invisible drift is how Q7 happened.
    Every literal occurrence of an evidence artifact name must live in the constant
    assignments — nowhere else in the module."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "device_class_runner.py"), encoding="utf-8").read()
    body = "\n".join(ln for ln in src.split("\n")
                     if not ln.lstrip().startswith("#"))
    for name in ("fingerprint%", "testssl%", "nuclei%"):
        hits = [ln for ln in body.split("\n") if f'"{name}"' in ln]
        assert len(hits) == 1, f"{name!r} appears {len(hits)}x outside the constant: {hits}"
        assert re.match(r"\s*_ART_[A-Z]+\s*=", hits[0]), \
            f"{name!r} is not in a constant assignment: {hits[0]!r}"


def test_passive_tool_names_are_part_of_the_capability_set():
    """light_stack_passive is READ by the classifier, so a light run that produced it IS
    evidence-capable. Measured: 2 of 225 light runs did. This is precisely why the test
    is artifact-based and not `intensity != 'light'`."""
    assert "light_stack_passive" in dcr.EVIDENCE_ARTIFACT_PATTERNS
    assert "stack_id_passive" in dcr.EVIDENCE_ARTIFACT_PATTERNS
    for n in dcr._PASSIVE_TOOL_NAMES:
        assert n in dcr.EVIDENCE_ARTIFACT_PATTERNS


def test_collection_status_still_maps_the_three_cases():
    """_collection_status is unchanged — only the MEANING of its second argument moved
    from "any scan" to "an evidence-capable scan". Pinned so a future edit that changes
    the mapping has to say so."""
    assert dcr._collection_status(True, True) == dcr._STATUS_READS_OK
    assert dcr._collection_status(True, False) == dcr._STATUS_READS_OK
    assert dcr._collection_status(False, True) == dcr._STATUS_GENUINE_EMPTY
    assert dcr._collection_status(False, False) == dcr._STATUS_NO_FRESH_COLLECTION

# ---------------------------------------------------------------------------
# the write gate — AST, because the branch itself needs a DB to exercise
# ---------------------------------------------------------------------------

def test_the_assets_update_is_gated_on_the_2b_decision():
    """⛔ The matrix is only a guard if the WRITE consults it. `apply_2b_matrix` could be
    perfect and every test above green while run() still wrote every unknown verdict
    straight to assets — a producer with no consumer, which is the defect family that
    cost us the enrich worker and the bare "httpx". The branch lives inside run(), which
    needs a live DSN, so it is pinned structurally instead of left unobserved.

    Asserts: the `update public.assets set device_class` statement is reachable ONLY
    under a test that mentions the 2b decision."""
    import ast
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "device_class_runner.py"), encoding="utf-8").read()
    tree = ast.parse(src)

    def writes_device_class(node):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                    and "update public.assets set device_class" in sub.value:
                return True
        return False

    guarded = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        if not any(writes_device_class(b) for b in node.body):
            continue
        guarded.append(ast.unparse(node.test))

    assert guarded, "the assets device_class UPDATE is not inside any `if` — it is ungated"
    for test_src in guarded:
        assert "_DECISION_WRITE" in test_src or "decision" in test_src, (
            "the assets UPDATE is guarded, but NOT by the 2b decision — the matrix would "
            f"be computed and ignored. Guard reads: {test_src!r}")
