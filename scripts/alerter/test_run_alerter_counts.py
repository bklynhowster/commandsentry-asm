#!/usr/bin/env python3
"""Tests for the digest's COUNT predicates — added 2026-09-14 (relay 133, rule 9).

WHY THIS FILE EXISTS. Before today scripts/alerter/ had ZERO tests. The digest
is the only human-facing output this system produces, and it printed
"0 finding change(s)" on a night when 65 findings were created. Nothing caught
it for three months because nothing was watching.

These tests pin the two things that were wrong:

  (1) the digest counted finding TRANSITIONS and called them finding changes,
      so creation was invisible;
  (2) the "New assets discovered" panel counted a PRODUCER's first look, not
      the fleet's first sighting, so a second producer re-announced months-old
      assets as new.

Both are count-semantics defects, so the tests assert on SEMANTICS (which
column each query reads, and what the rendered text claims) rather than on
formatting.

⛔ SQL EXECUTION IS NOT TESTED HERE. These run without a database. Executing the
queries against real Postgres is the alerter.yml workflow_dispatch with
dry_run=true, which runs the real SQL and sends nothing. That is the
verification step, and it is Howie's to fire.
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_alerter as ra  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

W_END = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
W_START = W_END - timedelta(hours=24)

# Column order matches SQL_NEW_CONFIRMED / SQL_NEW_FINDINGS_IN_WINDOW:
#   r[0]=finding_id  r[1]=asset_id  r[2]=title  r[3]=severity
FINDING = ("F-0001", "unimacgraphics.com", "Missing DMARC record", "MODERATE",
           "detected", "light", W_END)

BASELINE = {
    "critical_open": 0, "high_open": 3, "mod_high_open": 1,
    "moderate_open": 7, "low_open": 12,
}


def _strip_sql_comments(sql: str) -> str:
    """Drop `-- ...` lines so a pin cannot be satisfied by prose.

    This is the same trap that bit the source-pin helper twice on 2026-09-14:
    a comment EXPLAINING a phrase satisfied a pin looking for that phrase.
    """
    return "\n".join(
        re.sub(r"--.*$", "", line) for line in sql.splitlines()
    )


def _render(**over):
    kw = dict(
        window_start=W_START, window_end=W_END,
        new_findings=[], confirmed=[], regressed=[], high_risk=[],
        new_assets=[], dark_assets=[], stale_assets=[], canary_violations=[],
        discovery_stale_hours=12, deepscan_stale_hours=48,
        baseline=BASELINE, dashboard_url="https://example.invalid",
        product_name="COMMANDsentry",
    )
    kw.update(over)
    # render_text takes no dashboard_url — it has no footer link.
    text_kw = {k: v for k, v in kw.items() if k != "dashboard_url"}
    return ra.render_html(**kw), ra.render_text(**text_kw)


# ---------------------------------------------------------------------------
# (1) creation vs transition
# ---------------------------------------------------------------------------

def test_new_findings_query_reads_creation_not_a_transition_log():
    """The count 4.7 named: findings.first_detected_at, from the findings table.

    If this query is ever rewritten to read v_alerter_changes or
    finding_history, the number goes back to zero on a 65-finding day —
    v_alerter_changes' outer WHERE admits only regressed/confirmed/open, and a
    new finding is born 'detected' and stays there.
    """
    sql = _strip_sql_comments(ra.SQL_NEW_FINDINGS_IN_WINDOW)
    assert "first_detected_at" in sql, "must read the creation timestamp"
    assert re.search(r"\bFROM\s+findings\b", sql, re.I), "must read findings"
    assert "v_alerter_changes" not in sql, "creation must NOT come from the transition view"
    assert "finding_history" not in sql, "creation must NOT come from the observation log"


def test_transition_queries_still_read_the_transition_view():
    """The fix is ADDITIVE. confirmed/regressed must be untouched, so no
    existing number moves and the regressed settle logic is not disturbed."""
    for sql in (ra.SQL_NEW_CONFIRMED, ra.SQL_REGRESSED):
        assert "v_alerter_changes" in _strip_sql_comments(sql)


def test_new_findings_applies_the_tier_2_gate():
    """Every other digest query excludes ct_ghost / namesake / unverified.
    A creation count that skipped the gate would print phantom findings."""
    sql = _strip_sql_comments(ra.SQL_NEW_FINDINGS_IN_WINDOW)
    assert "a.ownership = 'owned'" in sql
    assert "a.discovery_status = 'confirmed_live'" in sql


def test_a_window_with_only_new_findings_is_not_reported_as_no_changes():
    """THE 2026-09-14 BUG, end to end.

    65 created, 0 transitions. The old code's has_changes read only
    confirmed/regressed/high_risk/new_assets/dark_assets, so the email said
    'No changes since last run — pipeline healthy.'
    """
    html, text = _render(new_findings=[FINDING])
    assert "No changes" not in html
    assert "No changes since last run" not in text
    assert "Missing DMARC record" in html
    assert "Missing DMARC record" in text


def test_headline_names_new_findings_and_status_changes_separately():
    """The two quantities must never be merged again. 'finding change(s)' over
    len(confirmed)+len(regressed) is a transition count wearing a creation
    count's name — that is exactly what printed 0 on a 65-finding day."""
    html, _ = _render(new_findings=[FINDING, FINDING], confirmed=[FINDING])
    assert "<strong>2</strong> new finding(s)" in html
    assert "<strong>1</strong> status change(s)" in html
    assert "finding change(s)" not in html, "the merged, misnamed count must stay dead"


def test_adding_the_new_section_did_not_displace_the_existing_ones():
    """⛔ CAUGHT A REAL DEFECT. Written after the fact, which is the point.

    The Prodex port of this change spliced the NEW FINDINGS block in ahead of
    NEWLY CONFIRMED and, in doing so, deleted the
    `lines.append(f"NEWLY CONFIRMED ...")` header. The plaintext digest still
    listed the confirmed findings — but with no heading above them, so they
    read as a continuation of the NEW FINDINGS list. Every other test passed.

    Inserting a section is exactly where a neighbouring section gets clipped,
    so every section header is asserted here, together, in both renderers.
    """
    html, text = _render(
        new_findings=[FINDING], confirmed=[FINDING], regressed=[FINDING],
    )
    for label in ("NEW FINDINGS", "NEWLY CONFIRMED", "REGRESSED"):
        assert label in text, f"plaintext lost the {label} header"
    for label in ("New findings", "Newly confirmed findings", "Regressed findings"):
        assert label in html, f"HTML lost the {label} section"

    # and each section's rows must actually be under it, not orphaned
    order = [text.index(x) for x in ("NEW FINDINGS", "NEWLY CONFIRMED", "REGRESSED")]
    assert order == sorted(order), "sections rendered out of order"


def test_the_two_counts_overlap_and_the_digest_says_so():
    """⛔ THE TWO NUMBERS ARE NOT ADDABLE, and the overlap is LARGE.

    A finding is created 'detected'; if it settles to 'confirmed' before the
    window closes it is both new AND a status change. Measured over the most
    recent 1000 v_alerter_changes rows: 254 of 570 transition events (44.6%)
    fired within 24h of their finding's creation — inside one typical window.
    That is not a corner case, so the digest states the intersection rather
    than disclaiming it, and the arithmetic reconciles.
    """
    shared = ("F-SHARED", "a.example", "Weak cipher", "LOW", "detected", "light", W_END)
    only_new = ("F-NEW", "b.example", "Missing SPF", "LOW", "detected", "light", W_END)

    html, text = _render(new_findings=[shared, only_new], confirmed=[shared])
    # 2 new + 1 change = 3 naive, 2 distinct
    assert "1 finding(s) are in both counts" in html
    assert "2 distinct" in html
    assert "counted in BOTH sections" in text
    assert "Distinct findings touched: 2" in text
    assert "not addable" in text


def test_no_overlap_note_when_the_sets_are_disjoint():
    """A caveat that always prints is a caveat nobody reads."""
    a = ("F-A", "a.example", "T", "LOW", "detected", "light", W_END)
    b = ("F-B", "b.example", "T", "LOW", "confirmed", "light", W_END)
    html, text = _render(new_findings=[a], confirmed=[b])
    assert "in both counts" not in html
    assert "counted in BOTH sections" not in text


def test_overlap_helper_degrades_to_zero_on_a_column_reorder():
    """It indexes r[0] for finding_id. If a future SELECT reorders columns the
    right failure is 'no note', not a confidently wrong number."""
    assert ra._count_overlap([None], [None], []) == 0
    assert ra._count_overlap([()], [()], []) == 0


def test_zero_new_findings_does_not_invent_a_section():
    """A quiet night must still read as quiet — no empty panel, no false
    'pipeline healthy' suppression of a real transition either."""
    html, text = _render()
    assert "New findings" not in html
    assert "No changes" in html
    assert "No changes since last run" in text


# ---------------------------------------------------------------------------
# (2) first-EVER vs first-per-producer
# ---------------------------------------------------------------------------

def test_every_sql_constant_gets_exactly_as_many_params_as_it_has_placeholders():
    """⛔ CAUGHT A CRASH THAT WOULD HAVE SHIPPED.

    Adding the first_observed predicate took SQL_NEW_ASSETS_IN_WINDOW from two
    %s to four, while main() still passed (window_start, window_end). psycopg
    raises ProgrammingError at execute time — and NOTHING in this file executes
    SQL, so every test stayed green. The dry-run would have caught it; a dry-run
    is not always run.

    This pins the arity of each SQL constant against the tuple its call site
    passes, parsed out of the source. It is a stand-in for execution, not a
    substitute for it.
    """
    import ast

    src = open(ra.__file__).read()
    tree = ast.parse(src)

    expected: dict[str, int] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr != "execute" or not node.args:
            continue
        target = node.args[0]
        if not (isinstance(target, ast.Name) and target.id.startswith("SQL_")):
            continue
        if len(node.args) < 2 or not isinstance(node.args[1], ast.Tuple):
            continue
        expected[target.id] = len(node.args[1].elts)

    assert expected, "found no SQL_* execute call sites — this guard is vacuous"

    for name, n_args in sorted(expected.items()):
        sql = getattr(ra, name)
        n_ph = _strip_sql_comments(sql).count("%s")
        assert n_ph == n_args, (
            f"{name}: {n_ph} placeholder(s) in the SQL but {n_args} argument(s) "
            f"at the call site — psycopg would raise ProgrammingError"
        )


def test_new_assets_is_gated_on_the_assets_own_first_observed():
    """THE NEWNESS TEST. 4.7, relay 133: "Either it reads first_observed (and
    the label is true) or the label changes to what it measures."

    A NOT EXISTS over earlier asset_first_seen rows is NOT a substitute and was
    shipped as one for several hours. asset_surface_event only has history back
    to when its writer went live, so an asset first observed before that has no
    such row and passes the test while being months old. Measured on the
    2026-09-13 -> 09-14 window: old digest 14, event-log test 9, first_observed
    test 0 — and 0 is the true answer.
    """
    sql = _strip_sql_comments(ra.SQL_NEW_ASSETS_IN_WINDOW)
    assert "a.first_observed >" in sql and "a.first_observed <=" in sql, \
        "newness must be decided by the asset's own first_observed"


def test_new_assets_requires_no_earlier_first_seen_event():
    """The panel claims first-ever discovery, so the query must exclude any
    asset that already has an earlier asset_first_seen row.

    surface_diff.py emits asset_first_seen per PRODUCER — correct there, wrong
    for this panel. Once the light-tier surface write-back went live
    (2026-09-09) every asset it touched re-announced itself as new; measured
    2026-09-13→14, all 14 'new' assets had first_observed months earlier.
    """
    sql = _strip_sql_comments(ra.SQL_NEW_ASSETS_IN_WINDOW)
    assert "NOT EXISTS" in sql.upper(), "must exclude assets with an earlier sighting"
    assert "e0.observed_at < e.observed_at" in sql, \
        "the exclusion must be ordered: strictly EARLIER, not merely different"
    assert "e0.event_type = 'asset_first_seen'" in sql


def test_dark_assets_query_is_not_given_the_same_guard():
    """Deliberate asymmetry, pinned so nobody 'fixes' it by symmetry.

    An asset can legitimately go dark more than once — it comes back and goes
    dark again later, and the second event is real news. asset_first_seen
    cannot legitimately happen twice for the same asset. Adding a
    first-ever guard here would silently drop every recurrence.
    """
    sql = _strip_sql_comments(ra.SQL_DARK_ASSETS_IN_WINDOW)
    assert "NOT EXISTS" not in sql.upper()


def test_both_surface_queries_keep_the_tier_2_gate():
    for sql in (ra.SQL_NEW_ASSETS_IN_WINDOW, ra.SQL_DARK_ASSETS_IN_WINDOW):
        s = _strip_sql_comments(sql)
        assert "a.ownership = 'owned'" in s
        assert "a.discovery_status = 'confirmed_live'" in s


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
