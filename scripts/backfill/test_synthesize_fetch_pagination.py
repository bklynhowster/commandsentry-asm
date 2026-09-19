#!/usr/bin/env python3
"""Tests for the enrich worker's work-queue read — 2026-09-15, relay 139.

⛔ THE DEFECT. fetch_findings issued `q.limit(5000)` with no where-clause and
no order, then filtered for thin rows in Python. PostgREST clamps every
response to the project's Data API max_rows = 1000, so the worker received an
unordered 1000-row sample of a 2511-row table. Measured on hdygktppfvuspnumpfuq
2026-09-15 14:05 UTC: 232 thin findings, ZERO of them inside the 1000 rows the
worker could see. 52 consecutive runs went green logging "No findings match."
while the precheck in the same run logged "221 thin finding(s) — running
synthesis."

Neither step failed. They disagreed, and nothing was watching. These tests
watch.

The fake client below returns EXACTLY PAGE_SIZE rows for every page until the
data runs out — the shape that makes an unpaginated reader believe it has seen
everything. That is the condition the production code silently mis-read.
"""

from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import synthesize_finding_descriptions as sfd  # noqa: E402

REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
)
WORKFLOW = os.path.join(
    REPO_ROOT, ".github", "workflows", "enrich-finding-descriptions.yml"
)


# ---------------------------------------------------------------------------
# (a) the precheck and the worker must ask the same question
# ---------------------------------------------------------------------------

def _yml_query() -> str:
    """The precheck's WHOLE filter string, not a fragment of it."""
    yml = open(WORKFLOW).read()
    m = re.search(r"^\s*QUERY='(?P<q>.*)'\s*$", yml, re.M)
    assert m, "could not find the QUERY='…' line in the workflow"
    return m.group("q")


def test_thin_predicate_matches_the_workflow_precheck_query():
    """The two disagreeing IS the defect, so the yml is read, not trusted.

    If someone edits one side, this fails and names both strings.
    """
    q = _yml_query()
    m = re.search(r"or=\((?P<pred>.*)\)$", q)
    assert m, f"no or=(…) group in the precheck query: {q}"
    assert m.group("pred") == sfd.THIN_PREDICATE, (
        "precheck and worker predicates have drifted:\n"
        f"  yml    : {m.group('pred')}\n"
        f"  worker : {sfd.THIN_PREDICATE}"
    )


def test_the_precheck_pin_compares_the_WHOLE_filter_not_just_the_or_group():
    """⛔ 4.7's condition, relay 154, and it is the reason the pin was widened.

    The precheck filter is now TWO terms ANDed: the sticky-reject exclusion and
    the thin or-group. A pin that reads only the or-group would stay green while
    someone deleted the rejection term — the precheck would go back to counting
    rejected rows as work, the worker would keep refusing them, and the run log
    would report a denominator it never processes. That is the exact drift this
    file exists to catch, one term to the left.

    So: reconstruct the WHOLE expected string from the worker's own constants and
    compare it to the whole line. Nothing in the query is unaccounted for.
    """
    q = _yml_query()
    expected = (f"{sfd.REJECTION_MARKER_COLUMN}=is.null"
                f"&or=({sfd.THIN_PREDICATE})")
    assert q == expected, (
        "the precheck filter and the worker's predicates have drifted:\n"
        f"  yml      : {q}\n"
        f"  expected : {expected}"
    )


def test_the_rejection_term_is_ANDed_not_folded_into_the_or_group():
    """An exclusion inside an OR is not an exclusion. If the marker term ever
    migrates inside the parentheses, a rejected row matches the FIRST clause
    (description_synth.is.null) and is counted again."""
    q = _yml_query()
    or_group = re.search(r"or=\((?P<pred>.*)\)$", q).group("pred")
    assert sfd.REJECTION_MARKER_COLUMN not in or_group, (
        "the rejection marker is inside the or-group — it must be an AND term")
    assert q.startswith(f"{sfd.REJECTION_MARKER_COLUMN}=is.null&")


def test_thin_predicate_is_a_superset_of_the_python_inclusion_test():
    """The Python filter includes a row when its description is THIN even if
    all three columns are non-NULL — reachable only when description_source is
    unattested. Without the 4th clause the server-side predicate would exclude
    exactly those rows, and filtering server-side would SHRINK the queue.
    """
    assert "description_source.not.in." in sfd.THIN_PREDICATE
    for src in ("ai_synthesized", "ai_synthesized_reviewed", "manual"):
        assert src in sfd.THIN_PREDICATE


def test_predicate_also_catches_a_null_description_source():
    """⚠ `not.in` is THREE-VALUED and the 4th clause alone has a hole.

    For description_source IS NULL, NOT (NULL IN (...)) evaluates to NULL, so
    PostgREST EXCLUDES the row — while Python's `in {...}` on None is False,
    so the worker WOULD have included it. The one value the 4th clause cannot
    see is exactly the population it exists to protect.

    Verified against the live API on a column that has NULLs:
        impact IS NULL 232 + impact not.in.(bogus) 2283 == 2515 total.
    """
    assert "description_source.is.null" in sfd.THIN_PREDICATE


def test_no_limit_above_the_max_rows_cap_survives_anywhere_in_the_worker():
    """`.limit(5000)` against a max_rows=1000 project is the original bug. Any
    `.limit(N)` with N > 1000 is the same mistake wearing a different number.
    """
    src = open(sfd.__file__).read()
    src = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    for n in re.findall(r"\.limit\((\d+)\)", src):
        assert int(n) <= 1000, (
            f".limit({n}) exceeds the Data API max_rows cap — it will be "
            f"silently clamped. Paginate with .range() instead."
        )


def test_page_size_stays_under_the_cap():
    """The loop terminates on a SHORT page. If PAGE_SIZE >= max_rows a clamped
    page is indistinguishable from a final one and the walk stops early.
    """
    assert sfd.PAGE_SIZE < 1000


# ---------------------------------------------------------------------------
# (b) the worker must walk past 1000
# ---------------------------------------------------------------------------

class _FakeBuilder:
    """Minimal postgrest-py builder double. Records the predicates applied and
    serves .range() windows out of a fixed row list, clamping like PostgREST."""

    MAX_ROWS = 1000

    def __init__(self, rows, state=None, head=False):
        self._rows = rows
        self._head = head          # PER-CHAIN, not shared: the count probe is a
                                   # separate chain from the page reads, and an
                                   # earlier head=True must not blank them.
        self.state = state if state is not None else {
            "or_": None, "ordered": None, "ranges": [], "cursors": [],
            "count": None, "is_": [], "eq": []
        }

    def _child(self, rows=None, head=None):
        # type(self), not _FakeBuilder: a subclass that overrides .range() must
        # survive the chain. Hard-coding the base class silently reverted the
        # double to honest behaviour after one call and made the guard test
        # pass vacuously.
        return type(self)(
            self._rows if rows is None else rows,
            self.state,
            self._head if head is None else head,
        )

    def select(self, *a, **kw):
        if kw.get("count"):
            self.state["count"] = kw["count"]
        return self._child(head=bool(kw.get("head")))

    def eq(self, col, val):
        # ⚠ THIS USED TO IGNORE ITS ARGUMENTS AND RETURN EVERY ROW. Harmless
        # while nothing tested a `--finding-id` run; the moment relay 154 added
        # a targeted path, a double that answers "all rows" to "this one row"
        # would have made the rejection probe pass over the wrong record and the
        # test green for the wrong reason. Same class as FakeRest having no
        # .patch() — a double that cannot represent the case cannot test it.
        self.state.setdefault("eq", []).append((col, val))
        return self._child([r for r in self._rows if r.get(col) == val])

    def is_(self, col, val):
        """PostgREST `col=is.null`. Recorded AND applied — the recording is what
        the pin reads, the applying is what makes the fires/doesn't-fire pair
        mean something."""
        self.state.setdefault("is_", []).append((col, val))
        if val == "null":
            return self._child([r for r in self._rows if not r.get(col)])
        if val == "not.null":
            return self._child([r for r in self._rows if r.get(col)])
        return self._child()

    def in_(self, col, vals):
        return self._child()

    def or_(self, pred):
        self.state["or_"] = pred
        return self._child()

    def order(self, col):
        self.state["ordered"] = col
        return self._child()

    def limit(self, n):
        return self._child(self._rows[: min(n, self.MAX_ROWS)])

    def gt(self, col, val):
        self.state["cursors"].append(val)
        return self._child([r for r in self._rows if r[col] > val])

    def range(self, start, end):
        self.state["ranges"].append((start, end))
        width = min(end - start + 1, self.MAX_ROWS)
        return self._child(self._rows[start : start + width])

    def update(self, payload):
        return self._child()

    def execute(self):
        rows = self._rows
        if self._head:
            return type("R", (), {"data": [], "count": len(rows)})()
        return type("R", (), {"data": rows, "count": len(rows)})()


class _FakeSB:
    def __init__(self, findings, assets=None, history=None):
        self._f = findings
        self._a = assets or []
        self._h = history or []
        self.state = {
            "or_": None, "ordered": None, "ranges": [], "cursors": [],
            "count": None, "is_": [], "eq": []
        }

    def table(self, name):
        rows = {"findings": self._f, "assets": self._a,
                "finding_history": self._h}[name]
        return _FakeBuilder(rows, self.state)


def _thin_row(i: int) -> dict:
    return {
        "finding_id": f"host.example:scanner:F-{i:05d}",
        "title": f"Finding {i}",
        "severity": "LOW",
        "asset_id": "host.example",
        "description": "Source: https://example.invalid/adv",
        "cve": [], "cwe": [], "category": None, "source": "scanner",
        "tags": [], "cvss_score": None,
        "affected_component": None, "affected_component_version": None,
        "matched_url": None, "frameworks": [],
        "description_synth": None, "description_source": "scanner",
        "description_synth_input_hash": None,
        # relay 154 — every fixture row carries the marker columns, unset.
        "description_synth_reviewed_at": None,
        "description_synth_reviewed_by": None,
        "impact": None, "remediation": None, "references": [],
    }


def _rejected_row(i: int, who: str = "admin-uuid",
                  when: str = "2026-09-19T12:00:00Z") -> dict:
    """A row the portal's rejectDescription would leave behind: the three synth
    columns NULLed, source flipped back to 'scanner', reviewed_at/by stamped.
    ⚠ Thin in every way THIN_PREDICATE can see — that is the whole trap."""
    r = _thin_row(i)
    r["description_synth_reviewed_at"] = when
    r["description_synth_reviewed_by"] = who
    return r


def test_worker_walks_past_the_1000_row_cap():
    """The regression that matters. 2511 rows, cap 1000 — an unpaginated read
    sees 1000 and stops. The paginated read must see all of them.
    """
    rows = [_thin_row(i) for i in range(2511)]
    sb = _FakeSB(rows)

    out = sfd.fetch_findings(sb, severities=None, finding_id=None, force=False)

    assert len(out) == 2511, (
        f"worker saw {len(out)} of 2511 — it is still reading a clamped window"
    )
    assert sb.state["ordered"] == "finding_id", \
        ".range() over an unordered set is not a stable window"
    assert sb.state["or_"] == sfd.THIN_PREDICATE, \
        "the thin filter must be applied SERVER-side, not after the fetch"
    assert len(sb.state["cursors"]) >= 2511 // sfd.PAGE_SIZE - 1, "did not paginate"


# ═══════════════════════════════════════════════════════════════════════════
# ⛔ REJECT IS STICKY — relay 154. Howie: "Reject means leave this one alone
# until a human says otherwise."
#
# The pair below is what 4.7 mutates: drop the AND-clause in _apply_scope and
# the FIRES half must go red. A rejected row is thin in every way the predicate
# can see, so if the exclusion is not reached, nothing else stops it.
# ═══════════════════════════════════════════════════════════════════════════

def test_a_rejected_row_is_excluded_from_the_paged_walk():
    """FIRES. Nine ordinary thin rows and one rejected — nine come back."""
    rows = [_thin_row(i) for i in range(9)] + [_rejected_row(99)]
    sb = _FakeSB(rows)
    out = sfd.fetch_findings(sb, severities=None, finding_id=None, force=False)
    ids = {f.finding_id for f in out}
    assert len(out) == 9, f"expected 9, got {len(out)} — the rejection leaked in"
    assert _rejected_row(99)["finding_id"] not in ids
    assert (sfd.REJECTION_MARKER_COLUMN, "null") in sb.state["is_"], \
        "the exclusion must be SERVER-side, not a post-fetch filter"


def test_an_unrejected_thin_row_is_still_picked_up():
    """DOESN'T FIRE. The other half of the pair: an exclusion that excludes
    everything is not an exclusion, it is an outage."""
    sb = _FakeSB([_thin_row(i) for i in range(9)])
    out = sfd.fetch_findings(sb, severities=None, finding_id=None, force=False)
    assert len(out) == 9


def test_force_does_NOT_override_a_rejection():
    """⛔ 4.7's condition 1, relay 154. A human said no; --force re-runs the
    MACHINE, it does not overrule the human. If force bypassed this, "sticky"
    would be a lie — and force is exactly what an operator reaches for when a
    row stubbornly has no text, which is what a rejected row looks like."""
    rows = [_thin_row(0), _rejected_row(99)]
    sb = _FakeSB(rows)
    out = sfd.fetch_findings(sb, severities=None, finding_id=None, force=True)
    ids = {f.finding_id for f in out}
    assert _rejected_row(99)["finding_id"] not in ids, \
        "--force re-synthesised a row a human rejected"
    assert _thin_row(0)["finding_id"] in ids, "--force stopped working entirely"
    # ⛔ AND THE QUERY ITSELF, NOT JUST THE OUTPUT. Two of my own mutants
    # survived this test before this line existed: moving the clause below the
    # `--finding-id` return, and moving it inside `if not force`. Both passed,
    # because the Python gate caught the row either way — the exclusion was
    # real, but ONE OF ITS TWO LAYERS WAS UNTESTED, its partner covering for it.
    # Asserting the outcome cannot tell a two-layer defence from a one-layer
    # one; asserting the query can. (It is also a live difference: without the
    # server-side term a --force run drags every reviewed row across the wire
    # to throw it away in Python.)
    assert (sfd.REJECTION_MARKER_COLUMN, "null") in sb.state["is_"], \
        "--force skipped the SERVER-side rejection filter"


def test_a_targeted_finding_id_run_on_a_rejected_row_says_so_and_exits_zero(capsys):
    """⛔ THE PATH THAT ROUTES AROUND EVERYTHING ELSE. `--finding-id` returns
    from _apply_scope BEFORE the thin filter, so an exclusion written next to
    the or_() would never execute here. It answers instead of going quiet:
    silence is the wrong reply to an operator who ran a targeted job BECAUSE
    the row has no text."""
    sb = _FakeSB([_rejected_row(99, who="howie@example", when="2026-09-19T12:00:00Z")])
    out = sfd.fetch_findings(
        sb, severities=None, finding_id=_rejected_row(99)["finding_id"], force=False)
    assert out == []
    printed = capsys.readouterr().out
    assert "rejected by howie@example" in printed
    assert "2026-09-19T12:00:00Z" in printed
    assert "clear the rejection in the portal" in printed


def test_a_targeted_finding_id_run_on_an_ordinary_row_still_works(capsys):
    """The doesn't-fire half of the targeted path."""
    sb = _FakeSB([_thin_row(3)])
    out = sfd.fetch_findings(
        sb, severities=None, finding_id=_thin_row(3)["finding_id"], force=False)
    assert len(out) == 1
    assert "rejected by" not in capsys.readouterr().out
    # Same reason as the --force test above: pin the QUERY, so the clause cannot
    # drift below the early return while the probe quietly covers for it.
    assert (sfd.REJECTION_MARKER_COLUMN, "null") in sb.state["is_"], \
        "the targeted path skipped the SERVER-side rejection filter"


def test_the_exclusion_is_applied_to_the_count_probe_AND_the_pages():
    """The guard at the end of fetch_findings compares a server-side COUNT to
    the number of rows walked. If the exclusion were applied to only one of
    them, the count and the walk would disagree and the worker would refuse to
    run on a queue that is not partial — a red build for a non-event, which is
    the trade this file already refused once."""
    rows = [_thin_row(i) for i in range(5)] + [_rejected_row(90 + i) for i in range(3)]
    sb = _FakeSB(rows)
    out = sfd.fetch_findings(sb, severities=None, finding_id=None, force=False)
    assert len(out) == 5
    # the marker filter was applied more than once: count probe + at least one page
    applied = [p for p in sb.state["is_"] if p[0] == sfd.REJECTION_MARKER_COLUMN]
    assert len(applied) >= 2, \
        f"exclusion applied {len(applied)} time(s) — probe and pages must both carry it"


def test_the_python_gate_holds_even_if_the_query_does_not():
    """BOTH GATES OR NEITHER. Hand fetch_findings a double that ignores the
    server-side filter entirely — the row must still not come back, because the
    Python inclusion test checks the marker too. An exclusion that lives only in
    the query is one a future code path walks past, which is how `--finding-id`
    got here in the first place."""
    class _BlindBuilder(_FakeBuilder):
        def is_(self, col, val):          # records, refuses to filter
            self.state.setdefault("is_", []).append((col, val))
            return self._child()

    class _BlindSB(_FakeSB):
        def table(self, name):
            rows = {"findings": self._f, "assets": self._a,
                    "finding_history": self._h}[name]
            return _BlindBuilder(rows, self.state)

    sb = _BlindSB([_thin_row(0), _rejected_row(99)])
    out = sfd.fetch_findings(sb, severities=None, finding_id=None, force=False)
    ids = {f.finding_id for f in out}
    assert _rejected_row(99)["finding_id"] not in ids, \
        "the Python gate did not hold when the server-side filter was blind"
    assert _thin_row(0)["finding_id"] in ids


def test_a_short_page_ends_the_walk():
    """Termination: don't loop forever, don't stop early on an exact multiple."""
    rows = [_thin_row(i) for i in range(sfd.PAGE_SIZE)]  # exactly one full page
    sb = _FakeSB(rows)
    out = sfd.fetch_findings(sb, severities=None, finding_id=None, force=False)
    assert len(out) == sfd.PAGE_SIZE
    # one full page + one empty page proves it checked for more
    assert len(sb.state["cursors"]) == 1  # the second page carried a cursor


def test_force_walks_everything_not_just_the_thin_rows():
    """--force means re-synthesise all in scope, so no thin predicate — but it
    still has to paginate, and on 2511 rows that is where it used to stop."""
    rows = [_thin_row(i) for i in range(2511)]
    sb = _FakeSB(rows)
    out = sfd.fetch_findings(sb, severities=None, finding_id=None, force=True)
    assert len(out) == 2511
    assert sb.state["or_"] is None, "--force must not apply the thin filter"
    assert sb.state["ordered"] == "finding_id"


# ---------------------------------------------------------------------------
# (c) the contradiction guard
# ---------------------------------------------------------------------------

class _ClampedBuilder(_FakeBuilder):
    """Counts the whole set honestly, but serves only the FIRST page and then
    claims exhaustion — the shape of a reinstated cap or a lost page."""

    def gt(self, col, val):
        self.state["cursors"].append(val)
        return self._child([])          # nothing after the first page


def test_guard_exits_when_the_count_and_the_walk_disagree():
    """⛔ THE ASSERTION THAT WOULD HAVE TURNED 52 GREEN NO-OPS RED ON DAY ONE.

    A worker that cannot see its whole queue must fail, not quietly process a
    subset and report success. Here the count probe says 2511 and the walk
    yields one page — exactly what a re-clamped read looks like.
    """
    rows = [_thin_row(i) for i in range(2511)]

    class SB(_FakeSB):
        def table(self, name):
            r = {"findings": self._f, "assets": self._a,
                 "finding_history": self._h}[name]
            return _ClampedBuilder(r, self.state)

    with pytest.raises(SystemExit) as ei:
        sfd.fetch_findings(SB(rows), severities=None, finding_id=None, force=False)
    assert ei.value.code == 1


def test_a_non_advancing_read_fails_loudly_instead_of_spinning():
    """⛔ FOUND BY MUTATION, and it was a flaw in the FIX, not the original bug.

    Reverting .range() to .limit(5000) makes every page come back full, so the
    short-page termination test never fires, the offset advances into a window
    the server ignores, and the loop spins until the workflow's 120-minute
    timeout kills it. The first version of this pagination had no bound: the
    mutation did not fail the suite, it HUNG it — and a job that hangs and
    reports nothing is the same failure class as the 52 green no-ops.
    """
    rows = [_thin_row(i) for i in range(2511)]

    class IgnoresCursor(_FakeBuilder):
        """Ignores the cursor: the same rows come back forever.

        ⚠ SELF-LIMITING ON PURPOSE. Without the production bound this loop
        never ends, and an unbounded double turns the mutation into an OOM
        kill (exit 137) rather than a named failure — which is how the first
        matrix run scored 'drop the page bound' as SURVIVED. The double stops
        well past the legitimate page count so a real failure is still
        attributable to THIS test.
        """
        def gt(self, col, val):
            self.state["cursors"].append(val)
            if len(self.state["cursors"]) > 40:
                raise AssertionError(
                    "pagination did not terminate and was not bounded — "
                    "the production loop would spin to the workflow timeout"
                )
            return self._child()

    class SB(_FakeSB):
        def table(self, name):
            r = {"findings": self._f, "assets": self._a,
                 "finding_history": self._h}[name]
            return IgnoresCursor(r, self.state)

    with pytest.raises(SystemExit) as ei:
        sfd.fetch_findings(SB(rows), severities=None, finding_id=None, force=False)
    assert ei.value.code == 1


def test_the_page_bound_does_not_trip_on_a_normal_walk():
    """A bound that fires on the happy path is worse than no bound."""
    rows = [_thin_row(i) for i in range(2511)]
    out = sfd.fetch_findings(_FakeSB(rows), severities=None,
                             finding_id=None, force=False)
    assert len(out) == 2511


def test_guard_proceeds_when_the_queue_GREW_during_the_walk():
    """⛔ THE PAIR TO THE GUARD ABOVE, and the reason the test is `<` not `!=`.

    This workflow is chained to Scanner completion — precisely when thin rows
    are inserted. findings went 2511 -> 2515 during the hour this was written.
    A count at t and a walk at t+2s legitimately disagree upward.

    `!=` shipped first. It would have emailed Howie a red workflow captioned
    "Refusing to run on a partial queue" for a queue that was not partial:
    alarming copy for a non-event, built into the fix for the silent-no-op
    class. Growth must be logged and processed, never fatal.

    ⚠ The first version of this test was VACUOUS — it grew the table before the
    count probe ran, so count and walk agreed and mutating `<` back to `!=`
    survived. The growth has to land BETWEEN them, which is why this counts
    table() calls: call 1 builds the base query, call 2 is the count probe,
    calls 3+ are the pages.
    """
    base = [_thin_row(i) for i in range(1000)]
    extra = [_thin_row(9000 + i) for i in range(5)]   # sort AFTER the base ids

    class GrowsBetweenCountAndWalk(_FakeSB):
        calls = 0

        def table(self, name):
            if name != "findings":
                return super().table(name)
            self.calls += 1
            # calls 1-2: base query + count probe. calls 3+: the page reads.
            rows = base if self.calls <= 2 else base + extra
            return _FakeBuilder(rows, self.state)

    sb = GrowsBetweenCountAndWalk(base)
    out = sfd.fetch_findings(sb, severities=None, finding_id=None, force=False)

    assert len(out) == 1005, (
        f"growth must be processed, not truncated — got {len(out)}, want 1005"
    )


def test_guard_is_silent_when_the_walk_is_complete():
    """A guard that fires on the happy path gets deleted."""
    rows = [_thin_row(i) for i in range(1200)]
    out = sfd.fetch_findings(_FakeSB(rows), severities=None,
                             finding_id=None, force=False)
    assert len(out) == 1200


# ---------------------------------------------------------------------------
# (d) transport retry
# ---------------------------------------------------------------------------

def test_retry_recovers_from_a_transient_transport_fault(monkeypatch):
    import httpx
    monkeypatch.setattr(sfd.time, "sleep", lambda *_: None)

    calls = {"n": 0}

    class B:
        def execute(self):
            calls["n"] += 1
            if calls["n"] < 3:
                raise httpx.RemoteProtocolError("server disconnected")
            return "ok"

    assert sfd._execute_with_retry(B(), "test") == "ok"
    assert calls["n"] == 3


def test_retry_gives_up_and_raises_rather_than_returning_empty(monkeypatch):
    """Silently returning [] after exhausting retries would recreate the exact
    failure mode being fixed: a green run that saw no work."""
    import httpx
    monkeypatch.setattr(sfd.time, "sleep", lambda *_: None)

    class B:
        def execute(self):
            raise httpx.ConnectError("refused")

    with pytest.raises(httpx.ConnectError):
        sfd._execute_with_retry(B(), "test")


def test_a_real_postgrest_error_is_not_retried(monkeypatch):
    """Retrying a malformed query just makes the same mistake three times."""
    monkeypatch.setattr(sfd.time, "sleep", lambda *_: None)
    calls = {"n": 0}

    class B:
        def execute(self):
            calls["n"] += 1
            raise ValueError("400 Bad Request: malformed or= clause")

    with pytest.raises(ValueError):
        sfd._execute_with_retry(B(), "test")
    assert calls["n"] == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
