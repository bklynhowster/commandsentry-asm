"""relay 454 — cross-run template coverage. The cursor, and what it must refuse.

    python3 -m pytest scripts/scanner/test_coverage_cursor.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from coverage_cursor import (  # noqa: E402
    DEFAULT_SLICE_SIZE,
    MIN_SLICE_SIZE,
    SLICE_CORPUS_CAP,
    effective_slice_size,
    NEW_CURSOR,
    CoveragePlanError,
    build_coverage_preview,
    corpus_identity,
    coverage_fraction,
    fold_dispatch,
    order_templates,
    plan_slice,
    resume_index,
)

# A stand-in corpus. Zero-padded so lexicographic order is also numeric order,
# which keeps the fixtures readable — the production corpus is template paths.
CORPUS = [f"cves/2024/CVE-2024-{i:05d}.yaml" for i in range(1, 101)]


# ── ordering is OURS and is total (4.7 fork B) ─────────────────────────────

def test_order_is_deterministic_across_input_order():
    """The same corpus must yield the same order on BOTH instances, or a
    dry-run preview does not describe what actually runs."""
    a = order_templates(list(reversed(CORPUS)))
    b = order_templates(CORPUS)
    assert a == b == sorted(CORPUS)


def test_order_dedupes():
    """-tl can list one template under two tags; a duplicate would burn a slice
    position twice and silently shrink coverage."""
    assert order_templates(["b.yaml", "a.yaml", "b.yaml"]) == ["a.yaml", "b.yaml"]


def test_order_drops_blanks_and_non_strings():
    assert order_templates(["a.yaml", "", "  ", None, 7]) == ["a.yaml"]


# ── the cursor advances, and that is the whole point ───────────────────────

def test_a_fresh_cursor_starts_at_the_beginning():
    p = plan_slice(CORPUS, None, size=10)
    assert p["start"] == 0 and p["templates"] == CORPUS[:10]


def test_the_next_run_RESUMES_instead_of_restarting():
    """⭐ THE DEFECT, CLOSED. Pre-454 every run re-dispatched templates 0..N —
    the same 27% forever. Run 2 must start where run 1 stopped."""
    p1 = plan_slice(CORPUS, None, size=10)
    c1 = fold_dispatch(NEW_CURSOR, p1, completed=True)
    p2 = plan_slice(CORPUS, c1, size=10)
    assert p2["start"] == 10
    assert p2["templates"] == CORPUS[10:20]
    assert not set(p1["templates"]) & set(p2["templates"]), "a run repeated work"


def test_the_union_of_consecutive_runs_covers_the_WHOLE_corpus():
    """⭐ THE ASSERTION THAT PROVES THE THESIS. Every other test here can pass
    while coverage still never accrues. This one says the blind spot closes."""
    cur, seen, runs = NEW_CURSOR, set(), 0
    while runs < 20:
        p = plan_slice(CORPUS, cur, size=10)
        if p["wrapped"]:
            break
        seen.update(p["templates"])
        cur = fold_dispatch(cur, p, completed=True)
        runs += 1
    assert seen == set(CORPUS), f"missed {len(set(CORPUS) - seen)} templates"
    assert runs == 10, runs


def test_the_real_numbers_reach_a_full_pass_in_three_runs():
    """⚠ CORRECTED FROM PRODUCTION (relay 470). This test used to say "8,716
    templates ... full pass in four runs". That was WRONG about production and
    the docstring taught the wrong number to anyone re-deriving from it: 8,716
    is nuclei's internal COUNTER-UNIT total, not a template count. The live
    cursor on uat.prodexlabs.com records the real figure — corpus_size 4318 for
    critical,high — so at DEFAULT_SLICE_SIZE 2000 a full pass is THREE runs
    (2000, 2000, 318), not four.

    The mechanism was never wrong; only the premise was. Measured, not guessed."""
    corpus = [f"t{i:05d}" for i in range(4318)]
    cur, runs = NEW_CURSOR, 0
    while runs < 10:
        p = plan_slice(corpus, cur, size=DEFAULT_SLICE_SIZE)
        if p["wrapped"]:
            break
        cur = fold_dispatch(cur, p, completed=True)
        runs += 1
    assert runs == 3, runs


# ── wrap: coverage is a cycle ──────────────────────────────────────────────

def test_reaching_the_end_WRAPS_and_counts_a_pass():
    cur = {"last_dispatched": CORPUS[-1], "pass_count": 0,
           "corpus_identity": "v1:abc"}
    p = plan_slice(CORPUS, cur, size=10)
    assert p["wrapped"] is True and p["start"] == 0
    assert fold_dispatch(cur, p, completed=True)["pass_count"] == 1


def test_a_non_wrapping_slice_does_NOT_count_a_pass():
    p = plan_slice(CORPUS, None, size=10)
    assert fold_dispatch(NEW_CURSOR, p, completed=True)["pass_count"] == 0


# ── ⛔ the over-claim boundary — the honesty hinge ──────────────────────────

def test_a_CUT_chunk_does_NOT_advance_the_cursor():
    """⛔ THE TRAP INSIDE THE RULING. 'The ledger records what we DISPATCHED' is
    only honest while dispatched == executed. nuclei's JSONL emits MATCHES, not
    ATTEMPTS, so a cut chunk cannot say where it stopped — advancing anyway
    would mark unexecuted templates as covered. That is WORSE than the 27%
    blind spot, because the blind spot is at least visible."""
    p = plan_slice(CORPUS, None, size=10)
    cur = fold_dispatch(NEW_CURSOR, p, completed=False)
    assert cur["last_dispatched"] is None
    assert plan_slice(CORPUS, cur, size=10)["start"] == 0, (
        "a cut run must re-dispatch the same window, never skip past it")


def test_a_cut_chunk_still_records_the_corpus_it_ran_against():
    cur = fold_dispatch(NEW_CURSOR, plan_slice(CORPUS, None, size=10),
                        completed=False, corpus_id="v10.4.9:abcdef")
    assert cur["corpus_identity"] == "v10.4.9:abcdef"


def test_fold_does_not_mutate_the_cursor_it_was_given():
    start = dict(NEW_CURSOR)
    fold_dispatch(start, plan_slice(CORPUS, None, size=10), completed=True)
    assert start["last_dispatched"] is None


# ── ⭐ the corpus-change trap, dissolved rather than handled ────────────────

def test_a_template_INSERTED_before_the_cursor_does_not_lose_our_place():
    """⛔ 4.7's 454 ruling: 'when the corpus changes the cursor's OFFSETS no
    longer map'. Correct — which is why this stores a PATH, not an offset. An
    integer 10 would now point at a different template; a path still points at
    itself."""
    cur = {"last_dispatched": CORPUS[9], "pass_count": 0,
           "corpus_identity": "v1"}
    grown = order_templates(CORPUS + ["cves/2024/CVE-2024-00000.yaml"])
    p = plan_slice(grown, cur, size=10)
    assert p["templates"][0] == CORPUS[10], (
        "resume landed on the wrong template after an insertion")


def test_a_template_APPENDED_after_the_cursor_is_picked_up_naturally():
    cur = {"last_dispatched": CORPUS[-2], "pass_count": 0}
    grown = order_templates(CORPUS + ["cves/2024/CVE-2024-99999.yaml"])
    p = plan_slice(grown, cur, size=10)
    assert "cves/2024/CVE-2024-99999.yaml" in p["templates"]


def test_the_cursor_template_being_DELETED_still_resolves():
    """bisect finds the first survivor greater than it — no reset, no diff, no
    persisted old list."""
    cur = {"last_dispatched": CORPUS[9], "pass_count": 0}
    shrunk = [t for t in CORPUS if t != CORPUS[9]]
    assert plan_slice(shrunk, cur, size=5)["templates"][0] == CORPUS[10]


def test_resume_index_is_exact_at_the_boundaries():
    assert resume_index(CORPUS, None) == 0
    assert resume_index(CORPUS, "") == 0
    assert resume_index(CORPUS, CORPUS[0]) == 1
    assert resume_index(CORPUS, CORPUS[-1]) == len(CORPUS)


# ── corpus identity SCOPES the claim ───────────────────────────────────────

def test_corpus_identity_needs_both_halves():
    assert corpus_identity("abc123", "v10.4.9") == "v10.4.9:abc123"
    assert corpus_identity(None, "v10.4.9") is None
    assert corpus_identity("abc123", None) is None, (
        "an unidentifiable corpus must not masquerade as a known one")


# ── derived coverage, never stored (fork C) ────────────────────────────────

def test_coverage_is_derived_from_position():
    assert coverage_fraction(CORPUS, None) == 0.0
    assert coverage_fraction(CORPUS, {"last_dispatched": CORPUS[49]}) == 0.5
    assert coverage_fraction(CORPUS, {"last_dispatched": CORPUS[-1]}) == 1.0


def test_coverage_of_an_empty_corpus_is_zero_not_a_crash():
    assert coverage_fraction([], None) == 0.0


# ── refusals + the preview is a description, never a request ───────────────

def test_a_nonpositive_slice_size_is_REFUSED():
    """Silently treating 0 as 'everything' or 'nothing' would either blow the
    wall or stall coverage forever with no error."""
    for bad in (0, -1):
        with pytest.raises(CoveragePlanError):
            plan_slice(CORPUS, None, size=bad)


def test_an_empty_corpus_is_exhausted_not_an_infinite_wrap():
    p = plan_slice([], None, size=10)
    assert p["exhausted"] is True and p["templates"] == []


def test_the_preview_dispatches_nothing():
    prev = build_coverage_preview(CORPUS, None, size=10, corpus_id="v1:abc")
    assert prev["dry_run"] is True
    assert prev["dispatched"] is False
    assert prev["corpus_size"] == 100
    assert prev["runs_to_full_pass"] == 10


def test_the_preview_reports_runs_to_a_full_pass_with_the_real_numbers():
    prev = build_coverage_preview([f"t{i}" for i in range(8716)], None, size=2427)
    assert prev["runs_to_full_pass"] == 4


def test_the_default_slice_sits_under_the_measured_throughput():
    """⚠ Sized to COMPLETE, not to fill the wall. Measured executed count on a
    cut critical,high chunk was 2,427 on BOTH instances; a slice at or above
    that would be cut, and a cut slice never advances the cursor."""
    assert DEFAULT_SLICE_SIZE < 2427


# ── ⛔ this module cannot dispatch anything ────────────────────────────────

def test_the_planner_carries_no_IO_of_its_own():
    """⛔ AST, NOT A TEXT SCAN. A substring search reds on this module's own
    docstring, which promises exactly the property being asserted — the
    prose-contains-the-token trap this codebase has now hit six times
    (relay 373, 382, 430, 444, 446, here). Read the IMPORTS, which prose cannot
    fake."""
    import ast
    import inspect

    import coverage_cursor
    tree = ast.parse(inspect.getsource(coverage_cursor))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    banned = {"subprocess", "requests", "urllib", "socket", "http", "psycopg",
              "os", "shutil", "sys"}
    assert not (imported & banned), f"the planner gained I/O: {sorted(imported & banned)}"


def test_the_TAIL_slice_reports_an_HONEST_end():
    """⚠ FOUND BY A SURVIVING MUTATION. `ordered[start:end]` clamps on its own,
    so an unclamped `end` yields the right templates and a WRONG number — the
    preview would advertise a window past the end of the corpus (e.g. [90, 110]
    on a 100-template corpus) and any consumer doing end/total would compute
    >100% coverage. The list was right, so nothing caught it."""
    cur = {"last_dispatched": CORPUS[89], "pass_count": 0}
    p = plan_slice(CORPUS, cur, size=50)
    assert p["start"] == 90
    assert p["end"] == 100, "end ran past the corpus"
    assert len(p["templates"]) == 10
    assert p["end"] <= len(CORPUS)


def test_the_preview_window_never_exceeds_the_corpus():
    prev = build_coverage_preview(
        CORPUS, {"last_dispatched": CORPUS[89]}, size=50)
    assert prev["window"][1] <= prev["corpus_size"], prev["window"]


# ── 262 ruling B: consecutive_holds (migration 20260924a) ───────────────────

def test_a_new_cursor_starts_with_zero_holds():
    assert NEW_CURSOR["consecutive_holds"] == 0


def test_a_CUT_run_counts_one_hold_and_does_not_move():
    p = plan_slice(CORPUS, None, size=10)
    cur = fold_dispatch(NEW_CURSOR, p, completed=False)
    assert cur["consecutive_holds"] == 1
    assert cur["last_dispatched"] is None


def test_holds_ACCUMULATE_run_over_run():
    """⛔ The whole point: 'stuck for N runs'. A counter that can only ever
    read 1 is indistinguishable from no counter."""
    cur = NEW_CURSOR
    for expected in (1, 2, 3, 4):
        cur = fold_dispatch(cur, plan_slice(CORPUS, cur, size=10), completed=False)
        assert cur["consecutive_holds"] == expected


def test_a_chunk_that_ADVANCED_then_FROZE_is_visible():
    """The case `last_dispatched IS NULL` cannot see: a real position, then no
    movement. This is why 4.7 approved the column."""
    cur = fold_dispatch(NEW_CURSOR, plan_slice(CORPUS, None, size=10), completed=True)
    assert cur["last_dispatched"] is not None and cur["consecutive_holds"] == 0
    for _ in range(3):
        cur = fold_dispatch(cur, plan_slice(CORPUS, cur, size=10), completed=False)
    assert cur["last_dispatched"] == CORPUS[9]        # position held
    assert cur["consecutive_holds"] == 3              # and now we can SAY so


def test_a_completed_ADVANCE_resets_holds_to_zero():
    cur = dict(NEW_CURSOR, consecutive_holds=5)
    cur = fold_dispatch(cur, plan_slice(CORPUS, cur, size=10), completed=True)
    assert cur["consecutive_holds"] == 0
    assert cur["last_dispatched"] == CORPUS[9]


def test_a_WRAP_that_lands_on_the_same_last_path_still_counts_as_moving():
    """⚠ medium:tech is 2 templates against a 2,000 slice: every run dispatches
    the whole corpus and ends on the SAME path, yet every run completes a pass.
    'Moved' means the fold advanced — not that the stored string changed.
    Comparing values would call our healthiest chunk permanently stuck."""
    small = ["tech/a.yaml", "tech/b.yaml"]
    cur = fold_dispatch(NEW_CURSOR, plan_slice(small, None, size=2000), completed=True)
    cur = dict(cur, consecutive_holds=2)          # pretend two earlier cuts
    p = plan_slice(small, cur, size=2000)
    assert p["wrapped"] and p["last"] == cur["last_dispatched"]   # same string
    cur = fold_dispatch(cur, p, completed=True)
    assert cur["consecutive_holds"] == 0
    assert cur["pass_count"] == 1


def test_a_completed_run_that_dispatched_NOTHING_leaves_holds_untouched():
    """Howie's ruling 2026-09-24: reset only when the cursor actually moves. A
    completed-but-empty fold is neither a hold nor an advance, so it must not
    wipe the stall signal."""
    cur = dict(NEW_CURSOR, last_dispatched=CORPUS[4], consecutive_holds=3)
    empty = plan_slice([], cur, size=10)
    assert empty["exhausted"] and empty["last"] is None
    after = fold_dispatch(cur, empty, completed=True)
    assert after["consecutive_holds"] == 3
    assert after["last_dispatched"] == CORPUS[4]


def test_a_cursor_from_before_the_migration_reads_as_zero_holds():
    """Rows and dicts written before 20260924a have no key at all."""
    legacy = {"last_dispatched": CORPUS[9], "pass_count": 0}
    cur = fold_dispatch(legacy, plan_slice(CORPUS, legacy, size=10), completed=False)
    assert cur["consecutive_holds"] == 1


def test_holding_does_not_mutate_the_cursor_it_was_given():
    start = dict(NEW_CURSOR, consecutive_holds=2)
    fold_dispatch(start, plan_slice(CORPUS, start, size=10), completed=False)
    assert start["consecutive_holds"] == 2


# ── 270 Change 1 — the slice may never BE the corpus ───────────────────────
# Regression cover for 269: medium:cve's 1,576-template corpus is SMALLER than
# DEFAULT_SLICE_SIZE, so plan_slice returned the whole corpus, deferral turned
# itself off, and six consecutive uat runs were cut at an identical 94% and
# banked nothing. These tests fail if that can happen again.

MEDIUM_CVE_CORPUS = 1576      # measured, uat/link/tour, 2026-09-25
CRITICAL_HIGH_CORPUS = 4318   # the control: bigger than the slice, always worked


def test_a_slice_is_never_the_whole_corpus():
    """⛔ THE 269 DEADLOCK. If the window can be the entire corpus there is
    nothing smaller to defer to, and a cut is unrecoverable forever."""
    for corpus in (MEDIUM_CVE_CORPUS, 335, 1999, DEFAULT_SLICE_SIZE + 1):
        eff = effective_slice_size(DEFAULT_SLICE_SIZE, corpus)
        assert eff < corpus, (
            f"corpus {corpus}: slice {eff} is the whole corpus — this is exactly "
            "the all-or-nothing state that deadlocked medium:cve")


def test_a_corpus_larger_than_the_slice_is_left_alone():
    """The control. critical,high always worked; the fix must not touch it."""
    assert effective_slice_size(DEFAULT_SLICE_SIZE, CRITICAL_HIGH_CORPUS) \
        == DEFAULT_SLICE_SIZE


def test_consecutive_holds_shrink_the_next_window():
    """262 ruling B's counter earning its keep: a chunk that cannot report how
    much it covered can still report how many times it failed."""
    sizes = [effective_slice_size(DEFAULT_SLICE_SIZE, MEDIUM_CVE_CORPUS, holds=h)
             for h in range(4)]
    assert sizes == sorted(sizes, reverse=True), sizes
    assert len(set(sizes)) == len(sizes), f"backoff did not move: {sizes}"


def test_the_backoff_has_a_floor():
    assert effective_slice_size(DEFAULT_SLICE_SIZE, MEDIUM_CVE_CORPUS,
                                holds=99) >= MIN_SLICE_SIZE


def test_a_tiny_corpus_is_still_covered_whole():
    """medium:tech is 2 templates and completes in ~3s. The cap must not
    subdivide something that trivially fits."""
    for corpus in (1, 2, 10):
        assert effective_slice_size(DEFAULT_SLICE_SIZE, corpus) == corpus


def test_plan_slice_applies_the_cap_and_reports_it():
    corpus = [f"t{i:05d}.yaml" for i in range(MEDIUM_CVE_CORPUS)]
    plan = plan_slice(corpus, cursor=dict(NEW_CURSOR))
    assert len(plan["templates"]) < len(corpus)
    assert plan["slice_size"] == len(plan["templates"])
    assert plan["requested_size"] == DEFAULT_SLICE_SIZE


def test_the_full_corpus_is_covered_and_the_wrap_does_not_re_deadlock():
    """⛔ THE ONE THAT MATTERS. Walks real runs against the real constraint:
    the wall completes a window only at or below ~94% of this corpus. Before the
    fix this covered ZERO templates on every run, forever."""
    corpus = [f"t{i:05d}.yaml" for i in range(MEDIUM_CVE_CORPUS)]
    fits = 1470                      # observed 94% cut point
    cursor, covered = dict(NEW_CURSOR), set()
    for _ in range(6):
        plan = plan_slice(corpus, cursor=cursor)
        completed = len(plan["templates"]) <= fits
        if completed:
            covered.update(plan["templates"])
        cursor = fold_dispatch(cursor, plan, completed=completed)
        assert cursor["consecutive_holds"] == 0, "a window was still cut"
    assert covered == set(corpus), f"only {len(covered)}/{len(corpus)} covered"
    assert cursor["pass_count"] >= 2, "the corpus never wrapped"


def test_the_preview_reports_the_window_it_will_ACTUALLY_use():
    """⛔ A dry-run that overstates its own reach is the same defect as a scan
    reporting `complete` on a corpus it never dispatched (269). Before 270 this
    previewed slice_size 2000 / runs_to_full_pass 1 for a 1,576 corpus whose
    real window was 1,340 and whose real answer was 2."""
    corpus = [f"t{i:05d}.yaml" for i in range(MEDIUM_CVE_CORPUS)]
    p = build_coverage_preview(corpus)
    assert p["slice_size"] == p["window"][1] - p["window"][0]
    assert p["slice_size"] < p["requested_slice_size"]
    assert p["runs_to_full_pass"] == 2, p["runs_to_full_pass"]


def test_the_preview_never_divides_by_a_zero_window():
    assert build_coverage_preview([])["runs_to_full_pass"] is None
