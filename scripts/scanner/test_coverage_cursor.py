"""relay 454 — cross-run template coverage. The cursor, and what it must refuse.

    python3 -m pytest scripts/scanner/test_coverage_cursor.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from coverage_cursor import (  # noqa: E402
    DEFAULT_SLICE_SIZE,
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


def test_the_real_numbers_reach_a_full_pass_in_four_runs():
    """8,716 critical/high templates at the measured ~2,427 executed per run."""
    corpus = [f"t{i:05d}" for i in range(8716)]
    cur, runs = NEW_CURSOR, 0
    while runs < 10:
        p = plan_slice(corpus, cur, size=2427)
        if p["wrapped"]:
            break
        cur = fold_dispatch(cur, p, completed=True)
        runs += 1
    assert runs == 4, runs


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
