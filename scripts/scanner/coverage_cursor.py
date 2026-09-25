"""relay 454 — CROSS-RUN TEMPLATE COVERAGE. Turn 27%-forever into 100% in ~4 runs.

⛔ THE DEFECT THIS CLOSES (relay 450, ruled in 454). run_medium's nuclei argv
carries no -shuffle, no -offset, no -exclude-id and no slice: it is -severity +
-tags in nuclei's own fixed internal order, cut by NUCLEI_CHUNK_WALL_S=400 and
MAX_REQUESTS_TOTAL=8000. Fixed order + fixed cut = THE SAME SUBSET EVERY RUN.
Measured independently on both instances the same day:

    Prodex  uat.prodexlabs.com        2,428 / 8,716 = 27%
    Command www.commandcompanies.com  2,427 / 8,716 = 27%

Two targets, two egress regions, two repos, within ONE request of each other.
That reproducibility IS the proof: ~6,289 critical/high templates have never
executed against these hosts and never would. The portal called it "51%
coverage", which implies sampling — it was not sampling, it was a permanent
blind spot wearing a percentage.

⭐ THE INPUT IS FREE. corpus_prewarm already runs `nuclei -tl -silent` every
scan (run_medium L3723), counts the lines, and throws the list away. Re-running
it WITH the chunk's own -severity/-tags yields that chunk's filtered universe.
We already stamp corpus identity (dir_sha256 + templates_version).

⚠ PURE. No I/O, no DB, no subprocess — pinned by AST in the tests. This module
decides WHICH templates the next run should dispatch; the dispatch itself lives
in the runner. Nothing here can send a packet.

⛔ WHAT THIS MODULE DELIBERATELY DOES NOT DO: change the wall. 4.7 ruled KEEP
NUCLEI_CHUNK_WALL_S and MAX_REQUESTS_TOTAL as they are. Raising them hides the
loss (you clear the wall and hit the request ceiling, reporting `complete` while
dropping ~40% of the corpus with no cut-reason). With a cursor, "the wall cuts
here, the next run resumes there" stops being a bug and becomes the design:
oversubscription turns into a rolling window instead of a silent 73% hole.
"""
from __future__ import annotations

import bisect
import math

# ── Slice sizing ───────────────────────────────────────────────────────────
# Measured executed-template count on a cut critical,high chunk, both
# instances: ~2,427. The slice is sized BELOW that on purpose — see
# plan_slice's docstring for why completing matters more than filling the wall.
DEFAULT_SLICE_SIZE = 2000

# ── 270 Change 1: the slice may never BE the corpus ────────────────────────
# ⛔ THE DEADLOCK THIS CLOSES (269, proven on live telemetry 2026-09-25).
# `medium:cve`'s corpus is 1,576 templates — SMALLER than DEFAULT_SLICE_SIZE.
# plan_slice therefore returned the WHOLE corpus as one window, which silently
# turns the rolling-window design OFF: there is no smaller unit left to defer
# to, so the chunk is all-or-nothing against NUCLEI_CHUNK_WALL_S=400. It was cut
# at an identical 94% on six consecutive uat runs (2,731 units, ~2,586 requests,
# +/-0.5%), banked nothing each time because fold_dispatch correctly refuses to
# advance on an incomplete chunk, and replanned the same losing window forever.
# `last_dispatched` is still NULL on uat, link AND tour.
#
# `critical,high` is the control: corpus 4,318 > slice 2,000, so its window IS a
# window — it completes in 230-349s and the cursor advances. The mechanism works.
# It just switches itself off, with no signal, whenever a corpus is smaller than
# a constant nobody re-checked when the corpus grew.
#
# CAP: a slice is never more than this fraction of its corpus, so a cut always
# has somewhere smaller to land. 0.85 against an observed 94% cut leaves ~9
# points of headroom. Applied UNCONDITIONALLY, not only after a failure: gating
# it on evidence of a hold would re-deadlock on every wrap, because the wrap
# resets the window to the full corpus with consecutive_holds back at 0.
SLICE_CORPUS_CAP = 0.85

# BACKOFF: belt and braces. If a chunk is STILL cut after the cap, each hold in
# a row shrinks the next window further. This is what consecutive_holds (262
# ruling B, migration 20260924a) was added to make possible — a chunk that
# cannot say how much it did can still say how many times it failed.
SLICE_HOLD_BACKOFF = 0.85

# Never shrink below this. A 3-template window would take 500 runs to cover a
# corpus and the per-invocation overhead would dominate; at that point the chunk
# is misbehaving and should be investigated, not subdivided into invisibility.
MIN_SLICE_SIZE = 25

# Cursor state keys. `last_dispatched` is a TEMPLATE PATH, never an integer
# offset — see resume_index for the reason, which is the correctness trap 4.7
# flagged in the 454 ruling.
NEW_CURSOR: dict = {
    "last_dispatched": None,
    "pass_count": 0,
    "corpus_identity": None,
    # 262 ruling B (migration 20260924a). Runs in a row this chunk did NOT move.
    # See fold_dispatch for exactly what counts as moving — it is not "completed".
    "consecutive_holds": 0,
}


class CoveragePlanError(ValueError):
    """The next slice cannot be planned honestly. Raised, never degraded."""


def corpus_identity(dir_sha256, templates_version) -> str | None:
    """The identity of the corpus a cursor position was taken against.

    Recorded so a coverage claim is SCOPED ("100% of v10.4.9") rather than
    asserted across a corpus bump that silently changed what the templates are.
    Returns None when either half is missing — an unidentifiable corpus must not
    masquerade as a known one.
    """
    if not dir_sha256 or not templates_version:
        return None
    return f"{templates_version}:{str(dir_sha256)[:16]}"


def order_templates(lines) -> list[str]:
    """⭐ OUR ORDER, NOT NUCLEI'S (4.7 fork B). Deterministic, total, stable.

    Takes the raw `nuclei -tl -silent` lines for ONE chunk (i.e. run with that
    chunk's own -severity/-tags) and returns the ordered universe for it.

    Sorted rather than shuffled because a sort needs no seed to persist and no
    seed to go stale: the same corpus always yields the same order on both
    instances, so a dry-run preview matches what actually runs and the two repos
    stay comparable. Deduped because -tl can list a template reachable by more
    than one tag, and a duplicate would consume a slice position twice.
    """
    seen = set()
    out = []
    for raw in lines or []:
        if not isinstance(raw, str):
            continue
        t = raw.strip()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return sorted(out)


def resume_index(ordered, last_dispatched) -> int:
    """Where the next slice starts. THE CORRECTNESS TRAP, SOLVED BY NOT HAVING IT.

    ⛔ 4.7's 454 ruling flagged: "when dir_sha256/templates_version changes, the
    cursor's OFFSETS no longer map to the same templates — reconcile (reset to
    0, or diff-and-append)." That is exactly right ABOUT OFFSETS. So this module
    does not store an offset. It stores the last dispatched TEMPLATE PATH, and
    resumes at the first path sorted after it.

    ⭐ WHY THAT DISSOLVES THE TRAP rather than handling it. Templates inserted
    anywhere in a sorted list shift every subsequent index, so ANY corpus change
    invalidates an integer cursor and forces either a reset (throwing away
    accrued coverage) or a diff (needing the full old list persisted). A path
    has no such dependency:
      - templates added BEFORE the position are picked up on the next wrap;
      - templates added AFTER it are covered naturally by the next slice;
      - the last dispatched template being DELETED still resolves, because
        bisect finds the first survivor greater than it.
    So a corpus bump costs no reset, no diff, and no over-claim — and the state
    stays ONE STRING per (asset, chunk), which is the coarse storage 4.7 ruled
    for in fork C.

    ⚠ Coverage claims are still SCOPED by corpus_identity, because "we have
    dispatched everything" means something different after the corpus changes.
    That is a labelling concern, not a cursor-arithmetic one.
    """
    if not last_dispatched:
        return 0
    return bisect.bisect_right(ordered, last_dispatched)


def effective_slice_size(size, corpus_len, holds=0) -> int:
    """The window size actually used. PURE.

    ⛔ Two independent guards, both from 270:
      1. CAP — never more than SLICE_CORPUS_CAP of the corpus, so `size` can
         never swallow a corpus whole and disable deferral (269).
      2. BACKOFF — shrink further per consecutive hold, so a chunk that still
         does not fit converges instead of repeating.

    Both floor at MIN_SLICE_SIZE and are clamped to the corpus, so this can
    never return more than there is nor less than is useful.
    """
    if corpus_len <= 0:
        return max(1, int(size))
    cap = max(MIN_SLICE_SIZE, math.ceil(corpus_len * SLICE_CORPUS_CAP))
    eff = min(int(size), cap)
    holds = max(0, int(holds or 0))
    if holds:
        # ⛔ The floor must never ENLARGE a window. Caught by
        # test_a_completed_ADVANCE_resets_holds_to_zero, which asks for a
        # 10-template slice: a bare max(MIN_SLICE_SIZE, ...) handed back 25 and
        # turned a backoff into a 2.5x expansion. A guard that can grow the
        # thing it is meant to shrink is worse than no guard.
        floor = min(MIN_SLICE_SIZE, eff)
        eff = max(floor, math.floor(eff * (SLICE_HOLD_BACKOFF ** holds)))
    return max(1, min(eff, corpus_len))


def plan_slice(ordered, cursor=None, size=DEFAULT_SLICE_SIZE) -> dict:
    """The next window to dispatch. PURE. Returns a description, never a request.

    ⛔ SIZED TO COMPLETE, NOT TO FILL THE WALL. This is the honesty hinge of the
    whole design. 4.7's ruling says the ledger records "what WE DISPATCHED" —
    but if we dispatch N and the wall cuts at M < N, then recording N is an
    OVER-CLAIM, and an over-claim is strictly worse than the 27% blind spot it
    replaces: the blind spot is at least visible. So the slice is sized below
    the measured per-run throughput (~2,427) and the cursor advances ONLY on a
    chunk that actually completed — see fold_dispatch.

    Returns:
      templates  — the exact list to hand nuclei
      start/end  — window bounds into `ordered`
      wrapped    — True when this slice restarted at 0 (a pass completed)
      last       — the path to store IF the chunk completes
      exhausted  — True when `ordered` is empty; nothing to plan
    """
    ordered = list(ordered or [])
    if size <= 0:
        raise CoveragePlanError(f"slice size must be positive, got {size}")
    if not ordered:
        return {"templates": [], "start": 0, "end": 0, "wrapped": False,
                "last": None, "exhausted": True}

    state = cursor or NEW_CURSOR
    start = resume_index(ordered, state.get("last_dispatched"))

    # WRAP: the previous pass reached the end. Start over — coverage is a cycle,
    # not a one-shot, because templates and the target both keep changing.
    wrapped = start >= len(ordered)
    if wrapped:
        start = 0

    # 270 Change 1. Sized from the CORPUS and the chunk's own hold history, not
    # from `size` alone — see effective_slice_size.
    eff = effective_slice_size(size, len(ordered),
                               holds=state.get("consecutive_holds"))
    end = min(start + eff, len(ordered))
    window = ordered[start:end]
    return {"templates": window, "start": start, "end": end,
            "wrapped": wrapped, "last": window[-1] if window else None,
            "exhausted": False, "slice_size": eff, "requested_size": int(size)}


def fold_dispatch(cursor, plan, *, completed, corpus_id=None) -> dict:
    """Advance the cursor after a run. PURE. Returns a NEW state dict.

    ⛔ ADVANCE ONLY ON COMPLETION — the refuse-rather-than-degrade direction.
    If the chunk was CUT, we do not know which template it stopped on (nuclei's
    JSONL emits MATCHES, not ATTEMPTS — the fact that ruled out the exact-set
    ledger in fork A), so advancing by the dispatched count would silently mark
    unexecuted templates as covered. Instead the cursor does not move and the
    next run re-dispatches the same window.

    ⚠ THAT IS DELIBERATELY WASTEFUL, and the waste is the point: re-running a
    window costs time we were spending anyway, while a false coverage claim
    costs an audit answer that is wrong. A cut slice means the size is
    mis-tuned — which is a measurement to act on, not a number to paper over.
    """
    state = dict(cursor or NEW_CURSOR)
    if corpus_id is not None:
        state["corpus_identity"] = corpus_id
    holds = int(state.get("consecutive_holds") or 0)
    if not completed:
        # ── 262 ruling B: a HOLD. The cursor stays put; count it. ─────────────
        # ⛔ This is the signal `last_dispatched IS NULL` cannot give: a chunk
        # that advanced once and then froze has a non-null position forever, and
        # asset_template_cursor.updated_at moves on every run, held or not. Only
        # a counter that survives across runs can say "stuck for N".
        state["consecutive_holds"] = holds + 1
        return state
    moved = bool(plan and plan.get("last"))
    if moved:
        state["last_dispatched"] = plan["last"]
    if plan and plan.get("wrapped"):
        state["pass_count"] = int(state.get("pass_count") or 0) + 1
    # ── RESET only when the cursor actually MOVED (Howie, 2026-09-24). ────────
    # 262 says "reset on a completed ADVANCE"; `completed` alone is not that. A
    # completed run whose plan dispatched nothing would otherwise wipe the stall
    # signal at the exact moment it mattered. Today the only caller never passes
    # such a plan (plan_and_write_slice raises first) — this keeps it true later.
    #
    # ⚠ "Moved" means THE FOLD ADVANCED (a non-empty window completed), NOT
    # "last_dispatched changed value". A corpus no larger than the slice
    # (medium:tech is 2 templates) re-dispatches the whole corpus every run and
    # lands on the SAME last path each time — yet every such run completes a
    # full pass (pass_count climbs). Comparing values would score the healthiest
    # chunk we have as permanently stuck.
    #
    # A completed-but-empty fold is neither a hold nor an advance: the counter
    # is left exactly as it was.
    if moved:
        state["consecutive_holds"] = 0
    else:
        state["consecutive_holds"] = holds
    return state


def coverage_fraction(ordered, cursor=None) -> float:
    """How far through the CURRENT pass this asset/chunk is, 0.0-1.0.

    ⚠ DERIVED, never stored (4.7 fork C: no per-template rows). The honest
    portal number is this plus pass_count — "62% of pass 3" — which replaces the
    misleading per-run "51%" that implied sampling.

    ⚠ Takes the ORDERED LIST, not a length, because the position is a
    bisect against the actual paths. A length alone cannot locate a path, and
    faking it with a stored integer would reintroduce exactly the offset
    fragility resume_index exists to avoid.
    """
    ordered = list(ordered or [])
    if not ordered:
        return 0.0
    state = cursor or NEW_CURSOR
    if not state.get("last_dispatched"):
        return 0.0
    return min(1.0, resume_index(ordered, state["last_dispatched"]) / len(ordered))


def build_coverage_preview(ordered, cursor=None,
                           size=DEFAULT_SLICE_SIZE, corpus_id=None) -> dict:
    """The DRY-RUN description an operator reads BEFORE anything is dispatched.

    ⛔ `dispatched` is hard-coded False because nothing in this module can
    dispatch; it is present so a reader never has to infer it. Same shape as the
    382 enforcement sweep and the 444 egress planner.
    """
    plan = plan_slice(ordered, cursor, size)
    total = len(ordered or [])
    state = cursor or NEW_CURSOR
    return {
        "dry_run": True,
        "dispatched": False,
        "corpus_identity": corpus_id or state.get("corpus_identity"),
        "corpus_size": total,
        # ⛔ 270: report the size ACTUALLY USED, not the one requested. Before
        # this, a 1,576-template corpus with a requested 2,000 previewed as
        # "slice_size 2000, runs_to_full_pass 1" while the real window was 1,340
        # and the real answer was 2. A dry-run that overstates its own reach is
        # the same defect as a scan reporting `complete` on a corpus it never
        # dispatched — see 269.
        "slice_size": plan.get("slice_size", size),
        "requested_slice_size": int(size),
        "window": [plan["start"], plan["end"]],
        "wrapped": plan["wrapped"],
        "pass_count": int(state.get("pass_count") or 0),
        "runs_to_full_pass": _runs_to_full_pass(total, plan.get("slice_size", size)),
    }


def _runs_to_full_pass(total, eff) -> int | None:
    """Ceiling division, against the EFFECTIVE window. Returns None when the
    window is zero — never a division error, never a silent 1."""
    eff = int(eff or 0)
    if eff <= 0 or not total:
        return None
    return (int(total) + eff - 1) // eff
