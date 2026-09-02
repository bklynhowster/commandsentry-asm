#!/usr/bin/env python3
"""phase_contract.py — the @phase contract + registry (spec 190 / 4.7 rulings 191).

WHY THIS EXISTS. 10,276 lines across three runners, ~150 hand-written bookkeeping
calls, ZERO phase abstractions. Every tool hand-wires five obligations —
tools_run.append, mark_tool_ok/mark_tool_degraded, artifacts, flush_progress,
source tag — and NOTHING enforces that all five happened, or happened in the
right order. That ceremony is why ~10 installed tools are wired into no tier, and
every bug found 2026-08-27/28 was an instance of it:

  * heavy close-out missing params
  * tools_run credited BEFORE the work, so a degraded tool counted as coverage
    (migration 20260828a had to fix the autocloser to compensate)
  * a phase defined but never called
  * source tied to run intensity (fixed in step 1: phase_source.py)
  * gau under-invoked with no declared yield floor

The framework here owns those obligations so they are true BY CONSTRUCTION. A
phase declares what it is and returns what happened; it never touches ctx
bookkeeping itself.

⚠ 4.7's 5th risk (191): centralising the ceremony makes THIS module load-bearing
for every phase — a bug here hits all phases uniformly, where the old hand-wiring
failed one tool at a time. That is why test_phase_contract.py mutation-tests each
obligation, and why content_fetch (built, dark, small) is the first citizen: prove
the contract on one phase before any tier migrates to it.

THE FIVE OBLIGATIONS the executor owns:
  1. credit tools_run AFTER the work returns — never before (the 20260828a bug)
  2. set tool_status for every credited tool, so the close_out set-equality
     invariant (assert_tool_status_invariant) holds by construction
  3. persist artifacts the phase produced
  4. tag findings.source by the phase's DECLARED tier (phase_source, step 1)
  5. flush progress + record timing

DEGRADATION TAXONOMY (4.7 ruling Q2 — do NOT collapse these):
  OK          — worked
  DEGRADED    — the tool failed/timed out/returned nothing. CONTINUE the scan.
  SKIPPED     — deliberately not run (policy/not-applicable). NOT a failure.
  ABORT_SCAN  — a HARM condition: ban detected, VPN egress lost, target
                unreachable. Continuing would deepen a ban or scan from the
                wrong egress. This is the ONLY outcome that stops the run, and
                it is why medium's 15 DegradedRunError raises cannot be blanket
                converted to degrade-and-continue.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from degradation import (COVERAGE_COMPLETE, COVERAGE_PARTIAL_MINIMAL,
                         COVERAGE_PARTIAL_SIGNIFICANT)
from phase_source import LIGHT, MEDIUM, HEAVY, source_for_tier

# Tier ordering — a tier selection is CUMULATIVE: heavy = light ∪ medium ∪ heavy.
# This single line is what makes heavy ADDITIVE instead of a replacement.
_TIER_RANK = {LIGHT: 1, MEDIUM: 2, HEAVY: 3}


# ── EXECUTION ORDER (4.7 ruling Q4 spec 194, corrected in 195) ──────────────
#
# Cheapest ban-detector FIRST, most-aggressive LAST, so an ABORT_SCAN cuts off
# everything expensive downstream. This ordering is load-bearing for TWO
# separate reasons and must not be reshuffled casually:
#
#  1. BAN BUDGET — do not fire nuclei's full ladder + dalfox + probes at a
#     target that is going to ban us. Find out first, abort cheaply.
#  2. 🔴 WAF CONTEXT — `build_chunk_plan` (run_medium) chooses the FortiGate
#     SAFE-ONLY plan vs the AGGRESSIVE plan by reading IN-SCAN state
#     (`ctx.waf_kind`, set by wafw00f; `ctx.waf_detected`, also set by
#     waf_differential). If the detectors run AFTER nuclei plans, heavy fires
#     broad templates at a WAF-fronted host — the exact self-inflicted ban the
#     safe-only branch exists to prevent. `httpx -td` populates
#     `ctx.tech_stack`, which the same plan reads for its stack-specific
#     chunks, so LIGHT must also precede MEDIUM_TOOLS.
#
# Gaps of 10 leave room to slot phases without renumbering.
ORDER_REACHABILITY = 10    # can we reach it at all; egress health
ORDER_BAN_DETECT = 20      # fwbbot_check, waf_differential, wafw00f (~5 reqs)
ORDER_LIGHT = 30           # DNS/TLS/headers/CSP/methods/paths/httpx/wpvuln
ORDER_PASSIVE_DEPTH = 40   # gau (zero target traffic), content_fetch, stack-id
ORDER_MEDIUM_TOOLS = 50    # nuclei chunked, nikto, ffuf, katana — attack-shaped
ORDER_HEAVY_DEPTH = 60     # naabu/fingerprintx + active probes (dalfox, arjun)

# Default order per tier when a phase does not declare one.
_DEFAULT_ORDER = {LIGHT: ORDER_LIGHT, MEDIUM: ORDER_MEDIUM_TOOLS,
                  HEAVY: ORDER_HEAVY_DEPTH}


# ── outcomes ────────────────────────────────────────────────────────────────

class Outcome:
    OK = "ok"
    DEGRADED = "degraded"
    SKIPPED = "skipped"          # legacy alias — see GATE_SKIPPED
    GATE_SKIPPED = "skipped"     # phase EXISTS, a per-asset gate says not here
    DISABLED = "disabled"        # phase not operational for ANY asset
    ABORT_SCAN = "abort_scan"
    # ── PARTIAL / MIXED — 4.7 rulings ⑪ + ⑫ on spec 200 (2026-08-30) ──────────
    # Ruling ⑦ originally collapsed PARTIAL_OK into DEGRADED here, on a premise I
    # supplied and that turned out to be FALSE on this path: run_phase re-derives
    # tool_status from the PhaseResult, and the _LegacyRecorder's rich entries are
    # never copied to the real ctx. So on the registry path PhaseResult is the
    # ONLY carrier, and collapsing into it does not merely simplify an in-flight
    # value — it deletes the distinction from the persisted record. Command run
    # #2632 proved it live: a cut nuclei phase persisted as
    # {"degraded": "wall_clock_cut_180s"}, and the portal's "cut short" label was
    # inert. 4.7 reversed ⑦ on that evidence.
    PARTIAL = "partial"          # ran, OUR bound cut it, output is a real subset
    MIXED = "mixed"              # sub-units disagree — see PhaseResult.per_unit_state


@dataclass
class UnitResult:
    """One sub-invocation of a phase — a nuclei chunk, an ffuf wordlist slice.

    4.7 ruling ⑫: "any chunk cut → PARTIAL" is not enough. A phase where 1 of 30
    chunks was cut has far more coverage than one where 15 of 30 were, and both
    would read as bare PARTIAL. MIXED only means anything if the per-unit
    breakdown travels with it, so the breakdown is the load-bearing half of ⑫.

    Deliberately generic: nuclei chunks are the first case, not the only one —
    ffuf wordlist slices and any tool run in a loop over parameters have the same
    shape.
    """
    name: str
    outcome: str = Outcome.OK
    reason: str = ""
    coverage: str | None = None
    matches: int = 0
    # ── EVIDENCE (increment 2b) ─────────────────────────────────────────────
    # The bucket is the verdict; these are what let a reader see WHICH cut
    # chunks were nearly done. Run #2645 shipped without them and the counts
    # were silently lost in translation — mark_tool_partial wrote them into the
    # recorder's per-chunk entries, but UnitResult had nowhere to put them, so
    # _units_from_recorder dropped them on the floor. Same shape of failure as
    # the ⑦ premise: data present upstream, discarded at a boundary.
    requests: int | None = None
    total: int | None = None
    percent: int | None = None
    rps: int | None = None

    def as_dict(self) -> dict:
        d = {"name": self.name, "outcome": self.outcome}
        if self.reason:
            d["reason"] = self.reason
        if self.coverage:
            d["coverage"] = self.coverage
        if self.matches:
            d["matches"] = self.matches
        for k in ("requests", "total", "percent", "rps"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


@dataclass
class PhaseResult:
    """What a phase returns. The phase does NO bookkeeping — it reports."""
    outcome: str = Outcome.OK
    reason: str = ""                                   # slug, for DEGRADED/SKIPPED/ABORT
    artifacts: list[tuple] = field(default_factory=list)   # (name, kind, payload)
    findings: list[Any] = field(default_factory=list)      # FindingEvent-likes
    meta: dict = field(default_factory=dict)               # shape for the yield floor
    coverage: str | None = None                            # bucket, PARTIAL/MIXED only
    per_unit_state: list = field(default_factory=list)     # list[UnitResult] (⑫)

    @classmethod
    def ok(cls, **kw) -> "PhaseResult":
        return cls(outcome=Outcome.OK, **kw)

    @classmethod
    def degraded(cls, reason: str, **kw) -> "PhaseResult":
        return cls(outcome=Outcome.DEGRADED, reason=reason, **kw)

    @classmethod
    def skipped(cls, reason: str, **kw) -> "PhaseResult":
        return cls(outcome=Outcome.SKIPPED, reason=reason, **kw)

    @classmethod
    def abort(cls, reason: str, **kw) -> "PhaseResult":
        return cls(outcome=Outcome.ABORT_SCAN, reason=reason, **kw)

    @classmethod
    def partial(cls, reason: str, coverage: str | None = None, **kw) -> "PhaseResult":
        """Every sub-unit that ran was cut by our own bound."""
        return cls(outcome=Outcome.PARTIAL, reason=reason, coverage=coverage, **kw)

    @classmethod
    def mixed(cls, reason: str, coverage: str | None = None, **kw) -> "PhaseResult":
        """Sub-units disagree — some clean, some cut/failed. per_unit_state carries
        the breakdown; the phase-level verdict alone is not sufficient and says so."""
        return cls(outcome=Outcome.MIXED, reason=reason, coverage=coverage, **kw)

    @property
    def is_coverage_negative(self) -> bool:
        """True when this phase must NOT be read as having established coverage.
        The single question every consumer actually needs answered."""
        return self.outcome in (Outcome.DEGRADED, Outcome.PARTIAL, Outcome.MIXED,
                                Outcome.GATE_SKIPPED, Outcome.ABORT_SCAN)


class DoubleExecutionError(Exception):
    """A phase executed twice in ONE scan (4.7 ruling Q1, spec 194/195).

    assert_no_double_registration() checks REGISTRATION overlap; this checks
    EXECUTION overlap, and only the second one can actually corrupt a scan. A
    phase may legitimately be registered in the registry AND still hand-called by
    a legacy runner during the migration window — that is safe precisely because
    only one path fires per scan (a scan runs exactly one tier). If both ever
    fire, tools_run is credited twice and the close_out set-equality invariant
    silently breaks. Fail LOUD, before the second credit."""

    def __init__(self, phase: str, scan_run_id: str = ""):
        super().__init__(
            f"phase {phase!r} already credited in scan {scan_run_id or '<unknown>'} "
            f"— registry executor AND legacy runner both invoking?")
        self.phase = phase


class PhaseAbort(Exception):
    """Raised by the executor when a phase returns ABORT_SCAN. Carries the reason
    so the runner can route it exactly like DegradedRunError's harm-condition
    path (stop scanning; do NOT keep poking a banned target)."""

    def __init__(self, phase: str, reason: str):
        super().__init__(f"{phase}: {reason}")
        self.phase = phase
        self.reason = reason


# ── the declaration ─────────────────────────────────────────────────────────

@dataclass
class PhaseSpec:
    name: str
    tier: str
    fn: Callable
    requires_binary: Optional[str] = None
    needs_vpn: bool = False
    timeout_s: Optional[int] = None
    healthy_yield: Optional[Callable[[dict], Optional[str]]] = None
    enabled: bool = True                 # dark-launch switch
    order: Optional[int] = None          # execution order; see ORDER_* constants

    @property
    def effective_order(self) -> int:
        """Declared order, else the tier default. Ties break on declaration
        order (Python's sort is stable), which keeps sibling phases in the
        sequence their authors wrote them."""
        return self.order if self.order is not None else _DEFAULT_ORDER[self.tier]

    @property
    def source(self) -> str:
        """findings.source for THIS phase — by declared tier, never run intensity."""
        return source_for_tier(self.tier)


REGISTRY: list[PhaseSpec] = []


def phase(*, name: str, tier: str, requires_binary: str | None = None,
          needs_vpn: bool = False,
          timeout_s: int | None = None,
          healthy_yield: Callable[[dict], Optional[str]] | None = None,
          enabled: bool = True, order: int | None = None):
    """Declare a phase. Registration is the ONLY wiring — no call-site edit, which
    is how a phase could previously be defined and never invoked."""
    def deco(fn):
        if any(p.name == name for p in REGISTRY):
            raise ValueError(f"phase {name!r} already registered — double registration")
        if tier not in _TIER_RANK:
            raise ValueError(f"phase {name!r}: unknown tier {tier!r}")
        REGISTRY.append(PhaseSpec(
            name=name, tier=tier, fn=fn, requires_binary=requires_binary,
            needs_vpn=needs_vpn,
            timeout_s=timeout_s, healthy_yield=healthy_yield, enabled=enabled,
            order=order))
        return fn
    return deco


def phases_for_tier(requested: str, ordered: bool = True) -> list[PhaseSpec]:
    """CUMULATIVE selection — the one line that makes heavy additive.
    heavy → light ∪ medium ∪ heavy.

    `ordered=True` (the default) sorts by execution order, NOT by tier: the
    ruled sequence interleaves tiers deliberately — medium's wafw00f runs in the
    ban-detection group at ORDER_BAN_DETECT, long before medium's own nuclei at
    ORDER_MEDIUM_TOOLS, because nuclei's plan reads the WAF context wafw00f
    sets. Sorting by tier would silently undo that."""
    if requested not in _TIER_RANK:
        raise ValueError(f"unknown tier {requested!r}")
    want = _TIER_RANK[requested]
    sel = [p for p in REGISTRY if _TIER_RANK[p.tier] <= want]
    if ordered:
        sel.sort(key=lambda p: p.effective_order)   # stable: ties keep decl order
    return sel


def get_phase(name: str) -> PhaseSpec:
    """Look up a registered phase. Raises if absent — a call site referring to a
    phase that never registered is the 'defined but never invoked' bug, and it
    should fail loud rather than silently skip."""
    for p in REGISTRY:
        if p.name == name:
            return p
    raise KeyError(f"no registered phase {name!r} (have: {[p.name for p in REGISTRY]})")


def clear_registry() -> None:
    """Tests only — REGISTRY is module-global by design (declaration = wiring)."""
    REGISTRY.clear()


# ── the executor: the five obligations, in order ────────────────────────────

def _default_mark_partial(ctx, tool_name: str, result: "PhaseResult") -> None:
    """Write the PARTIAL/MIXED tool_status entry (4.7 ⑪/⑫).

    Shape is the same one mark_tool_partial writes on the legacy medium path, so
    the two invocation paths agree — plus `per_chunk` when the phase has
    sub-units, and `mixed` when the sub-units disagree.

        {"ok": false, "partial": true, "reason": ..., "coverage": ...,
         "matches": N, "mixed": true,
         "per_chunk": [{"name": "nuclei[critical,high]", "outcome": "partial", ...}, ...]}

    `ok: false` is the load-bearing field — it is what keeps migration
    20260828a's `tool ->> 'ok' = 'true'` predicate and delta_close_eligible from
    reading a cut-short phase as coverage. Everything else is diagnostics.
    """
    units = list(result.per_unit_state or [])
    entry = {
        "ok": False,
        "partial": True,
        "reason": result.reason or "wall_clock_cut",
        "coverage": result.coverage or "unknown",
    }
    if result.outcome == Outcome.MIXED:
        # ⑫ — a bare "partial" cannot distinguish 1-of-30 cut from 15-of-30 cut.
        # This flag tells a reader the phase-level verdict is NOT sufficient and
        # per_chunk is where the answer is.
        entry["mixed"] = True
    total_matches = sum(getattr(u, "matches", 0) or 0 for u in units)
    if total_matches:
        entry["matches"] = total_matches
    if units:
        # Summed evidence at phase level — see aggregate_coverage for why this
        # sums requests rather than averaging buckets.
        #
        # ONE SOURCE OF TRUTH for the bucket: the ADAPTER derives it (it owns
        # the units and builds the PhaseResult, which is the carrier), and this
        # writer trusts result.coverage. A first attempt had BOTH compute the
        # aggregate — which looked like belt-and-braces but actually meant
        # mutating either one left the other correct, so neither mutation was
        # detectable. Redundancy that masks mutations is worse than a single
        # path, because it converts a real regression into a silent one.
        _bucket, agg = aggregate_coverage(units)
        entry.update(agg)
        entry["per_chunk"] = [u.as_dict() for u in units]
        entry["chunks_ok"] = sum(1 for u in units if u.outcome == Outcome.OK)
        entry["chunks_cut"] = sum(1 for u in units
                                  if u.outcome in (Outcome.PARTIAL, Outcome.MIXED))
    ctx.tool_status[tool_name] = entry
    try:                                   # live progress; no-op without a dsn
        from run_medium import flush_progress
        flush_progress(ctx)
    except Exception:                      # noqa: BLE001 — best-effort only
        pass


def _merge_phase_diagnostics(ctx, tool_name: str) -> None:
    """Fold a phase's own diagnostics back into its tool_status entry (⑭′.4).

    Runs on EVERY outcome path, and it has to, for two separate reasons.

    1. mark_ok/mark_degraded REPLACE the entry wholesale
       (`ctx.tool_status[tool_name] = {"ok": True}`), so anything the phase
       body wrote there is gone by the time run_phase returns. Run #2649 lost
       every tech-detect field this way and persisted a bare `{"ok": true}` —
       the third time in this workstream that data written upstream was
       discarded at a translation boundary.
    2. A plan shrunk upstream can complete every chunk it DID plan, so it
       reads as a clean fully-OK run. `planned_chunks > actual_chunks` is the
       only surviving signal, so it must be written even when nothing was cut.

    `ctx.tool_diag` is per-tool and keyed by name. `ctx.chunk_plan_meta`
    describes the NUCLEI CHUNK PLAN specifically, and is scoped to nuclei
    here: it lives on ctx for the whole run, so an unguarded merge stamped
    `planned_chunks` onto nikto and ffuf as well (observed on run #2649).
    Those tools have no chunks — the field was meaningless on them, and a
    meaningless field that looks meaningful is how a reader gets misled.
    """
    entry = (getattr(ctx, "tool_status", None) or {}).get(tool_name)
    if not isinstance(entry, dict):
        return
    diag = (getattr(ctx, "tool_diag", None) or {}).get(tool_name)
    if diag:
        entry.update(diag)
    if tool_name.startswith("nuclei"):
        meta = getattr(ctx, "chunk_plan_meta", None)
        if meta:
            entry.update(meta)


def run_phase(spec: PhaseSpec, ctx, work_dir, *,
              mark_ok=None, mark_degraded=None, mark_skipped=None,
              mark_partial=None) -> PhaseResult:
    """Execute one phase and own ALL of its bookkeeping.

    ORDER IS THE POINT. tools_run is credited AFTER fn returns, never before, so
    a tool that ran and failed can never count as coverage for the note-127
    autocloser. A phase that is disabled, gated out, or SKIPPED does not enter
    tools_run at all — a phase that did not run is not coverage.

    Never raises for a phase-level failure: any exception becomes DEGRADED, so a
    single flaky tool cannot sink a cumulative run (4.7 Q2). The ONE exception is
    ABORT_SCAN, which is re-raised as PhaseAbort because continuing would be
    HARMFUL, not merely unproductive.
    """
    if mark_ok is None or mark_degraded is None or mark_skipped is None:
        from run_medium import (mark_tool_ok, mark_tool_degraded,  # noqa: E402
                                mark_tool_skipped)
        mark_ok = mark_ok or mark_tool_ok
        mark_degraded = mark_degraded or mark_tool_degraded
        mark_skipped = mark_skipped or mark_tool_skipped
    mark_partial = mark_partial or _default_mark_partial

    # ── double-EXECUTION guard (4.7 Q1, spec 195). Registration overlap is legal
    #    during the migration window; EXECUTION overlap is the corruption. Check
    #    BEFORE any credit so the failure is loud and nothing is written twice.
    if spec.name in ctx.tools_run:
        raise DoubleExecutionError(spec.name, getattr(ctx, "scan_run_id", ""))

    # ── pre-flight gates. TWO DIFFERENT KINDS OF "SKIP" — do not merge them.
    #
    #    They answer different questions:
    #      DISABLED     — "is this phase part of the scanner's tool set at all?"
    #                     Dark launch / feature-flagged off / config-disabled.
    #                     Not operational for ANY asset ⇒ NOT credited, no
    #                     tool_status entry. It is not in the set of things that
    #                     could have run, so set-equality is unaffected.
    #      GATE_SKIPPED — "did we look at THIS asset?"  The phase is real and
    #                     operational; a per-asset gate says it does not apply
    #                     here (e.g. the legacy adapter's
    #                     'legacy_not_applicable'). The
    #                     autocloser NEEDS this recorded: a gated-off phase did
    #                     NOT establish "we looked and found nothing" ⇒ credited
    #                     + {"skipped": reason}.
    #
    # 🔴 WHY CREDITING A SKIP IS SAFE NOW WHEN IT WAS NOT BEFORE (do not reopen).
    # Step 2 deliberately credited neither, reasoning "a phase that did not run
    # is not coverage." That was CORRECT AGAINST THE PRE-FIX AUTOCLOSER, which
    # read mere presence in tools_run as coverage. Migration 20260828a changed
    # the predicate to require `tool_status -> tool ->> 'ok' = 'true'`, so a
    # credited-but-skipped entry can no longer be misread as coverage. That
    # predicate change is the enabling condition for this reconciliation — and
    # it restores the pre-existing convention, since mark_tool_skipped's own
    # docstring already requires callers to append to tools_run first.
    if not spec.enabled:
        return PhaseResult(outcome=Outcome.DISABLED, reason="disabled")

    # REMOVED 2026-09-01 (4.7 ruling ㉓) — the is_active_probe gate.
    #
    # A PhaseSpec.is_active_probe flag used to gate a phase here on
    # assets.active_probe_authorized, under the comment "attack-shaped traffic
    # only goes to assets explicitly flagged active_probe_authorized."
    #
    # That claim was FALSE. No registered phase ever set is_active_probe=True —
    # it appeared only in the dataclass, the factory signature, and this check.
    # All 14 phases ran with the default False, so nuclei/nikto/ffuf (which ARE
    # attack-shaped) were ungated regardless of the asset's flag, while the code
    # documented a per-asset ROE control that never operated. A control that is
    # described but does not run is worse than an absent one: it survives code
    # review and audit as evidence of protection it does not provide.
    #
    # Deleted rather than wired: wiring it would have halted scanning on every
    # asset until each was individually opted in (all 66 Prodex assets are
    # flagged false), which is an operational decision, not a cleanup.
    #
    # NOT affected, verified before deletion:
    #   * assets.active_probe_authorized — still the real gate for Ship 188's
    #     fwbbot / waf_differential / safe_exploit probes, which are NOT
    #     registered phases and gate themselves (run_heavy L1726, L1833:
    #     `fire = authorized and _ACTIVE_PROBE_LIVE`).
    #   * Outcome.GATE_SKIPPED — still produced by the legacy adapter
    #     ('legacy_not_applicable') and still consumed below.
    #
    # Do not re-add this pattern without wiring a phase to it in the same commit.

    t0 = time.time()
    try:
        result = spec.fn(ctx, work_dir)
        if result is None:                     # a phase that returns nothing = OK
            result = PhaseResult.ok()
    except Exception as e:                     # noqa: BLE001 — see docstring
        # Outer operational safety net (4.7 ruling ⑧): a bug inside one phase —
        # including a mark_tool_partial misuse ValueError — degrades THAT phase
        # and lets the rest of the scan proceed, rather than killing the run.
        # The strictness stays at the producer; the recovery lives here.
        #
        # Reason slug: keep it low-cardinality and machine-groupable, but stop
        # throwing away the diagnostic. A DegradedRunError already carries a
        # stable slug of its own — propagate it instead of flattening every one
        # to "exception_DegradedRunError", which is what made run #2624's nikto
        # entry read {"degraded": "exception_DegradedRunError"} and lose the
        # actual reason. Free-text messages go to meta, never into the slug.
        reason = getattr(e, "reason", None)
        slug = reason if isinstance(reason, str) and reason else \
            f"exception_{type(e).__name__}"
        result = PhaseResult.degraded(slug)
        result.meta["exception_type"] = type(e).__name__
        result.meta["exception_detail"] = str(e)[:500]
    elapsed = round(time.time() - t0, 1)
    result.meta.setdefault("elapsed_s", elapsed)

    # ── declared yield floor ("ok" is not evidence of yield — the gau lesson).
    #    A tool can exit 0, return something, and still not have done its job.
    #
    #    4.7 ruling ⑲: this MUST also gate PARTIAL and MIXED, not just OK. The two
    #    checks are orthogonal — "did meaningful work happen?" is a different
    #    question from "did it finish?". A chunk killed by the wall clock having
    #    sent 0-3 requests is not partial work; it is a BROKEN chunk that also got
    #    cut (WAF banned us at chunk start, template load failed, DNS timeout).
    #    Recording that as PARTIAL would claim partial coverage we never had.
    #    Yield floor failing therefore wins over the cut: DEGRADED, not PARTIAL.
    if (result.outcome in (Outcome.OK, Outcome.PARTIAL, Outcome.MIXED)
            and spec.healthy_yield is not None):
        verdict = spec.healthy_yield(result.meta)
        if verdict:
            result = PhaseResult(outcome=Outcome.DEGRADED, reason=verdict,
                                 artifacts=result.artifacts,
                                 findings=result.findings, meta=result.meta,
                                 per_unit_state=result.per_unit_state)

    # ── obligation 3: artifacts — persisted for EVERY outcome, because evidence
    #    is least available exactly when it is most needed (the gau `if urls:`
    #    bug persisted nothing on the first real failure).
    for art in result.artifacts:
        ctx.artifacts.append(art)

    # ── obligation 4: source tagged by DECLARED tier, never run intensity.
    for f in result.findings:
        if getattr(f, "source", None) in (None, ""):
            try:
                f.source = spec.source
            except Exception:                  # frozen/immutable finding — leave it
                pass
        ctx.findings.append(f)

    # ── harm condition: stop the scan (4.7 Q2). Credited as degraded first so
    #    the run's forensics show WHY it stopped.
    if result.outcome == Outcome.ABORT_SCAN:
        ctx.tools_run.append(spec.name)
        mark_degraded(ctx, spec.name, result.reason or "abort_scan")
        raise PhaseAbort(spec.name, result.reason or "abort_scan")

    # ── obligations 1 + 2: credit AFTER the work, and set tool_status in the
    #    same breath so tools_run and tool_status can never diverge.
    ctx.tools_run.append(spec.name)
    if result.outcome == Outcome.GATE_SKIPPED:
        # The phase RAN and decided it does not apply to this asset (e.g. a
        # non-WordPress target for a WP check). Same semantics as the gate
        # above: credited so the autocloser knows we did NOT establish
        # coverage here, marked skipped so it can never read as 'ok'.
        mark_skipped(ctx, spec.name, result.reason or "not_applicable")
        return result
    if result.outcome == Outcome.OK:
        mark_ok(ctx, spec.name)
    elif result.outcome in (Outcome.PARTIAL, Outcome.MIXED):
        # 4.7 rulings ⑪ + ⑫ + ⑱. THE FIX for what run #2632 exposed: write the
        # full four-field shape here instead of flattening to {"degraded": ...}.
        #
        # Keyed on spec.name, NOT on per-chunk names. That is deliberate and is
        # what makes this ship code-only (⑱): the autocloser's producer patterns
        # are LIKE patterns ('nuclei%'), which match the phase name fine, and
        # set-equality with tools_run holds by construction. Restoring per-chunk
        # KEYS is ruling ⑬ and waits for its own coordinated ship — it drags in
        # the executed_phases guard rework (⑯) and an all-match predicate
        # migration (⑰), because with per-chunk keys a clean nuclei[php] would
        # satisfy the any-match autocloser for a finding only the CUT chunk would
        # have re-detected.
        #
        # The per-chunk breakdown is not lost meanwhile — it rides inside the
        # entry as `per_chunk`, so an operator can still see 3 cut of 6 rather
        # than a bare "partial".
        mark_partial(ctx, spec.name, result)
    else:
        mark_degraded(ctx, spec.name, result.reason or "degraded")
    # ⑭′.4 — after the entry exists, on whichever path wrote it.
    _merge_phase_diagnostics(ctx, spec.name)
    return result


# ── legacy adapter (3b) ─────────────────────────────────────────────────────
#
# 🔴 THE PROBLEM 4.7's Q1 MECHANISM DID NOT ANTICIPATE. The ruling says heavy's
# runner should "select from the registry and execute via run_phase()", with the
# legacy runners still hand-calling the same functions. Verified 2026-08-29:
# EVERY legacy phase SELF-BOOKKEEPS — check_dns_posture, check_tls,
# check_headers, check_httpx_tech et al. each call ctx.tools_run.append,
# mark_tool_ok/degraded, ctx.findings.append and ctx.artifacts.append internally.
# Calling one through run_phase() would credit it TWICE (and trip the
# DoubleExecutionError guard shipped in inc 1 — the guard earning its keep on
# day one).
#
# THE FIX, without refactoring ~17 legacy functions (which would mean migrating
# light and medium NOW, violating hard-cut-per-tier / heavy-first):
# run the legacy function against a RECORDING PROXY. The proxy carries its own
# empty bookkeeping collections, so the legacy function's self-bookkeeping lands
# in the recorder instead of the real scan; every OTHER attribute read or write
# forwards to the real ctx, so genuine cross-phase state still propagates —
# critically `ctx.waf_detected` / `ctx.waf_kind` (wafw00f) and `ctx.tech_stack`
# (httpx -td), which build_chunk_plan reads later in the run.
#
# The adapter then TRANSLATES what was recorded into a PhaseResult, and
# run_phase applies the five obligations to the real ctx exactly once.

_RECORDED = ("tools_run", "tool_status", "findings", "artifacts")


class _LegacyRecorder:
    """Proxy ctx: captures bookkeeping, forwards everything else."""

    def __init__(self, real):
        object.__setattr__(self, "_real", real)
        object.__setattr__(self, "tools_run", [])
        object.__setattr__(self, "tool_status", {})
        object.__setattr__(self, "findings", [])
        object.__setattr__(self, "artifacts", [])
        # 🔴 SUPPRESS THE LEGACY PROGRESS FLUSH. Found in production, run
        # #2621 (2026-08-29): the live scan_run row went from 11 tools to 1
        # MID-RUN. Cause — mark_tool_ok/degraded/skipped each call
        # flush_progress(ctx) internally, which does its own DB UPDATE writing
        # ctx.tools_run + ctx.tool_status. A legacy phase calls those with the
        # RECORDER, so the recorder's deliberately-isolated single-entry
        # bookkeeping was overwriting the real accumulated row.
        #
        # flush_progress early-returns on a falsy ctx.dsn, so a None DSN here
        # makes the legacy phase's internal flush a no-op while the REAL ctx
        # keeps its DSN for the executor's own flush after the phase returns.
        # Final close_out is unaffected either way (it uses the real ctx), so
        # the damage was to live progress + mid-run forensics, not the result.
        object.__setattr__(self, "dsn", None)

    def __getattr__(self, name):          # only called when not found locally
        return getattr(object.__getattribute__(self, "_real"), name)

    def __setattr__(self, name, value):
        if name in _RECORDED:
            object.__setattr__(self, name, value)
        else:
            # Real state (waf_detected, waf_kind, tech_stack, counters…) must
            # reach the actual scan or later phases lose it.
            setattr(object.__getattribute__(self, "_real"), name, value)


def _as_finding_event(f, tier, ctx):
    """Translate a legacy LightFinding-shaped object into a FindingEvent.

    🔴 THE THIRD FACE OF THE SAME ROOT CAUSE (production, run #2622,
    2026-08-29): legacy phases assume they own the context, the bookkeeping AND
    the finding TYPE. Heavy's writer consumes FindingEvent (finding_id,
    asset_id, scan_id, source, observed_at…); light/medium phases emit
    LightFinding (check_name, tags, normalized_key_override…). The run scanned
    for 28m37s, all tools green, then died at persistence with
    `AttributeError("'LightFinding' object has no attribute 'finding_id'")`
    and discarded every finding.

    IDENTITY MUST MATCH THE LEGACY PATH EXACTLY, or the same finding gets two
    identities depending on which runner produced it — re-creating the dedup
    split that step 1 (declared-tier source) exists to prevent. Replicated
    verbatim from run_light.write_findings_and_artifacts:
        finding_id     = f"{asset_id}:{TIER}:{check_name}"     (tier, NOT 'heavy')
        normalized_key = normalized_key_override
                         else sorted-lowercased-comma-joined CVEs
                         else check_name
    (migration 20260601a rule 2b/2c; the override MUST win over the CVE join —
    see the P-008 regression 20260604c fought.)

    Objects that are already FindingEvent-shaped pass through untouched, so a
    heavy phase's own findings are unaffected."""
    if getattr(f, "finding_id", None) is not None:
        return f                                   # already a FindingEvent

    check = getattr(f, "check_name", None)
    if check is None:
        return f            # unknown shape — let the writer surface it loudly

    cve = list(getattr(f, "cve", []) or [])
    override = getattr(f, "normalized_key_override", None)
    if override:
        norm = override
    elif cve:
        norm = ",".join(sorted(c.lower() for c in cve))
    else:
        norm = check

    from cs_parsers.common import FindingEvent
    return FindingEvent(
        finding_id=f"{ctx.asset_id}:{tier}:{check}",
        asset_id=ctx.asset_id,
        scan_id=getattr(ctx, "scan_run_id", ""),
        source=source_for_tier(tier),              # declared tier (step 1)
        title=getattr(f, "title", check),
        severity=getattr(f, "severity", "INFO"),
        category=getattr(f, "category", "config"),
        observed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        description=getattr(f, "description", None),
        cve=cve,
        cwe=list(getattr(f, "cwe", []) or []),
        references=list(getattr(f, "references", []) or []),
        raw_excerpt=getattr(f, "raw_excerpt", None),
        normalized_key=norm,
        # Heavy's writer hardcodes tags=[], so tags would be silently dropped.
        # Park them in params rather than lose them.
        params={"legacy_tags": list(getattr(f, "tags", []) or [])}
        if getattr(f, "tags", None) else {},
    )


def _units_from_recorder(tool_status: dict) -> list:
    """Translate the recorder's per-sub-invocation tool_status into UnitResults.

    This is where per-chunk detail is RESCUED. Verified empirically 2026-08-30:
    the recorder does capture per-chunk keys (`nuclei[critical,high]`, …) with
    the full four-field partial shape — re-derivation was throwing it away, not
    failing to collect it. Ruling ⑬ will restore these as tool_status KEYS; until
    then they ride inside the phase entry as `per_chunk`.
    """
    units = []
    for name, v in (tool_status or {}).items():
        if not isinstance(v, dict):
            continue
        if v.get("partial") is True:
            outcome = Outcome.PARTIAL
        elif "degraded" in v:
            outcome = Outcome.DEGRADED
        elif "skipped" in v:
            outcome = Outcome.GATE_SKIPPED
        elif v.get("ok") is True:
            outcome = Outcome.OK
        else:                              # unrecognised shape — never call it ok
            outcome = Outcome.DEGRADED
        units.append(UnitResult(
            name=name, outcome=outcome,
            reason=v.get("reason") or v.get("degraded") or v.get("skipped") or "",
            coverage=v.get("coverage"), matches=v.get("matches", 0) or 0,
            requests=v.get("requests"), total=v.get("total"),
            percent=v.get("percent"), rps=v.get("rps"),
        ))
    return units


def aggregate_coverage(units: list) -> tuple[str | None, dict]:
    """Phase-level coverage from the sub-units, plus the summed evidence.

    ⚠ REPLACES `next((u.coverage for u in units if u.coverage), None)`, which
    took the FIRST unit's bucket and called it the phase's. On run #2645 that
    happened to read partial_minimal because `critical,high` sorts first — the
    right answer for the wrong reason. A phase whose first chunk finished and
    whose last four were cut would have reported `complete`.

    Aggregate over REQUESTS, not over buckets: chunk denominators differ by
    250x (7255 vs 29 on #2637), so averaging percentages would let a 29-request
    chunk finishing outvote a 7255-request chunk stalling at 9%.

    Returns (bucket | None, evidence) — None when no unit carried a count, so
    the caller keeps 'unknown' rather than inventing one.
    """
    req = sum(u.requests for u in units if u.requests is not None)
    tot = sum(u.total for u in units if u.total is not None)
    if not tot:
        # No measurable unit. Fall back to a bucket only if some unit had one.
        return next((u.coverage for u in units if u.coverage), None), {}
    pct = (req * 100) // tot
    if pct >= 100:
        bucket = COVERAGE_COMPLETE
    elif pct >= 50:
        bucket = COVERAGE_PARTIAL_SIGNIFICANT
    else:
        bucket = COVERAGE_PARTIAL_MINIMAL
    return bucket, {"requests": req, "total": tot, "percent": pct}


def legacy_adapter(fn, tier, *args, **kwargs):
    """Wrap a self-bookkeeping legacy phase function as a contract phase.

    Translation rules — derived from what the legacy functions actually do:
      * any tool marked degraded  → PhaseResult.degraded(first reason)
      * any tool marked PARTIAL   → PhaseResult.degraded(the wall-clock reason).
        See the note below — this is a deliberate DOWNGRADE, not an oversight.
      * nothing credited at all   → GATE_SKIPPED ('legacy_not_applicable'):
        the function chose not to run (e.g. non-WordPress target for the WP
        check). Credited-but-skipped, never coverage.
      * otherwise                 → OK
    Findings and artifacts are carried across for run_phase to persist.

    ⚠ WHY PARTIAL MUST NOT FALL THROUGH TO OK (spec 198, 4.7's "biggest risk").
    A partial entry is {"ok": False, "partial": True, ...} — it carries no
    "degraded" key, so the degraded scan below does not see it, and tools_run IS
    populated, so the skipped branch does not either. Without the explicit check
    a wall-clock-cut nuclei chunk would return PhaseResult.ok() and the executor
    would log the phase as clean coverage — re-creating the exact defect one
    layer up from where we fixed it.

    PhaseResult has no partial state of its own yet. Mapping to `degraded` here
    is the conservative direction: it is coverage-negative, which is the
    load-bearing property. The richer partial/coverage detail is NOT lost — it
    lives in the tool_status entry the recorder copies to the real ctx, which is
    what actually reaches the DB. A first-class PhaseResult.partial belongs with
    the ruling-⑤ generalisation, not here.
    """
    def _phase(ctx, work_dir):
        rec = _LegacyRecorder(ctx)
        fn(rec, *args, **kwargs)
        degraded = [(t, v.get("degraded")) for t, v in rec.tool_status.items()
                    if isinstance(v, dict) and "degraded" in v]
        partial = [(t, v.get("reason")) for t, v in rec.tool_status.items()
                   if isinstance(v, dict) and v.get("partial") is True]
        # Shape-translate before handing findings to the executor — heavy's
        # writer consumes FindingEvent, legacy phases emit LightFinding.
        events = [_as_finding_event(f, tier, ctx) for f in rec.findings]
        result_kw = dict(artifacts=list(rec.artifacts), findings=events,
                         meta={"legacy_tools": list(rec.tools_run)})
        if degraded:
            return PhaseResult.degraded(degraded[0][1] or "legacy_degraded", **result_kw)
        if partial:
            # ⑦ REVERSED by 4.7 on 2026-08-30 (spec 200, ruling ⑪). ⑦ collapsed
            # this to PhaseResult.degraded on the premise — which I supplied and
            # which was wrong — that the recorder's rich tool_status reaches the
            # DB. It does not: run_phase re-derives tool_status from the
            # PhaseResult, so on THIS path PhaseResult is the only carrier and
            # the collapse deleted the distinction from the record. Run #2632
            # persisted {"degraded": "wall_clock_cut_180s"} and the portal's
            # "cut short" label was inert.
            #
            # Phase-level verdict is DERIVED from the sub-units, not "any cut
            # wins" (⑫): all-cut is PARTIAL, some-cut-some-clean is MIXED. A
            # phase with 1 of 30 chunks cut has far more coverage than one with
            # 15 of 30, and MIXED plus per_unit_state is what carries that.
            units = _units_from_recorder(rec.tool_status)
            all_cut = all(u.outcome != Outcome.OK for u in units) if units else True
            coverage, _agg = aggregate_coverage(units)
            reason = partial[0][1] or "legacy_partial"
            ctor = PhaseResult.partial if all_cut else PhaseResult.mixed
            return ctor(reason, coverage=coverage,
                        per_unit_state=units, **result_kw)
        if not rec.tools_run:
            return PhaseResult.skipped("legacy_not_applicable", **result_kw)
        return PhaseResult.ok(**result_kw)
    _phase.__name__ = getattr(fn, "__name__", "legacy_phase")
    _phase.__doc__ = f"legacy_adapter({getattr(fn, '__name__', '?')})"
    return _phase


# ── wall-clock budget (4.7 rulings Q3 + Q4, spec 194/195) ───────────────────

# 30 minutes, NOT the 45 first suggested. A cumulative heavy holds a VPN slot for
# its WHOLE duration while cron ticks every 10 min, so this ceiling is a function
# of THIS INSTANCE'S slot count: at VPN_SLOTS_N=1 a 30-min hold blocks every other
# VPN'd scan for 3 cron cycles (45 min would block 4-5).
#
# ⚠ BOTH THE CEILING AND THE CONSTRAINT BEHIND IT ARE PER-INSTANCE, and both are
# GitHub repo VARIABLES rather than code:
#     CUMULATIVE_WALL_CLOCK_S: ${{ vars.CUMULATIVE_WALL_CLOCK_S || '1800' }}
#     VPN_SLOTS_N:             ${{ vars.VPN_SLOTS_N || '1' }}
# So raising the ceiling on one instance is a settings change, not a ship — but it
# is only JUSTIFIED by that instance's real slot count.
#
# 🔴 DO NOT reason from vpn_slot.py's docstring. It says Command=1, Prodex=2
# against a shared Mullvad 5-device account, but BOTH repos default to 1 and the
# docstring is only true if the repo variable is actually set. An earlier version
# of this comment asserted "Command runs VPN_SLOTS_N=1" and parity copied that
# sentence verbatim into the Prodex repo, where it cited the wrong instance
# entirely. Read the variable, not the prose.
#
# ⚠ DO NOT RAISE THIS TO ACCOMMODATE A SLOW RUN. If a run legitimately needs
# more, take the honest partial coverage (cut-off phases are recorded DEGRADED);
# if it is misbehaviour, fix the misbehaviour. Raising the ceiling to hide slow
# behaviour is the failure mode 4.7 named explicitly.
#
# ── 4.7 rulings ㉖/㉗/㉘, 2026-09-01 — READ BEFORE PROPOSING A RAISE ──────────
#
# This ceiling was tested against a real aspiration and HELD. nuclei's
# `critical,high` chunk is 7255 counter-units at a measured 3.8 units/sec, so it
# needs ~1909s to complete — for that ONE chunk. With the other five (~1000s
# combined) a complete scan needs ~2900s against this 1800s ceiling. Splitting
# it into sub-chunks (⑰′) does NOT reduce the work; it only moves where the cut
# lands, at ANY sub-chunk count. So ⑰′ was SHELVED and `critical,high` is
# ACCEPTED as permanently PARTIAL, honestly recorded. ⑮ (400s per chunk) already
# lifted it from ~9% to ~22% for free; everything beyond that trades a real
# constraint for marginal coverage.
#
# REVISIT this number only when a CONSTRAINT changes:
#   * VPN slot capacity changes (Command VPN_SLOTS_N=1, Prodex=2 — the env var
#     exists precisely so the instances can differ)
#   * cron cadence changes
#   * phases become able to yield the VPN slot mid-run
#
# DO NOT revisit for:
#   * "critical,high is tantalisingly close to complete"
#   * one asset or one tier wanting more time
#   * any coverage aspiration unaccompanied by a constraint change
#
# Coverage aspirations do not override fleet-level constraints. If you are here
# because a number looks nearly achievable, that is the exact itch this comment
# exists to stop. See Obsidian 205.
CUMULATIVE_WALL_CLOCK_S = int(os.environ.get("CUMULATIVE_WALL_CLOCK_S", "1800"))

WALL_CLOCK_REASON = "wall_clock_ceiling_reached"


class WallClock:
    """Tracks the run's wall-clock budget and decides whether the next phase
    may start.

    🔴 A PHASE CUT OFF BY THE CEILING IS **DEGRADED, NOT SKIPPED** (4.7 Q4).
    The autocloser cannot otherwise distinguish "this phase never ran" from
    "this phase ran and found nothing" — and would auto-close prior findings
    from a phase that never executed. Degraded is credited (set-equality holds)
    but can never satisfy the 20260828a `ok='true'` coverage predicate."""

    def __init__(self, budget_s: int | None = None, now=time.time):
        self.budget_s = CUMULATIVE_WALL_CLOCK_S if budget_s is None else budget_s
        self._now = now
        self.started = now()

    @property
    def elapsed_s(self) -> float:
        return self._now() - self.started

    @property
    def remaining_s(self) -> float:
        return self.budget_s - self.elapsed_s

    def exhausted(self) -> bool:
        return self.remaining_s <= 0


def cutoff_result() -> PhaseResult:
    """The result recorded for a phase the ceiling prevented from starting."""
    return PhaseResult.degraded(WALL_CLOCK_REASON)


ABORTED_UPSTREAM_REASON = "scan_aborted_upstream"


def run_phases(specs, ctx, work_dir, wall_clock=None, log=None,
               mark_ok=None, mark_degraded=None, mark_skipped=None):
    """Execute an ordered phase list under the wall-clock budget.

    Returns (results, abort) — abort is the PhaseAbort that stopped the run, or
    None. The caller decides how to close out; this owns only the loop.

    THREE WAYS A PHASE DOES NOT PRODUCE COVERAGE, all recorded, none silent:
      * ran and failed        → DEGRADED (run_phase)
      * ceiling hit first     → DEGRADED `wall_clock_ceiling_reached` (4.7 Q4)
      * an earlier phase ABORTED → DEGRADED `scan_aborted_upstream`

    The last one is my extension of 4.7's Q4 reasoning to a case it did not
    rule on: after a harm-condition abort we stop deliberately, so the remaining
    phases did not establish coverage either. Crediting them degraded keeps the
    set-equality invariant true and leaves an honest forensic trail; it can
    never read as coverage because 20260828a requires ok='true'.
    """
    if mark_degraded is None:
        from run_medium import (mark_tool_ok, mark_tool_degraded,  # noqa: E402
                                mark_tool_skipped)
        mark_ok = mark_ok or mark_tool_ok
        mark_degraded = mark_degraded or mark_tool_degraded
        mark_skipped = mark_skipped or mark_tool_skipped
    markers = dict(mark_ok=mark_ok, mark_degraded=mark_degraded,
                   mark_skipped=mark_skipped)
    _log = log or (lambda *_a: None)

    wc = wall_clock or WallClock()
    results, abort = [], None

    for i, spec in enumerate(specs):
        if abort is not None:
            _credit_not_run(spec, ctx, mark_degraded, ABORTED_UPSTREAM_REASON)
            continue
        if wc.exhausted():
            _log(f"  wall-clock ceiling ({wc.budget_s}s) reached — "
                 f"{len(specs) - i} phase(s) cut off")
            _credit_not_run(spec, ctx, mark_degraded, WALL_CLOCK_REASON)
            continue
        try:
            results.append(run_phase(spec, ctx, work_dir, **markers))
        except PhaseAbort as e:
            # Harm condition: ban / VPN lost / unreachable. Stop poking.
            _log(f"  ABORT_SCAN from {e.phase}: {e.reason} — "
                 f"halting, {len(specs) - i - 1} phase(s) will not run")
            abort = e
    return results, abort


def _credit_not_run(spec, ctx, mark_degraded, reason: str) -> None:
    """Record a phase that never started. Credited (set-equality) + degraded
    (never coverage). Disabled phases stay invisible — they were never in the
    set of things that could run."""
    if not spec.enabled or spec.name in ctx.tools_run:
        return
    ctx.tools_run.append(spec.name)
    mark_degraded(ctx, spec.name, reason)


