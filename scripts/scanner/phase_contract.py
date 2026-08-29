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
from typing import Any, Callable, Optional

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


@dataclass
class PhaseResult:
    """What a phase returns. The phase does NO bookkeeping — it reports."""
    outcome: str = Outcome.OK
    reason: str = ""                                   # slug, for DEGRADED/SKIPPED/ABORT
    artifacts: list[tuple] = field(default_factory=list)   # (name, kind, payload)
    findings: list[Any] = field(default_factory=list)      # FindingEvent-likes
    meta: dict = field(default_factory=dict)               # shape for the yield floor

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
    is_active_probe: bool = False        # gated on assets.active_probe_authorized
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
          needs_vpn: bool = False, is_active_probe: bool = False,
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
            needs_vpn=needs_vpn, is_active_probe=is_active_probe,
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

def run_phase(spec: PhaseSpec, ctx, work_dir, *,
              mark_ok=None, mark_degraded=None, mark_skipped=None) -> PhaseResult:
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
    #                     here (e.g. active_probe_authorized=false). The
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

    if spec.is_active_probe and not _probe_authorized(ctx):
        # ROE boundary AND ban protection (4.7 Q6): attack-shaped traffic only
        # goes to assets explicitly flagged active_probe_authorized.
        ctx.tools_run.append(spec.name)
        mark_skipped(ctx, spec.name, "active_probe_not_authorized")
        return PhaseResult(outcome=Outcome.GATE_SKIPPED,
                           reason="active_probe_not_authorized")

    t0 = time.time()
    try:
        result = spec.fn(ctx, work_dir)
        if result is None:                     # a phase that returns nothing = OK
            result = PhaseResult.ok()
    except Exception as e:                     # noqa: BLE001 — see docstring
        result = PhaseResult.degraded(f"exception_{type(e).__name__}")
    elapsed = round(time.time() - t0, 1)
    result.meta.setdefault("elapsed_s", elapsed)

    # ── declared yield floor ("ok" is not evidence of yield — the gau lesson).
    #    A tool can exit 0, return something, and still not have done its job.
    if result.outcome == Outcome.OK and spec.healthy_yield is not None:
        verdict = spec.healthy_yield(result.meta)
        if verdict:
            result = PhaseResult(outcome=Outcome.DEGRADED, reason=verdict,
                                 artifacts=result.artifacts,
                                 findings=result.findings, meta=result.meta)

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
    else:
        mark_degraded(ctx, spec.name, result.reason or "degraded")
    return result


# ── wall-clock budget (4.7 rulings Q3 + Q4, spec 194/195) ───────────────────

# 30 minutes, NOT the 45 first suggested. Command runs VPN_SLOTS_N=1, so a
# cumulative heavy holds the ONLY VPN slot for its whole duration while cron
# ticks every 10 min — 45 min blocks 4-5 cycles, 30 blocks 3. Env-var because
# Prodex's slot capacity may differ.
#
# ⚠ DO NOT RAISE THIS TO ACCOMMODATE A SLOW RUN. If a run legitimately needs
# more, take the honest partial coverage (cut-off phases are recorded DEGRADED);
# if it is misbehaviour, fix the misbehaviour. Raising the ceiling to hide slow
# behaviour is the failure mode 4.7 named explicitly.
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


def _probe_authorized(ctx) -> bool:
    """Active-probe gate. Reads the per-asset flag the runner already resolved.
    Defaults to FALSE — an unreadable/absent policy is NOT authorization
    (fail-closed on a verdict, per the fail-closed-gates rule)."""
    return bool(getattr(ctx, "active_probe_authorized", False))
