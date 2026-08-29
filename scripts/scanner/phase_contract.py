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

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from phase_source import LIGHT, MEDIUM, HEAVY, source_for_tier

# Tier ordering — a tier selection is CUMULATIVE: heavy = light ∪ medium ∪ heavy.
# This single line is what makes heavy ADDITIVE instead of a replacement.
_TIER_RANK = {LIGHT: 1, MEDIUM: 2, HEAVY: 3}


# ── outcomes ────────────────────────────────────────────────────────────────

class Outcome:
    OK = "ok"
    DEGRADED = "degraded"
    SKIPPED = "skipped"
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

    @property
    def source(self) -> str:
        """findings.source for THIS phase — by declared tier, never run intensity."""
        return source_for_tier(self.tier)


REGISTRY: list[PhaseSpec] = []


def phase(*, name: str, tier: str, requires_binary: str | None = None,
          needs_vpn: bool = False, is_active_probe: bool = False,
          timeout_s: int | None = None,
          healthy_yield: Callable[[dict], Optional[str]] | None = None,
          enabled: bool = True):
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
            timeout_s=timeout_s, healthy_yield=healthy_yield, enabled=enabled))
        return fn
    return deco


def phases_for_tier(requested: str) -> list[PhaseSpec]:
    """CUMULATIVE selection — the one line that makes heavy additive.
    heavy → light ∪ medium ∪ heavy, in declared tier order."""
    if requested not in _TIER_RANK:
        raise ValueError(f"unknown tier {requested!r}")
    want = _TIER_RANK[requested]
    return [p for p in REGISTRY if _TIER_RANK[p.tier] <= want]


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

    # ── pre-flight gates. NONE of these credit tools_run: a phase that never ran
    #    must be invisible to the completeness machinery and the autocloser.
    if not spec.enabled:
        return PhaseResult.skipped("disabled")

    if spec.is_active_probe and not _probe_authorized(ctx):
        # ROE boundary AND ban protection (4.7 Q6): attack-shaped traffic only
        # goes to assets explicitly flagged active_probe_authorized.
        return PhaseResult.skipped("not_active_probe_authorized")

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
    if result.outcome == Outcome.SKIPPED:
        # A skipped phase is NOT coverage and NOT a failure: no tools_run entry.
        return result

    ctx.tools_run.append(spec.name)
    if result.outcome == Outcome.OK:
        mark_ok(ctx, spec.name)
    else:
        mark_degraded(ctx, spec.name, result.reason or "degraded")
    return result


def _probe_authorized(ctx) -> bool:
    """Active-probe gate. Reads the per-asset flag the runner already resolved.
    Defaults to FALSE — an unreadable/absent policy is NOT authorization
    (fail-closed on a verdict, per the fail-closed-gates rule)."""
    return bool(getattr(ctx, "active_probe_authorized", False))
