"""Evidence for tool-success claims (4.7 rulings 83-87, spec 220).

WHY THIS EXISTS
---------------
The crediting primitive could not verify its own docstring:

    def mark_tool_ok(ctx, tool_name) -> None:
        \"\"\"Record that a tool produced real output.\"\"\"
        ctx.tool_status[tool_name] = {"ok": True}

No parameter existed through which output, counts, or any measurement could be
supplied. Measured 2026-09-03 across BOTH instances, entire history:

    nuclei chunk records           245
    claimed ok                     211
    claimed ok with ZERO evidence  211      <- 100%
    honest ok:false (cut path)      16
    assets                          34

**211 of 211.** The only nuclei records carrying evidence are the ones that got
CUT. Every claim of nuclei coverage we hold is unevidenced — not necessarily
wrong, but unverifiable — and the autocloser has been licensing closure off
those `ok=true` values under the ⑰ all-match predicate.

The asymmetry was structural, not accidental:

    if <cut by wall clock>:
        stats = parse_nuclei_stats(chunk_stderr)   # parsed HERE only
        floor = nuclei_yield_floor_failed(stats)
        if floor: mark_tool_degraded(...)
        else:     mark_tool_partial(..., stats=stats)
    else:
        mark_tool_ok(ctx, chunk_name)              # stderr in scope, never read

25 bare `mark_tool_ok()` call sites exist (light 13, medium 7, heavy 5) against
**2** declared yield floors. Every past fix — the gau lesson, ⑯'s rc=124, ⑭′'s
tech floor — added a floor to one tool's one path. This module exists so the
class becomes enumerable and closed instead: `grep unmeasurable` returns
exactly the tools that still lack a floor, in source, provably shrinking.

WHAT THIS PHASE DOES *NOT* DO
-----------------------------
**No floor. No DEGRADED. No behaviour change.** Phase 1 records measurements
only.

The clean-path ratio floor (4.7 ruling 85) CANNOT be calibrated yet, because
history contains zero clean-path request counts — the finding blocks its own
fix's calibration. Forced sequence: ship measurement, collect real completion
ratios from live runs, THEN calibrate and enable the floor. That is 4.7's
staged detection-before-autocloser-impact (86), compelled by the data rather
than chosen.

A floor here would also be dangerous before calibration: `medium:tech`
legitimately completes at ~10 requests, so a naive absolute minimum would
false-DEGRADE a healthy chunk, and under ⑰ all-match a degraded producer blocks
closure of that source's findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# Evidence kinds. These land in tool_status and are part of the data contract.
MEASURED = "measured"
UNMEASURABLE = "unmeasurable"


@dataclass(frozen=True)
class Evidence:
    """What a tool actually did, or an explicit statement that we cannot tell.

    Deliberately has no `ok`/`degraded` verdict of its own — Evidence is the
    OBSERVATION; the verdict belongs to the crediting primitive. Keeping them
    separate is what lets Phase 1 record measurements without changing any
    behaviour.
    """

    kind: str
    # Work actually performed. `requests`/`total` are nuclei's shape; `items`
    # is the generic count for row/finding-producing tools (gau URLs, httpx
    # rows, ffuf hits) so non-nuclei tools can migrate without a bespoke type.
    requests: Optional[int] = None
    total: Optional[int] = None
    percent: Optional[int] = None
    items: Optional[int] = None
    # Why we cannot measure. REQUIRED for UNMEASURABLE, forbidden otherwise —
    # an unmeasurable claim without a reason is exactly the silent gap this
    # module exists to remove.
    reason: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    # ── constructors ────────────────────────────────────────────────────
    @classmethod
    def measured(
        cls,
        *,
        requests: Optional[int] = None,
        total: Optional[int] = None,
        percent: Optional[int] = None,
        items: Optional[int] = None,
        **extra: Any,
    ) -> "Evidence":
        """A real measurement. At least one count must be present — an
        'measured' Evidence carrying nothing is just the old bug wearing a
        new type."""
        if requests is None and total is None and percent is None and items is None:
            raise ValueError(
                "Evidence.measured() requires at least one count; use "
                "Evidence.unmeasurable(reason) when the tool exposes none"
            )
        return cls(
            kind=MEASURED,
            requests=requests,
            total=total,
            percent=percent,
            items=items,
            extra={k: v for k, v in extra.items() if v is not None},
        )

    @classmethod
    def unmeasurable(cls, reason: str) -> "Evidence":
        """This tool exposes no yield signal we can read — say so explicitly.

        `grep unmeasurable` over the call sites IS the enumerable list of tools
        still lacking a floor. That list is the deliverable: it shrinks
        visibly as floors get built, instead of being discovered one live run
        at a time.
        """
        if not reason or not str(reason).strip():
            raise ValueError(
                "Evidence.unmeasurable() requires a reason — an unexplained "
                "gap is the silent ok:true bug in a different costume"
            )
        return cls(kind=UNMEASURABLE, reason=str(reason).strip())

    @classmethod
    def from_nuclei_stats(cls, stats: Optional[dict]) -> "Evidence":
        """Adapt `parse_nuclei_stats()` output. Absent stats is UNMEASURABLE,
        never a zero measurement — unmeasurable and 'did nothing' are
        different claims and must not collapse into one."""
        if not stats:
            return cls.unmeasurable("nuclei_stats_absent")
        counts = {
            k: stats.get(k)
            for k in ("requests", "total", "percent")
            if stats.get(k) is not None
        }
        if not counts:
            return cls.unmeasurable("nuclei_stats_had_no_counts")
        return cls.measured(
            **counts,
            templates=stats.get("templates"),
            matched=stats.get("matched"),
            errors=stats.get("errors"),
        )

    # ── properties ──────────────────────────────────────────────────────
    @property
    def is_measured(self) -> bool:
        return self.kind == MEASURED

    @property
    def completion_ratio(self) -> Optional[float]:
        """Fraction of scoped work performed, or None when unknowable.

        The input to the FUTURE clean-path floor (4.7 ruling 85: ratio, never
        an absolute minimum — `medium:tech` legitimately completes at ~10
        requests and a global floor would false-DEGRADE it). Computed and
        recorded now so the floor can be calibrated from real data later.
        """
        if not self.is_measured:
            return None
        if self.percent is not None:
            return self.percent / 100.0
        if self.requests is not None and self.total:
            return self.requests / self.total
        return None

    # ── serialisation ───────────────────────────────────────────────────
    def to_status(self) -> dict[str, Any]:
        """The dict merged into the tool_status entry.

        Namespaced under `evidence` so it cannot collide with the existing
        verdict keys (`ok`, `degraded`, `partial`, `reason`, `coverage`) that
        consumers — including the ⑰ autoclose predicate — already branch on.
        """
        body: dict[str, Any] = {"kind": self.kind}
        if self.kind == UNMEASURABLE:
            body["reason"] = self.reason
            return {"evidence": body}
        for k in ("requests", "total", "percent", "items"):
            v = getattr(self, k)
            if v is not None:
                body[k] = v
        ratio = self.completion_ratio
        if ratio is not None:
            body["completion_ratio"] = round(ratio, 4)
        body.update(self.extra)
        return {"evidence": body}
