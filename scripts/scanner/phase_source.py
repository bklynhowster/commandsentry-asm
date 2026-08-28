#!/usr/bin/env python3
"""phase_source.py — the single source of truth for findings.source per tier.

WHY THIS EXISTS (spec 190 / rulings 191, 2026-08-28). Historically each runner
derived findings.source from the RUN's intensity:
    source = f"commandsentry_{ctx.intensity}"
That ties a finding's source to *which run invoked the phase*, not to the phase's
own tier. It is a latent data-corruption bug that today's mutually-exclusive tier
dispatch masks:

  * run_medium accepts intensity in ("medium", "standard") (run_medium.py:3939).
    A "standard" scan would emit source='commandsentry_standard', which has NO
    entry in asm_autoclose_producer_patterns → permanently un-autocloseable, and
    (once tiers go cumulative) a different finding identity than the same check's
    'commandsentry_medium' emission → duplicate findings. Verified 2026-08-28:
    ZERO commandsentry_standard rows exist today, so normalizing standard→medium
    here is a no-op on existing data AND closes the latent trap.

4.7 ruling Q1 (191): tag findings.source by the phase's DECLARED tier, never by
run intensity. This module is that mechanism — imported by BOTH the legacy
runners (now) and the @phase registry (step 2) so a phase's source can never
again depend on the run that invoked it. Ships FIRST, standalone, before any
phase migrates to a cumulative tier (the source-fix-before-heavy-migration rule).

No-op proof for the current codebase (why this is safe to land first):
  * light/medium finding_id is f"{asset}:{tier-literal}:{check}" — source is NOT
    part of their key, so changing source cannot churn a light/medium finding_id.
  * heavy uses stable_finding_id (source IS in the key) but already tags with
    explicit constants ('commandsentry_heavy', 'testssl', ...), never intensity —
    so routing those through source_for_tier(HEAVY) returns byte-identical strings.
  * every existing finding's source already equals its tier's canonical value
    (verified: commandsentry_light/medium/heavy present, commandsentry_standard
    absent).
"""
from __future__ import annotations

# Canonical tier tokens. Match the scan_run/scan_queue intensity vocabulary.
LIGHT = "light"
MEDIUM = "medium"
HEAVY = "heavy"

# The ONLY place a per-tier findings.source string is defined. The autocloser's
# asm_autoclose_producer_patterns keys on exactly these values — keep them in
# lockstep with that function's CASE branches.
_TIER_SOURCE = {
    LIGHT: "commandsentry_light",
    MEDIUM: "commandsentry_medium",
    HEAVY: "commandsentry_heavy",
}

# Intensity values that normalize onto a tier before lookup. run_medium accepts
# "standard" as an alias for the medium tier (run_medium.py:3939); it must map to
# commandsentry_medium, NOT commandsentry_standard. Any future alias goes here.
_INTENSITY_ALIAS = {
    "standard": MEDIUM,
}


def source_for_tier(tier: str) -> str:
    """Canonical findings.source for a DECLARED tier. Raises on an unknown tier
    so a typo fails loud at import/first-call rather than silently minting an
    un-autocloseable source (the exact failure mode this module prevents)."""
    key = _INTENSITY_ALIAS.get(tier, tier)
    try:
        return _TIER_SOURCE[key]
    except KeyError as e:
        raise ValueError(
            f"no findings.source mapping for tier {tier!r} "
            f"(known: {sorted(_TIER_SOURCE)}, aliases: {sorted(_INTENSITY_ALIAS)})"
        ) from e


def all_tier_sources() -> frozenset[str]:
    """Every canonical per-tier source — for tests and producer-map assertions."""
    return frozenset(_TIER_SOURCE.values())
