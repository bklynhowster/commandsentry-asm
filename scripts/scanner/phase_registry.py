#!/usr/bin/env python3
"""phase_registry.py — declares the existing light + medium phases as registry
citizens (step 4 inc 3b, spec 194 / 4.7 ruling 195 Q1).

WHAT THIS IS FOR. Cumulative heavy selects `phases_for_tier(HEAVY)` = light ∪
medium ∪ heavy-depth. For that to return anything, light's and medium's phases
must be DECLARED. This file is that declaration — and nothing more.

WHAT THIS DOES NOT DO (deliberately):
  * It does not change light or medium behaviour. Their legacy runners keep
    hand-calling the same functions directly; per 4.7 Q3 the hard cut is PER
    TIER, and heavy migrates first because it is the lowest-traffic tier
    (2 runs/30d vs light's 275).
  * It does not execute anything. Registration is inert until the cumulative
    runner (inc 3c) iterates the registry behind CUMULATIVE_HEAVY_ENABLED.

🔴 WHY EVERY PHASE IS WRAPPED IN legacy_adapter. 4.7's Q1 assumed heavy could
"execute via run_phase()". It cannot: every legacy phase SELF-BOOKKEEPS —
check_dns_posture and friends call ctx.tools_run.append + mark_tool_* +
ctx.findings.append internally. Executed through run_phase that credits TWICE
and trips the DoubleExecutionError guard. legacy_adapter runs them against a
recording proxy instead; see phase_contract for the full reasoning.

ORDER IS LOAD-BEARING, NOT COSMETIC. Two medium phases are deliberately hoisted
far ahead of medium's other tools:
  * detect_waf (wafw00f) at ORDER_BAN_DETECT — it is the ONLY thing that sets
    ctx.waf_kind, which build_chunk_plan reads to choose the FortiGate SAFE-ONLY
    nuclei plan. Run it after nuclei and heavy fires broad templates at a
    WAF-fronted host: the exact self-inflicted ban the safe branch prevents.
  * detect_tech_stack (httpx -td) at ORDER_LIGHT — it populates ctx.tech_stack,
    which the same plan reads for its stack-specific chunks.
Both are verified by test_phase_registry.py.
"""
from __future__ import annotations

from phase_contract import (phase, legacy_adapter,  # noqa: E402
                            ORDER_BAN_DETECT, ORDER_LIGHT, ORDER_MEDIUM_TOOLS)
from phase_source import LIGHT, MEDIUM  # noqa: E402

import run_light as _light  # noqa: E402
import run_medium as _medium  # noqa: E402


def _register(name, tier, fn, order, **kw):
    """One legacy function → one registry citizen. `name` MUST match the tool
    name the legacy function credits, so tool_status keys stay stable across the
    legacy and registry paths (and so findings reconcile the same either way)."""
    phase(name=name, tier=tier, order=order, **kw)(legacy_adapter(fn))


# ── LIGHT tier — no attack-shaped traffic ───────────────────────────────────
# Names mirror what each function credits today (verified from source).
_register("dns_posture", LIGHT, _light.check_dns_posture, ORDER_LIGHT)
_register("tls_check", LIGHT, _light.check_tls, ORDER_LIGHT)
_register("headers_check", LIGHT, _light.check_headers, ORDER_LIGHT)
_register("common_paths", LIGHT, _light.check_common_paths, ORDER_LIGHT)
_register("httpx_tech", LIGHT, _light.check_httpx_tech, ORDER_LIGHT)
_register("methods_check", LIGHT, _light.check_methods, ORDER_LIGHT)
_register("csp_nonce_check", LIGHT, _light.check_csp_nonce, ORDER_LIGHT)
_register("wpvulnerability", LIGHT, _light.check_wpvulnerability, ORDER_LIGHT)
_register("behavioral_probes", LIGHT, _light.check_behavioral_probes, ORDER_LIGHT)

# ── MEDIUM tier ─────────────────────────────────────────────────────────────
# Context-populating phases FIRST — see the ORDER note in the module docstring.
_register("wafw00f", MEDIUM, _medium.detect_waf, ORDER_BAN_DETECT)
_register("httpx[-td]", MEDIUM, _medium.detect_tech_stack, ORDER_LIGHT)

# Attack-shaped tools last within medium. These are the ones whose ban exposure
# the ordering above exists to bound.
_register("nuclei", MEDIUM, _medium.run_nuclei_chunked, ORDER_MEDIUM_TOOLS)
_register("nikto", MEDIUM, _medium.run_nikto, ORDER_MEDIUM_TOOLS)
_register("ffuf", MEDIUM, _medium.run_ffuf_chunked, ORDER_MEDIUM_TOOLS)

# NOT registered yet, on purpose:
#   check_ssh / check_smtp / check_ftp — take a `port` argument and are called
#   conditionally per open port, so they are not a flat phase list. They need a
#   fan-out shape the contract does not model yet. Registering them naively
#   would credit one tool name for N ports.
