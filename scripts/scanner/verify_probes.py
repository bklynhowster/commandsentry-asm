#!/usr/bin/env python3
"""
verify_probes.py — behavioral-probe fixture self-check (P-PROBE-FIXTURES)

Iterates the BEHAVIORAL_PROBES registry in run_light.py. For each probe
with declared fixture hostnames in PROBE_FIXTURES, calls the probe
against each fixture host and confirms it produces at least one finding.

Per Opus advisor brief #4 (2026-05-31 PM) — a probe returning None on a
fixture host is AMBIGUOUS: either the vuln was remediated (fixture
should be downgraded) or the probe's match condition no longer fits
(probe is stale). Silent None is the same false-all-clear failure mode
the standing rule exists to prevent.

When this script reports STALE:
  1. FIRST hypothesis: probe is stale. Read the probe code and check
     whether the target's response shape changed.
  2. SECOND hypothesis: vuln was remediated on the fixture host. Verify
     manually before downgrading the fixture in PROBE_FIXTURES.
  3. Update PROBE_FIXTURES accordingly and re-run.

Exit codes:
  0 — all fixtured probes matched their fixtures
  1 — at least one fixture/probe combo returned no finding (STALE)
  2 — script error (network failure, import error, etc.)

Usage:
  # Manual / pre-push verification
  python3 scripts/scanner/verify_probes.py

  # Cron / weekly schedule via GH Actions workflow (queue P-PROBE-FIXTURES
  # for the workflow wiring; this script is the worker).

Design notes:
  - We intentionally DON'T import the whole Light tier — just the
    BEHAVIORAL_PROBES registry, PROBE_FIXTURES dict, and the ScanContext
    dataclass to feed each probe.
  - Probes with empty fixture lists in PROBE_FIXTURES are skipped (e.g.,
    a probe for a finding class we haven't captured a known-positive
    for yet). That's correct behavior — better than fabricating a
    fixture.
  - One probe failure does NOT abort the rest — we want the full
    stale-probe inventory at end so we can triage in one pass.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Add the scanner directory to path so we can import run_light's registry.
SCANNER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCANNER_DIR))

try:
    from run_light import (  # noqa: E402
        BEHAVIORAL_PROBES,
        PROBE_FIXTURES,
        ScanContext,
    )
except Exception as e:
    print(f"FATAL: failed to import probe registry from run_light: {e!r}",
          file=sys.stderr)
    sys.exit(2)


def _make_fixture_ctx(hostname: str) -> ScanContext:
    """Build a minimal ScanContext suitable for firing a probe directly.

    Probes only read ctx.hostname for their network requests and
    append to ctx.findings on match. The other fields are unused
    by the probe call path.
    """
    return ScanContext(
        descriptor={},
        hostname=hostname,
        asset_id="<fixture-check>",
        scan_run_id="<verify-probes>",
        queue_id="<verify-probes>",
        intensity="light",
    )


def main() -> int:
    print("=" * 70)
    print("Behavioral-probe fixture self-check")
    print("=" * 70)
    print(f"Registry has {len(BEHAVIORAL_PROBES)} probe(s).")
    print(f"PROBE_FIXTURES has {len(PROBE_FIXTURES)} entries.")
    print()

    stale: list[tuple[str, str]] = []  # (probe_name, fixture_host)
    healthy: list[tuple[str, str, int]] = []  # (probe, fixture, finding_count)
    no_fixtures: list[str] = []  # probes with empty fixture list

    for probe_name, probe_fn in BEHAVIORAL_PROBES:
        fixtures = PROBE_FIXTURES.get(probe_name, [])
        if not fixtures:
            no_fixtures.append(probe_name)
            print(f"⊘  {probe_name}: no fixtures declared — SKIPPED")
            continue

        for fixture_host in fixtures:
            ctx = _make_fixture_ctx(fixture_host)
            try:
                probe_fn(ctx)
            except Exception as e:
                print(f"✗  {probe_name} @ {fixture_host}: probe raised {e!r}")
                stale.append((probe_name, fixture_host))
                continue

            if len(ctx.findings) == 0:
                print(f"✗  {probe_name} @ {fixture_host}: NO FINDING — STALE")
                stale.append((probe_name, fixture_host))
            else:
                count = len(ctx.findings)
                healthy.append((probe_name, fixture_host, count))
                check_names = ", ".join(f.check_name for f in ctx.findings)
                print(f"✓  {probe_name} @ {fixture_host}: "
                      f"{count} finding(s) [{check_names}]")

    print()
    print("=" * 70)
    print(f"Summary: {len(healthy)} healthy / "
          f"{len(stale)} STALE / {len(no_fixtures)} no fixtures")
    print("=" * 70)

    if stale:
        print()
        print("STALE probes — manual triage required:")
        for probe_name, fixture_host in stale:
            print(f"  • {probe_name} against {fixture_host}")
        print()
        print("Triage steps:")
        print("  1. Read the probe code and check whether the target's")
        print("     response shape changed (UA-aware filtering, path moved, etc.)")
        print("  2. Manually verify whether the vuln was remediated on the")
        print("     fixture host (curl + the probe's documented detection path)")
        print("  3. Update either the probe code OR PROBE_FIXTURES accordingly")
        return 1

    if no_fixtures:
        print()
        print("Probes WITHOUT fixtures — silently failing class:")
        for probe_name in no_fixtures:
            print(f"  • {probe_name}")
        print()
        print("These probes cannot be self-checked. Find a known-positive")
        print("fixture host and add it to PROBE_FIXTURES so future stalls fail loud.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
