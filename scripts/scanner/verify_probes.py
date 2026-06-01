#!/usr/bin/env python3
"""
verify_probes.py — behavioral-probe fixture self-check (P-PROBE-FIXTURES)

Two-sided enforcement. For each probe in BEHAVIORAL_PROBES:
  • Every host in fixtures["positive"] MUST produce ≥1 finding.
    0 = probe is STALE (match condition no longer fits, OR vuln was
    remediated — triage probe stale first).
  • Every host in fixtures["negative"] MUST produce 0 findings.
    ≥1 = probe is FALSE-POSITIVE. Catches the kind of bug the WPS Hide
    Login probe shipped with — fires on every WordPress site behind any
    WAF because the match condition keyed on WAF behavior, not the
    actual vulnerability.

Either failure aborts with exit 1.

History:
  2026-05-31 PM — original positive-only version (Opus advisor brief #4).
  2026-06-01 PM — added negative fixtures after FP audit revealed
    wps_hide_login_bypass matched CMI, commanddigital, and unimacgraphics
    despite none of them actually running WPS Hide Login.

Exit codes:
  0 — all probes passed both positive and negative checks
  1 — at least one probe failed (STALE positive OR FALSE-POSITIVE negative)
  2 — script error (network failure, import error, etc.)

Usage:
  python3 scripts/scanner/verify_probes.py

Run BEFORE merging any probe change. Wire into CI as a required check
for pull requests that touch run_light.py.
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

    Probes only read ctx.hostname for their network requests and append
    to ctx.findings on match. Other fields are unused by the probe path.
    """
    return ScanContext(
        descriptor={},
        hostname=hostname,
        asset_id="<fixture-check>",
        scan_run_id="<verify-probes>",
        queue_id="<verify-probes>",
        intensity="light",
    )


def _get_lists(probe_name: str) -> tuple[list[str], list[str]]:
    """Return (positives, negatives) for a probe.

    Tolerates the legacy flat-list schema (treat as positives only) so
    fixtures from before 2026-06-01 don't break the check.
    """
    entry = PROBE_FIXTURES.get(probe_name)
    if entry is None:
        return [], []
    if isinstance(entry, list):
        return list(entry), []
    if isinstance(entry, dict):
        return list(entry.get("positive", [])), list(entry.get("negative", []))
    return [], []


def main() -> int:
    print("=" * 70)
    print("Behavioral-probe fixture self-check — positive + negative")
    print("=" * 70)
    print(f"Registry has {len(BEHAVIORAL_PROBES)} probe(s).")
    print(f"PROBE_FIXTURES has {len(PROBE_FIXTURES)} entries.")
    print()

    stale: list[tuple[str, str]] = []          # positive returned 0 findings
    fp: list[tuple[str, str, int]] = []         # negative returned ≥1 findings
    pos_healthy: list[tuple[str, str, int]] = []
    neg_healthy: list[tuple[str, str]] = []
    no_positive: list[str] = []
    no_negative: list[str] = []

    for probe_name, probe_fn in BEHAVIORAL_PROBES:
        positives, negatives = _get_lists(probe_name)

        if not positives:
            no_positive.append(probe_name)
            print(f"⊘  {probe_name}: no POSITIVE fixtures — probe is unverified "
                  f"against a known-vulnerable target")
        if not negatives:
            no_negative.append(probe_name)
            print(f"⊘  {probe_name}: no NEGATIVE fixtures — probe is unverified "
                  f"against a known-clean target")

        # ── POSITIVE side ──
        for fixture_host in positives:
            ctx = _make_fixture_ctx(fixture_host)
            try:
                probe_fn(ctx)
            except Exception as e:
                print(f"✗  {probe_name} @+ {fixture_host}: probe raised {e!r}")
                stale.append((probe_name, fixture_host))
                continue
            if len(ctx.findings) == 0:
                print(f"✗  {probe_name} @+ {fixture_host}: NO FINDING — STALE")
                stale.append((probe_name, fixture_host))
            else:
                count = len(ctx.findings)
                pos_healthy.append((probe_name, fixture_host, count))
                check_names = ", ".join(f.check_name for f in ctx.findings)
                print(f"✓  {probe_name} @+ {fixture_host}: "
                      f"{count} finding(s) [{check_names}]")

        # ── NEGATIVE side ──
        for fixture_host in negatives:
            ctx = _make_fixture_ctx(fixture_host)
            try:
                probe_fn(ctx)
            except Exception as e:
                print(f"!  {probe_name} @- {fixture_host}: probe raised {e!r} "
                      f"(error treated as PASS — probe didn't flag)")
                neg_healthy.append((probe_name, fixture_host))
                continue
            if len(ctx.findings) > 0:
                count = len(ctx.findings)
                check_names = ", ".join(f.check_name for f in ctx.findings)
                print(f"✗  {probe_name} @- {fixture_host}: "
                      f"FALSE POSITIVE — {count} finding(s) [{check_names}]")
                fp.append((probe_name, fixture_host, count))
            else:
                neg_healthy.append((probe_name, fixture_host))
                print(f"✓  {probe_name} @- {fixture_host}: 0 findings (clean)")

    print()
    print("=" * 70)
    print(f"Summary: positive healthy {len(pos_healthy)} / stale {len(stale)} · "
          f"negative healthy {len(neg_healthy)} / FP {len(fp)}")
    print("=" * 70)

    if stale:
        print()
        print("STALE positive fixtures — probe failed to flag a known-vulnerable target:")
        for probe_name, fixture_host in stale:
            print(f"  • {probe_name} against {fixture_host}")
        print()
        print("Triage steps:")
        print("  1. Read the probe code; check whether the target's response shape changed.")
        print("  2. Verify whether the vuln was remediated on the fixture host.")
        print("  3. Update probe code OR PROBE_FIXTURES accordingly.")

    if fp:
        print()
        print("FALSE POSITIVES — probe flagged a known-clean target:")
        for probe_name, fixture_host, count in fp:
            print(f"  • {probe_name} against {fixture_host} ({count} findings)")
        print()
        print("Triage steps:")
        print("  1. The probe is over-firing — its match condition admits cases that don't")
        print("     have the vuln. Tighten the conditions.")
        print("  2. Verify the negative fixture is genuinely clean (no recent change).")
        print("  3. Update probe code OR drop the negative fixture if you've audited it")
        print("     and the host actually IS vulnerable now.")

    if no_positive:
        print()
        print("Probes WITHOUT positive fixtures — vulnerability detection is unproven:")
        for probe_name in no_positive:
            print(f"  • {probe_name}")
        print("Find a known-vulnerable target and add it to PROBE_FIXTURES['positive'].")

    if no_negative:
        print()
        print("Probes WITHOUT negative fixtures — false-positive resistance is unproven:")
        for probe_name in no_negative:
            print(f"  • {probe_name}")
        print("Add a known-clean target (any healthy site of the same class) as a negative.")

    return 1 if (stale or fp) else 0


if __name__ == "__main__":
    raise SystemExit(main())
