#!/usr/bin/env python3
"""Per-host scan planner (P1) — the dispatcher's pure core.

Spec: TARGETED_SCAN_ARCHITECTURE_SPEC.md §6/§10. Given a host's discovery data
(open ports, fingerprint, kind) and the validated matrix, compute a ScanPlan:
the profile (role union), the exposure-is-the-finding rows, the unmatched-port
fallbacks, and the baseline plan. PURE — no I/O, no DB, no subprocess — so it is
fully unit-testable and cannot silently narrow coverage.

The EXECUTION wiring (read discovery from asset_surface, emit these findings,
run the http packs, stamp scan_profile) lands in run_medium and goes to 4.7 as
the execution-touching part of P1. This module is the decision layer it calls.

Key guarantees encoded here:
  - Role is a VECTOR — the plan is the UNION of matched packs (match_roles).
  - Exposure-is-the-finding (§6): network-role ports get a finding by PRESENCE,
    at the TWO-COLUMN severity (base vs auth_detected — an open DB that needs an
    auth handshake is HIGH, not CRITICAL).
  - Exposure ⟂ CVE: exposure findings are their own rows (distinct check_name),
    never collapsed with a later CVE finding.
  - Unmatched open port → a fallback exposure row (never a silent gap).
  - Engine split: http roles are runnable in P1; network/dast roles are carried
    as `deferred_roles` (matrix data) until their engine ships (P3/P4) — but
    their EXPOSURE finding still emits now, off the discovery port data.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from matrix_loader import match_roles


@dataclass(frozen=True)
class ExposureFinding:
    """A finding emitted by the mere PRESENCE of an exposed service."""
    port: int
    role: str
    severity: str
    check_name: str
    title: str
    note: str


@dataclass
class ScanPlan:
    roles: list[str]                      # full matched profile (union)
    http_roles: list[str]                 # engine == http → runnable in P1
    deferred_roles: list[str]             # engine network/dast → matrix data, not yet run
    unmatched_ports: list[int]
    exposure_findings: list[ExposureFinding]
    baseline: dict                        # matrix.baseline (always runs, §5)
    scan_profile: list[str]               # sorted union → stamped on scan_run

    def summary(self) -> str:
        return (f"profile={self.scan_profile} http={self.http_roles} "
                f"deferred={self.deferred_roles} exposure={len(self.exposure_findings)} "
                f"unmatched_ports={self.unmatched_ports}")


def _severity_for(role_def: dict, role: str, auth_results: dict | None) -> str:
    """Two-column exposure severity (§6). Use auth_detected_severity iff an auth
    handshake was detected for this role AND that column exists; else base."""
    base = role_def.get("base_severity")
    auth_sev = role_def.get("auth_detected_severity")
    if auth_results and auth_results.get(role) and auth_sev:
        return auth_sev
    return base


def build_scan_plan(
    matrix: dict,
    *,
    open_ports,
    fingerprint_tokens=None,
    has_http: bool | None = None,
    kind: str | None = None,
    auth_results: dict | None = None,
) -> ScanPlan:
    """Compute the per-host plan. `auth_results` (optional) maps role → bool from
    an engine-side auth probe (e.g. Postgres startup challenge); when absent, the
    conservative base severity is used (never under-reports)."""
    roles_def = matrix["roles"]
    roles, unmatched = match_roles(
        matrix, open_ports, fingerprint_tokens, has_http, kind)
    ports = set(int(p) for p in open_ports)

    http_roles = [r for r in roles if roles_def[r]["engine"] == "http"]
    deferred_roles = [r for r in roles if roles_def[r]["engine"] in ("network", "dast")]

    exposure: list[ExposureFinding] = []
    # Exposure-is-the-finding for every matched role that carries a base severity
    # (network roles). Web roles are per-finding → no exposure-by-presence.
    for r in roles:
        rd = roles_def[r]
        base = rd.get("base_severity")
        if base is None:
            continue
        sev = _severity_for(rd, r, auth_results)
        matched_ports = sorted(ports.intersection(rd.get("match", {}).get("ports", [])))
        for p in matched_ports:
            exposure.append(ExposureFinding(
                port=p, role=r, severity=sev,
                check_name=f"exposure-{r}-{p}",
                title=f"{r.upper()} exposed to the internet on port {p}",
                note=(f"{r} service reachable on port {p}. Internet exposure is a "
                      f"finding by presence, independent of any CVE. "
                      f"Severity reflects "
                      f"{'auth handshake detected' if auth_results and auth_results.get(r) else 'no auth handshake confirmed'}."),
            ))

    # Unmatched open port → fallback exposure (never a silent gap, §4).
    unm = matrix["unmatched_port"]
    for p in unmatched:
        exposure.append(ExposureFinding(
            port=p, role="unmatched", severity=unm["base_severity"],
            check_name=f"exposure-unmatched-{p}",
            title=f"Unrecognized service exposed on port {p}",
            note=unm.get("note", "unknown open port — flag for matrix backfill"),
        ))

    return ScanPlan(
        roles=roles,
        http_roles=http_roles,
        deferred_roles=deferred_roles,
        unmatched_ports=unmatched,
        exposure_findings=exposure,
        baseline=matrix["baseline"],
        scan_profile=sorted(roles),
    )
