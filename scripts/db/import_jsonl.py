#!/usr/bin/env python3
"""
import_jsonl.py — One-shot JSONL → Supabase Postgres importer.

Reads the canonical files produced by run_normalize.py:
    assets.jsonl
    scans.jsonl
    findings.jsonl  (history is embedded as a list per record)
    events.jsonl    (intermediate — not loaded directly)
    asm_scans.jsonl (ASM scan metadata — not loaded in Phase 2)

Loads them into the Postgres schema in schema.sql.

Idempotent — every INSERT is ON CONFLICT DO UPDATE on the natural key.
Re-running the script after a fresh normalize is the supported path.

Usage:
    export SUPABASE_DSN='postgresql://postgres:PASSWORD@db.PROJECT.supabase.co:5432/postgres'
    python3 scripts/db/import_jsonl.py \\
        --normalized "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning/_normalized" \\
        --dsn "$SUPABASE_DSN"

Add --truncate to wipe the loadable tables first (during early iteration).

Add --delta-close to mark any previously-open findings for the (asset, source)
combos in this import as `remediated` if they weren't re-observed in any of
the incoming scans. Use this when ingesting an incremental re-scan; do NOT
use with --truncate (pointless — the tables were just emptied).

The importer ALWAYS calls refresh_all_asset_posture() at the end so
assets.current_risk reflects reality. Apply scripts/db/maintenance.sql at
least once before running this script.

2026-06-15: refresh_all_asset_last_observed() was DROPPED (migration
20260615a). It implemented B semantic (MAX(scans.completed_at)) which
contradicts the A semantic for assets.last_observed (DISCOVERY clock —
owned by import_asm_to_surface, monotonic via GREATEST, NOT bumped by
light/medium scans or finding ingestion). import_jsonl no longer writes
to assets.last_observed at all — full eject, see _asset_row docstring.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    import psycopg
    from psycopg.types.json import Json
except ImportError:
    print(
        "error: psycopg (psycopg3) is required.\n"
        "  install it with: pip install --user 'psycopg[binary]'",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_jsonl(path: Path) -> Iterable[dict]:
    """Yield each JSON record from a .jsonl file. Skips blank lines."""
    if not path.is_file():
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def get(d: dict, key: str, default: Any = None) -> Any:
    """Treat empty strings as missing — Postgres rejects '' in timestamp columns."""
    v = d.get(key, default)
    if v == "":
        return default
    return v


def coerce_int(v: Any) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Per-table importers
# ---------------------------------------------------------------------------

def _asset_row(asset_id: str, name: str | None = None, org: str = "unknown",
               asset_type: str = "single_host", stub: bool = False) -> tuple:
    """Build a parameter tuple matching the assets INSERT column order.

    NOTE: last_observed is intentionally NOT in this tuple (2026-06-15
    full-eject). assets.last_observed is the DISCOVERY clock — owned by
    import_asm_to_surface (asm-discover path), monotonic via GREATEST.
    import_jsonl is the scan-results-ingest path and MUST NOT write to
    the discovery clock. Stub-created rows get last_observed=NULL until
    asm-discover sees them; the alerter correctly reads NULL as
    'not yet discovered.'
    """
    return (
        asset_id,
        name or asset_id,
        asset_type,
        org,
        ["stub"] if stub else [],
        None,           # first_observed
        "UNKNOWN",      # current_risk
        "stub asset auto-created during import for FK integrity" if stub else None,
        Json({}),
    )


def load_assets(cur, path: Path) -> int:
    rows = []
    for rec in read_jsonl(path):
        # 2026-06-15 full-eject: last_observed deliberately excluded.
        # See _asset_row docstring for rationale (discovery clock is
        # owned by import_asm_to_surface, NOT by import_jsonl). Any
        # `last_observed` value in the JSONL is intentionally ignored
        # here — the asm-discover GREATEST writer is the only one that
        # bumps assets.last_observed.
        rows.append((
            rec["asset_id"],
            rec.get("name") or rec["asset_id"],
            rec.get("type") or "apex_domain",
            rec.get("organization") or "command_companies",
            rec.get("tags") or [],
            get(rec, "first_observed"),
            rec.get("current_risk") or "UNKNOWN",
            rec.get("current_risk_reason"),
            Json(rec.get("metadata") or {}),
        ))
    if not rows:
        return 0
    cur.executemany(
        """
        INSERT INTO assets (
            asset_id, name, type, organization, tags,
            first_observed, current_risk, current_risk_reason, metadata
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (asset_id) DO UPDATE SET
            name                = EXCLUDED.name,
            type                = EXCLUDED.type,
            organization        = EXCLUDED.organization,
            tags                = EXCLUDED.tags,
            first_observed      = COALESCE(assets.first_observed, EXCLUDED.first_observed),
            current_risk        = EXCLUDED.current_risk,
            current_risk_reason = EXCLUDED.current_risk_reason,
            metadata            = EXCLUDED.metadata
        """,
        rows,
    )
    return len(rows)


def load_scans(cur, path: Path) -> int:
    rows = []
    for rec in read_jsonl(path):
        rows.append((
            rec["scan_id"],
            rec["asset_id"],
            rec.get("scan_type") or "vuln_full_assessment",
            rec["started_at"],
            get(rec, "completed_at"),
            rec.get("command_line"),
            coerce_int(rec.get("exit_code")),
            rec.get("output_dir"),
            rec.get("source") or "mac_local_scan",
            rec.get("notes"),
            Json(rec.get("tools_run") or []),
        ))
    if not rows:
        return 0
    cur.executemany(
        """
        INSERT INTO scans (
            scan_id, asset_id, scan_type, started_at, completed_at,
            command_line, exit_code, output_dir, source, notes, tools_run
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (scan_id) DO UPDATE SET
            asset_id     = EXCLUDED.asset_id,
            scan_type    = EXCLUDED.scan_type,
            started_at   = EXCLUDED.started_at,
            completed_at = EXCLUDED.completed_at,
            command_line = EXCLUDED.command_line,
            exit_code    = EXCLUDED.exit_code,
            output_dir   = EXCLUDED.output_dir,
            source       = EXCLUDED.source,
            notes        = EXCLUDED.notes,
            tools_run    = EXCLUDED.tools_run
        """,
        rows,
    )
    return len(rows)


def load_findings(cur, path: Path) -> tuple[int, int]:
    """Load findings + their embedded history. Returns (findings, history)."""
    find_rows = []
    hist_rows = []

    for rec in read_jsonl(path):
        find_rows.append((
            rec["finding_id"],
            rec["asset_id"],
            rec.get("title") or rec["finding_id"],
            rec.get("severity") or "INFO",
            rec.get("category") or "other",
            rec.get("description"),
            rec.get("cwe") or [],
            rec.get("cve") or [],
            rec.get("references") or [],
            rec.get("current_status") or "detected",
            get(rec, "first_detected_at"),
            rec.get("first_detected_scan") or None,
            get(rec, "last_observed_at"),
            get(rec, "remediated_at"),
            rec.get("owner") or None,
            get(rec, "deadline"),
            rec.get("source") or "other",
            rec.get("subdomain") or None,
            rec.get("host_ip") or None,
            coerce_int(rec.get("port")),
            rec.get("protocol") or None,
            rec.get("tags") or [],
            # #36 — normalized_key derived in rollup_findings via
            # apply_cross_source_equivalence(). None when no curated entry
            # matched (caller preserves whatever DB-side derivation is
            # already there — see UPDATE clause's COALESCE).
            rec.get("normalized_key") or None,
        ))

        for h in rec.get("history", []) or []:
            hist_rows.append((
                rec["finding_id"],
                h["scan_id"],
                get(h, "observed_at"),
                h.get("status") or "detected",
                h.get("severity_at_scan") or None,
                h.get("matched_at") or None,
                h.get("raw_excerpt") or None,
                h.get("notes") or None,
            ))

    if find_rows:
        cur.executemany(
            """
            INSERT INTO findings (
                finding_id, asset_id, title, severity, category, description,
                cwe, cve, "references", current_status, first_detected_at,
                first_detected_scan, last_observed_at, remediated_at,
                owner, deadline, source, subdomain, host_ip, port, protocol, tags,
                normalized_key
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s)
            ON CONFLICT (finding_id) DO UPDATE SET
                asset_id            = EXCLUDED.asset_id,
                title               = EXCLUDED.title,
                category            = EXCLUDED.category,
                description         = EXCLUDED.description,
                cwe                 = EXCLUDED.cwe,
                cve                 = EXCLUDED.cve,
                "references"        = EXCLUDED."references",

                -- STATUS-DOWNGRADE GUARD (added 2026-05-19 after second
                -- re-open incident): once a finding is closed, the JSONL
                -- importer is NOT allowed to reopen it. JSONL only knows
                -- what scanners detect — it doesn't carry the human
                -- decision that closed the finding. Manual closures and
                -- verdict_md scans set the closed state; an ordinary
                -- re-scan that re-observes the underlying condition must
                -- not invalidate that decision. Exception: an explicit
                -- 'regressed' status from the JSONL is allowed through —
                -- that's the "was fixed, came back" signal.
                current_status = CASE
                  WHEN findings.current_status IN (
                         'remediated','validated_remediated',
                         'false_positive','wont_fix','accepted_risk'
                       )
                       AND EXCLUDED.current_status NOT IN (
                         'remediated','validated_remediated',
                         'false_positive','wont_fix','accepted_risk',
                         'regressed'
                       )
                    THEN findings.current_status
                  ELSE EXCLUDED.current_status
                END,
                remediated_at = CASE
                  WHEN findings.current_status IN (
                         'remediated','validated_remediated',
                         'false_positive','wont_fix','accepted_risk'
                       )
                       AND EXCLUDED.current_status NOT IN (
                         'remediated','validated_remediated',
                         'false_positive','wont_fix','accepted_risk',
                         'regressed'
                       )
                    THEN findings.remediated_at
                  ELSE EXCLUDED.remediated_at
                END,

                -- SEVERITY-DOWNGRADE PROTECTION: if the operator (via
                -- backfill SQL) classified a finding as LESS severe than
                -- the JSONL is now asserting, keep the lower DB value.
                -- This is the equivalent of the status guard above, for
                -- the severity field. A re-scan can lower severity but
                -- can't blindly raise it back above the manual override.
                severity = CASE
                  WHEN (CASE findings.severity
                         WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                         WHEN 'MODERATE-HIGH' THEN 3 WHEN 'MODERATE' THEN 4
                         WHEN 'LOW' THEN 5 WHEN 'INFO' THEN 6 ELSE 9 END)
                     > (CASE EXCLUDED.severity
                         WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                         WHEN 'MODERATE-HIGH' THEN 3 WHEN 'MODERATE' THEN 4
                         WHEN 'LOW' THEN 5 WHEN 'INFO' THEN 6 ELSE 9 END)
                    THEN findings.severity
                  ELSE EXCLUDED.severity
                END,

                first_detected_at   = LEAST(findings.first_detected_at, EXCLUDED.first_detected_at),
                first_detected_scan = COALESCE(findings.first_detected_scan, EXCLUDED.first_detected_scan),
                last_observed_at    = EXCLUDED.last_observed_at,
                owner               = EXCLUDED.owner,
                deadline            = EXCLUDED.deadline,
                source              = EXCLUDED.source,
                subdomain           = EXCLUDED.subdomain,
                host_ip             = EXCLUDED.host_ip,
                port                = EXCLUDED.port,
                protocol            = EXCLUDED.protocol,
                tags                = EXCLUDED.tags,
                -- #36 — cross-source equivalence key wins when present (the
                -- whole point: collapse same-fact findings across sources).
                -- When EXCLUDED.normalized_key is NULL (no curated entry
                -- matched), preserve whatever derivation is already in the
                -- DB (e.g. run_light's per-source key, or a prior backfill
                -- migration). COALESCE is correct here: NULL from the
                -- importer means "I have no opinion," not "set it to NULL."
                normalized_key      = COALESCE(EXCLUDED.normalized_key, findings.normalized_key)
            """,
            find_rows,
        )

    if hist_rows:
        cur.executemany(
            """
            INSERT INTO finding_history (
                finding_id, scan_id, observed_at, status,
                severity_at_scan, matched_at, raw_excerpt, notes
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (finding_id, scan_id) DO UPDATE SET
                observed_at      = EXCLUDED.observed_at,
                status           = EXCLUDED.status,
                severity_at_scan = EXCLUDED.severity_at_scan,
                matched_at       = EXCLUDED.matched_at,
                raw_excerpt      = EXCLUDED.raw_excerpt,
                notes            = EXCLUDED.notes
            """,
            hist_rows,
        )

    return len(find_rows), len(hist_rows)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--normalized", required=True, help="Directory with assets.jsonl / scans.jsonl / findings.jsonl")
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN"), help="Postgres DSN (or set SUPABASE_DSN)")
    ap.add_argument("--truncate", action="store_true", help="TRUNCATE loadable tables before insert (destructive)")
    ap.add_argument("--delta-close", action="store_true",
                    help="!! BROKEN as of 2026-05-19 — do NOT use. Closes findings "
                         "against every historical scan and wrongly closes manual_named "
                         "+ curated_html + summary_md + verdict_md findings. Will be "
                         "re-enabled once latest-scan-only logic ships. Use "
                         "scripts/db/maintenance.sql close_findings_by_id() instead.")
    ap.add_argument("--no-refresh", action="store_true",
                    help="Skip the post-import refresh of last_observed and "
                         "current_risk. Default behavior is to always refresh.")
    args = ap.parse_args()

    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN required", file=sys.stderr)
        sys.exit(2)

    norm = Path(args.normalized).expanduser().resolve()
    assets_p   = norm / "assets.jsonl"
    scans_p    = norm / "scans.jsonl"
    findings_p = norm / "findings.jsonl"

    for p in (assets_p, scans_p, findings_p):
        if not p.is_file():
            print(f"error: missing file: {p}", file=sys.stderr)
            sys.exit(2)

    with psycopg.connect(args.dsn, autocommit=False) as conn:
        with conn.cursor() as cur:
            if args.truncate:
                print(">> TRUNCATE findings, scans, assets (CASCADE)")
                cur.execute("TRUNCATE finding_history, evidence_artifacts, findings, scans, assets RESTART IDENTITY CASCADE")

            n_assets   = load_assets(cur, assets_p)

            # Auto-stub any orphan asset_ids referenced by scans/findings
            # but missing from assets.jsonl (e.g. mail subdomains, parser
            # bugs leaking www. variants). Preserves FK integrity without
            # discarding data; stubs are tagged for later cleanup.
            referenced: set[str] = set()
            for rec in read_jsonl(scans_p):
                referenced.add(rec["asset_id"])
            for rec in read_jsonl(findings_p):
                referenced.add(rec["asset_id"])

            cur.execute("SELECT asset_id FROM assets")
            existing = {r[0] for r in cur.fetchall()}
            orphans = sorted(referenced - existing)
            if orphans:
                print(f">> Auto-stubbing {len(orphans)} orphan asset(s): {orphans}")
                stub_rows = [_asset_row(o, stub=True) for o in orphans]
                # 2026-06-15 full-eject: last_observed deliberately excluded.
                # Stub rows get last_observed=NULL until asm-discover sees
                # them. Alerter reads NULL as "not yet discovered."
                cur.executemany(
                    """
                    INSERT INTO assets (
                        asset_id, name, type, organization, tags,
                        first_observed, current_risk, current_risk_reason, metadata
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (asset_id) DO NOTHING
                    """,
                    stub_rows,
                )
                n_assets += len(orphans)

            n_scans    = load_scans(cur, scans_p)

            # Auto-stub any scan_ids referenced by findings/history but
            # missing from scans.jsonl (parser naming inconsistency:
            # curated_html emits __synthetic_root, walker emits ___target_root).
            # Build a map from synthetic scan_id -> asset_id by reading findings.
            scan_to_asset: dict[str, str] = {}
            for rec in read_jsonl(findings_p):
                fid_scan = rec.get("first_detected_scan")
                if fid_scan:
                    scan_to_asset.setdefault(fid_scan, rec["asset_id"])
                for h in rec.get("history", []) or []:
                    sid = h.get("scan_id")
                    if sid:
                        scan_to_asset.setdefault(sid, rec["asset_id"])

            cur.execute("SELECT scan_id FROM scans")
            existing_scans = {r[0] for r in cur.fetchall()}
            orphan_scans = sorted(set(scan_to_asset.keys()) - existing_scans)
            if orphan_scans:
                print(f">> Auto-stubbing {len(orphan_scans)} orphan scan(s): {orphan_scans}")
                stub_scan_rows = [
                    (
                        sid,
                        scan_to_asset[sid],
                        "vuln_full_assessment",
                        None, None, None, None, None,
                        "mac_local_scan",
                        "stub scan auto-created during import (parser naming inconsistency)",
                        Json([]),
                    )
                    for sid in orphan_scans
                ]
                cur.executemany(
                    """
                    INSERT INTO scans (
                        scan_id, asset_id, scan_type, started_at, completed_at,
                        command_line, exit_code, output_dir, source, notes, tools_run
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scan_id) DO NOTHING
                    """,
                    stub_scan_rows,
                )
                n_scans += len(orphan_scans)

            n_findings, n_hist = load_findings(cur, findings_p)

            # ---------------------------------------------------------
            # Post-import maintenance
            # ---------------------------------------------------------
            n_closed = 0
            if args.delta_close and not args.truncate:
                print("error: --delta-close is currently disabled because the "
                      "close logic has known bugs (see --help). Refusing to run. "
                      "Use scripts/db/maintenance.sql close_findings_by_id() or "
                      "a one-off backfill SQL instead.", file=sys.stderr)
                sys.exit(3)
            if False:  # ----- DISABLED BLOCK BELOW -----
                # Collect the scan_ids that came in with this import
                scan_ids_in_batch: list[str] = []
                for rec in read_jsonl(scans_p):
                    scan_ids_in_batch.append(rec["scan_id"])
                # Synthetic scan_ids referenced by findings but not in scans.jsonl
                # (e.g. ___synthetic_root) — include them too. They were stubbed
                # in earlier.
                for rec in read_jsonl(findings_p):
                    sid = rec.get("first_detected_scan")
                    if sid and sid not in scan_ids_in_batch:
                        scan_ids_in_batch.append(sid)
                    for h in rec.get("history", []) or []:
                        sid = h.get("scan_id")
                        if sid and sid not in scan_ids_in_batch:
                            scan_ids_in_batch.append(sid)

                for sid in scan_ids_in_batch:
                    cur.execute("SELECT delta_close_for_scan(%s)", (sid,))
                    n_closed += (cur.fetchone()[0] or 0)
                if n_closed:
                    print(f">> Delta-close: marked {n_closed} stale finding(s) "
                          f"as remediated across {len(scan_ids_in_batch)} scan(s)")

            if not args.no_refresh:
                # 2026-06-15: refresh_all_asset_last_observed() was DROPPED
                # (migration 20260615a). It implemented B semantic
                # (MAX(scans.completed_at)) which contradicts the A semantic
                # (assets.last_observed = DISCOVERY clock, owned by
                # import_asm_to_surface, monotonic via GREATEST). Only
                # refresh_all_asset_posture() remains — independent of
                # last_observed, recomputes current_risk + reason only.
                cur.execute("SELECT refresh_all_asset_posture()")
                n_pos = cur.fetchone()[0] or 0
                print(f">> Refresh: posture recomputed for {n_pos} asset(s)")

        conn.commit()

    print(">> Import complete:")
    print(f"   assets:           {n_assets}")
    print(f"   scans:            {n_scans}")
    print(f"   findings:         {n_findings}")
    print(f"   finding_history:  {n_hist}")
    if args.delta_close and not args.truncate:
        print(f"   delta-closed:     {n_closed}")


if __name__ == "__main__":
    main()
