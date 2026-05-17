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

def load_assets(cur, path: Path) -> int:
    rows = []
    for rec in read_jsonl(path):
        rows.append((
            rec["asset_id"],
            rec.get("name") or rec["asset_id"],
            rec.get("type") or "apex_domain",
            rec.get("organization") or "command_companies",
            rec.get("tags") or [],
            get(rec, "first_observed"),
            get(rec, "last_observed"),
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
            first_observed, last_observed, current_risk, current_risk_reason, metadata
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (asset_id) DO UPDATE SET
            name                = EXCLUDED.name,
            type                = EXCLUDED.type,
            organization        = EXCLUDED.organization,
            tags                = EXCLUDED.tags,
            first_observed      = COALESCE(assets.first_observed, EXCLUDED.first_observed),
            last_observed       = EXCLUDED.last_observed,
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
            rec["first_detected_at"],
            rec.get("first_detected_scan"),
            get(rec, "last_observed_at"),
            get(rec, "remediated_at"),
            rec.get("owner"),
            get(rec, "deadline"),
            rec.get("source") or "other",
            rec.get("subdomain"),
            rec.get("host_ip"),
            coerce_int(rec.get("port")),
            rec.get("protocol"),
            rec.get("tags") or [],
        ))

        for h in rec.get("history", []) or []:
            hist_rows.append((
                rec["finding_id"],
                h["scan_id"],
                h["observed_at"],
                h.get("status") or "detected",
                h.get("severity_at_scan"),
                h.get("matched_at"),
                h.get("raw_excerpt"),
                h.get("notes"),
            ))

    if find_rows:
        cur.executemany(
            """
            INSERT INTO findings (
                finding_id, asset_id, title, severity, category, description,
                cwe, cve, "references", current_status, first_detected_at,
                first_detected_scan, last_observed_at, remediated_at,
                owner, deadline, source, subdomain, host_ip, port, protocol, tags
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (finding_id) DO UPDATE SET
                asset_id            = EXCLUDED.asset_id,
                title               = EXCLUDED.title,
                severity            = EXCLUDED.severity,
                category            = EXCLUDED.category,
                description         = EXCLUDED.description,
                cwe                 = EXCLUDED.cwe,
                cve                 = EXCLUDED.cve,
                "references"        = EXCLUDED."references",
                current_status      = EXCLUDED.current_status,
                first_detected_at   = LEAST(findings.first_detected_at, EXCLUDED.first_detected_at),
                first_detected_scan = COALESCE(findings.first_detected_scan, EXCLUDED.first_detected_scan),
                last_observed_at    = EXCLUDED.last_observed_at,
                remediated_at       = EXCLUDED.remediated_at,
                owner               = EXCLUDED.owner,
                deadline            = EXCLUDED.deadline,
                source              = EXCLUDED.source,
                subdomain           = EXCLUDED.subdomain,
                host_ip             = EXCLUDED.host_ip,
                port                = EXCLUDED.port,
                protocol            = EXCLUDED.protocol,
                tags                = EXCLUDED.tags
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
            n_scans    = load_scans(cur, scans_p)
            n_findings, n_hist = load_findings(cur, findings_p)
        conn.commit()

    print(">> Import complete:")
    print(f"   assets:           {n_assets}")
    print(f"   scans:            {n_scans}")
    print(f"   findings:         {n_findings}")
    print(f"   finding_history:  {n_hist}")


if __name__ == "__main__":
    main()
