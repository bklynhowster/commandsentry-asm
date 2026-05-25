#!/usr/bin/env python3
"""
import_asm_to_surface.py — push legacy ASM JSON into the portal's asset_surface table.

The legacy `commandsentry-asm` cron writes one JSON file per asset to
`data/assets/*.json`. The Surface tab on the portal reads from the new
`asset_surface` table in Supabase. This script bridges the two until the
cron itself writes Supabase directly (Phase 4 cloud-scan migration).

Two-step ingest per asset:
  1. UPSERT public.assets  — make sure the asset row exists (FK target).
     New assets get organization='UNKNOWN' so Howie can tag them later.
  2. UPSERT public.asset_surface — write the full ASM blob + derived
     convenience columns (top_hosting_org, primary_asn, primary_ptr,
     alive, counts).

Idempotent. Safe to re-run. Used initially for backfill (locally) and
later from GH Actions after every cron scan.

USAGE
-----
    export SUPABASE_DSN='postgresql://postgres:PASSWORD@db.PROJECT.supabase.co:5432/postgres'
    python3 scripts/db/import_asm_to_surface.py [--dry-run] [--data-dir PATH]

ENV VARS
--------
    SUPABASE_DSN   Postgres DSN (or pass --dsn)

EXIT CODES
----------
    0  success
    1  failure (DSN missing, schema error, etc.)
    2  partial success (some files failed, others succeeded)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

try:
    import psycopg
    from psycopg.types.json import Json
except ImportError:
    print(
        "error: psycopg (psycopg3) is required.\n"
        "  install it with: pip install --user --break-system-packages 'psycopg[binary]'",
        file=sys.stderr,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = REPO_ROOT / "data" / "assets"


# ---------------------------------------------------------------------------
# Asset-id mapping
# ---------------------------------------------------------------------------
# Legacy ASM uses dash-form IDs internally (`24-157-51-68`, `commandcommcentral`)
# but stores the canonical value in `asset.value`. The portal's `assets.asset_id`
# uses the canonical form (`24.157.51.68`, `commandcommcentral.com`). Always
# derive from `value`, never from `id`.


def derive_portal_asset_id(asm_doc: dict) -> str | None:
    asset = asm_doc.get("asset") or {}
    val = (asset.get("value") or "").strip()
    if not val:
        return None
    return val


def derive_asset_type(asm_doc: dict) -> str:
    """Legacy ASM types: ip / apex / fqdn / cidr / asn — same as portal."""
    asset = asm_doc.get("asset") or {}
    return (asset.get("type") or "fqdn").lower()


def derive_organization(asm_doc: dict) -> str:
    """Legacy ASM has free-form 'owner' (often 'unknown'). Map to portal org."""
    asset = asm_doc.get("asset") or {}
    owner = (asset.get("owner") or "").strip().lower()
    if not owner or owner in ("unknown", ""):
        return "UNKNOWN"
    # Common mappings — extend as patterns emerge in the data.
    mapping = {
        "command digital": "COMMAND_DIGITAL",
        "command_digital": "COMMAND_DIGITAL",
        "command companies": "COMMAND_COMPANIES",
        "command marketing": "COMMAND_MARKETING",
        "command financial": "COMMAND_FINANCIAL",
        "command missouri": "COMMAND_MISSOURI",
        "unimac": "UNIMAC",
        "sci": "SCI",
    }
    return mapping.get(owner, owner.upper().replace(" ", "_"))


# ---------------------------------------------------------------------------
# Derive convenience columns from the ASM blob
# ---------------------------------------------------------------------------


def derive_convenience(asm_doc: dict) -> dict[str, Any]:
    summary = asm_doc.get("summary") or {}
    subs = asm_doc.get("subdomains") or []

    # Pull host context from the first subdomain's first host. Most assets
    # only have one host; for multi-host assets this is the "primary" view.
    primary_host: dict[str, Any] = {}
    for sub in subs:
        hosts = sub.get("hosts") or []
        if hosts:
            primary_host = hosts[0]
            break

    # Alive if any subdomain reports reachability.live=true
    alive = False
    for sub in subs:
        reach = sub.get("reachability") or {}
        if reach.get("live"):
            alive = True
            break

    asn = primary_host.get("asn")
    asn_str = str(asn) if asn else None

    return {
        "top_hosting_org": summary.get("top_hosting_org"),
        "platforms": summary.get("platforms") or [],
        "primary_asn": asn_str,
        "primary_ptr": primary_host.get("reverse_dns"),
        "subdomain_count": int(summary.get("subdomain_count") or 0),
        "live_subdomain_count": int(summary.get("live_subdomain_count") or 0),
        "host_count": int(summary.get("host_count") or 0),
        "service_count": int(summary.get("service_count") or 0),
        "newest_cert_expiry_days": summary.get("newest_cert_expiry_days"),
        "alive": alive,
    }


def derive_lifecycle(asm_doc: dict) -> dict[str, Any]:
    """first_discovered / last_seen from the asset's subdomain history."""
    subs = asm_doc.get("subdomains") or []
    asset = asm_doc.get("asset") or {}
    first_seen = None
    last_seen = None
    for sub in subs:
        fd = sub.get("first_discovered")
        ls = sub.get("last_seen")
        if fd and (not first_seen or fd < first_seen):
            first_seen = fd
        if ls and (not last_seen or ls > last_seen):
            last_seen = ls
    return {
        "discovered_via": asset.get("discovered_via"),
        "first_discovered": first_seen,
        "last_seen": last_seen,
    }


# ---------------------------------------------------------------------------
# DB upserts
# ---------------------------------------------------------------------------

UPSERT_ASSET = """
INSERT INTO public.assets (asset_id, name, type, organization, first_observed, last_observed)
VALUES (%(asset_id)s, %(name)s, %(type)s, %(organization)s, %(first_observed)s, %(last_observed)s)
ON CONFLICT (asset_id) DO UPDATE SET
  last_observed = GREATEST(public.assets.last_observed, EXCLUDED.last_observed)
RETURNING asset_id, (xmax = 0) AS inserted;
"""

UPSERT_SURFACE = """
INSERT INTO public.asset_surface (
  asset_id, asset_type, alive, top_hosting_org, platforms,
  primary_asn, primary_ptr,
  subdomain_count, live_subdomain_count, host_count, service_count,
  newest_cert_expiry_days,
  discovered_via, first_discovered, last_seen,
  surface_data, updated_at, updated_by
)
VALUES (
  %(asset_id)s, %(asset_type)s, %(alive)s, %(top_hosting_org)s, %(platforms)s,
  %(primary_asn)s, %(primary_ptr)s,
  %(subdomain_count)s, %(live_subdomain_count)s, %(host_count)s, %(service_count)s,
  %(newest_cert_expiry_days)s,
  %(discovered_via)s, %(first_discovered)s, %(last_seen)s,
  %(surface_data)s, NOW(), %(updated_by)s
)
ON CONFLICT (asset_id) DO UPDATE SET
  asset_type              = EXCLUDED.asset_type,
  alive                   = EXCLUDED.alive,
  top_hosting_org         = EXCLUDED.top_hosting_org,
  platforms               = EXCLUDED.platforms,
  primary_asn             = EXCLUDED.primary_asn,
  primary_ptr             = EXCLUDED.primary_ptr,
  subdomain_count         = EXCLUDED.subdomain_count,
  live_subdomain_count    = EXCLUDED.live_subdomain_count,
  host_count              = EXCLUDED.host_count,
  service_count           = EXCLUDED.service_count,
  newest_cert_expiry_days = EXCLUDED.newest_cert_expiry_days,
  discovered_via          = EXCLUDED.discovered_via,
  first_discovered        = COALESCE(public.asset_surface.first_discovered, EXCLUDED.first_discovered),
  last_seen               = GREATEST(public.asset_surface.last_seen, EXCLUDED.last_seen),
  surface_data            = EXCLUDED.surface_data,
  updated_at              = NOW(),
  updated_by              = EXCLUDED.updated_by;
"""


def import_one(conn, asm_doc: dict, source_tag: str, dry_run: bool) -> dict[str, Any]:
    """Push one asset JSON to the DB. Returns a small status dict."""
    asset_id = derive_portal_asset_id(asm_doc)
    if not asset_id:
        return {"status": "skipped", "reason": "no asset.value"}

    asset_type = derive_asset_type(asm_doc)
    organization = derive_organization(asm_doc)
    lifecycle = derive_lifecycle(asm_doc)
    convenience = derive_convenience(asm_doc)

    asset_row = {
        "asset_id": asset_id,
        "name": asset_id,
        "type": asset_type,
        "organization": organization,
        "first_observed": lifecycle["first_discovered"],
        "last_observed": lifecycle["last_seen"],
    }

    surface_row = {
        "asset_id": asset_id,
        "asset_type": asset_type,
        **convenience,
        "discovered_via": lifecycle["discovered_via"],
        "first_discovered": lifecycle["first_discovered"],
        "last_seen": lifecycle["last_seen"],
        "surface_data": Json(asm_doc),
        "updated_by": source_tag,
    }

    if dry_run:
        return {
            "status": "dry_run",
            "asset_id": asset_id,
            "would_upsert_asset": asset_row,
            "would_upsert_surface_keys": list(surface_row.keys()),
        }

    with conn.cursor() as cur:
        cur.execute(UPSERT_ASSET, asset_row)
        row = cur.fetchone()
        asset_inserted = row[1] if row else False
        cur.execute(UPSERT_SURFACE, surface_row)

    return {
        "status": "ok",
        "asset_id": asset_id,
        "asset_inserted": asset_inserted,
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help=f"Directory of legacy ASM asset JSON files (default: {DEFAULT_DATA_DIR})",
    )
    ap.add_argument(
        "--dsn",
        default=os.environ.get("SUPABASE_DSN"),
        help="Postgres DSN (or set SUPABASE_DSN)",
    )
    ap.add_argument(
        "--source-tag",
        default="legacy_asm_import",
        help="Stamp written to asset_surface.updated_by",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse + derive but don't write to DB",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Only process first N files (debug aid). 0 = all.",
    )
    args = ap.parse_args()

    if not args.dry_run and not args.dsn:
        print("error: --dsn or SUPABASE_DSN required (or use --dry-run)", file=sys.stderr)
        return 1

    if not args.data_dir.is_dir():
        print(f"error: data dir not found: {args.data_dir}", file=sys.stderr)
        return 1

    files = sorted(args.data_dir.glob("*.json"))
    if args.limit > 0:
        files = files[: args.limit]
    if not files:
        print(f"no JSON files in {args.data_dir}", file=sys.stderr)
        return 1

    print(f"importing {len(files)} asset(s) from {args.data_dir}")
    if args.dry_run:
        print("  (dry-run — no DB writes)")

    okay = 0
    new_assets = 0
    skipped = 0
    failed = 0

    conn = None
    if not args.dry_run:
        conn = psycopg.connect(args.dsn, autocommit=False)

    try:
        for path in files:
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"  ! {path.name}: parse error: {e}", file=sys.stderr)
                failed += 1
                continue

            try:
                result = import_one(conn, doc, args.source_tag, args.dry_run)
            except Exception as e:
                print(f"  ! {path.name}: import error: {e}", file=sys.stderr)
                if conn:
                    conn.rollback()
                failed += 1
                continue

            if result["status"] == "skipped":
                print(f"  - {path.name}: skipped ({result['reason']})")
                skipped += 1
            elif result["status"] == "dry_run":
                print(f"  · {path.name}: would upsert asset_id={result['asset_id']}")
                okay += 1
            else:
                tag = "NEW" if result.get("asset_inserted") else "upd"
                print(f"  ✓ {path.name}: {tag} {result['asset_id']}")
                okay += 1
                if result.get("asset_inserted"):
                    new_assets += 1

        if conn and not args.dry_run:
            conn.commit()
    finally:
        if conn:
            conn.close()

    print()
    print(f"summary: {okay} ok ({new_assets} new), {skipped} skipped, {failed} failed")

    if failed and okay == 0:
        return 1
    if failed:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
