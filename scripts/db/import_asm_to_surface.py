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
    """Map legacy ASM type values to portal asset_type_t enum.

    Legacy ASM uses:  ip | apex | fqdn | cidr | asn
    Portal enum:      ip | apex_domain | single_host | ip_range | ...

    Anything we don't recognize defaults to 'single_host' (the catch-all
    for a named host that isn't an apex).
    """
    asset = asm_doc.get("asset") or {}
    raw = (asset.get("type") or "").strip().lower()
    mapping = {
        "ip":   "ip",
        "apex": "apex_domain",
        "fqdn": "single_host",
        "cidr": "ip_range",
        "asn":  "ip_range",
    }
    return mapping.get(raw, "single_host")


def derive_organization(asm_doc: dict) -> str:
    """Map legacy ASM 'owner' (free-form) to portal organization_t enum.

    Portal enum values are LOWERCASE:
      command_companies | command_digital | command_financial |
      command_missouri  | command_marketing | unimac | sci | unknown

    Unknown/missing → 'unknown' (the enum's catch-all).
    """
    asset = asm_doc.get("asset") or {}
    owner = (asset.get("owner") or "").strip().lower()
    if not owner or owner in ("unknown", ""):
        return "unknown"
    mapping = {
        "command digital":   "command_digital",
        "command_digital":   "command_digital",
        "command companies": "command_companies",
        "command_companies": "command_companies",
        "command marketing": "command_marketing",
        "command_marketing": "command_marketing",
        "command financial": "command_financial",
        "command_financial": "command_financial",
        "command missouri":  "command_missouri",
        "command_missouri":  "command_missouri",
        "unimac":            "unimac",
        "sci":               "sci",
    }
    # Default to 'unknown' if the owner string doesn't match a known org —
    # safer than inventing a new enum value that would fail the insert.
    return mapping.get(owner, "unknown")


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
# Event-diff helpers — produce asset_surface_event rows from old vs new blob.
# ---------------------------------------------------------------------------
# Service identity is the tuple (host, port, proto). Same triple in both
# blobs = no event. Triple only in new = port_opened. Triple only in old =
# port_closed. We keep extra detail (service, tls) on the event row but
# don't use it for identity — banner-name / TLS-detection flips should
# not look like a close-and-reopen.


def flatten_services(blob: dict) -> dict[tuple[str, int, str], dict]:
    """Walk surface_data.subdomains[].hosts[].services[] (or the legacy
    surface_data.subdomains[].services[] shape) and return a map keyed by
    (host, port, proto) → service detail dict.

    Returns an empty dict for any unparseable blob — the importer never
    fails an upsert because of event-diff problems.
    """
    out: dict[tuple[str, int, str], dict] = {}
    if not isinstance(blob, dict):
        return out
    subs = blob.get("subdomains") or []
    if not isinstance(subs, list):
        return out

    for sub in subs:
        if not isinstance(sub, dict):
            continue
        sub_name = sub.get("name") or sub.get("subdomain")

        # Two possible shapes — the ASM JSON has services attached either
        # to each host or directly to the subdomain. Handle both.
        host_entries = sub.get("hosts") or []
        if host_entries:
            for h in host_entries:
                if not isinstance(h, dict):
                    continue
                host_addr = h.get("ip") or h.get("address") or sub_name or "?"
                for svc in (h.get("services") or []):
                    _record_service(out, host_addr, sub_name, svc)
        else:
            host_addr = sub_name or "?"
            for svc in (sub.get("services") or []):
                _record_service(out, host_addr, sub_name, svc)

    return out


def _record_service(
    out: dict[tuple[str, int, str], dict],
    host: str,
    subdomain: str | None,
    svc: dict,
) -> None:
    if not isinstance(svc, dict):
        return
    try:
        port = int(svc.get("port"))
    except (TypeError, ValueError):
        return
    proto = (svc.get("protocol") or svc.get("proto") or "tcp").lower()
    key = (host, port, proto)
    # First-wins: if a service appears twice across hosts for the same
    # (host, port, proto), keep the first detail.
    if key in out:
        return
    out[key] = {
        "host": host,
        "subdomain": subdomain,
        "port": port,
        "proto": proto,
        "service": svc.get("service") or svc.get("name"),
        "tls": bool(svc.get("tls")),
    }


def compute_events(
    asset_id: str,
    existing_blob: dict | None,
    new_blob: dict,
    source_tag: str,
) -> list[dict]:
    """Return a list of asset_surface_event row dicts (ready for executemany).

    Rules:
      - existing_blob is None (asset never seen) → one asset_first_seen row
        and NOTHING ELSE (don't flood on new-asset discovery)
      - both blobs present → port_opened for keys in new not in old,
        port_closed for keys in old not in new
    """
    if existing_blob is None:
        return [
            {
                "asset_id": asset_id,
                "event_type": "asset_first_seen",
                "host": None,
                "port": None,
                "proto": None,
                "service": None,
                "tls": None,
                "prev_value": None,
                "new_value": None,
                "source_tag": source_tag,
            }
        ]

    old_map = flatten_services(existing_blob)
    new_map = flatten_services(new_blob)

    events: list[dict] = []

    for key in new_map.keys() - old_map.keys():
        det = new_map[key]
        events.append(
            {
                "asset_id": asset_id,
                "event_type": "port_opened",
                "host": det["host"],
                "port": det["port"],
                "proto": det["proto"],
                "service": det.get("service"),
                "tls": det.get("tls"),
                "prev_value": None,
                "new_value": Json(det),
                "source_tag": source_tag,
            }
        )

    for key in old_map.keys() - new_map.keys():
        det = old_map[key]
        events.append(
            {
                "asset_id": asset_id,
                "event_type": "port_closed",
                "host": det["host"],
                "port": det["port"],
                "proto": det["proto"],
                "service": det.get("service"),
                "tls": det.get("tls"),
                "prev_value": Json(det),
                "new_value": None,
                "source_tag": source_tag,
            }
        )

    return events


INSERT_EVENT = """
INSERT INTO public.asset_surface_event (
  asset_id, event_type, host, port, proto, service, tls,
  prev_value, new_value, source_tag
) VALUES (
  %(asset_id)s, %(event_type)s, %(host)s, %(port)s, %(proto)s, %(service)s, %(tls)s,
  %(prev_value)s, %(new_value)s, %(source_tag)s
);
"""


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


def import_one(
    conn,
    asm_doc: dict,
    source_tag: str,
    dry_run: bool,
    skip_events: bool = False,
) -> dict[str, Any]:
    """Push one asset JSON to the DB. Returns a small status dict.

    With skip_events=False (default), diffs the incoming surface_data vs
    the existing row and emits asset_surface_event rows for any deltas.
    Pass skip_events=True for a silent backfill (e.g., re-running the
    importer against unchanged data, or one-time historical loads).
    """
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

    events: list[dict] = []
    with conn.cursor() as cur:
        # 1. Fetch existing surface_data BEFORE we overwrite it. If the
        #    row doesn't exist yet, existing_blob stays None — we'll emit
        #    a single asset_first_seen event instead of per-port events.
        existing_blob: dict | None = None
        if not skip_events:
            cur.execute(
                "SELECT surface_data FROM public.asset_surface WHERE asset_id = %s",
                (asset_id,),
            )
            row = cur.fetchone()
            if row and row[0] is not None:
                existing_blob = row[0]

        # 2. Upsert asset + surface (overwrites surface_data).
        cur.execute(UPSERT_ASSET, asset_row)
        a_row = cur.fetchone()
        asset_inserted = a_row[1] if a_row else False
        cur.execute(UPSERT_SURFACE, surface_row)

        # 3. Compute + write events. Failures here MUST NOT roll back the
        #    upsert — current-state correctness is more important than
        #    perfect history. Catch and log instead.
        if not skip_events:
            try:
                events = compute_events(asset_id, existing_blob, asm_doc, source_tag)
                if events:
                    cur.executemany(INSERT_EVENT, events)
            except Exception as e:
                # Print but don't re-raise. The transaction will still
                # commit the surface row at the outer level.
                print(
                    f"  ! event-diff for {asset_id} failed (non-fatal): {e}",
                    file=sys.stderr,
                )

    return {
        "status": "ok",
        "asset_id": asset_id,
        "asset_inserted": asset_inserted,
        "events_emitted": len(events),
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
    ap.add_argument(
        "--skip-events",
        action="store_true",
        help=(
            "Suppress asset_surface_event writes. Use for silent backfills "
            "where you don't want to flood the event log with asset_first_seen "
            "rows for assets that have actually been around for ages."
        ),
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
                result = import_one(
                    conn, doc, args.source_tag, args.dry_run, args.skip_events
                )
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
                ev = result.get("events_emitted") or 0
                ev_str = f" [+{ev} event{'s' if ev != 1 else ''}]" if ev else ""
                print(f"  ✓ {path.name}: {tag} {result['asset_id']}{ev_str}")
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
