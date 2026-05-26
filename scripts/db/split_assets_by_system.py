#!/usr/bin/env python3
"""
split_assets_by_system.py — propose (and optionally execute) asset rows
for each distinct system discovered under existing apex assets.

CONTEXT
-------
Howie's Flavor 1 architecture (Obsidian 43 - Asset Decomposition Design
Spec.md). Each subdomain that represents a real attack surface gets its
own asset row. portal.unimacgraphics.com and myorders.unimacgraphics.com
become separate assets, siblings of unimacgraphics.com in the dashboard.

WHAT THIS SCRIPT DOES
---------------------
1. Reads existing assets + their asset_surface (the ASM blob)
2. For each asset, walks subdomains[] and splits by the rules below
3. Reports a plan: what new asset rows would be created, what aliases
   would be assigned, what kind classifications would apply
4. With --execute: writes the new rows. Without it: prints the plan only.

SPLIT RULES (codified from the design spec)
-------------------------------------------
- Default: each subdomain becomes its own asset
- ALIAS: `www.X` is always an alias of `X`
- ALIAS: bare apex variants (trailing dot, etc.) merge to canonical
- ALWAYS SEPARATE:
    - mail.* (kind='mail')
    - *-test / *-staging / *-dev / *-uat / *-qa (kind='staging')
    - subdomains pointing to a different IP than the apex
- Apex itself stays as its own asset (it represents the canonical home page /
  primary system of the apex)

USAGE
-----
    export SUPABASE_DSN='postgresql://...'

    # Show the proposed split, write nothing
    python3 scripts/db/split_assets_by_system.py --dry-run

    # Same, but only show one apex
    python3 scripts/db/split_assets_by_system.py --dry-run --apex unimacgraphics.com

    # Actually create the new asset rows
    python3 scripts/db/split_assets_by_system.py --execute

EXIT CODES
----------
    0  success
    1  failure (DSN missing, etc.)
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    import psycopg
    from psycopg.types.json import Json
except ImportError:
    print(
        "error: psycopg (psycopg3) is required.\n"
        "  install with: pip install --user --break-system-packages 'psycopg[binary]'",
        file=sys.stderr,
    )
    sys.exit(1)


# ----------------------------------------------------------------------------
# Subdomain classification rules
# ----------------------------------------------------------------------------

STAGING_PATTERNS = re.compile(
    r'(-test|-staging|-dev|-uat|-qa|test\.|staging\.|dev\.|uat\.|qa\.)',
    re.IGNORECASE,
)

MAIL_PATTERNS = re.compile(
    r'^(mail|smtp|imap|mx[0-9]*|pop3?|webmail|exchange)\.',
    re.IGNORECASE,
)

API_PATTERNS = re.compile(
    r'^(api|rest|graphql)\.',
    re.IGNORECASE,
)

FTP_PATTERNS = re.compile(
    r'^(ftp|sftp|ftps)[0-9]*\.',
    re.IGNORECASE,
)

# Infrastructure-class subdomains: nameservers (ns01, ns02), VPN endpoints
# (vpn, vpn2), jump hosts, hypervisor admin panels, backup servers. These
# all run software that's a real attack surface — BIND CVEs, FortiOS,
# vCenter, etc. — so they get tracked as their own assets even though
# they're "infrastructure" rather than user-facing apps.
INFRA_PATTERNS = re.compile(
    r'^(ns[0-9]+|dns[0-9]*|vpn[0-9]*|jump[0-9]*|bastion|hyperv|xen|admin|backup|vcenter|esxi)\.',
    re.IGNORECASE,
)


def classify_kind(subdomain: str) -> str:
    """Return the asset_kind_t value for a given subdomain name.

    Order matters — more specific patterns checked first. Mail wins over
    infra because mx01.example.com should be classified as mail, not infra,
    even though mx[0-9]+ syntactically matches both patterns.
    """
    if MAIL_PATTERNS.search(subdomain):
        return "mail"
    if STAGING_PATTERNS.search(subdomain):
        return "staging"
    if API_PATTERNS.search(subdomain):
        return "api"
    if FTP_PATTERNS.search(subdomain):
        return "ftp"
    if INFRA_PATTERNS.search(subdomain):
        return "infra"
    return "unknown"


def derive_apex(name: str) -> str | None:
    """Last two segments of the hostname. Returns None for IPs."""
    if not name or "." not in name:
        return None
    if re.match(r'^[0-9.]+$', name) or ":" in name:
        return None
    parts = name.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return None
    return ".".join(parts[-2:])


def is_www_alias_of(sub: str, apex: str) -> bool:
    """www.X is always an alias of X."""
    return sub.lower() == f"www.{apex.lower()}"


def is_apex_alias(sub: str, apex: str) -> bool:
    """The apex itself, with or without trailing dot."""
    return sub.lower().rstrip(".") == apex.lower()


# ----------------------------------------------------------------------------
# Decomposition logic
# ----------------------------------------------------------------------------


def decompose_asset(
    asset_id: str,
    surface_data: dict | None,
    organization: str,
) -> dict[str, dict]:
    """Given an existing asset_id and its surface_data blob, return a dict
    mapping new_asset_id -> proposed row data. The original asset_id is
    always included in the output as the "primary" — its `aliases` get
    populated with www and apex variants.

    Returns a dict keyed by canonical asset_id, value is:
        {
            "kind": "web" | "mail" | ...,
            "apex_domain": "unimacgraphics.com",
            "organization": "unimac",
            "aliases": ["www.unimacgraphics.com", ...],
            "subdomains_in_asm": [...],
        }
    """
    apex = derive_apex(asset_id) or asset_id
    out: dict[str, dict] = {}

    # Seed with the original apex asset row
    out[asset_id] = {
        "kind": "web",  # apex defaults to web
        "apex_domain": apex,
        "organization": organization,
        "aliases": [],
        "subdomains_in_asm": [asset_id],
    }

    if not isinstance(surface_data, dict):
        return out

    subs = surface_data.get("subdomains") or []
    if not isinstance(subs, list):
        return out

    for sub in subs:
        if not isinstance(sub, dict):
            continue
        name = (sub.get("name") or sub.get("subdomain") or "").lower().strip()
        if not name:
            continue

        # www.X and bare apex variants → aliases of the apex asset
        if is_www_alias_of(name, apex) or is_apex_alias(name, apex):
            if name != asset_id and name not in out[asset_id]["aliases"]:
                out[asset_id]["aliases"].append(name)
            continue

        # Everything else → its own asset row
        if name not in out:
            out[name] = {
                "kind": classify_kind(name),
                "apex_domain": apex,
                "organization": organization,
                "aliases": [],
                "subdomains_in_asm": [name],
            }

    return out


# ----------------------------------------------------------------------------
# Driver
# ----------------------------------------------------------------------------


FETCH_EXISTING = """
SELECT a.asset_id, a.organization::text, s.surface_data
FROM public.assets a
LEFT JOIN public.asset_surface s ON s.asset_id = a.asset_id
ORDER BY a.asset_id;
"""

INSERT_NEW_ASSET = """
INSERT INTO public.assets
  (asset_id, name, type, organization, kind, apex_domain, aliases,
   first_observed, last_observed)
VALUES
  (%(asset_id)s, %(asset_id)s, 'single_host', %(organization)s,
   %(kind)s, %(apex_domain)s, %(aliases)s, now(), now())
ON CONFLICT (asset_id) DO NOTHING
RETURNING asset_id;
"""

UPDATE_EXISTING_APEX = """
UPDATE public.assets
SET
  kind = %(kind)s,
  apex_domain = %(apex_domain)s,
  aliases = %(aliases)s
WHERE asset_id = %(asset_id)s;
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN"))
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the plan without writing anything (default).",
    )
    ap.add_argument(
        "--execute",
        action="store_true",
        help="Actually write the new asset rows. Without this flag, runs read-only.",
    )
    ap.add_argument(
        "--apex",
        default=None,
        help="Only process assets under this apex (e.g., 'unimacgraphics.com'). Default: all.",
    )
    args = ap.parse_args()

    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN required", file=sys.stderr)
        return 1

    write_mode = args.execute and not args.dry_run

    with psycopg.connect(args.dsn, autocommit=False) as conn:
        with conn.cursor() as cur:
            cur.execute(FETCH_EXISTING)
            rows = cur.fetchall()

        plans: dict[str, dict[str, dict]] = {}
        for asset_id, organization, surface_data in rows:
            apex = derive_apex(asset_id) or asset_id
            if args.apex and apex != args.apex.lower():
                continue
            plans[asset_id] = decompose_asset(asset_id, surface_data, organization)

        # Print the plan
        total_existing = len(plans)
        total_new = sum(
            sum(1 for k in p.keys() if k != root)
            for root, p in plans.items()
        )

        print(f"==========================================================")
        print(f"  ASSET DECOMPOSITION PLAN")
        print(f"==========================================================")
        print(f"  Mode: {'EXECUTE (will write)' if write_mode else 'DRY-RUN (read-only)'}")
        print(f"  Apex filter: {args.apex or '(all)'}")
        print(f"  Existing assets in scope: {total_existing}")
        print(f"  Proposed NEW asset rows:  {total_new}")
        print(f"  Proposed total after:     {total_existing + total_new}")
        print(f"==========================================================\n")

        for root, decomposed in sorted(plans.items()):
            if len(decomposed) == 1 and not decomposed[root]["aliases"]:
                continue  # nothing changes — single-asset apex with no aliases
            print(f"📦 {root}  (apex={decomposed[root]['apex_domain']})")
            for new_id, info in sorted(decomposed.items()):
                tag = "EXISTING" if new_id == root else "NEW"
                alias_str = (
                    f"  aliases={info['aliases']}" if info["aliases"] else ""
                )
                print(
                    f"   {tag:8s}  {new_id:55s}  "
                    f"kind={info['kind']:8s}  org={info['organization']}{alias_str}"
                )
            print()

        if not write_mode:
            print("DRY-RUN complete. Re-run with --execute to write the rows.")
            return 0

        # WRITE MODE — execute the plan
        print("EXECUTING…\n")
        written = 0
        updated = 0
        with conn.cursor() as cur:
            for root, decomposed in plans.items():
                # Update the existing apex row with its new kind + aliases
                if decomposed[root]["aliases"] or decomposed[root]["kind"] != "unknown":
                    cur.execute(
                        UPDATE_EXISTING_APEX,
                        {
                            "asset_id": root,
                            "kind": decomposed[root]["kind"],
                            "apex_domain": decomposed[root]["apex_domain"],
                            "aliases": decomposed[root]["aliases"],
                        },
                    )
                    updated += 1

                # Create new asset rows for every system that isn't the apex
                for new_id, info in decomposed.items():
                    if new_id == root:
                        continue
                    cur.execute(
                        INSERT_NEW_ASSET,
                        {
                            "asset_id": new_id,
                            "organization": info["organization"],
                            "kind": info["kind"],
                            "apex_domain": info["apex_domain"],
                            "aliases": info["aliases"],
                        },
                    )
                    if cur.fetchone():
                        written += 1
        conn.commit()
        print(f"DONE. {written} new asset row(s) created, {updated} existing row(s) updated.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
