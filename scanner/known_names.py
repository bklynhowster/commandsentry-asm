#!/usr/bin/env python3
"""known_names.py — discovery's sixth source: every name Sentry already knows (job 5a, plan v3 A).

WHY (Howie 2026-11-05 07:29, on ns02.commandcommcentral.com dropping out of discovery on
Nov 3: "Why did we lose sight of it? That's ridiculous. There should be some type of fail-safe
where we recheck it."). Discovery's five sources are rebuilt from scratch every run; a known
name is looked up only if an outside source happens to list it again. This source hands every
name Sentry already holds for the apex back to the run, so it is looked up whether or not an
outside source lists it.

WHERE THE NAMES COME FROM (both read only):
  1. the previous saved copy of this target (data/assets/<id>.json): its subdomains, plus the
     names in its DNS readings that are not yet long gone (nx_streak below NX_CARRY_LIMIT, about
     a week of runs: after that the existing notice and demotion decide, not this list);
  2. the database, when SUPABASE_DSN is set: assets under this apex that are owned and once
     answered (confirmed_live or dns_only). Best-effort: any database trouble is a warning and
     source 1 still counts.
Only names under the apex are written. asm-discover.sh re-applies the same suffix filter.

Usage: python3 known_names.py --apex APEX --previous FILE --out FILE
"""
from __future__ import annotations

import argparse
import json
import os
import sys

NX_CARRY_LIMIT = 28   # runs; about 7 days at four runs a day

KNOWN_NAMES_SQL = """
SELECT asset_id FROM public.assets
 WHERE lower(apex_domain) = lower(%s)
   AND ownership = 'owned'
   AND discovery_status IN ('confirmed_live', 'dns_only')
"""


def _name(v) -> str:
    return (str(v or "")).strip().lower().rstrip(".")


def in_scope(name: str, apex: str) -> bool:
    n, a = _name(name), _name(apex)
    return bool(n) and bool(a) and (n == a or n.endswith("." + a))


def names_from_previous(prev: dict | None, apex: str) -> set[str]:
    """PURE. The names a previous saved copy knew, minus the long-gone ones."""
    out: set[str] = set()
    if not isinstance(prev, dict):
        return out
    for s in prev.get("subdomains") or []:
        if isinstance(s, dict) and in_scope(s.get("name"), apex):
            out.add(_name(s.get("name")))
    for n, r in (prev.get("dns_readings") or {}).items():
        if not in_scope(n, apex) or not isinstance(r, dict):
            continue
        if int(r.get("nx_streak") or 0) < NX_CARRY_LIMIT:
            out.add(_name(n))
    return out


def names_from_db(dsn: str, apex: str) -> set[str]:
    import psycopg  # lazy: the reader must work without a database driver
    with psycopg.connect(dsn, connect_timeout=10) as conn, conn.cursor() as cur:
        cur.execute(KNOWN_NAMES_SQL, (apex,))
        return {_name(r[0]) for r in cur.fetchall() if in_scope(r[0], apex)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="discovery's sixth source: names Sentry knows")
    ap.add_argument("--apex", required=True)
    ap.add_argument("--previous", default="")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    prev = None
    if a.previous and os.path.exists(a.previous):
        try:
            with open(a.previous, encoding="utf-8") as fh:
                prev = json.load(fh)
        except Exception as e:  # noqa: BLE001
            print(f"WARN: previous copy unreadable ({e}); using the database only", file=sys.stderr)
    names = names_from_previous(prev, a.apex)
    n_prev = len(names)
    dsn = os.environ.get("SUPABASE_DSN") or ""
    n_db = 0
    if dsn:
        try:
            got = names_from_db(dsn, a.apex)
            n_db = len(got)
            names |= got
        except Exception as e:  # noqa: BLE001
            print(f"WARN: known names from the database skipped ({type(e).__name__})", file=sys.stderr)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("".join(n + "\n" for n in sorted(names)))
    print(f"known names: {len(names)} (previous copy {n_prev}, database {n_db})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
