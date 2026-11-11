#!/usr/bin/env python3
"""Daily backstop: one heavy per authorized Prodex address without a recent full sweep.

Only existing owned, confirmed-live names are queued. Bare IPs are never inserted. Command
has no scope file and exits before reading a DSN or opening a database connection.
"""
from __future__ import annotations
import argparse
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prodex_full_ports as pf

MAX_PER_DAY = 5
ASSETS_SQL = "select asset_id::text, name from public.assets where ownership='owned' and discovery_status='confirmed_live' order by name;"
RECENT_SQL = """
select distinct a.name from public.assets a
join public.scan_run s on s.asset_id=a.asset_id
join public.scan_run_artifacts x on x.scan_run_id=s.scan_run_id
where a.ownership='owned' and a.discovery_status='confirmed_live'
  and s.intensity::text='heavy' and s.status::text in ('complete','degraded')
  and s.started_at > now() - interval '7 days' and x.tool_name='prodex_full_ports'
  and x.content_jsonb->>'proof_complete'='true';
"""
ACTIVE_SQL = """
select distinct a.name from public.assets a join public.scan_queue q on q.asset_id=a.asset_id
where q.intensity::text='heavy' and (q.status::text='queued'
  or (q.status::text='running' and q.started_at > now() - interval '8 hours'));
"""
ENQUEUE_SQL = """
insert into public.scan_queue (asset_id,intensity,authenticated,source,notes)
values (%(asset_id)s,'heavy',false,'workflow_dispatch',%(notes)s);
"""


def choose(assets, recent, active, *, scope, resolver, limit=MAX_PER_DAY) -> list[dict]:
    """Pure after DNS injection: group by current authorized address, then choose one name."""
    recent, active, by_address = set(recent), set(active), {}
    for row in assets:
        address = pf.authorized_address(row["name"], scope=scope, resolver=resolver)
        if address:
            by_address.setdefault(address, []).append(row)
    out = []
    for address in sorted(scope):
        names = by_address.get(address) or []
        if not names or any(r["name"] in recent for r in names):
            continue
        available = sorted((r for r in names if r["name"] not in active), key=lambda r: r["name"])
        if available:
            row = available[0]
            out.append({"asset_id": row["asset_id"], "name": row["name"], "address": address,
                        "notes": f"prodex_port_backstop: no successful full-port heavy on {address} in 7 days"})
        if len(out) >= limit:
            break
    return out


def run(conn, *, scope, resolver=pf.resolve_ipv4, dry_run=False, log=print) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(ASSETS_SQL)
        assets = [dict(r) for r in cur.fetchall()]
        cur.execute(RECENT_SQL)
        recent = {r[0] for r in cur.fetchall()}
        cur.execute(ACTIVE_SQL)
        active = {r[0] for r in cur.fetchall()}
    selected = choose(assets, recent, active, scope=scope, resolver=resolver)
    for row in selected:
        log(f"  {row['address']}: queue heavy for {row['name']}")
        if not dry_run:
            with conn.cursor() as cur:
                cur.execute(ENQUEUE_SQL, row)
    if dry_run:
        conn.rollback()
        log("DRY-RUN: nothing written")
    else:
        conn.commit()
    return selected


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    scope = pf.load_scope()
    if not scope:
        print("prodex_port_backstop: no authorized scope file; nothing to do")
        return 0
    dsn = os.environ.get("SUPABASE_DSN")
    if not dsn:
        print("SUPABASE_DSN not set", file=sys.stderr)
        return 2
    import psycopg
    from psycopg.rows import dict_row
    with psycopg.connect(dsn, row_factory=dict_row, autocommit=False) as conn:
        run(conn, scope=scope, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
