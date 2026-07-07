#!/usr/bin/env python3
"""
SUPPLEMENTARY TOOL (4.7 ruling D5, 2026-07-07). The ACTIVE V3 deploy gate is
commandsentry-portal/tests/column-guard.mjs (build-time, Netlify-blocking). This
snapshot generator supports the offline/independent-CI parity check only — not the
active gate.

dump_schema_snapshot.py — ASM Verification Procedure V3 helper.

Snapshot a Supabase/Postgres instance's public-schema columns to JSON so the
cross-instance column-parity gate (check_column_parity.py) can verify that any
new column READ exists on EVERY instance. Run this from the migration-APPLY job
(so the snapshot reflects what is actually deployed) — NOT from a PR.

Uses `psql` under the hood — no Python DB driver required.

Usage:
    dump_schema_snapshot.py --instance command \
        --dsn "$COMMAND_SUPABASE_DSN" \
        --out scripts/db/schema_snapshot.command.json
    # DSN may also come from env SUPABASE_DSN / DSN.
Exit: 0 ok | 2 error.
"""
import argparse, datetime, json, os, subprocess, sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--instance', required=True, help='e.g. command | prodex')
    ap.add_argument('--dsn', default=os.environ.get('SUPABASE_DSN') or os.environ.get('DSN'))
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    if not args.dsn:
        print("::error::no DSN (pass --dsn or set SUPABASE_DSN)", file=sys.stderr)
        return 2

    q = ("SELECT table_name || E'\\t' || column_name "
         "FROM information_schema.columns "
         "WHERE table_schema = 'public' ORDER BY 1, 2;")
    try:
        res = subprocess.run(["psql", args.dsn, "-At", "-c", q],
                             capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print("::error::psql not found on PATH", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as e:
        print(f"::error::psql failed: {e.stderr.strip()}", file=sys.stderr)
        return 2

    tables = {}
    for line in res.stdout.splitlines():
        if '\t' not in line:
            continue
        t, c = line.split('\t', 1)
        tables.setdefault(t, []).append(c)

    snap = {"instance": args.instance,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "tables": {t: sorted(cols) for t, cols in tables.items()}}
    with open(args.out, 'w') as fh:
        json.dump(snap, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {args.out}: {len(tables)} tables, "
          f"{sum(len(v) for v in tables.values())} columns")
    return 0


if __name__ == '__main__':
    sys.exit(main())
