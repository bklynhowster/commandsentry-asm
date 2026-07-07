#!/usr/bin/env python3
"""
SUPPLEMENTARY TOOL (4.7 ruling D5, 2026-07-07). The ACTIVE V3 deploy gate is
commandsentry-portal/tests/column-guard.mjs (build-time, Netlify-blocking). This
script is for offline verification / an independent CI check — a green run here does
NOT substitute for the build-time gate.

check_column_parity.py — ASM Verification Procedure V3 (cross-instance column parity).

Mechanical, fail-closed assist for the HARD pre-deploy gate. Given the committed
per-instance schema snapshots, scan changed files for NEW column READS against DB
tables and verify each referenced column exists on EVERY instance DB. If a
referenced column is missing on any instance -> exit 1 (BLOCK). With --strict, a
read that cannot be parsed with confidence also blocks (fail-closed) rather than
silently pass — V3's whole point is to avoid the illusion of coverage.

Until schema snapshots are generated for BOTH instances (dump_schema_snapshot.py)
and this parser is validated against the portal's real query patterns, the ACTIVE
gate is the PR label `cross-instance-column-parity-confirmed` (see the portal
`column-parity-gate` workflow). This checker runs alongside as a fail-closed
advisory and is promoted to the sole gate once trusted.

Snapshot shape (from dump_schema_snapshot.py):
    {"instance": "command", "tables": {"assets": ["asset_id","kind",...], ...}}

Read surfaces detected:
  * Supabase JS/TS builder:  .from("table") ... .select("col_a, col_b, ...")
  * SQL:                     qualified refs  table.column

Usage:
    check_column_parity.py --snapshots A.json B.json --scan src/
    check_column_parity.py --snapshots A.json B.json -- FILE [FILE ...]
Exit: 0 clean | 1 missing (or strict+unverified) | 2 usage/snapshot error.
"""
import argparse, glob, json, os, re, sys

SUPA_FROM   = re.compile(r"""\.from\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]""")
SUPA_SELECT = re.compile(r"""\.select\(\s*(['"`])(.*?)\1""", re.S)
SQL_QUALIFIED = re.compile(r"""\b([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\b""")


def load_snapshot(path):
    with open(path) as fh:
        data = json.load(fh)
    inst = data.get("instance") or os.path.basename(path)
    tables = {t: set(cols) for t, cols in (data.get("tables") or {}).items()}
    return inst, tables


def parse_select_columns(select_str):
    """Bare column names in a Supabase .select() string. Drops '*', embedded
    relation blocks foo(...), aggregates, ::casts; resolves alias:real -> real."""
    depth, buf = 0, []
    for ch in select_str:               # strip embedded relation(...) blocks (joins)
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth = max(0, depth - 1)
        elif depth == 0:
            buf.append(ch)
    out = []
    for tok in "".join(buf).split(','):
        tok = tok.strip()
        if not tok or tok == '*':
            continue
        if ':' in tok:                  # Supabase alias syntax  alias:real
            tok = tok.split(':', 1)[1].strip()
        tok = tok.split('::', 1)[0].strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tok):
            out.append(tok)
    return out


def reads_from_text(path, text):
    if path.endswith(('.ts', '.tsx', '.js', '.jsx')):
        for m in SUPA_FROM.finditer(text):
            table = m.group(1)
            sm = SUPA_SELECT.search(text[m.end(): m.end() + 2000])  # nearest select in the chain
            if sm:
                for c in parse_select_columns(sm.group(2)):
                    yield table, c, 'portal.select'
    if path.endswith('.sql'):
        for m in SQL_QUALIFIED.finditer(text):
            yield m.group(1), m.group(2), 'sql.qualified'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--snapshots', nargs='+', required=True)
    ap.add_argument('--scan', help='directory to scan recursively')
    ap.add_argument('--strict', action='store_true',
                    help='fail-closed on unparseable / unknown-table reads')
    ap.add_argument('files', nargs='*')
    args = ap.parse_args()

    try:
        snaps = [load_snapshot(p) for p in args.snapshots]
    except Exception as e:  # noqa
        print(f"::error::cannot load snapshot: {e}", file=sys.stderr)
        return 2
    if not snaps:
        print("::error::no snapshots loaded", file=sys.stderr)
        return 2

    files = list(args.files)
    if args.scan:
        for ext in ('ts', 'tsx', 'js', 'jsx', 'sql'):
            files += glob.glob(os.path.join(args.scan, '**', f'*.{ext}'), recursive=True)
    files = sorted(set(files))
    if not files:
        print("no files to scan")
        return 0

    known_tables = set().union(*[t.keys() for _, t in snaps])
    missing, unverified = [], []
    for f in files:
        try:
            text = open(f, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        for table, col, kind in reads_from_text(f, text):
            if table not in known_tables:
                if kind == 'portal.select':          # a select on an untracked table = can't verify
                    unverified.append((table, col, f, 'table not in snapshots'))
                continue
            for inst, tables in snaps:
                cols = tables.get(table)
                if cols is None:
                    unverified.append((table, col, f, f'{inst}: table absent'))
                elif col not in cols:
                    missing.append((inst, table, col, f))

    missing = sorted(set(missing))
    unverified = sorted(set(unverified))
    if missing:
        print("::error::cross-instance column parity FAILED — missing columns:")
        for inst, table, col, f in missing:
            print(f"  MISSING  {inst}: {table}.{col}   (read in {f})")
        for t, c, f, why in unverified:
            print(f"  unverified  {t}.{c}  ({why}, {f})")
        return 1
    if args.strict and unverified:
        print("::error::strict mode — unverified reads block the gate (fail-closed):")
        for t, c, f, why in unverified:
            print(f"  UNVERIFIED  {t}.{c}  ({why}, {f})")
        return 1
    print(f"column parity OK — {len(files)} file(s) vs {len(snaps)} snapshot(s)")
    for t, c, f, why in unverified:
        print(f"  note: unverified {t}.{c} ({why})")
    return 0


if __name__ == '__main__':
    sys.exit(main())
