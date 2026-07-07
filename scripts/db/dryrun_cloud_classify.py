#!/usr/bin/env python3
"""
dryrun_cloud_classify.py — READ-ONLY dry-run of the cloud-endpoint classifier
against the live DB (4.7: "dry-run over the whole fleet before it writes a byte").

Classifies every subdomain in data/assets/*.json, reads the CURRENT
assets.cloud_* fields, and prints what the importer (import_asm_to_surface.py)
WOULD do to each row — STAMP / sticky-preserve(manual) / DRIFT — WITHOUT WRITING.

    export SUPABASE_DSN=...        # or COMMAND_SUPABASE_DSN
    python3 scripts/db/dryrun_cloud_classify.py
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "normalize"))
from derive_cloud_endpoint import classify, load_registry  # noqa: E402

try:
    import psycopg
except ImportError:
    sys.exit("psycopg required (run in the scanner env).")

DSN = os.environ.get("SUPABASE_DSN") or os.environ.get("COMMAND_SUPABASE_DSN")
if not DSN:
    sys.exit("set SUPABASE_DSN (or COMMAND_SUPABASE_DSN)")

REG = load_registry()
ROOT = Path(__file__).resolve().parent.parent.parent
ASSETS = ROOT / "data" / "assets"

# 1. Derived classification per subdomain name (what the classifier says now)
derived: dict[str, tuple[bool, str | None]] = {}
for f in sorted(ASSETS.glob("*.json")):
    try:
        d = json.loads(f.read_text())
    except Exception:
        continue
    for s in (d.get("subdomains") or []):
        n = s.get("name")
        if not n:
            continue
        r = classify(s, REG)
        derived[n] = (bool(r["is_cloud_endpoint"]), r["cloud_provider"]) if r else (False, None)

# 2. Current DB state (read-only)
print(f"classified {len(derived)} subdomains locally; connecting to DB (10s timeout)...", flush=True)
with psycopg.connect(DSN, connect_timeout=10) as conn, conn.cursor() as cur:
    cur.execute("SELECT name, is_cloud_endpoint, cloud_provider, cloud_source FROM public.assets")
    cur_state = {row[0]: (row[1], row[2], row[3]) for row in cur.fetchall()}
print(f"read {len(cur_state)} asset rows from DB.\n", flush=True)

# 3. Diff
stamp = sticky = drift = nochange = no_row = 0
print(f"{'ASSET':44s} {'CURRENT':24s} {'DERIVED':22s} ACTION")
for name in sorted(derived):
    dcloud, dprov = derived[name]
    row = cur_state.get(name)
    if row is None:
        no_row += 1
        continue
    ccloud, cprov, csource = row
    disagree = (bool(ccloud) != dcloud) or ((cprov or None) != (dprov or None))
    cur_s = f"{cprov or '-'}/{ccloud} [{csource}]"
    der_s = f"{dprov or '-'}/{dcloud}"
    if csource == "manual":
        action = "DRIFT (manual kept + audit)" if disagree else "sticky-preserve (manual==derived)"
        drift += disagree
        sticky += (not disagree)
    else:
        action = "STAMP" if disagree else "no-change"
        stamp += disagree
        nochange += (not disagree)
    if action not in ("no-change",):
        print(f"{name:44s} {cur_s:24s} {der_s:22s} {action}")

print(f"\nSTAMP={stamp}  sticky-preserve={sticky}  DRIFT={drift}  "
      f"no-change={nochange}  (no-assets-row={no_row})")
print("READ-ONLY — no writes performed.")
