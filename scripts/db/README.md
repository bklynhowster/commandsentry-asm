# COMMANDsentry — Phase 2 DB scripts

Postgres schema, importer, and verification queries for the canonical
COMMANDsentry data layer. Target: Supabase project `commandsentry`
(free tier during Phase 2 iteration; revisit Pro at Phase 3 SPA cutover).

## Files

- `schema.sql` — idempotent DDL: enums, tables, indexes, views, triggers.
- `reset.sql` — destructive drop-all; use during early iteration only.
- `import_jsonl.py` — one-shot `_normalized/*.jsonl` → Postgres importer.
  Idempotent (ON CONFLICT DO UPDATE) and supports `--truncate` for clean reloads.
- `checks/` — verification SQL that reproduces the throwaway-dashboard
  numbers from the DB. Compare against `run_normalize.py`'s console summary
  and against the `preview-dashboard.html` posture cards.

## Workflow

```bash
# One-time: create the Supabase project (manually in the dashboard, free tier).
# Project name: commandsentry
# Region: us-east-1
# DB password: store in 1Password under "Supabase — commandsentry"

# Export the DSN. Supabase → Project Settings → Database → Connection string (URI).
export SUPABASE_DSN='postgresql://postgres:PASSWORD@db.PROJECT_REF.supabase.co:5432/postgres'

# Apply schema (safe to re-run):
psql "$SUPABASE_DSN" -f scripts/db/schema.sql

# Import the canonical data:
python3 scripts/db/import_jsonl.py \
    --normalized "$HOME/Downloads/ISMS Procedures/Vulnerability Scanning/_normalized" \
    --dsn "$SUPABASE_DSN" \
    --truncate                  # only the first time; drop --truncate for incrementals

# Verify:
psql "$SUPABASE_DSN" -f scripts/db/checks/01_posture_counts.sql
psql "$SUPABASE_DSN" -f scripts/db/checks/02_ccc_mediums.sql
psql "$SUPABASE_DSN" -f scripts/db/checks/03_duplicate_finding_check.sql
```

## Dependencies

```bash
pip install --user 'psycopg[binary]'
```

## Phase 2 success criteria

The DB is "done" when these all hold:

1. `01_posture_counts.sql` matches the per-asset severity-by-status table at
   the bottom of `run_normalize.py`'s console output.
2. `02_ccc_mediums.sql` returns exactly 4 rows (M-01..M-04) for
   commandcommcentral.com — i.e. cross-source dedup survived the round trip.
3. `03_duplicate_finding_check.sql` returns zero rows.
4. Re-running `import_jsonl.py` without `--truncate` produces no new rows
   (idempotency).
