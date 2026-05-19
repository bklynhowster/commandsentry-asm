#!/usr/bin/env bash
# ============================================================================
# ingest-rescan.sh — one-command path from "I just ran a scan" to "Supabase
#                    reflects it, including closing things I confirmed fixed."
#
# What it does (in order):
#   1. Walker re-crawls ~/Downloads/ISMS Procedures/Vulnerability Scanning/
#      so any new scan-run dirs get picked up
#   2. Normalize re-runs against the manifest, refreshing JSONL output
#   3. Import to Supabase with --delta-close — anything the new scans saw
#      stays open; anything they didn't observe (and was previously open)
#      gets marked remediated. Posture + last_observed are recomputed.
#   4. Prints a posture diff (before vs after) so you can sanity-check the
#      result without opening the dashboard.
#
# Usage:
#   ./scripts/db/ingest-rescan.sh                 # process whatever's on disk
#   ./scripts/db/ingest-rescan.sh --dry-run       # show what would change, don't write
#   ./scripts/db/ingest-rescan.sh --no-walker     # skip walker re-crawl (faster)
#   ./scripts/db/ingest-rescan.sh --no-normalize  # skip normalize (faster, use existing JSONL)
#
# Prereqs:
#   - SUPABASE_DSN exported  (see Obsidian: 21 - Supabase Project Credentials)
#   - scripts/db/maintenance.sql has been applied at least once
#   - psycopg installed:  pip3 install --user --break-system-packages 'psycopg[binary]==3.3.4'
#
# Idempotent. Safe to re-run.
# ============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCAN_ROOT="${SCAN_ROOT:-$HOME/Downloads/ISMS Procedures/Vulnerability Scanning}"
NORMALIZED_DIR="${NORMALIZED_DIR:-$SCAN_ROOT/_normalized}"
WEB_DATA="${WEB_DATA:-$REPO_ROOT/web/data}"

DRY_RUN=0
SKIP_WALKER=0
SKIP_NORMALIZE=0

for arg in "$@"; do
  case "$arg" in
    --dry-run)      DRY_RUN=1 ;;
    --no-walker)    SKIP_WALKER=1 ;;
    --no-normalize) SKIP_NORMALIZE=1 ;;
    -h|--help)
      sed -n '2,/^set -uo/p' "$0" | sed -n '/^#/p' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

if [[ -z "${SUPABASE_DSN:-}" ]]; then
  echo "error: SUPABASE_DSN not exported." >&2
  echo "       See Obsidian: '21 - Supabase Project Credentials.md'" >&2
  exit 2
fi

cd "$REPO_ROOT"

echo "============================================================"
echo "  COMMANDsentry — Re-scan ingest"
echo "============================================================"
echo "  scan root:  $SCAN_ROOT"
echo "  normalized: $NORMALIZED_DIR"
echo "  dry run:    $([[ $DRY_RUN -eq 1 ]] && echo YES || echo no)"
echo

# ---------------------------------------------------------------------------
# Capture before-state for the diff
# ---------------------------------------------------------------------------
echo ">> [pre] Snapshotting posture..."
python3 - <<'PY' > /tmp/cs_posture_before.txt
import os, psycopg
with psycopg.connect(os.environ["SUPABASE_DSN"], autocommit=True) as conn:
    with conn.cursor() as cur:
        cur.execute("""
          SELECT
            COUNT(*) FILTER (WHERE severity='CRITICAL'),
            COUNT(*) FILTER (WHERE severity='HIGH'),
            COUNT(*) FILTER (WHERE severity='MODERATE-HIGH'),
            COUNT(*) FILTER (WHERE severity='MODERATE'),
            COUNT(*) FILTER (WHERE severity='LOW')
          FROM findings WHERE current_status IN ('detected','confirmed','open','regressed')
        """)
        r = cur.fetchone()
        print(f"CRIT {r[0]}  HIGH {r[1]}  MOD-HIGH {r[2]}  MOD {r[3]}  LOW {r[4]}")
        cur.execute("SELECT COUNT(*) FROM v_alerter_high_risk_assets")
        print(f"elevated assets: {cur.fetchone()[0]}")
PY
echo "  before: $(cat /tmp/cs_posture_before.txt | tr '\n' ' | ')"
echo

# ---------------------------------------------------------------------------
# 1. Walker
# ---------------------------------------------------------------------------
if [[ $SKIP_WALKER -eq 0 ]]; then
  echo ">> [1/3] walker.py — crawl scan dirs"
  mkdir -p "$NORMALIZED_DIR"
  python3 scripts/normalize/walker.py \
      --scan-root "$SCAN_ROOT" \
      --commandsentry-data "$WEB_DATA" \
      --output "$NORMALIZED_DIR" || { echo "walker failed" >&2; exit 1; }
  echo
else
  echo ">> [1/3] walker — SKIPPED"
  echo
fi

# ---------------------------------------------------------------------------
# 2. Normalize
# ---------------------------------------------------------------------------
if [[ $SKIP_NORMALIZE -eq 0 ]]; then
  echo ">> [2/3] run_normalize.py — refresh JSONL"
  python3 scripts/normalize/run_normalize.py \
      --manifest "$NORMALIZED_DIR/manifest.json" \
      --scan-root "$SCAN_ROOT" \
      --output "$NORMALIZED_DIR" || { echo "normalize failed" >&2; exit 1; }
  echo
else
  echo ">> [2/3] normalize — SKIPPED"
  echo
fi

# ---------------------------------------------------------------------------
# 3. Import with --delta-close
# ---------------------------------------------------------------------------
IMPORT_ARGS=(--normalized "$NORMALIZED_DIR" --dsn "$SUPABASE_DSN")
if [[ $DRY_RUN -eq 1 ]]; then
  echo ">> [3/3] import — DRY RUN (would call: --delta-close)"
  # We don't have a true dry-run on the importer; the best we can do is
  # skip step 3 entirely. Diff at the end will then show no change.
  echo "  (skipping actual import — re-run without --dry-run to apply)"
else
  echo ">> [3/3] import_jsonl.py --delta-close"
  IMPORT_ARGS+=(--delta-close)
  python3 scripts/db/import_jsonl.py "${IMPORT_ARGS[@]}" \
    || { echo "import failed" >&2; exit 1; }
fi
echo

# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------
echo ">> [post] Posture diff"
python3 - <<'PY'
import os, psycopg
before_line = open("/tmp/cs_posture_before.txt").read()
with psycopg.connect(os.environ["SUPABASE_DSN"], autocommit=True) as conn:
    with conn.cursor() as cur:
        cur.execute("""
          SELECT
            COUNT(*) FILTER (WHERE severity='CRITICAL'),
            COUNT(*) FILTER (WHERE severity='HIGH'),
            COUNT(*) FILTER (WHERE severity='MODERATE-HIGH'),
            COUNT(*) FILTER (WHERE severity='MODERATE'),
            COUNT(*) FILTER (WHERE severity='LOW')
          FROM findings WHERE current_status IN ('detected','confirmed','open','regressed')
        """)
        r = cur.fetchone()
        print(f"  before: {before_line.strip()}")
        print(f"  after:  CRIT {r[0]}  HIGH {r[1]}  MOD-HIGH {r[2]}  MOD {r[3]}  LOW {r[4]}")
        cur.execute("SELECT COUNT(*) FROM v_alerter_high_risk_assets")
        print(f"  elevated assets: {cur.fetchone()[0]}")
        # Recently changed findings
        cur.execute("""
          SELECT severity, current_status, COUNT(*)
            FROM findings
           WHERE updated_at > now() - interval '5 minutes'
           GROUP BY severity, current_status
           ORDER BY severity, current_status
        """)
        rows = cur.fetchall()
        if rows:
            print("\n  Findings touched in last 5 min:")
            for row in rows:
                print(f"    [{row[0]:<13}] {row[1]:<10} {row[2]}")
        else:
            print("\n  No findings touched. (Either nothing changed, or --dry-run was used.)")
PY

echo
echo "============================================================"
echo "  Done."
echo "============================================================"
