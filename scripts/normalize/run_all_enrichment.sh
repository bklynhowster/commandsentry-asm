#!/usr/bin/env bash
# ============================================================================
# run_all_enrichment.sh — chains all four post-ingest enrichment scripts:
#
#   1. synthesize_finding_descriptions.py  — AI prose + structured extractions
#   2. scan_artifact_walker.py             — Path C, on-disk scanner artifacts
#   3. asset_tech_profile_populator.py     — tech_profile JSONB + change history
#   4. cve_enricher.py                     — NVD + EPSS + CISA KEV per CVE
#
# Every script is idempotent and non-destructive: running them twice in a
# row on unchanged data is a no-op. They're safe to invoke on every scan
# ingest, on a cron, or manually.
#
# Called from:
#   · scripts/db/ingest-rescan.sh   (auto, after every scan import)
#   · launchd nightly cron          (belt-and-suspenders)
#   · manually                      (whenever you want)
#
# Flags:
#   --skip-synth         skip step 1 (synthesis is the slowest + most expensive)
#   --skip-walker        skip step 2
#   --skip-populator     skip step 3
#   --skip-cve           skip step 4 (slowest — NVD rate-limits to 1/6.5s)
#   --severity-only X    pass severity filter to synth (e.g. "CRITICAL HIGH")
#   --log-file PATH      append a one-line summary to this file (for cron)
#
# Exit code: 0 if all enabled steps succeeded, non-zero otherwise.
# ============================================================================

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENV_PYTHON="${VENV_PYTHON:-$REPO_ROOT/.venv/bin/python}"

SKIP_SYNTH=0
SKIP_WALKER=0
SKIP_POPULATOR=0
SKIP_CVE=0
SEVERITY_FILTER=""
LOG_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-synth)     SKIP_SYNTH=1;     shift ;;
    --skip-walker)    SKIP_WALKER=1;    shift ;;
    --skip-populator) SKIP_POPULATOR=1; shift ;;
    --skip-cve)       SKIP_CVE=1;       shift ;;
    --severity-only)  SEVERITY_FILTER="$2"; shift 2 ;;
    --log-file)       LOG_FILE="$2";    shift 2 ;;
    -h|--help)
      sed -n '2,/^set -uo/p' "$0" | sed -n '/^#/p' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Make sure the venv exists — we depend on supabase + anthropic installed there.
if [[ ! -x "$VENV_PYTHON" ]]; then
  echo "error: venv python not found at $VENV_PYTHON" >&2
  echo "       Set VENV_PYTHON env var or create the venv:" >&2
  echo "         cd $REPO_ROOT && python3 -m venv .venv && source .venv/bin/activate && pip install anthropic supabase python-dotenv" >&2
  exit 2
fi

cd "$REPO_ROOT"

# Timestamp helper so log lines line up across long runs.
ts() { date '+%Y-%m-%d %H:%M:%S'; }

# Track results so we can print a summary at the end.
declare -A STATUS
STATUS[synth]="-"
STATUS[walker]="-"
STATUS[populator]="-"
STATUS[cve]="-"

declare -i overall=0

echo "============================================================"
echo "  COMMANDsentry — Post-ingest enrichment chain"
echo "  $(ts)"
echo "============================================================"
echo

# ---------------------------------------------------------------------------
# 1. AI synthesis
# ---------------------------------------------------------------------------
if [[ $SKIP_SYNTH -eq 0 ]]; then
  echo ">> [1/4] $(ts)  synthesize_finding_descriptions.py"
  SYNTH_ARGS=(--limit 200)
  if [[ -n "$SEVERITY_FILTER" ]]; then
    SYNTH_ARGS+=(--severity $SEVERITY_FILTER)
  fi
  if "$VENV_PYTHON" scripts/backfill/synthesize_finding_descriptions.py "${SYNTH_ARGS[@]}"; then
    STATUS[synth]="ok"
  else
    STATUS[synth]="FAILED"
    overall=1
    echo "  ! synth failed — continuing with remaining steps"
  fi
  echo
else
  echo ">> [1/4] synth — SKIPPED"; echo
  STATUS[synth]="skipped"
fi

# ---------------------------------------------------------------------------
# 2. Scan artifact walker
# ---------------------------------------------------------------------------
if [[ $SKIP_WALKER -eq 0 ]]; then
  echo ">> [2/4] $(ts)  scan_artifact_walker.py"
  if "$VENV_PYTHON" scripts/normalize/scan_artifact_walker.py; then
    STATUS[walker]="ok"
  else
    STATUS[walker]="FAILED"
    overall=1
    echo "  ! walker failed — continuing with remaining steps"
  fi
  echo
else
  echo ">> [2/4] walker — SKIPPED"; echo
  STATUS[walker]="skipped"
fi

# ---------------------------------------------------------------------------
# 3. Asset tech profile populator
# ---------------------------------------------------------------------------
if [[ $SKIP_POPULATOR -eq 0 ]]; then
  echo ">> [3/4] $(ts)  asset_tech_profile_populator.py"
  if "$VENV_PYTHON" scripts/normalize/asset_tech_profile_populator.py; then
    STATUS[populator]="ok"
  else
    STATUS[populator]="FAILED"
    overall=1
    echo "  ! populator failed — continuing with remaining steps"
  fi
  echo
else
  echo ">> [3/4] populator — SKIPPED"; echo
  STATUS[populator]="skipped"
fi

# ---------------------------------------------------------------------------
# 4. CVE enricher (NVD/EPSS/KEV)
# ---------------------------------------------------------------------------
if [[ $SKIP_CVE -eq 0 ]]; then
  echo ">> [4/4] $(ts)  cve_enricher.py"
  if "$VENV_PYTHON" scripts/normalize/cve_enricher.py; then
    STATUS[cve]="ok"
  else
    STATUS[cve]="FAILED"
    overall=1
    echo "  ! cve_enricher failed — continuing"
  fi
  echo
else
  echo ">> [4/4] cve_enricher — SKIPPED"; echo
  STATUS[cve]="skipped"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "============================================================"
echo "  Summary  ($(ts))"
echo "============================================================"
printf "  synth:     %s\n" "${STATUS[synth]}"
printf "  walker:    %s\n" "${STATUS[walker]}"
printf "  populator: %s\n" "${STATUS[populator]}"
printf "  cve:       %s\n" "${STATUS[cve]}"
echo

if [[ -n "$LOG_FILE" ]]; then
  mkdir -p "$(dirname "$LOG_FILE")"
  printf "%s  synth=%s  walker=%s  populator=%s  cve=%s  overall=%s\n" \
    "$(ts)" "${STATUS[synth]}" "${STATUS[walker]}" "${STATUS[populator]}" "${STATUS[cve]}" \
    "$([[ $overall -eq 0 ]] && echo ok || echo FAILED)" \
    >> "$LOG_FILE"
fi

exit $overall
