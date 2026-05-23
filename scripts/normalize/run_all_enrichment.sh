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
# Default severity filter — only synthesize the meaningful-severity findings.
# Most thin findings in the DB are testssl INFO/LOW entries that don't need
# AI synth at all. Override with --severity-only or pass --severity-only ""
# (literal empty) to run on every severity.
SEVERITY_FILTER="CRITICAL HIGH MODERATE-HIGH MODERATE"
SYNTH_LIMIT=100
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

# Track results so we can print a summary at the end. Plain variables
# rather than associative array — macOS ships bash 3.2 which lacks
# 'declare -A', and we want to work without a Homebrew bash dependency.
STATUS_SYNTH="-"
STATUS_WALKER="-"
STATUS_POPULATOR="-"
STATUS_CVE="-"
overall=0

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
  SYNTH_ARGS=(--limit "$SYNTH_LIMIT")
  if [[ -n "$SEVERITY_FILTER" ]]; then
    # shellcheck disable=SC2086
    SYNTH_ARGS+=(--severity $SEVERITY_FILTER)
    echo "    (severity filter: $SEVERITY_FILTER · limit: $SYNTH_LIMIT)"
  else
    echo "    (no severity filter · limit: $SYNTH_LIMIT)"
  fi
  if "$VENV_PYTHON" scripts/backfill/synthesize_finding_descriptions.py "${SYNTH_ARGS[@]}"; then
    STATUS_SYNTH="ok"
  else
    STATUS_SYNTH="FAILED"
    overall=1
    echo "  ! synth failed — continuing with remaining steps"
  fi
  echo
else
  echo ">> [1/4] synth — SKIPPED"; echo
  STATUS_SYNTH="skipped"
fi

# ---------------------------------------------------------------------------
# 2. Scan artifact walker
# ---------------------------------------------------------------------------
if [[ $SKIP_WALKER -eq 0 ]]; then
  echo ">> [2/4] $(ts)  scan_artifact_walker.py"
  if "$VENV_PYTHON" scripts/normalize/scan_artifact_walker.py; then
    STATUS_WALKER="ok"
  else
    STATUS_WALKER="FAILED"
    overall=1
    echo "  ! walker failed — continuing with remaining steps"
  fi
  echo
else
  echo ">> [2/4] walker — SKIPPED"; echo
  STATUS_WALKER="skipped"
fi

# ---------------------------------------------------------------------------
# 3. Asset tech profile populator
# ---------------------------------------------------------------------------
if [[ $SKIP_POPULATOR -eq 0 ]]; then
  echo ">> [3/4] $(ts)  asset_tech_profile_populator.py"
  if "$VENV_PYTHON" scripts/normalize/asset_tech_profile_populator.py; then
    STATUS_POPULATOR="ok"
  else
    STATUS_POPULATOR="FAILED"
    overall=1
    echo "  ! populator failed — continuing with remaining steps"
  fi
  echo
else
  echo ">> [3/4] populator — SKIPPED"; echo
  STATUS_POPULATOR="skipped"
fi

# ---------------------------------------------------------------------------
# 4. CVE enricher (NVD/EPSS/KEV)
# ---------------------------------------------------------------------------
if [[ $SKIP_CVE -eq 0 ]]; then
  echo ">> [4/4] $(ts)  cve_enricher.py"
  if "$VENV_PYTHON" scripts/normalize/cve_enricher.py; then
    STATUS_CVE="ok"
  else
    STATUS_CVE="FAILED"
    overall=1
    echo "  ! cve_enricher failed — continuing"
  fi
  echo
else
  echo ">> [4/4] cve_enricher — SKIPPED"; echo
  STATUS_CVE="skipped"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "============================================================"
echo "  Summary  ($(ts))"
echo "============================================================"
printf "  synth:     %s\n" "$STATUS_SYNTH"
printf "  walker:    %s\n" "$STATUS_WALKER"
printf "  populator: %s\n" "$STATUS_POPULATOR"
printf "  cve:       %s\n" "$STATUS_CVE"
echo

if [[ -n "$LOG_FILE" ]]; then
  mkdir -p "$(dirname "$LOG_FILE")"
  if [[ $overall -eq 0 ]]; then OVERALL_TXT="ok"; else OVERALL_TXT="FAILED"; fi
  printf "%s  synth=%s  walker=%s  populator=%s  cve=%s  overall=%s\n" \
    "$(ts)" "$STATUS_SYNTH" "$STATUS_WALKER" "$STATUS_POPULATOR" "$STATUS_CVE" \
    "$OVERALL_TXT" \
    >> "$LOG_FILE"
fi

exit $overall
