#!/usr/bin/env bash
# COMMANDsentry — sync asset JSON into web/data/ for the dashboard
# ─────────────────────────────────────────────────────────────────
# Copies data/assets/*.json into web/data/ and writes _manifest.json.
# Both local dev (python -m http.server) and Netlify build can call this.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SRC_DIR="$REPO_ROOT/data/assets"
DST_DIR="$SCRIPT_DIR/data"

mkdir -p "$DST_DIR"

# Wipe stale files (don't delete the directory itself)
find "$DST_DIR" -maxdepth 1 -type f -name '*.json' -delete

# Find candidates: prefer real assets; fall back to .example if no real data exists
shopt -s nullglob
real_files=("$SRC_DIR"/*.json)
example_files=("$SRC_DIR"/*.example.json)
shopt -u nullglob

# Filter out example files from real_files
filtered_real=()
for f in "${real_files[@]:-}"; do
  [[ "$f" == *.example.json ]] && continue
  filtered_real+=("$f")
done

if [[ ${#filtered_real[@]} -gt 0 ]]; then
  echo "Syncing ${#filtered_real[@]} real asset file(s) to $DST_DIR"
  for f in "${filtered_real[@]}"; do
    name="$(basename "$f")"
    cp "$f" "$DST_DIR/$name"
  done
elif [[ ${#example_files[@]} -gt 0 ]]; then
  echo "No real asset data yet — seeding dashboard with example file(s)"
  for f in "${example_files[@]}"; do
    name="$(basename "$f" .example.json).json"
    cp "$f" "$DST_DIR/$name"
  done
else
  echo "WARN: No asset JSON in $SRC_DIR — dashboard will load empty"
fi

# Build manifest: list of asset IDs (= filenames sans .json)
ids=()
shopt -s nullglob
for f in "$DST_DIR"/*.json; do
  bn="$(basename "$f" .json)"
  [[ "$bn" == "_manifest" ]] && continue
  ids+=("$bn")
done
shopt -u nullglob

# Write manifest as JSON
{
  printf '{\n  "generated_at": "%s",\n  "assets": [' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for i in "${!ids[@]}"; do
    [[ $i -gt 0 ]] && printf ", "
    printf '"%s"' "${ids[$i]}"
  done
  printf ']\n}\n'
} > "$DST_DIR/_manifest.json"

echo "Wrote $DST_DIR/_manifest.json — ${#ids[@]} asset(s)"
echo ""
echo "Serve dashboard locally:"
echo "  cd $SCRIPT_DIR && python3 -m http.server 8000"
echo "  open http://localhost:8000"
