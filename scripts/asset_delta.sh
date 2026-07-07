#!/usr/bin/env bash
# asset_delta.sh — ASM Verification Procedure V4: report asset deltas by NAME.
# Prints ADDED / REMOVED subdomain names between two revisions of an apex asset
# file. Run from inside the repo. Typo-safe wrapper around the comm/jq idiom so
# nobody hand-types it wrong at 2am.
#
# Usage:
#   scripts/asset_delta.sh <asset-json-path> <old_ref> [new_ref]
#     new_ref omitted => current working tree
# Examples:
#   scripts/asset_delta.sh data/assets/commandcommcentral.json 69fe347
#   scripts/asset_delta.sh data/assets/commandcommcentral.json b67620b origin/main
set -uo pipefail
f="${1:-}"; old="${2:-}"; new="${3:-}"
if [[ -z "$f" || -z "$old" ]]; then
  echo "usage: $0 <asset-json-path> <old_ref> [new_ref]   (new_ref omitted => working tree)" >&2
  exit 2
fi
names() { jq -r '.subdomains[]?.name // empty' 2>/dev/null | sort -u; }
old_t="$(mktemp)"; new_t="$(mktemp)"; trap 'rm -f "$old_t" "$new_t"' EXIT
if ! git show "$old:$f" 2>/dev/null | names > "$old_t"; then
  echo "error: cannot read '$f' at ref '$old'" >&2; exit 1
fi
if [[ -n "$new" ]]; then
  if ! git show "$new:$f" 2>/dev/null | names > "$new_t"; then
    echo "error: cannot read '$f' at ref '$new'" >&2; exit 1
  fi
  new_label="$new"
else
  [[ -f "$f" ]] || { echo "error: working-tree file not found: '$f'" >&2; exit 1; }
  names < "$f" > "$new_t"; new_label="(working tree)"
fi
added="$(comm -13 "$old_t" "$new_t")"; removed="$(comm -23 "$old_t" "$new_t")"
echo "# asset delta: $f"
echo "#   $old ($(wc -l <"$old_t"|tr -d ' ')) -> $new_label ($(wc -l <"$new_t"|tr -d ' '))"
echo "ADDED:";   [[ -n "$added"   ]] && echo "$added"   | sed 's/^/  + /' || echo "  (none)"
echo "REMOVED:"; [[ -n "$removed" ]] && echo "$removed" | sed 's/^/  - /' || echo "  (none)"
