#!/usr/bin/env python3
"""
COMMANDsentry — backfill service history from git
──────────────────────────────────────────────────

One-time script. Walks the git log of each `data/assets/<id>.json`,
replays every historical commit, extracts (ip, port) tuples from each
historical scan, and rebuilds the asset's `history` array with the new
`ports_by_host` field populated for every entry.

After running this, dashboards see the timeline / change-log / flap
detection populated retroactively instead of needing to wait 30 days
for natural accrual.

Idempotent. Safe to re-run. Limits to the last 120 entries to match
the retention cap in normalize.py.

Usage:
    python3 scanner/backfill-service-history.py

Then `git add data/assets/*.json web/data/*.json` and commit.
"""

from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT  = Path(__file__).resolve().parent.parent
ASSETS_DIR = REPO_ROOT / "data" / "assets"
WEB_DIR    = REPO_ROOT / "web"  / "data"
RETENTION  = 120

def git(args: list[str]) -> str:
    """Run a git command, return stdout. Empty string on failure."""
    try:
        out = subprocess.run(
            ["git"] + args,
            cwd=REPO_ROOT, check=True, capture_output=True, text=True,
        )
        return out.stdout
    except subprocess.CalledProcessError:
        return ""

def commits_touching(file_path: Path) -> list[str]:
    """SHAs of every commit that modified this file, oldest first."""
    rel = file_path.relative_to(REPO_ROOT)
    out = git(["log", "--reverse", "--pretty=format:%H", "--", str(rel)])
    return [line.strip() for line in out.splitlines() if line.strip()]

def file_at_commit(sha: str, file_path: Path) -> dict | None:
    """Return the parsed JSON content of file at given commit, or None if missing/invalid."""
    rel = file_path.relative_to(REPO_ROOT)
    out = git(["show", f"{sha}:{rel}"])
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None

def ports_by_host_from_record(record: dict) -> dict[str, list[int]]:
    """Walk subdomains[].services[] and group ports by IP."""
    out: dict[str, list[int]] = {}
    for sub in record.get("subdomains", []) or []:
        for svc in sub.get("services", []) or []:
            ip = svc.get("ip")
            port = svc.get("port")
            if not ip or not isinstance(port, int):
                continue
            out.setdefault(ip, [])
            if port not in out[ip]:
                out[ip].append(port)
    for ip in out:
        out[ip].sort()
    return out

def history_entry_from_record(record: dict) -> dict | None:
    """Reconstruct one history-array entry from a historical asset JSON."""
    scan = record.get("scan") or {}
    summary = record.get("summary") or {}
    scan_id = scan.get("id")
    if not scan_id:
        return None
    return {
        "scan_id":              scan_id,
        "started_at":           scan.get("started_at"),
        "completed_at":         scan.get("completed_at"),
        "subdomain_count":      summary.get("subdomain_count", 0),
        "live_subdomain_count": summary.get("live_subdomain_count", 0),
        "host_count":           summary.get("host_count", 0),
        "service_count":        summary.get("service_count", 0),
        "ports_by_host":        ports_by_host_from_record(record),
    }

def backfill_asset(asset_path: Path) -> tuple[int, str]:
    """Returns (new_history_length, status_message)."""
    if not asset_path.exists():
        return 0, "file does not exist"
    current = json.loads(asset_path.read_text())
    if current.get("schema_version") != "3.0":
        return 0, f"skipped (schema {current.get('schema_version')})"

    shas = commits_touching(asset_path)
    if not shas:
        return 0, "no git history found"

    # Replay every historical commit, collecting unique scan_ids in order.
    seen_scan_ids: set[str] = set()
    rebuilt: list[dict] = []
    for sha in shas:
        record = file_at_commit(sha, asset_path)
        if not record or record.get("schema_version") != "3.0":
            continue
        entry = history_entry_from_record(record)
        if not entry:
            continue
        if entry["scan_id"] in seen_scan_ids:
            continue
        seen_scan_ids.add(entry["scan_id"])
        rebuilt.append(entry)

    # Also include the CURRENT in-memory scan (most recent)
    current_entry = history_entry_from_record(current)
    if current_entry and current_entry["scan_id"] not in seen_scan_ids:
        rebuilt.append(current_entry)

    # Apply retention cap
    rebuilt = rebuilt[-RETENTION:]

    # Write back to the asset JSON
    current["history"] = rebuilt
    asset_path.write_text(json.dumps(current, indent=2) + "\n")

    # Also mirror into web/data/ if that file exists (dashboard reads from there)
    mirror = WEB_DIR / asset_path.name
    if mirror.exists():
        try:
            mirror_content = json.loads(mirror.read_text())
            if mirror_content.get("schema_version") == "3.0":
                mirror_content["history"] = rebuilt
                mirror.write_text(json.dumps(mirror_content, indent=2) + "\n")
        except Exception as e:
            print(f"  warning: failed to update mirror {mirror.name}: {e}", file=sys.stderr)

    return len(rebuilt), "ok"

def main():
    if not ASSETS_DIR.exists():
        print(f"data/assets/ not found at {ASSETS_DIR}", file=sys.stderr)
        sys.exit(1)

    asset_files = sorted(ASSETS_DIR.glob("*.json"))
    if not asset_files:
        print("no asset files to process")
        return

    print(f"Backfilling service history from git for {len(asset_files)} asset(s)…")
    print(f"Retention cap: {RETENTION} entries per asset (~30 days at 6h cadence)")
    print()

    total_entries = 0
    for path in asset_files:
        if path.name.endswith(".example.json"):
            continue
        count, status = backfill_asset(path)
        total_entries += count
        print(f"  {path.stem:35s}  {count:3d} entries  ({status})")

    print()
    print(f"Done. {total_entries} total history entries across {len(asset_files)} assets.")
    print("Next: git add data/assets/*.json web/data/*.json && git commit && git push")

if __name__ == "__main__":
    main()
