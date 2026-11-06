#!/usr/bin/env python3
"""load_dns_history.py — job 5a push 2 (plan v3 E): load the DNS changes in this instance's own
saved discovery copies into asset_surface_event, ONCE.

Howie, 2026-11-05 13:30, asked whether to load the history since May: "Yes."

What it reads: only this repository's own git history of data/assets/<apex>.json (the copies
discovery has saved every run since May). Nothing is looked up, nothing is sent anywhere.

What it writes: one asset_surface_event row per change, with the same kinds, the same values and
the same fingerprint the live importer writes (surface_diff.dns_changes and dns_event_rows, the
code the replay gate checks), observed_at = the copy's own completed_at, source_tag
'dns_backfill', and new_value.loaded_from_history = {copy, completed_at}. The old copies' DNS
block was best-effort, so (surface_diff.legacy_readings) an empty set there is "not known": the
history can show a move, a CNAME, name-server, mail-server or mail-policy change, never a
removal, a "gone" or a "back".

Where the history ends: at the first copy of each apex that carries dns_readings (push-414's
first reading). From that copy on, the live importer compares readings itself, so the last pair
the history load writes is (the last copy before it, that copy). Nothing is written twice and
nothing falls between the two.

When it writes nothing:
  * a row with source_tag 'dns_backfill' already exists ("already loaded"): every run after
    a load stops here, after one query (a history with no change at all writes no row, so then
    each run reads it again and finds nothing again: harmless, and not the case on either
    instance);
  * the checkout is shallow (or not a git repository): the history needs every saved copy, and
    a shallow one would read as "no changes" (asm-discover.yml checks out with fetch-depth 0;
    a test pins it);
  * an enabled apex target in data/targets.yml has no copy with dns_readings yet ("waiting");
  * the cloud classifier cannot load (without it a rotating cloud name would read as hundreds
    of moves);
  * more than MAX_ROWS rows would be written (a sanity bound: the replay of every copy found
    18 changes on Command and 19 on Prodex);
  * --dry-run.
Everything is one transaction under an advisory lock: all the rows, or none.

Run by asm-discover.yml after the importer (continue-on-error), so the first discovery run after
the merge loads the history, and every later run stops at "already loaded".

Exit: 0 = loaded, already loaded, waiting, or dry run; 1 = refused or failed (nothing written).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import import_asm_to_surface as imp  # noqa: E402  (psycopg, Json, dns_asset_id, the classifier)
import surface_diff as sd  # noqa: E402

SOURCE_TAG = "dns_backfill"
LOCK_KEY = "dns_backfill_5a"
MAX_ROWS = 100
# Which record dates the old side of each kind of row (address: A and AAAA are read together).
RECORD_OF_EVENT = {"dns_address_changed": "a", "dns_cname_changed": "cname", "dns_ns_changed": "ns",
                   "dns_mx_changed": "mx", "dns_mail_policy_changed": "txt"}
REPO_ROOT = HERE.parents[1]

ALREADY_SQL = ("SELECT count(*), min(observed_at) FROM public.asset_surface_event "
               "WHERE source_tag = %s")
ASSET_IDS_SQL = "SELECT asset_id FROM public.assets"
INSERT_HISTORY_SQL = """
INSERT INTO public.asset_surface_event (
  asset_id, event_type, host, port, proto, service, tls,
  prev_value, new_value, source_tag, observed_at
) VALUES (
  %(asset_id)s, %(event_type)s, %(host)s, %(port)s, %(proto)s, %(service)s, %(tls)s,
  %(prev_value)s, %(new_value)s, %(source_tag)s, %(observed_at)s::timestamptz
);
"""


# ── reading the saved copies from git ──────────────────────────────────────────────────────────
def git_copies(repo: Path, rel_path: str):
    """Yields (commit, committed_at, blob or None) for every saved version of one copy, oldest
    first, ONE AT A TIME (an apex's history is hundreds of copies of up to ~0.7 MB each; they are
    never all held at once). A version that is not valid JSON (or a deletion) yields None."""
    import json
    import threading
    log = subprocess.run(["git", "-C", str(repo), "log", "--reverse", "--format=%H %cI", "--", rel_path],
                         capture_output=True, text=True, check=True).stdout.split("\n")
    revs = [ln.split(" ", 1) for ln in log if ln.strip()]
    if not revs:
        return
    p = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def feed():
        try:
            for h, _ in revs:
                p.stdin.write(f"{h}:{rel_path}\n".encode())
            p.stdin.close()
        except (BrokenPipeError, ValueError):
            pass
    t = threading.Thread(target=feed, daemon=True)
    t.start()
    try:
        for h, at in revs:
            header = p.stdout.readline().decode().split()
            if len(header) < 3 or header[1] != "blob":
                yield h, at, None
                continue
            raw = p.stdout.read(int(header[2]))
            p.stdout.read(1)                              # the newline after each object
            try:
                blob = json.loads(raw)
            except ValueError:
                blob = None
            yield h, at, blob if isinstance(blob, dict) else None
    finally:
        p.stdout.close()
        p.kill()
        p.wait()
        t.join(timeout=5)


def is_shallow(repo: Path) -> bool:
    """True unless git says plainly that this is a full (not shallow) repository: fails closed."""
    r = subprocess.run(["git", "-C", str(repo), "rev-parse", "--is-shallow-repository"],
                       capture_output=True, text=True)
    return r.returncode != 0 or r.stdout.strip() != "false"


def apex_targets(repo: Path) -> set[str]:
    """The ids of the enabled apex targets in data/targets.yml (the ones discovery reads now)."""
    import yaml
    doc = yaml.safe_load((repo / "data" / "targets.yml").read_text()) or {}
    return {str(t["id"]) for t in (doc.get("targets") or [])
            if isinstance(t, dict) and t.get("type") == "apex" and t.get("enabled", True) is not False}


# ── the history of one apex (PURE) ─────────────────────────────────────────────────────────────
def _copy_time(blob: dict, committed_at: str) -> str:
    return (blob.get("scan") or {}).get("completed_at") or committed_at


def _cloud_of(blob: dict, classify) -> dict:
    out = {}
    for s in blob.get("subdomains") or []:
        if isinstance(s, dict) and s.get("name"):
            c = classify(s) or {}
            out[str(s["name"]).strip().lower().rstrip(".")] = (bool(c.get("is_cloud_endpoint")),
                                                                 c.get("cloud_provider"))
    return out


def history_rows(copies, apex_asset_id: str, aliases, have, classify, source_tag: str = SOURCE_TAG) -> dict:
    """The rows for one apex's saved copies (oldest first), up to and including the first copy
    that carries dns_readings. PURE: no database, no network.

    Each copy's legacy readings against the last OBSERVED ones, record by record: an old copy's
    lookups were best-effort, so a record missing from a copy (empty, or the name absent) keeps
    its last observed value, as discovery's own readings keep the last good record when a lookup
    fails. Then the cloud view from each copy's own classification (carried the same way),
    surface_diff.dns_changes and dns_event_rows. Each row's old side is dated by when that record
    was really last observed (read_at; for a move also last_seen), never by a copy that did not
    show it (code review of push-415, must-fix 1); a move's old ports come from that same copy.

    Returns {rows, changes, skipped (names with no asset row), read, unreadable, ends_at}."""
    prev_r, prev_cloud = None, {}
    seen_at: dict[tuple, str] = {}           # (name, record type) -> when that record was last observed
    last_ports: dict[str, list] = {}         # name -> ports in the copy that last showed its addresses
    rows, changes, skipped = [], [], []
    read = unreadable = 0
    ends_at = None
    for commit, committed_at, blob in copies:
        if not isinstance(blob, dict):
            unreadable += 1
            continue
        read += 1
        at = _copy_time(blob, committed_at)
        cur = sd.legacy_readings(blob)
        cl = _cloud_of(blob, classify)
        ports_here = {str(k).strip().lower().rstrip("."): v for k, v in sd.ports_by_name(
            blob, {s.get("name") for s in (blob.get("subdomains") or []) if isinstance(s, dict)}).items()}
        if prev_r is not None:
            cloud = {n: {"old": prev_cloud.get(n, (False, None)),
                         "new": cl.get(n, prev_cloud.get(n, (False, None)))} for n in cur}
            found = sd.dns_changes(prev_r, cur, cloud, apex=apex_asset_id)
            if found:
                moved = sd.moved_names(found)
                ids = {c["name"]: imp.dns_asset_id(c["name"], apex_asset_id, aliases) for c in found}
                got = sd.dns_event_rows(
                    found, lambda n: ids[n] if ids[n] in have else None, source_tag,
                    ports_old={n: last_ports.get(n, []) for n in moved},
                    ports_new={n: ports_here.get(n, []) for n in moved},
                    old_seen_at=None, old_address_now=None,
                )
                for r in got:
                    r["prev_value"].pop("owned_address_now", None)   # "now" is not a historical fact
                    t = RECORD_OF_EVENT.get(r["event_type"])   # gone and back never come from old copies
                    if t:
                        r["prev_value"]["read_at"] = seen_at.get((r["host"], t))
                        if "last_seen" in r["prev_value"]:
                            r["prev_value"]["last_seen"] = seen_at.get((r["host"], t))
                    r["new_value"]["loaded_from_history"] = {"copy": commit, "completed_at": at}
                    r["observed_at"] = at
                rows.extend(got)
                changes.extend({"at": at, **c} for c in found)
                skipped.extend(sorted({c["name"] for c in found if ids[c["name"]] not in have}))
        merged = dict(prev_r or {})
        for n, r in cur.items():
            old = merged.get(n)
            recs = {**((old or {}).get("records") or {}), **r["records"]}
            owners = {**((old or {}).get("owners") or {}), **(r.get("owners") or {})}
            merged[n] = {**r, "records": recs, "owners": owners,
                         "name_status": "exists" if recs else "unknown"}
            for t in r["records"]:
                seen_at[(n, t)] = at
            if "a" in r["records"]:
                last_ports[n] = ports_here.get(n, [])
        prev_r = merged
        pc = dict(prev_cloud)
        pc.update(cl)
        prev_cloud = pc
        if "dns_readings" in blob:
            ends_at = commit
            break
    return {"rows": rows, "changes": changes, "skipped": sorted(set(skipped)), "read": read,
            "unreadable": unreadable, "ends_at": ends_at}


# ── the load ───────────────────────────────────────────────────────────────────────────────────
def plan_load(repo: Path, aliases_of, have, classify, data_dir: Path | None = None) -> dict:
    """Every apex file's history rows, or the reason to wait. PURE apart from reading git.

    `aliases_of(apex_asset_id) -> list`; `have`: the asset ids that exist now."""
    import json
    data_dir = data_dir or (repo / "data" / "assets")
    targets = apex_targets(repo)
    per_apex, waiting, rows = {}, [], []
    for f in sorted(data_dir.glob("*.json")):
        try:
            now = json.loads(f.read_text())
        except ValueError:
            continue
        if not isinstance(now, dict) or (now.get("asset") or {}).get("type") != "apex":
            continue                                    # IP targets: no names, no DNS
        apex = imp.derive_portal_asset_id(now)
        if not apex:
            continue
        res = history_rows(git_copies(repo, str(f.relative_to(repo))), apex, aliases_of(apex), have, classify)
        if f.stem in targets and res["ends_at"] is None:
            waiting.append(f.stem)                      # live coverage has not started: no gap allowed
            continue
        per_apex[f.stem] = {k: v for k, v in res.items() if k != "rows"}
        rows.extend(res["rows"])
    return {"rows": rows, "per_apex": per_apex, "waiting": waiting}


def run(conn, repo: Path, *, dry_run: bool = False, classify=None, out=print) -> int:
    """The whole load in ONE transaction. Returns the exit code."""
    if classify is None:
        if imp._classify_cloud is None or imp._CLOUD_REGISTRY is None:
            out("REFUSED: the cloud classifier did not load; without it a rotating cloud name "
                "would read as hundreds of moves. Nothing written.")
            return 1
        classify = lambda s: imp._classify_cloud(s, imp._CLOUD_REGISTRY)  # noqa: E731
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (LOCK_KEY,))
            cur.execute(ALREADY_SQL, (SOURCE_TAG,))
            n, first = cur.fetchone()
            if n:
                conn.rollback()
                out(f"already loaded: {n} history row(s) since {first}; nothing to do.")
                return 0
            if is_shallow(repo):
                conn.rollback()
                out("REFUSED: the checkout is shallow (or not a git repository); the history needs "
                    "every saved copy. Nothing written.")
                return 1
            cur.execute(ASSET_IDS_SQL)
            have = {r[0] for r in cur.fetchall()}
            plan = plan_load(repo, lambda a: imp.lookup_existing_aliases(conn, a), have, classify)
            if plan["waiting"]:
                conn.rollback()
                out("waiting: no copy with DNS readings yet for " + ", ".join(plan["waiting"])
                    + "; nothing written (the next run tries again).")
                return 0
            rows = plan["rows"]
            for apex, r in sorted(plan["per_apex"].items()):
                out(f"{apex}: {r['read']} copies read ({r['unreadable']} unreadable), "
                    f"{len(r['changes'])} change(s), history ends at {r['ends_at'] or 'the newest copy'}"
                    + (f"; no asset row for {', '.join(r['skipped'])}" if r["skipped"] else ""))
                for c in r["changes"]:
                    out(f"    {c['at']}  {c['name']}  {c['kind']}")
            if len(rows) > MAX_ROWS:
                conn.rollback()
                out(f"REFUSED: {len(rows)} rows is more than {MAX_ROWS}; nothing written.")
                return 1
            if not rows:
                conn.rollback()
                out("no changes in the history; nothing written (the next run looks again).")
                return 0
            if dry_run:
                conn.rollback()
                out(f"dry run: {len(rows)} row(s) would be written; nothing written.")
                return 0
            for r in rows:
                r["prev_value"] = imp.Json(r["prev_value"])
                r["new_value"] = imp.Json(r["new_value"])
            cur.executemany(INSERT_HISTORY_SQL, rows)
        conn.commit()
        out(f"loaded: {len(rows)} history row(s), source_tag {SOURCE_TAG}.")
        return 0
    except Exception as e:  # noqa: BLE001
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        out(f"FAILED (nothing written): {e}")
        return 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--repo", type=Path, default=REPO_ROOT)
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN"))
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if not a.dsn:
        print("SUPABASE_DSN not set; nothing done.")
        return 0
    with imp.psycopg.connect(a.dsn, autocommit=False) as conn:
        return run(conn, a.repo, dry_run=a.dry_run)


if __name__ == "__main__":
    sys.exit(main())
