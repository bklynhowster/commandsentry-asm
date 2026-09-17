#!/usr/bin/env python3
"""Backfill the `stack_id_wafw00f` artifacts that heavy runs threw away.

Relay 216/217/220. DRY-RUN BY DEFAULT — `--write` is Howie's, after 4.7 reads the plan.

    set -a && . ./.env && set +a && python3 scripts/db/backfill_stack_id_wafw00f.py          # plan
    set -a && . ./.env && set +a && python3 scripts/db/backfill_stack_id_wafw00f.py --write  # Howie

⚠ `set -a` IS REQUIRED, and `. ./.env` ALONE IS NOT ENOUGH. The .env file is bare
`KEY=value` lines with no `export`, so sourcing it in zsh creates SHELL variables,
not ENVIRONMENT variables — `os.environ.get("SUPABASE_URL")` sees nothing and the
script exits telling you to source the file you just sourced. `set -a` marks
everything assigned until `set +a` for export. (Command's run on 2026-09-16 hit
exactly this; the usage line above is what it should have said.)

⛔ WHY THERE IS ANYTHING TO BACKFILL. `phase_registry` registers the FUNCTION
`_medium.detect_waf`, which parses wafw00f and writes the RAW artifact. The
structured verdict — the only form `gather_observations` reads — was written by a
separate call in run_medium.run()'s linear body. When the heavy cutover
(b51ef0c1 / 16d778e9, 2026-08-29) began dispatching phases through `run_phases`,
heavy inherited the parse and not the persist:

    heavy runs with raw `wafw00f` and no `stack_id_wafw00f`     18 of 18
    medium runs with both                                       22 of 22

The verdicts were never lost — they are still in the raw text. This reparses them.
The fold (relay 217) stops the bleeding; this recovers what already bled.

⛔ TRANSPORT: PostgREST, NOT psycopg (4.7, relay 220). The psycopg version wanted
`SUPABASE_DSN` — a password-bearing string Howie would have to copy out of the
Supabase Connect dialog, and rotating the DB password to get one would break every
workflow using the `SUPABASE_DSN` GitHub secret. `.env` already carries
`SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY`, the same credential the enrich worker
uses. One sourced command, nothing copied.

⚠ KEYSET PAGINATION, not offset/limit. The enrich worker was BLIND for weeks
because `max_rows=1000` silently clamped a `.limit(5000)` — a truncated read that
looks exactly like a small result set. Every read here pages on `artifact_id` and
stops ONLY on an empty page — never on a short one, because PostgREST enforces its
own `max_rows` and a server capping below our page size makes every page "short".

⛔ THE PARSE IS IMPORTED, NEVER RE-IMPLEMENTED. A second copy of the regexes would
be a third home for this defect class — the reason 4.7's ruling was FOLD rather
than register-a-pair. This runs `run_medium._classify_wafw00f_output` against a
duck-typed ctx, exactly as a live scan does.

⚠ WHAT IT WILL NOT DO
  * Never overwrites: a run that already has a `stack_id_wafw00f` is skipped.
  * Never invents: an absent or unparseable raw is REPORTED and skipped, not
    defaulted to "no WAF found". Absent and negative are different facts, and
    conflating them is the defect family this whole thread is about.
  * Never touches `assets`. The classifier re-derives on its next pass.

⚠ WHAT IT CANNOT FIX. `gather_observations` filters on the SCAN's `completed_at`,
not the artifact's `created_at`, so a backfilled verdict only re-enters the
classifier if its scan is inside the 30-day window. commandcommcentral.com (13d)
comes back; the three hosts whose last capable scan was 54-56d ago do not. Those
need a scan, not a backfill — stated so nobody reads a clean run here as a fix for
them.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import types
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "scanner"))

import httpx  # noqa: E402
import run_medium as _medium  # noqa: E402  — the parse lives THERE, not here

PAGE = 1000


class Rest:
    """Minimal PostgREST client. Separate class so the tests can swap it."""

    def __init__(self, url: str, key: str, timeout: float = 60.0):
        self.base = url.rstrip("/") + "/rest/v1"
        self.h = {"apikey": key, "Authorization": f"Bearer {key}"}
        self.timeout = timeout

    def page(self, path: str, after: str | None, order_col: str = "artifact_id") -> list:
        q = f"{self.base}/{path}&order={order_col}.asc&limit={PAGE}"
        if after:
            q += f"&{order_col}=gt.{after}"
        r = httpx.get(q, headers=self.h, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def patch(self, path: str, body: dict) -> None:
        r = httpx.patch(f"{self.base}/{path}", headers={**self.h,
                        "Content-Type": "application/json",
                        "Prefer": "return=minimal"},
                        json=body, timeout=self.timeout)
        r.raise_for_status()

    def insert(self, path: str, rows: list) -> None:
        r = httpx.post(f"{self.base}/{path}", headers={**self.h,
                       "Content-Type": "application/json",
                       "Prefer": "return=minimal"},
                       json=rows, timeout=self.timeout)
        r.raise_for_status()


def paginate(rest: Rest, path: str, order_col: str = "artifact_id"):
    """Keyset-paginate until a SHORT page arrives.

    ⚠ TERMINATES ONLY ON AN EMPTY PAGE — never on `len(rows) < PAGE`.

    The short-page test is what the enrich worker's clamp defeated, and my first
    draft of this function reproduced it: PostgREST enforces its OWN `max_rows`,
    so if the server caps below the size we ask for, EVERY page comes back
    "short" and the loop stops after the first one. A truncated read then looks
    exactly like a small result set — the original defect, inside the guard
    written to prevent it. Caught by test_an_exactly_full_final_page_...; one
    extra round-trip per read is the whole cost of not being able to be clamped."""
    after = None
    while True:
        rows = rest.page(path, after, order_col)
        if not rows:
            return
        for row in rows:
            yield row
        after = rows[-1][order_col]


@contextlib.contextmanager
def quiet_parser():
    """Silence the SCANNER's logging for the duration — not ours.

    ⚠ WHY THIS EXISTS. `_classify_wafw00f_output` and `persist_stack_id_wafw00f` each
    `log()` their verdict to stderr, which is right during a scan and wrong here: a
    --reparse-generic pass calls the parser once per candidate run, so 93 rows buried
    the PLAN — the only output a reviewer needs — under ~180 lines of
    "WAF detected: fortiweb". A plan you have to scroll to find is a plan that gets
    skimmed.

    ⚠ RESTORED IN A `finally`, AND THE SAVE IS TAKEN BEFORE THE SWAP. If the parser
    raises mid-row, a runner left permanently mute would silence the NEXT caller in
    the same process — the tests import this module and run_medium together. Swapping
    the module attribute is the narrowest available seam: run_medium's functions call
    the global `log`, so rebinding the name is what a no-op has to touch."""
    saved = getattr(_medium, "log", None)
    _medium.log = lambda *_a, **_k: None
    try:
        yield
    finally:
        if saved is not None:
            _medium.log = saved
        else:                                    # pragma: no cover — defensive
            delattr(_medium, "log")


def verdict_from_raw(raw: str) -> dict | None:
    """Reparse a stored raw wafw00f artifact with the SCANNER'S OWN parser.

    Returns the verdict `persist_stack_id_wafw00f` would have written, or None if
    the raw is absent/unusable — never a fabricated negative."""
    if not raw or not raw.strip():
        return None
    ctx = types.SimpleNamespace(waf_detected=False, waf_kind=None, artifacts=[])
    # rc=0: the artifact exists, so wafw00f produced output. _classify_wafw00f_output
    # treats rc != 0 as "assume no WAF" — exactly the fabricated negative refused here.
    #
    # ⚠ QUIET HERE, NOT AT THE CALL SITES. Both loops (backfill and --reparse-generic)
    # call this, and the plan table calls it again per row; silencing at each call site
    # is three places to forget one. We borrow the scanner's PARSER, not its live-scan
    # narration — so the borrow is where the narration stops.
    with quiet_parser():
        _medium._classify_wafw00f_output(ctx, raw, 0)
        _medium.persist_stack_id_wafw00f(ctx)
    if not ctx.artifacts:
        return None
    v = json.loads(ctx.artifacts[-1][2])
    # ⚠ PROVENANCE, deliberately additive. The consumer reads only
    # wafw00f_detected / wafw00f_kind, so this is inert to it — but a row recovered
    # from text months later should not be indistinguishable from one a live scan
    # wrote. Greppable, and it keeps "what did we observe" honest.
    v["backfilled_from_raw"] = True
    return v


def _raw_of(art: dict) -> str:
    blob = art.get("content_jsonb")
    if isinstance(blob, dict):
        return blob.get("raw") or json.dumps(blob)
    return blob or ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="actually insert (Howie only, after 4.7 reads the dry-run)")
    ap.add_argument("--limit", type=int, default=0, help="bound the runs considered")
    ap.add_argument("--reparse-generic", action="store_true",
                    help="ALSO correct existing generic/null verdicts whose raw names a "
                         "vendor (relay 222 ruling 10). Never touches a row that already "
                         "names one.")
    args = ap.parse_args()

    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        sys.exit("set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY "
                 "(run: set -a && . ./.env && set +a  — `. ./.env` alone leaves them "
                 "as shell variables, not environment variables)")

    rest = Rest(url, key)
    mode = "WRITE" if args.write else "DRY-RUN"
    print(f"backfill_stack_id_wafw00f — {mode}   ({url.split('//')[-1].split('.')[0]})")
    print("  parser: run_medium._classify_wafw00f_output (imported, not reimplemented)")
    print("  transport: PostgREST, keyset-paginated\n")

    raws = {a["scan_run_id"]: a for a in paginate(
        rest, "scan_run_artifacts?select=artifact_id,scan_run_id,content_jsonb"
              "&tool_name=eq.wafw00f")}
    have_rows = list(paginate(
        rest, "scan_run_artifacts?select=artifact_id,scan_run_id,content_jsonb"
              "&tool_name=eq.stack_id_wafw00f"))
    haves = {a["scan_run_id"] for a in have_rows}
    # ⚠ LAUNDERED ROWS ARE NOT EVIDENCE (relay 222, ruling 10). A stored verdict of
    # `generic`/null whose RAW names a vendor is not a weaker observation — it is the
    # ANSI parse defect written down. Correcting it is not an overwrite.
    # The rule is strict in one direction only: replace ONLY generic/null with a
    # NAMED vendor. A row that already names one is never touched, whatever the raw
    # now says — re-deciding settled vendor calls is not this script's job.
    existing = {a["scan_run_id"]: (a.get("content_jsonb") or {}) for a in have_rows}
    todo = sorted(set(raws) - haves)
    relaundered = []
    if args.reparse_generic:
        for rid in sorted(set(raws) & haves):
            cur = existing.get(rid, {}).get("wafw00f_kind")
            if cur not in (None, "generic"):
                continue                      # already names a vendor — never touched
            fresh = verdict_from_raw(_raw_of(raws[rid]))
            if fresh and fresh["wafw00f_kind"] not in (None, "generic"):
                fresh["reparsed_from_raw"] = True
                fresh.pop("backfilled_from_raw", None)
                relaundered.append((rid, cur, fresh))

    print(f"  runs with a raw wafw00f        : {len(raws)}")
    print(f"  of those, already have parsed  : {len(set(raws) & haves)}")
    print(f"  TO BACKFILL (no verdict yet)   : {len(todo)}")
    if args.reparse_generic:
        print(f"  TO RE-PARSE (generic/null -> named vendor) : {len(relaundered)}")
    else:
        print("  (--reparse-generic not set: existing generic/null rows left alone)")
    if args.limit:
        todo = todo[: args.limit]
        print(f"  (--limit {args.limit} applied)")
    if not todo:
        print("\n  nothing to do.")
        return 0

    runs = {}
    for chunk in [todo[i:i + 50] for i in range(0, len(todo), 50)]:
        ids = ",".join(chunk)
        for r in paginate(rest,
                          f"scan_run?select=scan_run_id,asset_id,intensity,completed_at"
                          f"&scan_run_id=in.({ids})", order_col="scan_run_id"):
            runs[r["scan_run_id"]] = r

    tally, unreadable, rows = Counter(), [], []
    print(f"\n    {'intensity':9s} {'completed':12s} {'detected':9s} {'kind':11s} asset")
    for rid in sorted(todo, key=lambda x: (runs.get(x, {}).get("completed_at") or ""), reverse=True):
        meta = runs.get(rid, {})
        v = verdict_from_raw(_raw_of(raws[rid]))
        asset = str(meta.get("asset_id", "?"))[:34]
        when = str(meta.get("completed_at", ""))[:10]
        tier = str(meta.get("intensity", "?"))
        if v is None:
            tally["unreadable"] += 1
            unreadable.append(f"{asset} {when} ({rid[:8]})")
            print(f"    {tier:9s} {when:12s} {'—':9s} {'UNREADABLE':11s} {asset}")
            continue
        tally[f"kind:{v['wafw00f_kind']}"] += 1
        tally["would_write"] += 1
        body = json.dumps(v)
        rows.append({"scan_run_id": rid, "tool_name": "stack_id_wafw00f",
                     "output_format": "json", "content_jsonb": v,
                     "size_bytes": len(body)})
        print(f"    {tier:9s} {when:12s} {str(v['wafw00f_detected']):9s} "
              f"{str(v['wafw00f_kind']):11s} {asset}")

    print(f"\n  summary: {dict(tally)}")
    # ⚠ demo.testfire.net is the PUBLIC VALIDATE-MODE TRAINING TARGET, not Command
    # estate. Named here so the negative count is not read as fleet posture.
    n_demo = sum(1 for rid in todo
                 if "testfire.net" in str((runs.get(rid) or {}).get("asset_id", "")))
    if n_demo:
        print(f"  note: {n_demo} of the above are demo.testfire.net — the public "
              f"validate-mode training target, NOT Command estate.")
    if unreadable:
        print("  ⚠ UNREADABLE — reported, NOT defaulted to 'no WAF found':")
        for u in unreadable:
            print(f"      {u}")

    if args.reparse_generic and relaundered:
        print(f"\n  RE-PARSE plan — laundered verdicts corrected:")
        print(f"    {'was':9s} {'becomes':11s} asset")
        for rid, was, fresh in relaundered:
            meta = runs.get(rid) or {}
            if not meta:
                for r in paginate(rest, f"scan_run?select=scan_run_id,asset_id,intensity,"
                                        f"completed_at&scan_run_id=eq.{rid}",
                                  order_col="scan_run_id"):
                    meta = r
            print(f"    {str(was):9s} {str(fresh['wafw00f_kind']):11s} "
                  f"{str(meta.get('asset_id','?'))[:40]}  {str(meta.get('completed_at',''))[:10]}")
        tally["reparse_generic_to_vendor"] = len(relaundered)

    if args.write:
        for chunk in [rows[i:i + 100] for i in range(0, len(rows), 100)]:
            rest.insert("scan_run_artifacts", chunk)
        for rid, _was, fresh in relaundered:
            rest.patch(f"scan_run_artifacts?tool_name=eq.stack_id_wafw00f"
                       f"&scan_run_id=eq.{rid}", {"content_jsonb": fresh,
                                                  "size_bytes": len(json.dumps(fresh))})
        print(f"\n  WROTE {len(rows)} new stack_id_wafw00f artifact(s)"
              f"{f' and CORRECTED {len(relaundered)} laundered one(s)' if relaundered else ''}.")
        print("  The classifier re-derives on its next device-class pass (dry-run).")
    else:
        print(f"\n  DRY-RUN — nothing written. {len(rows)} row(s) would be inserted"
              f"{f', {len(relaundered)} corrected' if relaundered else ''}.")
        print("  Re-run with --write after 4.7 reads this.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
