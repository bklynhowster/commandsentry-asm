#!/usr/bin/env python3
"""Production INVARIANTS — the regression suite for bugs that DO NOT CRASH.
Relay 246/247, ruling from Howie's "why do these keep happening". 2026-09-17.

⛔ WHY THIS FILE EXISTS, AND IT IS NOT "MORE TESTS".
Six production breaks in one week. A pre-merge dry-run gate catches exactly ONE of
them — b3a96e90, which raised an AttributeError 1m51s in. The other four exited
CLEAN, with plausible numbers, and were found days later by reading the data:

    the persist fold      heavy wrote the raw wafw00f artifact and not the parsed
                          one. 18 of 18 runs. rc=0, no error, verdict discarded.
    the ANSI parse        wafw00f colourised the vendor name, so 32 FortiWeb
                          identifications were stored as "generic". A positive
                          claim of a weaker fact — worse than absence.
    the collector order   nikto earned a FortiGate ban 35s before the passive
                          collector ran, which then collected nothing and wrote
                          a well-formed EMPTY envelope.
    the capability gap    a light scan's empty evidence counted as "we looked and
                          found nothing", so real labels were downgradable.

⇒ A GATE THAT ONLY ASKS "DID IT CRASH" GOES GREEN ON ALL FOUR. These are not
  exceptions; they are FACTS ABOUT PRODUCTION THAT STOPPED BEING TRUE. So the check
  has to be a fact about production, asserted on real data, every time.

⚠ EACH INVARIANT IS STATED SO THAT IT WOULD HAVE FAILED ON THE TREE THAT HAD THE
  BUG. That is the acceptance test for an invariant, and `--selftest` proves it
  both ways: every invariant is run against a fixture of the BAD shape (must fail)
  and the GOOD shape (must pass). An invariant that cannot fail is not an
  invariant, it is a comment — the same rule as a mutation-tested guard.

⚠ THE LIST GROWS BY ONE EVERY TIME A WRONG-ANSWER BUG IS FIXED. That is the point:
  the tests cannot see this class, because the fixtures are built from the shape
  the code expects. Production is the only place the real shape lives.

READ-ONLY. Every query is a SELECT. This runs against the live DB from the
pre-merge gate and must never write.

    python3 scripts/db/premerge_invariants.py --selftest    # no DB, fixtures both ways
    SUPABASE_DSN=... python3 scripts/db/premerge_invariants.py --live
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scanner"))

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover — --selftest needs no DB driver
    psycopg = None

# The wafw00f parse, IMPORTED — never re-implemented. A second copy of those
# regexes would be a third home for the defect family this file exists to catch
# (4.7 ruling 8: FOLD, not register-a-pair).
import run_medium as _medium  # noqa: E402

WINDOW_DAYS = 30
RECENT_HOURS = 24
PASSIVE_FIELDS = ("set_cookie_names", "headers", "cert")
# ⚠ I3's population floor. The gate's first live run counted 10 hosts, of which
# 8 had a real HTTP surface. A population below this is a PREDICATE BUG, not a
# pass — see i3_empty_envelopes for why "nothing to check" must not look like
# "everything checked out".
I3_MIN_POPULATION = 5
SUMMARY_PREFIX = "premerge-invariants:"     # ruling 21 — the line the gate asserts


# ══ PURE DECISIONS — every invariant's verdict, with no DB in sight ════════
# The queries feed these; --selftest drives them directly with fixtures. Keeping
# the decision pure is what makes "would it have failed on the bad tree?" a test
# rather than a claim.

def i1_violations(runs) -> list:
    """I1 — THE PERSIST FOLD. A heavy that produced a raw `wafw00f` artifact must
    also have produced the parsed `stack_id_wafw00f`.

    ⚠ STATED AS AN IMPLICATION, NOT A CONJUNCTION. `ftp.sciimage.com` and
    `ftp.unimacgraphics.com` are the SFTP pair with no HTTPS surface; a heavy there
    legitimately has NEITHER artifact. "has both" would fail on them forever and
    the gate would be turned off. "has the parsed one IF it has the raw one" is the
    actual rule.

    BAD TREE (pre-217): 18 of 18 heavy runs -> 18 violations -> FAIL."""
    return [r for r in runs if r.get("has_raw") and not r.get("has_parsed")]


def i2_laundered(rows) -> list:
    """I2 — THE ANSI PARSE. No stored verdict may say generic/null when the RAW
    text it came from names a vendor.

    ⚠ NOT "at least one named vendor exists in the fleet" — that is a fact about
    the fleet, not about the parser, and it would pass on a broken parser the
    moment someone backfilled one row. This re-parses the raw with the SCANNER'S
    OWN parser and compares. It is exactly the bug or it is nothing.

    BAD TREE (pre-222): 32 FortiWeb identifications stored as 'generic' -> 32
    violations -> FAIL. Post-fix and post-backfill: 0."""
    out = []
    for r in rows:
        fresh = kind_from_raw(r.get("raw"))
        if fresh in (None, "generic"):
            continue                       # raw names no vendor — nothing to launder
        if r.get("stored_kind") in (None, "generic"):
            out.append({**r, "raw_says": fresh})
    return out


def kind_from_raw(raw):
    """The scanner's parser against a duck-typed ctx — the backfill's approach,
    and the only one that cannot drift from what a live scan decides."""
    if not raw or not str(raw).strip():
        return None
    import types
    ctx = types.SimpleNamespace(waf_detected=False, waf_kind=None, artifacts=[])
    saved = getattr(_medium, "log", None)
    _medium.log = lambda *_a, **_k: None          # borrow the parser, not its narration
    try:
        _medium._classify_wafw00f_output(ctx, raw, 0)
    finally:
        if saved is not None:
            _medium.log = saved
    return ctx.waf_kind


def wafw00f_saw_http(raw) -> bool:
    """Did THIS RUN find an HTTP surface to collect from? (Ruling 23.)

    ⛔ WHY I3 NEEDED THIS AT ALL. Its first population was "hosts with 443 open",
    from asset_surface. The gate's first live run (premerge-gate #2) failed I3 at
    80% of 10 — and the two "failures" were `ftp.sciimage.com` and
    `ftp.unimacgraphics.com`: 443 open, nothing HTTP behind it, so an empty
    envelope is the TRUE answer there. The invariant's POPULATION was wrong, not
    production. Exactly the pair excluded from the 233 fixture, walking back in
    through a different door.

    ⇒ 443 OPEN IS NOT AN HTTP SURFACE. naabu sees the port, not the protocol.
      And "httpx OK" would be circular — httpx is one of the things the ban kills.

    ⚠ IMPORTED, NOT WRITTEN. `wafw00f_is_degraded` is the scanner's own shipped
    predicate for "did wafw00f produce a verdict", and it already excludes the
    down case by construction: a host that only prints "appears to be down" has no
    `[+] `, no "No WAF detected by the generic detection" and no "is behind", so it
    reads degraded. Ruling 23 said "does not report the site down"; this is that,
    expressed as the tool's own positive test — strictly stronger, because a run
    whose wafw00f died for some *other* reason is also excluded rather than
    counted. Flagged in the relay entry as a deliberate strengthening.

    wafw00f runs FIRST, on a fresh egress, before anything noisy — which is what
    makes its verdict the cleanest in-run evidence that there was something to
    collect from. rc=0 for the same reason verdict_from_raw passes it: the artifact
    exists, so the tool produced output."""
    if not raw or not str(raw).strip():
        return False
    try:
        degraded, _reason = _medium.wafw00f_is_degraded(str(raw), 0)
    except Exception:
        return False
    return not degraded


def envelope_is_empty(blob) -> bool:
    """A `stack_id_passive` envelope that carries none of the three collected
    fields. THE 09-03 SHAPE: {schema, collected_at, hostname} — well-formed,
    present, and empty, which is why nothing complained for two weeks."""
    if blob is None:
        return True
    if isinstance(blob, str):
        try:
            blob = json.loads(blob)
        except Exception:
            return True
    if not isinstance(blob, dict):
        return True
    return not any(blob.get(f) for f in PASSIVE_FIELDS)


def i3_empty_envelopes(runs, floor_pct: int = 90,
                       min_population: int = I3_MIN_POPULATION) -> dict:
    """I3 — THE COLLECTOR ORDER. Of the newest heavies on hosts THAT ANSWERED HTTP
    IN THAT SAME RUN, at least `floor_pct`% must carry a non-empty passive envelope.

    ⚠ A RATIO, NOT AN ABSOLUTE, and the floor is measured rather than chosen: the
    post-cutover reality was 5 of 11 full (45%) and the pre-cutover reality was
    130 of 130 (100%). 90% fails the first and passes the second with room for one
    genuinely banned run, so the gate reports a real regression instead of flapping
    on a single bad night. A gate that flaps gets bypassed, which is the same
    failure as a gate that passes vacuously.

    ⛔ AND THE POPULATION IS THE HALF THAT WAS WRONG (ruling 23). A host with no
    HTTP surface has nothing to collect, so its empty envelope is CORRECT and
    counting it makes the invariant fail on healthy production — which is what
    premerge-gate #2 did, at 80% of 10, naming the SFTP pair. Excluded hosts are
    RETURNED, not silently dropped: an invariant that quietly narrows its own
    population until it passes is the vacuous-pass shape wearing a ratio.

    ⚠ HENCE `min_population`. With `total == 0` the ratio is undefined and the old
    code returned ok=True — so a predicate bug that excluded everything would have
    read as a clean pass. A population below the floor is now a FAILURE with its
    own reason, because "nothing to check" and "everything checked out" must never
    look the same.

    BAD TREE (post-93e8acea, pre-233): 45% -> FAIL."""
    counted, excluded = [], []
    for r in runs:
        if wafw00f_saw_http(r.get("wafw00f_raw")):
            counted.append(r)
        else:
            excluded.append({"asset_id": r.get("asset_id"),
                             "reason": "no HTTP surface in that run (wafw00f: no verdict)"})
    total = len(counted)
    empty = [r for r in counted if envelope_is_empty(r.get("envelope"))]
    pct = round(100 * (total - len(empty)) / total) if total else 0
    thin = total < min_population
    return {"total": total, "empty": empty, "excluded": excluded, "full_pct": pct,
            "ok": (not thin) and pct >= floor_pct,
            "floor_pct": floor_pct, "min_population": min_population,
            "population_too_thin": thin}


def i4_unmarked_downgrades(rows) -> list:
    """I4 — THE CAPABILITY GAP. A SAME-CLASS confidence downgrade written for an
    asset whose newest heavy collected an EMPTY envelope must carry the R5 preserve
    marker in `prior_state.preserve`.

    ⚠ WHY THE MARKER AND NOT THE ROW'S ABSENCE. A preserve still EMITS a
    TRANSITION_DOWNGRADE audit row every pass — that is how the streak accumulates
    without a migration. So "no downgrade row exists" cannot distinguish preserved
    from written; only the marker can. The marker is the field 2c added for exactly
    this audit trail, and this is the consumer that makes it load-bearing.

    ⚠ SCOPED TO SAME-CLASS (prior class == computed class). A move to `unknown` is
    2b's territory and has its own, untouched audit shape.

    BAD TREE (pre-2c): api/edelivery/testapi.commandcommcentral.com, whose cookie
    evidence is 55-57d old, downgrade with no marker -> 3 violations -> FAIL."""
    out = []
    for r in rows:
        if not r.get("newest_envelope_empty"):
            continue
        prior = r.get("prior_state") or {}
        if isinstance(prior, str):
            try:
                prior = json.loads(prior)
            except Exception:
                prior = {}
        if not (prior.get("preserve") or {}).get("reason"):
            out.append(r)
    return out


# ══ THE QUERIES — read-only, bounded, one per invariant ════════════════════

Q_I1 = """
select r.scan_run_id::text as scan_run_id, r.asset_id, r.completed_at,
       exists (select 1 from scan_run_artifacts a
                where a.scan_run_id = r.scan_run_id and a.tool_name = 'wafw00f') as has_raw,
       exists (select 1 from scan_run_artifacts a
                where a.scan_run_id = r.scan_run_id and a.tool_name = 'stack_id_wafw00f') as has_parsed
  from scan_run r
 where r.intensity = 'heavy'
   and r.completed_at > now() - interval '%s days'
 order by r.completed_at desc
 limit 100
"""

Q_I2 = """
select r.scan_run_id::text as scan_run_id, r.asset_id,
       (select coalesce(a.content_jsonb->>'raw', a.content_jsonb::text)
          from scan_run_artifacts a
         where a.scan_run_id = r.scan_run_id and a.tool_name = 'wafw00f' limit 1) as raw,
       (select a.content_jsonb->>'wafw00f_kind'
          from scan_run_artifacts a
         where a.scan_run_id = r.scan_run_id and a.tool_name = 'stack_id_wafw00f' limit 1) as stored_kind
  from scan_run r
 where r.completed_at > now() - interval '%s days'
   and exists (select 1 from scan_run_artifacts a
                where a.scan_run_id = r.scan_run_id and a.tool_name = 'stack_id_wafw00f')
 order by r.completed_at desc
 limit 200
"""

# ⚠ THE POPULATION IS DECIDED IN PYTHON, FROM THE RUN'S OWN wafw00f OUTPUT —
# not in SQL from asset_surface. The previous version keyed on "443 open" via a
# jsonb walk over subdomains[].services[] and hosts[].services[], and it was wrong
# in fact: naabu sees the port, not the protocol. Ruling 23.
#
# ⇒ THE 443 WALK IS GONE, AND SO IS THE SECOND READER IT CREATED. It duplicated
#   demotion_writer.known_ports()'s traversal with deliberately different
#   defaulting, which was a footnote waiting to become a bug. One fewer home.
Q_I3 = """
select distinct on (r.asset_id)
       r.asset_id, r.scan_run_id::text as scan_run_id, r.completed_at,
       (select a.content_jsonb::text from scan_run_artifacts a
         where a.scan_run_id = r.scan_run_id and a.tool_name = 'stack_id_passive'
         order by a.artifact_id desc limit 1) as envelope,
       (select coalesce(a.content_jsonb->>'raw', a.content_jsonb::text)
          from scan_run_artifacts a
         where a.scan_run_id = r.scan_run_id and a.tool_name = 'wafw00f'
         order by a.artifact_id desc limit 1) as wafw00f_raw
  from scan_run r
 where r.intensity = 'heavy'
   and r.completed_at > now() - interval '%s days'
 order by r.asset_id, r.completed_at desc
"""

Q_I4 = """
select d.asset_id, d.device_class, d.confidence, d.prior_state, d.evaluated_at,
       (select a.content_jsonb::text
          from scan_run_artifacts a
          join scan_run r2 on r2.scan_run_id = a.scan_run_id
         where r2.asset_id = d.asset_id and r2.intensity = 'heavy'
           and a.tool_name = 'stack_id_passive'
         order by r2.completed_at desc limit 1) as newest_envelope
  from public.device_class_dryrun d
 where d.event_type = 'TRANSITION_DOWNGRADE'
   and d.evaluated_at > now() - interval '%s hours'
   and d.device_class <> 'unknown'
   and d.prior_state->>'device_class' = d.device_class
 order by d.evaluated_at desc
 limit 200
"""


def _rows(cur, sql, arg):
    cur.execute(sql % int(arg))
    return cur.fetchall() or []


def run_live(dsn: str) -> int:
    conn = psycopg.connect(dsn, row_factory=dict_row, connect_timeout=15)
    conn.autocommit = True                      # read-only; never opens a write txn
    failures = []
    try:
        with conn.cursor() as cur:
            r1 = i1_violations(_rows(cur, Q_I1, WINDOW_DAYS))
            _report("I1", "heavy with a raw wafw00f and no parsed verdict",
                    not r1, f"{len(r1)} violation(s)",
                    [f"{v['asset_id']} {v['scan_run_id'][:8]}" for v in r1[:5]], failures)

            r2 = i2_laundered(_rows(cur, Q_I2, WINDOW_DAYS))
            _report("I2", "stored verdict says generic/null while the raw names a vendor",
                    not r2, f"{len(r2)} laundered row(s)",
                    [f"{v['asset_id']} raw={v['raw_says']} stored={v['stored_kind']}"
                     for v in r2[:5]], failures)

            r3 = i3_empty_envelopes(_rows(cur, Q_I3, WINDOW_DAYS))
            _report("I3", "newest heavy on a host that answered HTTP carries a full envelope",
                    r3["ok"],
                    f"{r3['full_pct']}% full of {r3['total']} host(s) "
                    f"(floor {r3['floor_pct']}%, min population {r3['min_population']})"
                    + ("  ⛔ POPULATION TOO THIN — predicate bug, not a pass"
                       if r3["population_too_thin"] else ""),
                    [f"EMPTY {v['asset_id']}" for v in r3["empty"][:5]]
                    + [f"excluded: {v['asset_id']} — {v['reason']}"
                       for v in r3["excluded"][:5]], failures)

            raw4 = _rows(cur, Q_I4, RECENT_HOURS)
            for r in raw4:
                r["newest_envelope_empty"] = envelope_is_empty(r.get("newest_envelope"))
            r4 = i4_unmarked_downgrades(raw4)
            _report("I4", "same-class downgrade on an empty envelope carries the preserve marker",
                    not r4, f"{len(r4)} unmarked of {len(raw4)} same-class downgrade(s)",
                    [v["asset_id"] for v in r4[:5]], failures)
    finally:
        conn.close()

    # ⛔ RULING 21 — the summary line. A job that ran nothing must FAIL, not pass;
    # the gate greps for this exact prefix, so a step that died early cannot read
    # as green. This is what caught lane 6, and it is the only cover for the
    # "step exited silently" class.
    print(f"{SUMMARY_PREFIX} {4 - len(failures)}/4 held"
          + (f" — FAILED: {', '.join(failures)}" if failures else ""))
    return 1 if failures else 0


def _report(iid, title, ok, measured, examples, failures):
    print(f"  {'PASS' if ok else '⛔ FAIL'}  {iid}  {title}")
    print(f"          measured: {measured}")
    for e in examples:
        print(f"          · {e}")
    if not ok:
        failures.append(iid)


# ══ SELFTEST — every invariant, BAD shape then GOOD shape ══════════════════
# An invariant that cannot fail is a comment. Each fixture below is the shape the
# bad tree actually produced, not an invented counterexample.

def _selftest() -> int:
    ok = True

    # I1 — the persist fold. Bad: raw without parsed (18 of 18). Good: both, and
    # the SFTP pair with NEITHER, which must not count as a violation.
    bad1 = [{"asset_id": "commandcommcentral.com", "scan_run_id": "a", "has_raw": True, "has_parsed": False}]
    good1 = [{"asset_id": "commandcommcentral.com", "scan_run_id": "a", "has_raw": True, "has_parsed": True},
             {"asset_id": "ftp.sciimage.com", "scan_run_id": "b", "has_raw": False, "has_parsed": False}]
    ok &= len(i1_violations(bad1)) == 1
    ok &= i1_violations(good1) == []
    print(f"  I1 fires on raw-without-parsed, silent on the SFTP pair (neither artifact): "
          f"{'ok' if len(i1_violations(bad1)) == 1 and not i1_violations(good1) else 'FAIL'}")

    # I2 — the ANSI parse. The raw is the PRODUCTION bytes, escapes and all.
    ansi_raw = ("[+] The site \x1b[1;94mhttps://commandcommcentral.com/\x1b[0m is behind "
                "\x1b[1;96mFortiWeb (Fortinet)\x1b[0m WAF.\n"
                "[*] The site https://commandcommcentral.com/ seems to be behind a WAF or "
                "some sort of security solution\n")
    bad2 = [{"asset_id": "commandcommcentral.com", "raw": ansi_raw, "stored_kind": "generic"}]
    good2 = [{"asset_id": "commandcommcentral.com", "raw": ansi_raw, "stored_kind": "fortiweb"},
             {"asset_id": "x", "raw": "[-] No WAF detected by the generic detection\n",
              "stored_kind": None}]
    ok &= len(i2_laundered(bad2)) == 1
    ok &= i2_laundered(good2) == []
    ok &= kind_from_raw(ansi_raw) == "fortiweb"            # the parser really de-ANSIs
    print(f"  I2 fires on a laundered FortiWeb, silent on a genuine negative: "
          f"{'ok' if len(i2_laundered(bad2)) == 1 and not i2_laundered(good2) else 'FAIL'}")

    # I3 — the collector order. The empty envelope is the real 09-03 key set, and
    # the POPULATION is what ruling 23 corrected after the gate's first live run.
    empty_env = json.dumps({"schema": 1, "collected_at": "2026-09-03T20:14:56Z",
                            "hostname": "commandcommcentral.com"})
    full_env = json.dumps({"schema": 1, "hostname": "commandcommcentral.com",
                           "set_cookie_names": ["cookiesession1"],
                           "headers": {"server": "nginx"}, "cert": "CN=*.x"})
    # wafw00f output, by what the tool actually prints.
    W_VERDICT = ("[+] The site https://commandcommcentral.com/ is behind "
                 "FortiWeb (Fortinet) WAF.\n")
    W_NOWAF   = "[-] No WAF detected by the generic detection\n"
    W_DOWN    = "[*] The site https://ftp.sciimage.com/ appears to be down.\n"
    ok &= wafw00f_saw_http(W_VERDICT) and wafw00f_saw_http(W_NOWAF)
    ok &= not wafw00f_saw_http(W_DOWN)
    ok &= not wafw00f_saw_http(None) and not wafw00f_saw_http("")
    print(f"  I3 population (ruling 23): a verdict counts, "
          f"'appears to be down' does NOT: "
          f"{'ok' if wafw00f_saw_http(W_NOWAF) and not wafw00f_saw_http(W_DOWN) else 'FAIL'}")

    # ⭐ FIRES: banned egress, HTTP surface confirmed in the same run -> 45%
    bad3 = ([{"asset_id": f"e{i}", "envelope": empty_env, "wafw00f_raw": W_VERDICT}
             for i in range(6)] +
            [{"asset_id": f"g{i}", "envelope": full_env, "wafw00f_raw": W_VERDICT}
             for i in range(5)])
    r_bad = i3_empty_envelopes(bad3)
    ok &= r_bad["ok"] is False and r_bad["full_pct"] == 45
    # ⭐ SILENT: the SFTP pair — empty envelope, but no HTTP surface, so EXCLUDED.
    #   This is the exact shape that failed premerge-gate #2 at 80% of 10.
    good3 = ([{"asset_id": f"g{i}", "envelope": full_env, "wafw00f_raw": W_VERDICT}
              for i in range(8)] +
             [{"asset_id": "ftp.sciimage.com", "envelope": empty_env, "wafw00f_raw": W_DOWN},
              {"asset_id": "ftp.unimacgraphics.com", "envelope": empty_env, "wafw00f_raw": W_DOWN}])
    r_good = i3_empty_envelopes(good3)
    ok &= r_good["ok"] is True and r_good["total"] == 8 and r_good["full_pct"] == 100
    ok &= len(r_good["excluded"]) == 2
    print(f"  I3 fires at 45% on a banned egress, and is SILENT on the SFTP pair "
          f"(8/8, 2 excluded): "
          f"{'ok' if not r_bad['ok'] and r_good['ok'] and r_good['total'] == 8 else 'FAIL'}")
    # ⛔ AND A POPULATION THAT COLLAPSES IS A FAILURE, NOT A PASS. The old code
    #   returned ok=True on total==0, so a predicate bug that excluded everything
    #   read as clean. "Nothing to check" and "everything checked out" must differ.
    r_thin = i3_empty_envelopes(
        [{"asset_id": "ftp.sciimage.com", "envelope": empty_env, "wafw00f_raw": W_DOWN}])
    ok &= r_thin["ok"] is False and r_thin["population_too_thin"] is True
    ok &= i3_empty_envelopes([])["ok"] is False
    print(f"  I3 population below the floor FAILS (and [] fails too): "
          f"{'ok' if not r_thin['ok'] and not i3_empty_envelopes([])['ok'] else 'FAIL'}")
    # ⛔ MUTANTS M3 AND M6 (4.7, relay 259) SURVIVED THE SELFTEST while dying in
    #   pytest — so the line this function prints ("proven to fire AND to stay
    #   silent") was claiming more than it had checked. Mirrored here so the claim
    #   and the coverage are the same thing.
    #   M3: floor not wired to the verdict. Every earlier floor fixture had pct=0,
    #       where ok is False either way. 3 hosts, ALL FULL, must still fail.
    r_m3 = i3_empty_envelopes([{"asset_id": f"f{i}", "envelope": full_env,
                                "wafw00f_raw": W_VERDICT} for i in range(3)])
    ok &= r_m3["full_pct"] == 100 and r_m3["population_too_thin"] is True and r_m3["ok"] is False
    #   M6: >= floor vs > floor. The docstring's design point is 9 of 10; nothing
    #       sat on it.
    _b = lambda nf, ne: i3_empty_envelopes(
        [{"asset_id": f"f{i}", "envelope": full_env, "wafw00f_raw": W_VERDICT} for i in range(nf)] +
        [{"asset_id": f"e{i}", "envelope": empty_env, "wafw00f_raw": W_VERDICT} for i in range(ne)])
    ok &= _b(9, 1)["full_pct"] == 90 and _b(9, 1)["ok"] is True
    ok &= _b(8, 2)["ok"] is False
    print(f"  I3 floor is wired to the verdict (3 full hosts -> FAIL) and 90% is the "
          f"boundary (9/10 pass, 8/10 fail): "
          f"{'ok' if not r_m3['ok'] and _b(9,1)['ok'] and not _b(8,2)['ok'] else 'FAIL'}")
    ok &= envelope_is_empty(empty_env) and not envelope_is_empty(full_env)
    ok &= envelope_is_empty(None) and envelope_is_empty("not json") and envelope_is_empty("[]")

    # I4 — the capability gap. Same asset, same row, with and without the marker.
    base4 = {"asset_id": "api.commandcommcentral.com", "device_class": "waf",
             "confidence": "suspected", "newest_envelope_empty": True}
    bad4 = [{**base4, "prior_state": {"device_class": "waf", "confidence": "confirmed"}}]
    good4 = [{**base4, "prior_state": {"device_class": "waf", "confidence": "confirmed",
                                       "preserve": {"reason": "EVIDENCE_AGED",
                                                    "evidence_age_days": {"set_cookie_names": 56}}}},
             # a FULL envelope is not this invariant's business, marker or not
             {**base4, "newest_envelope_empty": False,
              "prior_state": {"device_class": "waf", "confidence": "confirmed"}}]
    ok &= len(i4_unmarked_downgrades(bad4)) == 1
    ok &= i4_unmarked_downgrades(good4) == []
    ok &= len(i4_unmarked_downgrades(
        [{**base4, "prior_state": json.dumps(bad4[0]["prior_state"])}])) == 1   # jsonb as text
    print(f"  I4 fires on an unmarked same-class downgrade over an empty envelope: "
          f"{'ok' if len(i4_unmarked_downgrades(bad4)) == 1 and not i4_unmarked_downgrades(good4) else 'FAIL'}")

    # ⛔ THE QUERIES MUST BE READ-ONLY. Stated as a test rather than a promise:
    # this runs against production with a service-role credential.
    for name, q in (("Q_I1", Q_I1), ("Q_I2", Q_I2), ("Q_I3", Q_I3), ("Q_I4", Q_I4)):
        low = " ".join(q.split()).lower()
        bad = [v for v in ("insert ", "update ", "delete ", "drop ", "alter ", "truncate ")
               if v in low]
        ok &= not bad
        ok &= low.startswith("select") or low.startswith("with")
        if bad:
            print(f"  ⛔ {name} contains {bad}")
    print(f"  all four queries are read-only and start with SELECT/WITH: "
          f"{'ok' if ok else 'FAIL'}")

    print(f"{SUMMARY_PREFIX} selftest {'PASS' if ok else 'FAIL'} "
          f"(4 invariants, each proven to fire AND to stay silent)")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true", help="fixtures only, no DB")
    ap.add_argument("--live", action="store_true", help="run against SUPABASE_DSN (read-only)")
    a = ap.parse_args()
    if a.selftest or not a.live:
        return _selftest()
    if psycopg is None:
        sys.exit("psycopg required for --live")
    dsn = os.environ.get("SUPABASE_DSN") or os.environ.get("COMMAND_SUPABASE_DSN")
    if not dsn:
        sys.exit("set SUPABASE_DSN")
    print(f"premerge invariants — LIVE, read-only, window {WINDOW_DAYS}d / {RECENT_HOURS}h")
    return run_live(dsn)


if __name__ == "__main__":
    sys.exit(main())
