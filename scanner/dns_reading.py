#!/usr/bin/env python3
"""dns_reading.py — one DNS reading per name, with its health (KB 12 job 5a, plan v3 section 0).

WHY (Howie 2026-11-05 09:25: "this discovery calls into question how we handle DNS changes on
our site ... we need to scan for it, compare it, report on it"). Discovery's own lookups cannot
tell "this name has no records" from "the lookup got no answer": the A/AAAA digs end in
`|| true` and the dnsx records snapshot is best-effort and non-fatal (asm-discover.sh
discover_fqdn). A comparison built on those would read a timeout as a removal. This reader
keeps the HEALTH of every lookup next to its answer, so a later comparison can refuse to
compare what was not actually observed (the plan review's must-fix 2, 2026-11-05 13:44).

WHAT IT ASKS: ordinary DNS questions (A, AAAA, CNAME, NS, MX, TXT; and TXT of _dmarc.<name>
for the apex), through dig, nothing else. No zone transfer, ever. Only names under the apex
it is given (the caller's list is already scope-verified; this re-checks the suffix). When the
apex's everyday name-server answer differs from the set last counted, the apex's own name
servers are asked its NS directly, one plain question each (see "asked directly" below).

HEALTH per record type:
  ok        the server answered: records, or NOERROR with none of this type (NODATA);
  nxdomain  NXDOMAIN for the name itself (no CNAME in the answer);
  failed    SERVFAIL, REFUSED, a timeout, no header, an unreadable answer, or dig missing.
A NXDOMAIN whose answer holds a CNAME is "ok" with `dead_target`: the name exists and points
at a target that does not (a dangling-name clue, never "gone"). A failed lookup is retried once.

NAME STATUS: exists (any type ok) | nxdomain (A and AAAA both nxdomain) | unknown (otherwise).

Values are normalized here, once, so every comparison downstream sees the same spelling:
lower case, trailing dot removed, TXT strings unquoted and joined, sorted, de-duplicated. The
TTL is kept as a note; it is never compared.

Usage: python3 dns_reading.py --names FILE --apex APEX --out FILE [--workers 8] [--previous FILE]
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

SCHEMA = "dns_readings_v1"
QTYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT")
HEALTH_OK, HEALTH_NX, HEALTH_FAILED = "ok", "nxdomain", "failed"
NAME_EXISTS, NAME_NX, NAME_UNKNOWN = "exists", "nxdomain", "unknown"
DIG_TIMEOUT_S = 15          # dig's own +time=3 +tries=2 ends sooner; this is the backstop
WORKERS = 8
RETRIES = 1

_HEADER = re.compile(r"->>HEADER<<-.*?status:\s*([A-Z]+)")
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _name(v: str) -> str:
    return (v or "").strip().lower().rstrip(".")


def normalize_value(qtype: str, rdata: str) -> str:
    """One record's data, in the one spelling every comparison uses. PURE."""
    q = qtype.upper()
    s = (rdata or "").strip()
    if q == "A":
        return s
    if q == "AAAA":
        try:
            return str(ipaddress.ip_address(s))
        except ValueError:
            return s.lower()
    if q in ("CNAME", "NS"):
        return _name(s)
    if q == "MX":
        parts = s.split()
        if len(parts) == 2 and parts[0].isdigit():
            return f"{int(parts[0])} {_name(parts[1])}"
        return _name(s)
    if q == "TXT":
        quoted = _QUOTED.findall(s)
        return "".join(quoted) if quoted else s
    return s


def normalize_values(qtype: str, values) -> list[str]:
    return sorted({normalize_value(qtype, v) for v in (values or []) if (v or "").strip()})


def parse_dig(output: str, qtype: str) -> dict:
    """Parse `dig +noall +comments +answer` output for one question. PURE.

    Returns {health, status, values, ttl[, cname_chain][, dead_target]}."""
    q = qtype.upper()
    m = _HEADER.search(output or "")
    if not m:
        return {"health": HEALTH_FAILED, "status": None, "values": [], "ttl": None}
    status = m.group(1)
    answers = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split(None, 4)
        if len(parts) < 5 or parts[2].upper() != "IN":
            continue
        try:
            ttl = int(parts[1])
        except ValueError:
            continue
        answers.append((ttl, parts[3].upper(), parts[4].strip()))
    chain = [normalize_value("CNAME", r[2]) for r in answers if r[1] == "CNAME"]
    mine = [r for r in answers if r[1] == q]
    out = {
        "status": status,
        "values": normalize_values(q, [r[2] for r in mine]),
        "ttl": min((r[0] for r in mine), default=None),
    }
    if status == "NOERROR":
        out["health"] = HEALTH_OK
    elif status == "NXDOMAIN":
        out["health"] = HEALTH_OK if chain else HEALTH_NX
        if chain:
            out["dead_target"] = chain[-1]
    else:
        out["health"] = HEALTH_FAILED
    if chain and q != "CNAME":
        out["cname_chain"] = chain
    return out


def run_dig(name: str, qtype: str) -> str:
    """Ask one question. Never raises: anything that goes wrong reads as no header (failed)."""
    try:
        p = subprocess.run(
            ["dig", "+noall", "+comments", "+answer", "+time=3", "+tries=2", qtype, name],
            capture_output=True, text=True, timeout=DIG_TIMEOUT_S,
        )
        return p.stdout or ""
    except Exception:  # noqa: BLE001 — timeout, dig missing: no answer, never a removal
        return ""


def _ask(runner, name: str, qtype: str) -> dict:
    r = parse_dig(runner(name, qtype), qtype)
    tries = 0
    while r["health"] == HEALTH_FAILED and tries < RETRIES:
        tries += 1
        r = parse_dig(runner(name, qtype), qtype)
    return r


def name_status(records: dict) -> str:
    """exists | nxdomain | unknown. NXDOMAIN needs two independent questions (A and AAAA). PURE."""
    if any((records.get(t.lower()) or {}).get("health") == HEALTH_OK for t in QTYPES):
        return NAME_EXISTS
    if all((records.get(t) or {}).get("health") == HEALTH_NX for t in ("a", "aaaa")):
        return NAME_NX
    return NAME_UNKNOWN


def read_name(name: str, *, apex: str = "", runner=None, now: str | None = None) -> dict:
    """Read one name: every record type with its health, plus DMARC for the apex."""
    runner = runner or run_dig
    name = _name(name)
    records = {qt.lower(): _ask(runner, name, qt) for qt in QTYPES}
    if apex and name == _name(apex):
        d = _ask(runner, "_dmarc." + name, "TXT")
        if d["health"] == HEALTH_NX:      # no _dmarc name at all = no policy: a real answer
            d = {"health": HEALTH_OK, "status": "NXDOMAIN", "values": [], "ttl": None}
        records["dmarc"] = d
    return {"name": name, "read_at": now or utc_now(), "name_status": name_status(records),
            "records": records}


def in_scope(name: str, apex: str) -> bool:
    n, a = _name(name), _name(apex)
    return bool(n) and bool(a) and (n == a or n.endswith("." + a))


# ── The apex's name servers, asked directly (job 5a, 2026-11-06) ─────────────────────────────
# WHY: sciimage.com and commandcommcentral.com kept answering two ways through the everyday
# lookup ("ns01" and "ns01 + ns02", the second with about 1,800 seconds left to live, the first
# with about 7,200), and every flip was written as a name-server change: four false rows on
# Command on Nov 6. "Seen twice in a row" would not have stopped them (sciimage.com read the
# two-server set three runs running). Howie, 2026-11-06 14:42: "I authorize discovery to query
# or ask each name server directly. I'm in favor of that."
# THE RULE: Sentry keeps the set it last COUNTED (ns_counted). When the everyday answer differs
# from it, each name server named in either set (and any server one of them names) is asked the
# same plain question directly, without recursion. A server has answered only when it answers for
# its own zone (authoritative, NOERROR, at least one name server). The counted set moves only
# when EVERY server asked has answered and they all give the same set. If they give different
# sets, nothing is counted and the disagreement is kept (ns_disagreement: which server says
# what, since when). If any server gives no answer, nothing is counted from this run. When the
# everyday answer matches the counted set, nothing is asked: no extra traffic on a quiet run.
# With no readable previous copy the count is unknown and nothing is asked: asked alone, a server
# agrees with itself (code review 2026-11-06, must-fix 1).
# Every count says where it came from (ns_counted_basis): "agreed" (the servers, asked directly,
# agreed on it) or "everyday" (copied from the everyday answer, on the first run under this rule).
# A copied count was never checked: the first run after push-418 copied sciimage.com's last
# everyday answer, ns01 + ns02, while commandcommcentral.com's servers, asked, both said ns01
# only. A change is written only between two agreed counts, so the first agreement after a copied
# count sets it quietly (read-back 2026-11-06 16:28; Howie 16:51 "yes", push-419).
# Plain NS questions about the apex only; no zone transfer, ever.
NS_ASK_MAX = 13                      # the most name servers asked about one zone in one run
NS_AGREE, NS_DISAGREE, NS_INCOMPLETE = "agree", "disagree", "incomplete"
BASIS_AGREED, BASIS_EVERYDAY = "agreed", "everyday"
_FLAGS = re.compile(r";;\s*flags:([^;]*);")


def run_dig_at(server: str, name: str, qtype: str) -> str:
    """Ask one name server one question directly, without recursion. Never raises."""
    try:
        p = subprocess.run(
            ["dig", "+noall", "+comments", "+answer", "+norecurse", "+time=3", "+tries=2",
             "@" + server, qtype, name],
            capture_output=True, text=True, timeout=DIG_TIMEOUT_S,
        )
        return p.stdout or ""
    except Exception:  # noqa: BLE001 — timeout, dig missing: no answer
        return ""


def parse_direct(output: str, qtype: str = "NS") -> dict:
    """parse_dig plus whether the server answered for its own zone (the aa flag). PURE."""
    r = parse_dig(output, qtype)
    m = _FLAGS.search(output or "")
    r["authoritative"] = bool(m) and "aa" in m.group(1).split()
    return r


def server_answered(r: dict) -> bool:
    """A direct answer counts only when the server answers for its own zone with name servers."""
    return (isinstance(r, dict) and r.get("health") == HEALTH_OK and r.get("status") == "NOERROR"
            and bool(r.get("authoritative")) and bool(r.get("values")))


def _ask_at(server_runner, server: str, name: str, qtype: str = "NS") -> dict:
    r = parse_direct(server_runner(server, name, qtype), qtype)
    tries = 0
    while not server_answered(r) and r["health"] == HEALTH_FAILED and tries < RETRIES:
        tries += 1
        r = parse_direct(server_runner(server, name, qtype), qtype)
    return r


def ask_name_servers(apex: str, servers, server_runner=None) -> dict:
    """Ask each server (and any server an answer names, up to NS_ASK_MAX) for the apex's NS."""
    server_runner = server_runner or run_dig_at
    apex = _name(apex)
    queue = sorted({_name(s) for s in (servers or []) if _name(s)})
    asked: dict[str, dict] = {}
    while queue and len(asked) < NS_ASK_MAX:
        s = queue.pop(0)
        if s in asked:
            continue
        r = _ask_at(server_runner, s, apex)
        asked[s] = {"health": r["health"], "status": r.get("status"),
                    "authoritative": bool(r.get("authoritative")), "values": r["values"], "ttl": r["ttl"]}
        if server_answered(r):
            queue = sorted(set(queue) | {v for v in r["values"] if v not in asked})
    answers = {s: tuple(e["values"]) for s, e in asked.items() if server_answered(e)}
    sets = set(answers.values())
    if len(sets) > 1:
        verdict, agreed = NS_DISAGREE, None
    elif len(sets) == 1 and len(answers) == len(asked) and not queue:
        verdict, agreed = NS_AGREE, list(next(iter(sets)))
    else:
        verdict, agreed = NS_INCOMPLETE, None
    return {"servers": asked, "verdict": verdict, "set": agreed}


def counted_basis(reading) -> str | None:
    """Where a reading's count came from: "agreed", "everyday", or None (no count). A reading
    written by push-418, before the basis was kept, is "agreed" only when its own run asked the
    servers and they agreed on that very set. PURE."""
    if not isinstance(reading, dict):
        return None
    c = reading.get("ns_counted")
    if not isinstance(c, list) or not normalize_values("NS", c):
        return None
    b = reading.get("ns_counted_basis")
    if b in (BASIS_AGREED, BASIS_EVERYDAY):
        return b
    chk = reading.get("ns_check") if isinstance(reading.get("ns_check"), dict) else {}
    if chk.get("verdict") == NS_AGREE and normalize_values("NS", chk.get("set")) == normalize_values("NS", c):
        return BASIS_AGREED
    return BASIS_EVERYDAY


def prev_ns_state(prev_reading) -> tuple:
    """(the set last counted, the disagreement kept, where the count came from) from the previous
    saved reading. A reading written before this rule has no ns_counted: its last good everyday
    answer is the count, copied ("everyday"), never checked."""
    if not isinstance(prev_reading, dict):
        return None, None, None
    dis = prev_reading.get("ns_disagreement")
    dis = dis if isinstance(dis, dict) else None
    if "ns_counted" in prev_reading:
        c = prev_reading.get("ns_counted")
        counted = (normalize_values("NS", c) or None) if isinstance(c, list) else None
        return counted, dis, (counted_basis(prev_reading) if counted else None)
    rec = (prev_reading.get("records") or {}).get("ns")
    if isinstance(rec, dict) and rec.get("health") == HEALTH_OK:
        counted = normalize_values("NS", rec.get("values")) or None
        return counted, dis, (BASIS_EVERYDAY if counted else None)
    return None, dis, None


def _last_everyday(prev_reading) -> list:
    rec = ((prev_reading or {}).get("records") or {}).get("ns") if isinstance(prev_reading, dict) else None
    if isinstance(rec, dict) and rec.get("health") == HEALTH_OK:
        return normalize_values("NS", rec.get("values"))
    return []


def ns_fields(prev_reading, resolver_rec, apex: str, server_runner=None, now: str | None = None) -> dict:
    """The apex reading's ns_counted / ns_disagreement (and ns_check when servers were asked).

    No previous saved reading (none yet, or the copy could not be read): the count is UNKNOWN and
    nothing is asked. A count set from scratch could rest on fewer servers than the one the
    database still holds, and comparing the two would write a false change (code review
    2026-11-06, must-fix 1). When the count is unknown, the previous everyday answer's servers are
    asked too, and a count set from scratch is marked ns_counted_fresh: it is never compared on
    the run that set it."""
    if not isinstance(prev_reading, dict):
        return {"ns_counted": None, "ns_counted_basis": None, "ns_disagreement": None}
    counted, dis, basis = prev_ns_state(prev_reading)
    out = {"ns_counted": counted, "ns_counted_basis": basis, "ns_disagreement": dis}
    if not isinstance(resolver_rec, dict) or resolver_rec.get("health") != HEALTH_OK:
        return out                                   # no everyday answer: nothing to go on
    everyday = normalize_values("NS", resolver_rec.get("values"))
    if everyday == (counted or []):
        return out                                   # the quiet case: nothing is asked
    now = now or utc_now()
    ask = set(everyday) | set(counted or [])
    if counted is None:
        ask |= set(_last_everyday(prev_reading))
    check = ask_name_servers(apex, ask, server_runner)
    check.update({"asked_at": now, "everyday_answer": everyday, "counted_before": counted})
    out["ns_check"] = check
    if check["verdict"] == NS_AGREE:
        out["ns_counted"], out["ns_disagreement"] = check["set"], None
        out["ns_counted_basis"] = BASIS_AGREED      # checked now, even when the set did not move
        if counted is None:
            out["ns_counted_fresh"] = True
    elif check["verdict"] == NS_DISAGREE:
        out["ns_disagreement"] = {
            "first_seen": (dis or {}).get("first_seen") or now, "last_seen": now,
            "answers": {s: (e["values"] if server_answered(e) else None)
                        for s, e in sorted(check["servers"].items())}}
    return out


def read_names(names, apex: str, *, runner=None, workers: int = WORKERS,
               prev_readings: dict | None = None, server_runner=None) -> dict:
    todo = sorted({_name(n) for n in names if in_scope(n, apex)})
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        got = list(ex.map(lambda n: read_name(n, apex=apex, runner=runner), todo))
    readings = {r["name"]: r for r in got}
    a = _name(apex)
    if a in readings:
        prev = (prev_readings or {}).get(a) if isinstance(prev_readings, dict) else None
        readings[a].update(ns_fields(prev, readings[a]["records"].get("ns"), a, server_runner,
                                     readings[a].get("read_at")))
    return {"schema": SCHEMA, "apex": a, "read_at": utc_now(), "readings": readings}


def load_prev_readings(path) -> dict:
    """The previous saved copy's dns_readings; {} when there is none or it cannot be read."""
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {}
    r = doc.get("dns_readings") if isinstance(doc, dict) else None
    return r if isinstance(r, dict) else {}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="DNS readings with health (job 5a)")
    ap.add_argument("--names", required=True)
    ap.add_argument("--apex", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=WORKERS)
    ap.add_argument("--previous", default="", help="the previous saved copy (for the counted name servers)")
    a = ap.parse_args(argv)
    with open(a.names, encoding="utf-8") as fh:
        names = [ln.strip() for ln in fh if ln.strip()]
    doc = read_names(names, a.apex, workers=a.workers, prev_readings=load_prev_readings(a.previous))
    tmp = a.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
    os.replace(tmp, a.out)            # all or nothing: a half-written file never exists
    st = {}
    for r in doc["readings"].values():
        st[r["name_status"]] = st.get(r["name_status"], 0) + 1
    print(f"dns readings: {len(doc['readings'])} name(s) {st}", file=sys.stderr)
    ap_r = doc["readings"].get(doc["apex"]) or {}
    chk = ap_r.get("ns_check")
    if chk:
        print(f"name servers asked directly: {len(chk['servers'])}, {chk['verdict']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
