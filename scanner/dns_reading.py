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
it is given (the caller's list is already scope-verified; this re-checks the suffix).

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

Usage: python3 dns_reading.py --names FILE --apex APEX --out FILE [--workers 8]
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


def read_names(names, apex: str, *, runner=None, workers: int = WORKERS) -> dict:
    todo = sorted({_name(n) for n in names if in_scope(n, apex)})
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        got = list(ex.map(lambda n: read_name(n, apex=apex, runner=runner), todo))
    return {"schema": SCHEMA, "apex": _name(apex), "read_at": utc_now(),
            "readings": {r["name"]: r for r in got}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="DNS readings with health (job 5a)")
    ap.add_argument("--names", required=True)
    ap.add_argument("--apex", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=WORKERS)
    a = ap.parse_args(argv)
    with open(a.names, encoding="utf-8") as fh:
        names = [ln.strip() for ln in fh if ln.strip()]
    doc = read_names(names, a.apex, workers=a.workers)
    tmp = a.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
    os.replace(tmp, a.out)            # all or nothing: a half-written file never exists
    st = {}
    for r in doc["readings"].values():
        st[r["name_status"]] = st.get(r["name_status"], 0) + 1
    print(f"dns readings: {len(doc['readings'])} name(s) {st}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
