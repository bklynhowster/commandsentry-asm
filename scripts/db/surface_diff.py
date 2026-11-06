#!/usr/bin/env python3
"""surface_diff.py — shared ASM-surface port-event diff (Obsidian 225, 4.7-ruled 2026-09-05).

ONE source of truth for turning a surface_data blob into asset_surface_event rows, used by
BOTH producers of surface state:

  * import_asm_to_surface.py  — the ASM discovery importer (source_tag='asm_discover').
  * run_light/medium/heavy    — the scanner surface write-back (source_tag='scanner_<tier>'),
                                per 225 (Option B: a scan writes the surface it observed).

225's LOAD-BEARING rule (4.7 Q6): each producer diffs against ITS OWN prior baseline, NEVER
cross-producer. A thin scan diffed against a fuller discover baseline would emit false
port_closed for every port it didn't scan — fleet-wide on the first run. The functions here
are baseline-AGNOSTIC: the caller passes `existing_blob` (its own prior), so the guard lives
at the call site (the scanner passes surface_data->'_scanner'->'<tier>', asm-discover passes
the top-level surface_data). This module never fetches a baseline itself.

PURE + psycopg-FREE on purpose: run_light imports this at module scope and must not eagerly
pull psycopg (it lazy-imports it). compute_events therefore takes a `json_wrap` callable
(the caller passes psycopg's Json); the default is identity so unit tests need no DB deps.
"""
from __future__ import annotations


def _identity(x):
    return x


# ── Service identity = (subdomain, port, proto). IP is DETAIL, never identity (4.7 J2). ──────────
def flatten_services(blob: dict) -> dict[tuple[str, int, str], dict]:
    """Walk a surface_data blob → map keyed by (subdomain, port, proto) → service detail.

    4.7 J1/J2 (2026-07-08): (J1) UNION subdomains[].services[] (live shape) with the legacy
    subdomains[].hosts[].services[] shape — do NOT if/else, the host-nested branch alone
    flattened nothing on real assets. (J2) identity is (subdomain, port, proto); the per-service
    `ip` rotates on cloud endpoints and is detail only, so a rotating pool collapses to one tuple
    per (subdomain, port) and never churns port events. Empty dict on any unparseable blob."""
    out: dict[tuple[str, int, str], dict] = {}
    if not isinstance(blob, dict):
        return out
    subs = blob.get("subdomains") or []
    if not isinstance(subs, list):
        return out

    for sub in subs:
        if not isinstance(sub, dict):
            continue
        sub_name = sub.get("name") or sub.get("subdomain") or "?"
        # UNION both shapes (J1) — host-nested is legacy/defensive; subdomain-level is live.
        svcs: list = []
        for h in (sub.get("hosts") or []):
            if isinstance(h, dict):
                svcs.extend(h.get("services") or [])
        svcs.extend(sub.get("services") or [])
        for svc in svcs:
            _record_service(out, sub_name, svc)

    return out


def _record_service(
    out: dict[tuple[str, int, str], dict],
    subdomain: str,
    svc: dict,
) -> None:
    if not isinstance(svc, dict):
        return
    try:
        port = int(svc.get("port"))
    except (TypeError, ValueError):
        return
    proto = (svc.get("protocol") or svc.get("proto") or "tcp").lower()
    # J2(A) — IP-agnostic identity. The rotating per-service IP is detail, NOT key.
    key = (subdomain, port, proto)
    # First-wins: multiple IPs serving the same (subdomain, port, proto) collapse to one tuple.
    if key in out:
        return
    out[key] = {
        "host": subdomain,
        "subdomain": subdomain,
        "ip": svc.get("ip"),          # detail only (may rotate); never identity
        "port": port,
        "proto": proto,
        "service": svc.get("service") or svc.get("name"),
        "tls": bool(svc.get("tls")),
    }


def _subdomain_naabu_ok(blob: dict) -> dict[str, bool]:
    """4.7 J5a — per-subdomain port-scanner health from probe_status. port_closed is gated on
    naabu having SUCCEEDED for that subdomain THIS scan; if it didn't, the port set is UNKNOWN
    and closes must carry forward (G1 at the port grain). naabu-ONLY (httpx/fingerprintx failing
    doesn't invalidate port existence). Fail-closed: missing/malformed → not ok."""
    out: dict[str, bool] = {}
    if not isinstance(blob, dict):
        return out
    for sub in (blob.get("subdomains") or []):
        if not isinstance(sub, dict):
            continue
        name = sub.get("name") or sub.get("subdomain") or "?"
        naabu = (sub.get("probe_status") or {}).get("naabu") or {}
        out[name] = bool(naabu.get("ok"))
    return out


def compute_events(
    asset_id: str,
    existing_blob: dict | None,
    new_blob: dict,
    source_tag: str,
    json_wrap=_identity,
    skip_port_names=frozenset(),
) -> list[dict]:
    """Return asset_surface_event row dicts (ready for executemany), diffing existing→new.

    225 (4.7 Q6): `existing_blob` is the CALLER'S OWN prior baseline (per-producer, never
    cross-producer). `json_wrap` wraps prev/new_value for jsonb insert (caller passes psycopg
    Json; default identity for tests).

    Rules:
      - existing_blob is None (this producer never saw the asset) → one asset_first_seen row and
        NOTHING else (no flood, and — the 225 guard — no false port_closed on a first write).
      - both present → port_opened for keys in new not in old; port_closed for keys in old not in
        new, EXCEPT where the new scan's naabu was not ok for that subdomain (J5a fail-closed).
      - job 5a (plan v3 C): a subdomain in `skip_port_names` MOVED this run (its address set
        changed, significantly: dns_changes). Comparing two different addresses' ports is not a
        port opening or closing, so NEITHER direction is written for it; the move event carries
        both addresses' ports instead."""
    if existing_blob is None:
        return [
            {
                "asset_id": asset_id,
                "event_type": "asset_first_seen",
                "host": None,
                "port": None,
                "proto": None,
                "service": None,
                "tls": None,
                "prev_value": None,
                "new_value": None,
                "source_tag": source_tag,
            }
        ]

    old_map = flatten_services(existing_blob)
    new_map = flatten_services(new_blob)
    # J5a — port_closed gated on the NEW scan's naabu health per subdomain; port_opened is NOT
    # (G2: a degraded/empty scan can't fabricate a port).
    new_naabu_ok = _subdomain_naabu_ok(new_blob)

    events: list[dict] = []

    skip = frozenset(skip_port_names or ())

    for key in new_map.keys() - old_map.keys():
        if key[0] in skip:
            continue
        det = new_map[key]
        events.append(
            {
                "asset_id": asset_id,
                "event_type": "port_opened",
                "host": det["host"],
                "port": det["port"],
                "proto": det["proto"],
                "service": det.get("service"),
                "tls": det.get("tls"),
                "prev_value": None,
                "new_value": json_wrap(det),
                "source_tag": source_tag,
            }
        )

    for key in old_map.keys() - new_map.keys():
        # J5a — a subdomain whose naabu failed/absent this scan has an UNTRUSTWORTHY port set →
        # carry forward as UNKNOWN, emit NO port_closed (G1 pattern; the 225 fail-closed rule).
        if not new_naabu_ok.get(key[0], False):
            continue
        if key[0] in skip:
            continue
        det = old_map[key]
        events.append(
            {
                "asset_id": asset_id,
                "event_type": "port_closed",
                "host": det["host"],
                "port": det["port"],
                "proto": det["proto"],
                "service": det.get("service"),
                "tls": det.get("tls"),
                "prev_value": json_wrap(det),
                "new_value": None,
                "source_tag": source_tag,
            }
        )

    return events


# Event INSERT SQL — shared so both producers write asset_surface_event identically (single
# source; plain SQL string, psycopg-free). import_asm_to_surface keeps its own identical constant.
EVENT_INSERT_SQL = """
INSERT INTO public.asset_surface_event (
  asset_id, event_type, host, port, proto, service, tls,
  prev_value, new_value, source_tag
) VALUES (
  %(asset_id)s, %(event_type)s, %(host)s, %(port)s, %(proto)s, %(service)s, %(tls)s,
  %(prev_value)s, %(new_value)s, %(source_tag)s
);
"""


# ── Scanner surface blob builder (225 Option B) ─────────────────────────────────────────────────
# Turns a scanner's own scan results into a surface_data blob in the SAME shape flatten_services
# reads, so the scanner reuses compute_events verbatim. Kept minimal: the scanner knows its host,
# the open ports naabu found, and whether naabu succeeded. Per-port detail (service/tls) is
# optional and carried as detail only (never identity, per J2).
SCANNER_SURFACE_SCHEMA = "scanner_surface_v1"


def build_scanner_surface_blob(
    hostname: str,
    open_ports,
    naabu_ok: bool,
    coverage: str,
    source_tag: str,
    port_detail: dict | None = None,
) -> dict:
    """Build a scanner surface_data blob (one subdomain = the scanned host).

    - `open_ports`: iterable of ints naabu saw open (svc identity = (host, port, 'tcp')).
    - `naabu_ok`: did naabu SUCCEED this scan? False → J5a suppresses port_closed downstream
      (a scan that couldn't port-scan must never close ports). A scan with 0 ports but naabu_ok
      True is a legitimate "nothing open" observation; naabu_ok False is "couldn't look".
    - `coverage`: 'partial' (light — thin top-ports) | 'full' (medium/heavy). Recorded for
      coverage-honesty (4.7 Q5); consumers must not present partial as full.
    - `port_detail`: optional {port: {'service':..., 'tls':bool}} to enrich (detail only).
    """
    detail = port_detail or {}
    services = []
    for p in sorted({int(x) for x in (open_ports or [])}):
        d = detail.get(p) or detail.get(str(p)) or {}
        services.append({
            "port": p,
            "protocol": "tcp",
            "service": d.get("service"),
            "tls": bool(d.get("tls")),
        })
    return {
        "schema": SCANNER_SURFACE_SCHEMA,
        "source": source_tag,
        "coverage": coverage,
        "subdomains": [{
            "name": hostname,
            "probe_status": {"naabu": {"ok": bool(naabu_ok)}},
            "services": services,
        }],
    }


# ── Job 5a: DNS changes (plan v3 sections 0, B, C, D; review 2026-11-05 13:44) ──────────────────
# Howie 2026-11-05 09:25: "we need to scan for it, compare it, report on it". discovery records
# where every name points (scanner/dns_reading.py, with each lookup's health) and this compares
# the run's readings with discovery's OWN previous readings (225's rule: the caller passes the
# apex surface blob discovery itself wrote). ONE pipeline, in this order:
#   1. a record type is compared only when BOTH readings OBSERVED it this time: health ok and not
#      carried (a carried record is the last good one, kept because this run's lookup failed).
#      A failed lookup is never a removal (lesson 58's twin for DNS).
#   2. values are compared in one spelling (lower case, no trailing dot, sorted); TTL is a note.
#   3. an address change is significant only when it means the name moved:
#        - a name that is a CNAME to the same target on both sides did not move (its addresses
#          are the target's business: Office 365, Azure Front Door rotate every run);
#        - a cloud endpoint or CDN moved only when its provider or its addresses' owner changed
#          (provider compared as text: Command's column is an enum, Prodex's is text);
#        - anything else: the set changed, it moved.
#   4. "gone" is when the name's run of NXDOMAIN answers (nx_streak, kept by the normalizer)
#      reaches 2 between the baseline and now: the second "no such name" in a row, said once even
#      if a failed write held the baseline back a run. NODATA, a dead CNAME target or a failed
#      lookup are never gone. "back" is the first answer after gone.
# Switching back and forth (D) is not an event: it is read later from these address events.
# PURE: no database, no network.

DNS_EVENT_TYPES = {
    "address": "dns_address_changed",
    "cname": "dns_cname_changed",
    "ns": "dns_ns_changed",
    "mx": "dns_mx_changed",
    "mail_policy": "dns_mail_policy_changed",
    "gone": "dns_name_gone",
    "back": "dns_name_back",
}
GONE_STREAK = 2


def _norm_values(values) -> tuple:
    return tuple(sorted({str(v).strip().lower().rstrip(".") for v in (values or []) if str(v).strip()}))


def _rec(reading: dict, key: str) -> dict | None:
    r = ((reading or {}).get("records") or {}).get(key)
    return r if isinstance(r, dict) else None


def _observed(rec) -> bool:
    return isinstance(rec, dict) and rec.get("health") == "ok" and not rec.get("carried")


def _values_if_observed(reading: dict, key: str):
    r = _rec(reading, key)
    return _norm_values(r.get("values")) if _observed(r) else None


def _addresses(reading: dict):
    a, aaaa = _values_if_observed(reading, "a"), _values_if_observed(reading, "aaaa")
    if a is None or aaaa is None:
        return None
    return tuple(sorted(set(a) | set(aaaa)))


def _mail_policy(reading: dict):
    txt = _values_if_observed(reading, "txt")
    if txt is None:
        return None
    spf = tuple(v for v in txt if v.startswith("v=spf1"))
    if _rec(reading, "dmarc") is None:
        return (spf, None)
    dmarc = _values_if_observed(reading, "dmarc")
    if dmarc is None:
        return None
    return (spf, tuple(v for v in dmarc if v.startswith("v=dmarc1")))


def _owners(reading: dict, addrs) -> frozenset | None:
    """Who holds the addresses, from discovery's own ipinfo read; None when any is unknown."""
    own = (reading or {}).get("owners") or {}
    names = set()
    for ip in addrs or ():
        o = own.get(ip) or {}
        label = (o.get("asn_org") or o.get("asn") or "").strip().lower()
        if not label:
            return None
        names.add(label)
    return frozenset(names)


def _provider(v) -> str:
    return str(v or "").strip().lower()


def address_move_is_significant(old: dict, new: dict, old_addrs, new_addrs, cloud: dict | None) -> bool:
    """Step 3 of the pipeline. PURE."""
    oc, nc = _values_if_observed(old, "cname"), _values_if_observed(new, "cname")
    if oc and nc and oc == nc:
        return False
    c = cloud or {}
    o_cloud, o_prov = (c.get("old") or (False, None))
    n_cloud, n_prov = (c.get("new") or (False, None))
    if o_cloud or n_cloud:
        if _provider(o_prov) != _provider(n_prov):
            return True
        oo, no = _owners(old, old_addrs), _owners(new, new_addrs)
        return oo is not None and no is not None and oo != no
    return True


def _summary(reading: dict) -> dict:
    return {"read_at": (reading or {}).get("read_at"), "name_status": (reading or {}).get("name_status")}


# The apex's name servers (job 5a, 2026-11-06; Howie 14:42: "I authorize discovery to query or ask
# each name server directly"). discovery keeps the set it last COUNTED (ns_counted), which moves
# only when every name server, asked directly, gives the same new set (scanner/dns_reading.py).
# A change is the counted set moving, never the everyday answer flipping. Both readings must
# carry ns_counted: the first run under this rule sets the baseline quietly (its previous reading
# holds only the everyday answer, which may be one side of a flip), and a counted set that is not
# known yet (None: no readable previous copy, or the servers never agreed) is never compared, nor
# is a count set from scratch on the run that set it (ns_counted_fresh; code review 2026-11-06).
# Readings with no ns_counted on either side (the saved copies before this rule, the history
# load) keep the everyday comparison.
# A change is written only between two AGREED counts (ns_counted_basis; readings written by
# push-418 before the basis was kept are agreed only when their own run's servers agreed on that
# set). A count copied from the everyday answer on the first run was never checked: the first
# agreement after it sets the count quietly (read-back 2026-11-06 16:28; Howie 16:51, push-419).
def _counted(reading: dict):
    c = (reading or {}).get("ns_counted")
    return (_norm_values(c) or None) if isinstance(c, list) else None


def _ns_basis(reading: dict):
    """"agreed" / "everyday" / None, as scanner/dns_reading.py counted_basis. PURE."""
    r = reading if isinstance(reading, dict) else {}
    c = _norm_values(r.get("ns_counted")) if isinstance(r.get("ns_counted"), list) else ()
    if not c:
        return None
    if r.get("ns_counted_basis") in ("agreed", "everyday"):
        return r["ns_counted_basis"]
    chk = r.get("ns_check") if isinstance(r.get("ns_check"), dict) else {}
    if chk.get("verdict") == "agree" and _norm_values(chk.get("set")) == c:
        return "agreed"
    return "everyday"


def _counted_ns_change(name: str, o: dict, n: dict) -> dict | None:
    if "ns_counted" not in o or "ns_counted" not in n:
        return None
    if n.get("ns_counted_fresh"):        # set from scratch this run: never compared (review 2026-11-06)
        return None
    if _ns_basis(o) != "agreed" or _ns_basis(n) != "agreed":   # a copied count is never compared (push-419)
        return None
    ov, nv = _counted(o), _counted(n)
    if ov is None or nv is None or ov == nv:
        return None
    servers = {s: e.get("values") for s, e in sorted(((n.get("ns_check") or {}).get("servers") or {}).items())}
    return {"name": name, "kind": "ns",
            "old": {**_summary(o), "values": list(ov), "ttl": (_rec(o, "ns") or {}).get("ttl")},
            "new": {**_summary(n), "values": list(nv), "ttl": (_rec(n, "ns") or {}).get("ttl"),
                    "servers": servers}}


def dns_changes(old_readings: dict | None, new_readings: dict | None, cloud: dict | None = None,
                apex: str = "") -> list[dict]:
    """The significant DNS changes between discovery's previous readings and this run's. PURE.

    `cloud` = {name: {"old": (is_cloud, provider), "new": (is_cloud, provider)}}.
    `apex`: name servers are compared for the apex only (the zone's own NS; a name inside the
    zone answers with the zone's, or its CNAME target's, which would repeat the apex's change).
    Returns [{name, kind, old, new, ...}], kind in DNS_EVENT_TYPES, sorted by name then kind."""
    old_r = old_readings if isinstance(old_readings, dict) else {}
    new_r = new_readings if isinstance(new_readings, dict) else {}
    cloud = cloud or {}
    out: list[dict] = []
    for name in sorted(set(old_r) & set(new_r)):
        o, n = old_r[name], new_r[name]
        if not isinstance(o, dict) or not isinstance(n, dict) or n.get("carried"):
            continue
        if n.get("name_status") == "nxdomain":
            if int(n.get("nx_streak") or 0) >= GONE_STREAK > int(o.get("nx_streak") or 0):
                out.append({"name": name, "kind": "gone", "old": _summary(o),
                            "new": {**_summary(n), "nx_streak": int(n.get("nx_streak") or 0)}})
            continue
        if n.get("name_status") != "exists":
            continue
        if int(o.get("nx_streak") or 0) >= GONE_STREAK:
            out.append({"name": name, "kind": "back", "old": {**_summary(o), "nx_streak": int(o.get("nx_streak") or 0)},
                        "new": _summary(n)})
            continue
        if o.get("name_status") != "exists":
            continue
        oa, na = _addresses(o), _addresses(n)
        if oa is not None and na is not None and oa != na and address_move_is_significant(o, n, oa, na, cloud.get(name)):
            out.append({"name": name, "kind": "address",
                        "old": {**_summary(o), "values": list(oa), "owners": (o.get("owners") or {}),
                                "ttl": (_rec(o, "a") or {}).get("ttl")},
                        "new": {**_summary(n), "values": list(na), "owners": (n.get("owners") or {}),
                                "ttl": (_rec(n, "a") or {}).get("ttl")}})
        apex_l = str(apex or "").strip().lower().rstrip(".")
        for kind in ("cname", "ns", "mx"):
            if kind == "ns" and apex_l and name != apex_l:
                continue
            if kind == "ns" and apex_l and ("ns_counted" in o or "ns_counted" in n):
                ns = _counted_ns_change(name, o, n)
                if ns:
                    out.append(ns)
                continue
            ov, nv = _values_if_observed(o, kind), _values_if_observed(n, kind)
            if ov is not None and nv is not None and ov != nv:
                out.append({"name": name, "kind": kind,
                            "old": {**_summary(o), "values": list(ov), "ttl": (_rec(o, kind) or {}).get("ttl")},
                            "new": {**_summary(n), "values": list(nv), "ttl": (_rec(n, kind) or {}).get("ttl")}})
        op, np_ = _mail_policy(o), _mail_policy(n)
        if op is not None and np_ is not None and op != np_:
            out.append({"name": name, "kind": "mail_policy",
                        "old": {**_summary(o), "spf": list(op[0]), "dmarc": None if op[1] is None else list(op[1])},
                        "new": {**_summary(n), "spf": list(np_[0]), "dmarc": None if np_[1] is None else list(np_[1])}})
    return out


def moved_names(changes) -> frozenset:
    """The names whose address changed significantly: compute_events writes no port events for them."""
    return frozenset(c["name"] for c in (changes or []) if c.get("kind") == "address")


def change_fingerprint(change: dict) -> str:
    """One stable id per change (kind, name, what it was, what it is): the say-once record and
    the backfill's logical identity both use it (plan v3 E, F). PURE."""
    import hashlib
    import json as _json
    def core(side):
        side = dict(side or {})
        side.pop("read_at", None)
        side.pop("ttl", None)
        side.pop("owners", None)
        side.pop("nx_streak", None)
        side.pop("servers", None)        # the direct answers are evidence, not identity
        return side
    blob = _json.dumps([change.get("kind"), change.get("name"), core(change.get("old")), core(change.get("new"))],
                       sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def dns_event_rows(changes, asset_id_of, source_tag: str, json_wrap=_identity,
                   ports_old: dict | None = None, ports_new: dict | None = None,
                   old_seen_at: str | None = None, old_address_now: dict | None = None) -> list[dict]:
    """asset_surface_event rows for the changes. A change whose name has no asset row
    (asset_id_of returns None) is skipped: the event table needs a real asset. For a move, the
    old address is described from discovery's own saved record (its ports, when last seen), and
    from its OWN record only when it is itself an owned asset (old_address_now); nothing here
    probes anything. PURE."""
    ports_old, ports_new, now_map = ports_old or {}, ports_new or {}, old_address_now or {}
    rows: list[dict] = []
    for c in changes or []:
        aid = asset_id_of(c["name"])
        if not aid:
            continue
        prev, new = dict(c.get("old") or {}), dict(c.get("new") or {})
        if c["kind"] == "address":
            prev["ports"] = ports_old.get(c["name"], [])
            prev["last_seen"] = old_seen_at
            prev["owned_address_now"] = {ip: now_map[ip] for ip in prev.get("values") or [] if ip in now_map}
            new["ports"] = ports_new.get(c["name"], [])
        new["fingerprint"] = change_fingerprint(c)
        rows.append({
            "asset_id": aid,
            "event_type": DNS_EVENT_TYPES[c["kind"]],
            "host": c["name"],
            "port": None,
            "proto": None,
            "service": None,
            "tls": None,
            "prev_value": json_wrap(prev),
            "new_value": json_wrap(new),
            "source_tag": source_tag,
        })
    return rows


def ports_by_name(blob: dict | None, names) -> dict[str, list[dict]]:
    """{name: [{ip, port, proto}]} for the given subdomains of a surface blob. PURE."""
    want = set(names or ())
    out: dict[str, list[dict]] = {}
    for (sub, port, proto), det in sorted(flatten_services(blob or {}).items()):
        if sub in want:
            out.setdefault(sub, []).append({"ip": det.get("ip"), "port": port, "proto": proto})
    return out


def legacy_readings(blob: dict | None) -> dict:
    """Readings rebuilt from a saved copy made BEFORE job 5a (its best-effort dnsx `dns` block,
    with no health). For the one-time history load (E) and the replay gate only. Because those
    lookups were best-effort, an EMPTY record set there is NOT KNOWN: only a non-empty set counts
    as observed (the addresses: when either A or AAAA is non-empty, both are taken as read), and
    a name is never nxdomain here, so the history load can never write a removal or a "gone".
    PURE."""
    out: dict[str, dict] = {}
    if not isinstance(blob, dict):
        return out
    seen_at = (blob.get("scan") or {}).get("completed_at")
    for s in blob.get("subdomains") or []:
        if not isinstance(s, dict) or not s.get("name"):
            continue
        d = s.get("dns") or {}
        recs: dict[str, dict] = {}
        a, aaaa = list(d.get("a") or []), list(d.get("aaaa") or [])
        if a or aaaa:
            recs["a"] = {"health": "ok", "values": sorted(set(a))}
            recs["aaaa"] = {"health": "ok", "values": sorted(set(aaaa))}
        if d.get("cname"):
            recs["cname"] = {"health": "ok", "values": [str(d["cname"])]}
        mx = [f"{m.get('priority', 0)} {m.get('host', '')}" if isinstance(m, dict) else str(m)
              for m in (d.get("mx") or [])]
        if mx:
            recs["mx"] = {"health": "ok", "values": sorted(set(mx))}
        if d.get("ns"):
            recs["ns"] = {"health": "ok", "values": sorted(set(d["ns"]))}
        if d.get("txt"):
            recs["txt"] = {"health": "ok", "values": sorted(set(d["txt"]))}
        owners = {h["ip"]: {"asn": h.get("asn"), "asn_org": h.get("asn_org")}
                  for h in (s.get("hosts") or []) if isinstance(h, dict) and h.get("ip")
                  and (h.get("asn") or h.get("asn_org"))}
        name = str(s["name"]).strip().lower().rstrip(".")
        out[name] = {"name": name, "read_at": seen_at, "name_status": "exists" if recs else "unknown",
                     "records": recs, "owners": owners, "legacy": True}
    return out

