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
) -> list[dict]:
    """Return asset_surface_event row dicts (ready for executemany), diffing existing→new.

    225 (4.7 Q6): `existing_blob` is the CALLER'S OWN prior baseline (per-producer, never
    cross-producer). `json_wrap` wraps prev/new_value for jsonb insert (caller passes psycopg
    Json; default identity for tests).

    Rules:
      - existing_blob is None (this producer never saw the asset) → one asset_first_seen row and
        NOTHING else (no flood, and — the 225 guard — no false port_closed on a first write).
      - both present → port_opened for keys in new not in old; port_closed for keys in old not in
        new, EXCEPT where the new scan's naabu was not ok for that subdomain (J5a fail-closed)."""
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

    for key in new_map.keys() - old_map.keys():
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
