"""4.7 J1/J2(A)/J3 anchor tests — asset_surface_event port-event identity.

compute_events → flatten_services keys service identity on (subdomain, port, proto),
NOT on the rotating per-service IP. These tests LOCK that design:

  * test_rotating_ip_pool_emits_zero_events — LOAD-BEARING (4.7 J2 pushback). A cloud
    endpoint whose IP pool fully rotates between scans while serving the same ports
    must emit ZERO port events. If someone regresses to IP-in-identity ("more
    precise"), this breaks and forces a design conversation — it's the exact churn
    class the cloud-endpoint suppression (D6-F5) killed.
  * test_real_port_* — a genuine port appearing/disappearing at the (subdomain, port)
    grain emits exactly one port_opened / port_closed.
  * test_flatten_reads_sublevel_services — J1: services are read from
    subdomains[].services[] (current blob shape), which the old if/else missed.

Run:  python3 scripts/db/test_compute_events_identity.py
  or: pytest scripts/db/test_compute_events_identity.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from import_asm_to_surface import flatten_services, compute_events  # noqa: E402

PORTS = [25, 80, 110, 143, 443, 587, 993, 995]
POOL_A = [f"40.104.2.{i}" for i in range(1, 25)]     # 24 O365 IPs "today"
POOL_B = [f"52.96.10.{i}" for i in range(1, 25)]     # a fully different 24 "tomorrow"


def _blob(ip_port_pairs, naabu_ok=True):
    """surface_data shaped like the live ASM blob: a subdomain with hosts[]
    (IP/geo metadata, NO services) AND services[] (the real list, each carrying
    its own possibly-rotating ip), plus per-subdomain probe_status (J5a gate)."""
    ips = sorted({ip for ip, _ in ip_port_pairs})
    return {"subdomains": [{
        "name": "email.commandcompanies.com",
        "probe_status": {"naabu": {"ok": naabu_ok}, "httpx_tech": {"ok": True}},
        "reachability": {"live": True, "http_status": 403},
        "hosts": [{"ip": ip, "asn": "AS8075", "asn_org": "Microsoft Corporation"} for ip in ips],
        "services": [
            {"ip": ip, "port": p, "protocol": "tcp",
             "service": "smtp" if p == 25 else "http",
             "tls": p in (443, 587, 993, 995)}
            for ip, p in ip_port_pairs
        ],
    }]}


def test_flatten_reads_sublevel_services():
    # J1 — the live blob carries services at subdomains[].services[]; the prior
    # if(hosts) branch read hosts[].services[] and found nothing (DB: 0 of 32).
    m = flatten_services(_blob([(POOL_A[0], p) for p in PORTS]))
    assert len(m) == len(PORTS), m
    assert all(k[0] == "email.commandcompanies.com" for k in m), \
        f"identity host must be the subdomain, got {list(m)[:3]}"


def test_rotating_ip_pool_emits_zero_events():
    # J2(A)/J3 LOAD-BEARING — full IP rotation, identical port menu → NO events.
    old = _blob([(ip, p) for ip in POOL_A for p in PORTS])   # 24 x 8 = 192 svc rows
    new = _blob([(ip, p) for ip in POOL_B for p in PORTS])   # different 24 IPs, same 8 ports
    events = compute_events("email.commandcompanies.com", old, new, "test")
    assert events == [], \
        f"IP rotation must not churn port events; got {[(e['event_type'], e['port']) for e in events]}"


def test_real_port_close_emits_one_event():
    old = _blob([(POOL_A[0], p) for p in PORTS])
    new = _blob([(POOL_A[0], p) for p in PORTS if p != 995])  # 995 genuinely gone
    events = compute_events("email.commandcompanies.com", old, new, "test")
    assert len(events) == 1 and events[0]["event_type"] == "port_closed" \
        and events[0]["port"] == 995, events


def test_real_port_open_emits_one_event():
    old = _blob([(POOL_A[0], p) for p in PORTS])
    new = _blob([(POOL_A[0], p) for p in PORTS] + [(POOL_A[0], 8443)])
    events = compute_events("email.commandcompanies.com", old, new, "test")
    assert len(events) == 1 and events[0]["event_type"] == "port_opened" \
        and events[0]["port"] == 8443, events


def test_first_seen_only_on_new_asset():
    # existing_blob None → exactly one asset_first_seen, nothing else (no flood).
    events = compute_events("x.prodexlabs.com", None, _blob([(POOL_A[0], 443)]), "test")
    assert len(events) == 1 and events[0]["event_type"] == "asset_first_seen", events


def test_j5a_degraded_scan_suppresses_port_closed():
    # 4.7 J5a — naabu failed on the NEW scan → the port set is UNKNOWN, so a port
    # that "disappeared" must NOT emit port_closed (carry forward). This is the
    # false-removal class (G1) at the port grain.
    old = _blob([(POOL_A[0], p) for p in PORTS])
    new = _blob([(POOL_A[0], p) for p in PORTS if p != 995], naabu_ok=False)
    events = compute_events("email.commandcompanies.com", old, new, "test")
    assert events == [], \
        f"degraded scan must not emit port_closed; got {[(e['event_type'], e['port']) for e in events]}"


def test_j5a_missing_probe_status_fails_closed():
    # No probe_status at all (shape drift / older blob) → treat as naabu-not-ok →
    # suppress port_closed. Absence of evidence isn't evidence of absence.
    old = _blob([(POOL_A[0], p) for p in PORTS])
    new = _blob([(POOL_A[0], p) for p in PORTS if p != 995])
    del new["subdomains"][0]["probe_status"]
    events = compute_events("email.commandcompanies.com", old, new, "test")
    assert events == [], f"missing probe_status must fail closed; got {events}"


def test_j5a_does_not_gate_port_opened():
    # port_opened is NOT gated (G2 — adds can't be false removals). Documents the
    # asymmetry: even on a naabu-failed scan, a genuinely new port still opens.
    old = _blob([(POOL_A[0], p) for p in PORTS])
    new = _blob([(POOL_A[0], p) for p in PORTS] + [(POOL_A[0], 8443)], naabu_ok=False)
    events = compute_events("email.commandcompanies.com", old, new, "test")
    assert [e["event_type"] for e in events] == ["port_opened"] and events[0]["port"] == 8443, events


if __name__ == "__main__":
    test_flatten_reads_sublevel_services()
    test_rotating_ip_pool_emits_zero_events()
    test_real_port_close_emits_one_event()
    test_real_port_open_emits_one_event()
    test_first_seen_only_on_new_asset()
    test_j5a_degraded_scan_suppresses_port_closed()
    test_j5a_missing_probe_status_fails_closed()
    test_j5a_does_not_gate_port_opened()
    print("all compute_events identity anchor tests PASSED")
