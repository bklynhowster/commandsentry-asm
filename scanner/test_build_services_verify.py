"""4.7 J6/K1–K5+K3′ anchor tests — service-verify phantom-port suppression.

The load-bearing invariant: DROP a naabu port only when it's a genuine phantom
(no fingerprintx, no httpx, cloud-LB scope) AND both naabu+fingerprintx ran clean.
A degraded probe NEVER drops (absence of evidence ≠ evidence of absence). A bug
here silently drops a REAL service from inventory — hence these tests.

Run:  python3 scanner/test_build_services_verify.py
  or: pytest scanner/test_build_services_verify.py -q
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import normalize  # noqa: E402

GCP_IP = "35.227.202.53"        # nmap-confirmed GCP LB (demo.prodexlabs.com)
GCP_ATTR = {"ip": GCP_IP, "asn": "AS15169", "asn_org": "Google LLC",
            "reverse_dns": "53.202.227.35.bc.googleusercontent.com"}
NONCLOUD_IP = "208.199.0.160"   # a self-hosted IP (Unimac), no cloud signal
NONCLOUD_ATTR = {"ip": NONCLOUD_IP, "asn": "AS6128", "asn_org": "Cablevision",
                 "reverse_dns": "host.example.net"}


def _jsonl(path: Path, records: list[dict]):
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


def run_bs(naabu_ports, fpx_ports, httpx_ports, ip, attr, *, naabu_ok=True, fpx_ok=True,
           cname="", scope=None, monkeypatch_env=None):
    """Build a tmp work dir and run build_services; return the set of kept ports."""
    import os
    if scope is not None:
        os.environ["SERVICE_VERIFY_SCOPE"] = scope
    else:
        os.environ.pop("SERVICE_VERIFY_SCOPE", None)
    normalize._cloud_providers_cache = None  # force reload per test
    with tempfile.TemporaryDirectory() as d:
        w = Path(d)
        _jsonl(w / "naabu.json", [{"host": ip, "port": p, "protocol": "tcp"} for p in naabu_ports])
        _jsonl(w / "fingerprintx.json", [{"host": ip, "port": p, "protocol": "http"} for p in fpx_ports])
        _jsonl(w / "httpx.json", [{"port": p, "status_code": 200} for p in httpx_ports])
        _jsonl(w / "dnsx.json", [{"cname": [cname] if cname else []}])
        (w / "_probe_status.json").write_text(json.dumps({
            "naabu": {"ok": True} if naabu_ok else {"degraded": "naabu_rc_1"},
            "fingerprintx": {"ok": True} if fpx_ok else {"degraded": "fpx_rc_1"},
        }))
        svcs = normalize.build_services(w, {ip: attr})
    return {s["port"] for s in svcs}


# ─── is_in_cloud_lb_scope (K3′ signal-set) ──────────────────────────────────
def test_scope_matches_each_signal_independently():
    prov = normalize._load_cloud_providers()
    assert normalize.is_in_cloud_lb_scope({"asn": "AS15169"}, "", prov)                       # ASN
    assert normalize.is_in_cloud_lb_scope({"asn_org": "Google LLC"}, "", prov)                # asn_org
    assert normalize.is_in_cloud_lb_scope({"reverse_dns": "x.bc.googleusercontent.com"}, "", prov)  # rDNS
    assert normalize.is_in_cloud_lb_scope({}, "y.googleusercontent.com", prov)                # CNAME
    assert normalize.is_in_cloud_lb_scope({"ip": "104.16.1.1"}, "", prov)                     # IP-prefix (Cloudflare)


def test_scope_rdns_only_host_caught_via_cname_suffixes():
    # rDNS present, no asn/asn_org/cname → must still match via cname_suffixes-as-rDNS.
    prov = normalize._load_cloud_providers()
    assert normalize.is_in_cloud_lb_scope(
        {"reverse_dns": "53.202.227.35.bc.googleusercontent.com"}, "", prov)


def test_scope_noncloud_is_false():
    prov = normalize._load_cloud_providers()
    assert not normalize.is_in_cloud_lb_scope(NONCLOUD_ATTR, "host.example.net", prov)
    assert not normalize.is_in_cloud_lb_scope({}, "", prov)   # ipinfo-fail → empty → False


# ─── build_services verify gate (K1/K2/K4) ──────────────────────────────────
def test_phantom_dropped_on_gcp():
    kept = run_bs([80, 443, 6692], [80, 443], [80, 443], GCP_IP, GCP_ATTR)
    assert kept == {80, 443}, kept   # 6692 phantom dropped


def test_real_nonstandard_kept_when_fpx_confirms():
    kept = run_bs([80, 443, 9200], [80, 443, 9200], [80, 443], GCP_IP, GCP_ATTR)
    assert kept == {80, 443, 9200}, kept


def test_degraded_fingerprintx_drops_nothing():
    kept = run_bs([80, 443, 6692], [80, 443], [80, 443], GCP_IP, GCP_ATTR, fpx_ok=False)
    assert kept == {80, 443, 6692}, kept   # fpx not clean → keep all (K4)


def test_degraded_naabu_drops_nothing():
    kept = run_bs([80, 443, 6692], [80, 443], [80, 443], GCP_IP, GCP_ATTR, naabu_ok=False)
    assert kept == {80, 443, 6692}, kept   # naabu not clean → keep all (K1 entry gate)


def test_noncloud_out_of_scope_keeps_all():
    kept = run_bs([80, 443, 6692], [80, 443], [80, 443], NONCLOUD_IP, NONCLOUD_ATTR)
    assert kept == {80, 443, 6692}, kept   # not in cloud-LB scope → no drops


def test_httpx_on_weird_port_kept():
    kept = run_bs([80, 443, 8888], [80, 443], [80, 443, 8888], GCP_IP, GCP_ATTR)
    assert kept == {80, 443, 8888}, kept   # 8888 httpx-confirmed → real, kept


def test_all_phantom_host_empty_fpx_keeps_all():
    # fpx empty → asm-discover would set fpx.ok=false → K4 → keep all (conservative).
    kept = run_bs([80, 443, 6692], [], [], GCP_IP, GCP_ATTR, fpx_ok=False)
    assert kept == {80, 443, 6692}, kept


def test_scope_off_keeps_all():
    kept = run_bs([80, 443, 6692], [80, 443], [80, 443], GCP_IP, GCP_ATTR, scope="off")
    assert kept == {80, 443, 6692}, kept


def test_all_ports_scope_drops_phantom_even_noncloud():
    kept = run_bs([80, 443, 6692], [80, 443], [80, 443], NONCLOUD_IP, NONCLOUD_ATTR, scope="all_ports")
    assert kept == {80, 443}, kept   # all_ports escape hatch verifies everywhere


if __name__ == "__main__":
    import os
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok {name}")
    os.environ.pop("SERVICE_VERIFY_SCOPE", None)
    print("all build_services verify anchor tests PASSED")
