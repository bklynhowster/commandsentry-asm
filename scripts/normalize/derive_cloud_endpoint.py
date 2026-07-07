#!/usr/bin/env python3
"""
derive_cloud_endpoint.py — ASM cloud-endpoint classifier (4.7 ruling D6).

Pure function. Given ONE subdomain record from a data/assets/*.json file, decide
whether it is a cloud/CDN endpoint and which provider, using the registry at
scripts/asm/cloud_providers.yaml.

Signal priority (D6): CNAME suffix > ASN / asn_org > IP prefix. The ASM already
records hosts[].asn / hosts[].asn_org per IP, so ASN/org is the strong signal.
Microsoft is disambiguated O365-vs-Azure by CNAME / mail ports / IP range.
CloudFront / Azure-CDN CNAMEs override rotating=false (they DO rotate).

Returns {"cloud_provider": <id>, "is_cloud_endpoint": <bool>} or None (not cloud).

Consumer (next step): the asset importer stamps assets.is_cloud_endpoint /
cloud_provider / cloud_source='derived' / cloud_endpoint_classified_at at UPSERT —
WITHOUT overwriting a manual flag. cloud_source='manual' is sticky; a derived vs
manual disagreement is logged for review, never auto-applied (mirrors kind_drift,
4.7 D9).

Deferred to v1.1 (4.7 rulings E4): cert-SAN signal (superseded by ASN — 4.7 E1),
volatility backstop, weekly re-eval (superseded by per-import re-derivation, E6).
Codified volatility-backstop TRIGGER (4.7 E4): add it when any single asset produces
>5 IP add/remove alerts in one scan AND is not already classified cloud. Also v1.1:
Microsoft-ASN services beyond O365/Azure (Teams/SharePoint/Graph) will need their own
disambiguation rows as the fleet grows (4.7 E3).

Self-test: `python3 scripts/normalize/derive_cloud_endpoint.py [asset_file.json]`
(defaults to data/assets/commandcompanies.json).
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

REGISTRY_PATH = Path(__file__).resolve().parent.parent / "asm" / "cloud_providers.yaml"
MAIL_PORTS = {"25", "465", "587", "993", "995", "110", "143"}


def load_registry(path: Path = REGISTRY_PATH) -> dict:
    if yaml is None:
        raise RuntimeError("PyYAML required to read cloud_providers.yaml")
    data = yaml.safe_load(path.read_text()) or {}
    return {
        "providers": data.get("providers") or {},
        "rotating_cname_overrides": data.get("rotating_cname_overrides") or [],
    }


def _signals(sub: dict) -> dict:
    dns = sub.get("dns") or {}
    hosts = sub.get("hosts") or []
    ips = set(dns.get("a") or []) | set(dns.get("aaaa") or [])
    for h in hosts:
        if h.get("ip"):
            ips.add(h["ip"])
    asn_orgs = {(h.get("asn_org") or "").lower() for h in hosts if h.get("asn_org")}
    asns = {(h.get("asn") or "").upper() for h in hosts if h.get("asn")}
    cn = dns.get("cname")
    if isinstance(cn, list):
        cname = (cn[0] if cn else "").lower()
    else:
        cname = (cn or "").lower()
    ports = {str(s.get("port")) for s in (sub.get("services") or []) if s.get("port") is not None}
    return {"ips": ips, "asn_orgs": asn_orgs, "asns": asns, "cname": cname, "ports": ports}


def _cname_match(cname: str, provider: dict) -> bool:
    return bool(cname) and any(cname.endswith(sfx) for sfx in (provider.get("cname_suffixes") or []))


def _asn_match(sig: dict, provider: dict) -> bool:
    if sig["asns"] & set(provider.get("asns") or []):
        return True
    pats = provider.get("asn_org_patterns") or []
    return any(pat in org for org in sig["asn_orgs"] for pat in pats)


def _ip_match(sig: dict, provider: dict) -> bool:
    pfx = tuple(provider.get("ip_prefixes") or [])
    return bool(pfx) and any(ip.startswith(pfx) for ip in sig["ips"])


def _disambiguate(hits: list, sig: dict, providers: dict) -> str:
    """When the Microsoft ASN matches both O365 and Azure, pick by signal."""
    ms = [h for h in hits if h in ("microsoft_o365", "azure")]
    if len(ms) <= 1:
        return hits[0]
    if _cname_match(sig["cname"], providers.get("microsoft_o365", {})):
        return "microsoft_o365"
    if _cname_match(sig["cname"], providers.get("azure", {})):
        return "azure"
    if sig["ports"] & MAIL_PORTS:
        return "microsoft_o365"
    if _ip_match(sig, providers.get("microsoft_o365", {})):
        return "microsoft_o365"
    return "azure"


def classify(sub: dict, registry: dict) -> dict | None:
    providers = registry.get("providers") or registry  # tolerate raw providers dict
    overrides = registry.get("rotating_cname_overrides") or []
    sig = _signals(sub)

    for tier in (_cname_match, _asn_match, _ip_match):
        if tier is _cname_match:
            hits = [pid for pid, p in providers.items() if _cname_match(sig["cname"], p)]
        elif tier is _asn_match:
            hits = [pid for pid, p in providers.items() if _asn_match(sig, p)]
        else:
            hits = [pid for pid, p in providers.items() if _ip_match(sig, p)]
        if hits:
            pid = _disambiguate(hits, sig, providers)
            prov = providers[pid]
            rotating = bool(prov.get("rotating"))
            # CloudFront / Azure-CDN etc. rotate even inside a static-cloud provider
            if not rotating and any(sig["cname"].endswith(o) for o in overrides):
                rotating = True
            return {"cloud_provider": pid, "is_cloud_endpoint": rotating}
    return None


def _selftest(asset_path: Path) -> int:
    import json
    reg = load_registry()
    d = json.loads(asset_path.read_text())
    subs = d.get("subdomains") or []
    print(f"# {asset_path.name}: {len(subs)} subdomain(s)")
    for s in subs:
        r = classify(s, reg)
        orgs = sorted({(h.get("asn_org") or "") for h in (s.get("hosts") or []) if h.get("asn_org")})
        print(f"  {s.get('name'):40s} asn_org={orgs}  -> {r}")
    return 0


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent.parent
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "data" / "assets" / "commandcompanies.json"
    sys.exit(_selftest(target))
