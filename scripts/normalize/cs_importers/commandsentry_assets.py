"""
commandsentry_assets.py — Import COMMANDsentry asset JSONs into canonical records.

COMMANDsentry's web/data/*.json files are the existing source-of-truth for
ASM state: apex domains, subdomains, hosts, services, and per-scan history.
This importer reads them and produces flat canonical entity records that
the eventual SPA + Postgres can join against findings.

Output files (under --output dir):
    assets.jsonl     — one line per COMMANDsentry asset
    subdomains.jsonl — one line per (asset, subdomain)
    hosts.jsonl      — one line per (asset, subdomain, IP)
    services.jsonl   — one line per (asset, subdomain, IP, port)
    asm_scans.jsonl  — one line per scan event from history[]
                       (separate from scans.jsonl which holds vuln-scan events)

Asset identity convention:
    apex domain → canonical asset_id = the FQDN value (e.g. commandcommcentral.com)
    single IP   → canonical asset_id = "ip:<dotted>" (e.g. ip:24.157.51.68)
    IP range    → canonical asset_id = "ip-range:<name>"

This matches the `infer_asset_id` convention in parsers/common.py — meaning
findings tied to `commandcommcentral.com` will join correctly with this
asset record by foreign-key.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


# ─── organization mapping ─────────────────────────────────────────────────────
# Best-effort assignment of each asset to a Command-family organization.
# Unknowns get "unknown" — don't fabricate.
ORG_BY_FQDN_SUFFIX = {
    "commandcommcentral.com":             "command_digital",
    "commanddigital.com":                 "command_digital",
    "commandcompanies.com":               "command_companies",
    "commandmarketinginnovations.com":    "command_marketing",
    "commandmarketing.com":               "command_marketing",
    "commandfinancial.com":               "command_financial",
    "commandmissouri.com":                "command_missouri",
    "unimacgraphics.com":                 "unimac",
    "sciimage.com":                       "sci",
    "commandweb.com":                     "unknown",  # ownership uncertain per recon notes
}

# IP ranges flagged as Command Digital from the recon (cablenet + naturalwireless)
ORG_BY_IP_PREFIX = [
    ("24.157.51.", "command_digital"),    # CABLE-NET-1 block A
    ("24.38.70.",  "command_digital"),    # CABLE-NET-1 block B
    ("52.119.65.", "command_digital"),    # NATURALWIRELESS failover
    ("70.39.251.", "command_digital"),    # Hivelocity (old commandcompanies origin)
    ("199.16.172.", "automattic"),         # Pressable CDN — not Command-owned
    ("199.16.173.", "automattic"),
]


def _infer_organization(asset_block: dict) -> str:
    atype = asset_block.get("type") or ""
    val = (asset_block.get("value") or "").lower()
    if atype == "apex":
        for suffix, org in ORG_BY_FQDN_SUFFIX.items():
            if val == suffix or val.endswith("." + suffix):
                return org
        return "unknown"
    if atype == "ip":
        for prefix, org in ORG_BY_IP_PREFIX:
            if val.startswith(prefix):
                return org
        return "unknown"
    return "unknown"


def _canonical_asset_id(asset_block: dict) -> str:
    """Translate COMMANDsentry asset.id/value into the canonical ID form."""
    atype = asset_block.get("type") or ""
    val = (asset_block.get("value") or "").lower()
    if atype == "apex":
        return val or asset_block.get("id") or "unknown"
    if atype == "ip":
        return f"ip:{val}"
    return val or asset_block.get("id") or "unknown"


def _canonical_asset_type(asset_block: dict) -> str:
    atype = asset_block.get("type") or "apex"
    # Canonical types: apex_domain, single_host, ip, ip_range, mail_server, vpn_endpoint, api_host
    if atype == "apex":
        return "apex_domain"
    if atype == "ip":
        return "ip"
    return atype


# ─── importer ─────────────────────────────────────────────────────────────────
def import_asset_file(asset_path: Path) -> dict:
    """
    Read one COMMANDsentry asset JSON and return a dict with all the canonical
    records flattened:
        {
            "asset":      {...},
            "subdomains": [...],
            "hosts":      [...],
            "services":   [...],
            "scans":      [...],   # one per history entry
        }
    """
    out = {"asset": None, "subdomains": [], "hosts": [], "services": [], "scans": []}
    try:
        data = json.loads(asset_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return out

    asset_block = data.get("asset") or {}
    if not asset_block:
        return out

    canon_id = _canonical_asset_id(asset_block)
    canon_type = _canonical_asset_type(asset_block)
    org = _infer_organization(asset_block)
    history = data.get("history") or []

    first_observed: Optional[str] = None
    last_observed: Optional[str] = None
    if history:
        first_observed = history[0].get("started_at") or history[0].get("completed_at")
        last_observed = history[-1].get("completed_at") or history[-1].get("started_at")

    out["asset"] = {
        "asset_id":         canon_id,
        "commandsentry_id": asset_block.get("id"),
        "name":             asset_block.get("value") or canon_id,
        "type":             canon_type,
        "organization":     org,
        "owner":            asset_block.get("owner"),
        "tags":             asset_block.get("tags") or [],
        "notes":            asset_block.get("notes"),
        "discovered_via":   asset_block.get("discovered_via"),
        "first_observed":   first_observed,
        "last_observed":    last_observed,
        "current_risk":     "UNKNOWN",  # set later by an asset-rollup pass that joins with findings
        "source":           "commandsentry_asm",
        "source_path":      str(asset_path),
    }

    # Subdomains, hosts, services from the CURRENT-state subdomains[] block.
    # (history entries capture older snapshots; we use the top-level subdomains
    # array for canonical "current state".)
    subs = data.get("subdomains") or []
    for sub in subs:
        sub_name = sub.get("name")
        if not sub_name:
            continue
        out["subdomains"].append({
            "asset_id":         canon_id,
            "name":             sub_name,
            "alive":            bool(sub.get("alive")),
            "is_root":          bool(sub.get("is_root")),
            "first_discovered": sub.get("first_discovered"),
            "last_seen":        sub.get("last_seen"),
            "discovered_via":   sub.get("discovered_via"),
            "tags":             sub.get("tags") or [],
            "reachability":     sub.get("reachability"),
            "server":           (sub.get("fingerprint") or {}).get("server"),
            "platform_label":   (sub.get("fingerprint") or {}).get("platform_label"),
            "waf":              sub.get("waf"),
        })
        for host in (sub.get("hosts") or []):
            ip = host.get("ip")
            if not ip:
                continue
            out["hosts"].append({
                "asset_id":     canon_id,
                "subdomain":    sub_name,
                "ip":           ip,
                "asn":          host.get("asn"),
                "asn_org":      host.get("asn_org"),
                "country":      host.get("country"),
                "region":       host.get("region"),
                "city":         host.get("city"),
                "reverse_dns":  host.get("reverse_dns"),
                "is_private":   bool(host.get("is_private")),
            })
        for svc in (sub.get("services") or []):
            ip = svc.get("ip")
            port = svc.get("port")
            if not ip or not isinstance(port, int):
                continue
            out["services"].append({
                "asset_id":   canon_id,
                "subdomain":  sub_name,
                "host_ip":    ip,
                "port":       port,
                "protocol":   svc.get("protocol") or "tcp",
                "service":    svc.get("service"),
                "banner":     svc.get("banner"),
                "tls":        bool(svc.get("tls")),
            })

    # ASM scan history → one canonical scan record per history entry
    for h in history:
        scan_id_str = h.get("scan_id") or ""
        out["scans"].append({
            "scan_id":      f"{canon_id}__asm:{scan_id_str}",
            "asset_id":     canon_id,
            "scan_type":    "asm_enumeration",
            "started_at":   h.get("started_at"),
            "completed_at": h.get("completed_at"),
            "command_line": None,
            "exit_code":    None,
            "output_dir":   str(asset_path),
            "tools_run":    [],  # ASM scanner is a single engine; doesn't split tools
            "source":       "commandsentry_asm",
            "notes":        None,
            "summary": {
                "subdomain_count":      h.get("subdomain_count"),
                "live_subdomain_count": h.get("live_subdomain_count"),
                "host_count":           h.get("host_count"),
                "service_count":        h.get("service_count"),
            },
        })

    return out


def run_import(manifest: dict, output_dir: Path) -> dict:
    """
    Import every COMMANDsentry asset JSON listed in the manifest's
    `commandsentry_assets` block and write the canonical JSONL files.

    Returns a stats dict for the run summary.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    cs_entries = manifest.get("commandsentry_assets") or []
    assets: list[dict] = []
    subdomains: list[dict] = []
    hosts: list[dict] = []
    services: list[dict] = []
    scans: list[dict] = []

    for entry in cs_entries:
        json_path = Path(entry.get("json_path") or "")
        if not json_path.is_file():
            continue
        result = import_asset_file(json_path)
        if result.get("asset"):
            assets.append(result["asset"])
        subdomains.extend(result.get("subdomains") or [])
        hosts.extend(result.get("hosts") or [])
        services.extend(result.get("services") or [])
        scans.extend(result.get("scans") or [])

    # Write JSONL files
    def write_jsonl(filename: str, records: list[dict]):
        path = output_dir / filename
        if records:
            path.write_text("\n".join(json.dumps(r, separators=(",", ":")) for r in records) + "\n")
        else:
            path.write_text("")

    write_jsonl("assets.jsonl", assets)
    write_jsonl("subdomains.jsonl", subdomains)
    write_jsonl("hosts.jsonl", hosts)
    write_jsonl("services.jsonl", services)
    write_jsonl("asm_scans.jsonl", scans)

    return {
        "assets":     len(assets),
        "subdomains": len(subdomains),
        "hosts":      len(hosts),
        "services":   len(services),
        "asm_scans":  len(scans),
    }
