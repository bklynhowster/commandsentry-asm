#!/usr/bin/env python3
"""
COMMANDsentry — normalize raw tool outputs into v3 ASM asset JSON.

v3 model: asset = apex domain. Subdomains are nested children, each with
its own hosts/services/cert/WAF/fingerprint.

For apex targets, asm-discover.sh produces per-subdomain working dirs under
$work_dir/subs/{subdomain}/. This script walks each, builds a subdomain
record, and rolls them up under the asset.

For fqdn / ip / cidr targets: produces a single-subdomain v3 record so
the schema is uniform.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "3.0"
ENGINE_VERSION = "3.0.0"

# ─── Utilities ────────────────────────────────────────────────────────────────

def utc_now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def read_jsonl(path: Path) -> list[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    out: list[dict] = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                out.append(obj)
            elif isinstance(obj, list):
                out.extend(x for x in obj if isinstance(x, dict))
        except json.JSONDecodeError:
            continue
    return out

def read_json(path: Path) -> dict | list | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        return json.loads(path.read_text(errors="replace"))
    except json.JSONDecodeError:
        return None

def read_text(path: Path) -> str:
    return path.read_text(errors="replace") if path.exists() else ""

# ─── Whois parsing ────────────────────────────────────────────────────────────

WHOIS_PATTERNS = {
    "registrar": [
        r"^(?:[Rr]egistrar|[Rr]egistrar\s*Name):\s*(.+?)\s*$",
        r"^Sponsoring\s+Registrar:\s*(.+?)\s*$",
    ],
    "registrar_url": [r"^(?:[Rr]egistrar\s*URL|[Rr]egistrar\s*WWW):\s*(.+?)\s*$"],
    "created": [
        r"^Creation\s*Date:\s*(.+?)(?:T|\s|$)",
        r"^Created\s*On:\s*(.+?)(?:T|\s|$)",
    ],
    "updated": [r"^Updated\s*Date:\s*(.+?)(?:T|\s|$)"],
    "expires": [
        r"^Registry\s+Expiry\s+Date:\s*(.+?)(?:T|\s|$)",
        r"^Registrar\s+Registration\s+Expiration\s+Date:\s*(.+?)(?:T|\s|$)",
        r"^Expir(?:y|ation)\s*Date:\s*(.+?)(?:T|\s|$)",
    ],
    "status": [r"^(?:Domain\s+)?Status:\s*([a-zA-Z]+)"],
}

def parse_whois_domain(text: str) -> dict:
    out: dict[str, Any] = {}
    if not text:
        return out
    for field, patterns in WHOIS_PATTERNS.items():
        for pat in patterns:
            m = re.search(pat, text, re.MULTILINE)
            if m:
                out[field] = m.group(1).strip()
                break
    return out

# ─── ASN / geo via ipinfo ────────────────────────────────────────────────────

def lookup_ip_attribution(ip: str, cache: dict) -> dict:
    if ip in cache:
        return cache[ip]
    out: dict[str, Any] = {"ip": ip}
    try:
        req = urllib.request.Request(
            f"https://ipinfo.io/{ip}/json",
            headers={"User-Agent": "commandsentry-asm/3.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        org = data.get("org") or ""
        m = re.match(r"^(AS\d+)\s+(.+)$", org)
        if m:
            out["asn"], out["asn_org"] = m.group(1), m.group(2)
        elif org:
            out["asn_org"] = org
        out["country"] = data.get("country")
        out["region"]  = data.get("region")
        out["city"]    = data.get("city")
        out["reverse_dns"] = data.get("hostname")
    except Exception as e:
        print(f"WARN: ipinfo lookup failed for {ip}: {e}", file=sys.stderr)
    try:
        out["is_private"] = ipaddress.ip_address(ip).is_private
    except Exception:
        out["is_private"] = False
    cache[ip] = out
    return out

# ─── Tech categorization ─────────────────────────────────────────────────────

CATEGORY_HINTS = {
    "wordpress": "cms", "drupal": "cms", "joomla": "cms",
    "wpbakery": "wp-plugin", "yoast seo": "wp-plugin",
    "slider revolution": "wp-plugin", "wpmu dev smush": "wp-plugin",
    "imagely nextgen gallery": "wp-plugin", "elementor": "wp-plugin",
    "elementor pro": "wp-plugin", "oceanwp": "wp-theme",
    "bootstrap": "frontend", "jquery": "frontend",
    "jquery migrate": "frontend", "font awesome": "frontend",
    "modernizr": "frontend",
    "nginx": "webserver", "apache": "webserver", "iis": "webserver",
    "microsoft-iis": "webserver",
    "cloudflare": "cdn", "wp engine": "hosting", "wp.cloud": "hosting",
    "wpcomstaging": "hosting", "jsdelivr": "cdn",
    "google tag manager": "tracking",
    "php": "language", "mysql": "database",
    "asp.net": "framework", "asp.net core": "framework",
    "microsoft asp.net": "framework", "microsoft power bi": "tracking",
    "hsts": "security", "http/3": "transport",
}

def categorize(name: str) -> str | None:
    return CATEGORY_HINTS.get((name or "").strip().lower())

# ─── Section builders (per-subdomain) ────────────────────────────────────────

def build_reachability(work: Path) -> dict:
    httpx_records = read_jsonl(work / "httpx.json")
    if not httpx_records:
        return {"live": False, "http_status": None, "title": None}
    rec = httpx_records[0]
    return {
        "live":        bool(rec.get("status_code")),
        "http_status": rec.get("status_code"),
        "title":       rec.get("title"),
    }

def build_hosts(work: Path, ip_cache: dict) -> list[dict]:
    dnsx_records = read_jsonl(work / "dnsx.json")
    ips: set[str] = set()
    for rec in dnsx_records:
        ips.update(rec.get("a", []) or [])
        ips.update(rec.get("aaaa", []) or [])
    resolved_file = work / "_resolved_ips.txt"
    if resolved_file.exists():
        for line in resolved_file.read_text().splitlines():
            line = line.strip()
            if line:
                ips.add(line)
    return [lookup_ip_attribution(ip, ip_cache) for ip in sorted(ips)]

PORT_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

def infer_service(port: int) -> str:
    return PORT_HINTS.get(port, "unknown")

def extract_cert_from_testssl(findings: list[dict]) -> dict | None:
    cert: dict[str, Any] = {}
    for f in findings:
        fid, val = f.get("id", ""), f.get("finding", "")
        if fid == "cert_subject":     cert["subject"] = val
        elif fid == "cert_issuer":    cert["issuer"]  = val
        elif fid == "cert_subjectAltName":
            cert["san"] = [s.strip() for s in str(val).split() if s.strip()]
        elif fid == "cert_notBefore": cert["not_before"] = val
        elif fid == "cert_notAfter":  cert["not_after"]  = val
    if not cert:
        return None
    if cert.get("not_after"):
        try:
            ext = datetime.strptime(cert["not_after"][:24], "%b %d %H:%M:%S %Y")
            cert["days_to_expiry"] = (ext - datetime.utcnow()).days
        except Exception:
            pass
    cert.setdefault("self_signed", False)
    return cert

def extract_cert_from_httpx(rec: dict) -> dict | None:
    tls = rec.get("tls") or rec.get("tls_grab") or {}
    if not tls:
        return None
    cert: dict[str, Any] = {
        "subject":   tls.get("subject_dn") or tls.get("subject_cn"),
        "issuer":    tls.get("issuer_dn")  or tls.get("issuer_cn"),
        "san":       tls.get("subject_an", []) or tls.get("dns_names", []),
        "not_before": tls.get("not_before"),
        "not_after":  tls.get("not_after"),
        "self_signed": tls.get("self_signed", False),
    }
    if cert["not_after"]:
        try:
            ext = datetime.fromisoformat(str(cert["not_after"]).replace("Z", "+00:00"))
            cert["days_to_expiry"] = (ext - datetime.now(tz=timezone.utc)).days
        except Exception:
            pass
    return cert if any(cert.values()) else None

def build_services(work: Path) -> list[dict]:
    services: list[dict] = []
    seen: set[tuple[str, int, str]] = set()

    naabu = read_jsonl(work / "naabu.json") or read_jsonl(work / "naabu_cidr.json")
    fpx   = read_jsonl(work / "fingerprintx.json")

    fpx_by_key: dict[tuple[str, int], dict] = {}
    for rec in fpx:
        host = rec.get("host") or rec.get("ip") or rec.get("address")
        port = rec.get("port")
        if host and port:
            fpx_by_key[(host, int(port))] = rec

    cert_443: dict | None = None
    testssl_data = read_json(work / "testssl.json")
    if isinstance(testssl_data, list) and testssl_data:
        cert_443 = extract_cert_from_testssl(testssl_data)
    if not cert_443:
        httpx_records = read_jsonl(work / "httpx.json")
        if httpx_records:
            cert_443 = extract_cert_from_httpx(httpx_records[0])

    for rec in naabu:
        host = rec.get("host") or rec.get("ip") or rec.get("address")
        port = rec.get("port")
        proto = rec.get("protocol") or "tcp"
        if not host or port is None:
            continue
        key = (host, int(port), proto)
        if key in seen:
            continue
        seen.add(key)

        fpx_rec = fpx_by_key.get((host, int(port)))
        service_name = (fpx_rec.get("protocol") if fpx_rec else infer_service(int(port)))
        banner = (fpx_rec or {}).get("metadata", {}).get("banner") if fpx_rec else None

        svc: dict[str, Any] = {
            "ip":       host,
            "port":     int(port),
            "protocol": proto,
            "service":  service_name,
            "banner":   banner,
            "tls":      bool((fpx_rec or {}).get("tls")) or int(port) in (443, 8443, 993, 995),
        }
        if int(port) == 443 and cert_443:
            svc["cert"] = cert_443
        services.append(svc)

    services.sort(key=lambda s: (s["ip"], s["port"]))
    return services

def build_dns(work: Path) -> dict:
    out: dict[str, Any] = {
        "a": [], "aaaa": [], "cname": None, "mx": [], "ns": [], "txt": [],
        "spf": None, "dnssec": False,
    }
    dnsx_records = read_jsonl(work / "dnsx.json")
    if not dnsx_records:
        return out
    rec = dnsx_records[0]
    out["a"]    = rec.get("a", []) or []
    out["aaaa"] = rec.get("aaaa", []) or []
    cnames = rec.get("cname", []) or []
    out["cname"] = cnames[0] if cnames else None
    for mx_str in rec.get("mx", []) or []:
        parts = mx_str.split(None, 1)
        if len(parts) == 2:
            try:
                out["mx"].append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
            except ValueError:
                out["mx"].append({"priority": 0, "host": mx_str})
    out["ns"]  = [n.rstrip(".") for n in (rec.get("ns", []) or [])]
    out["txt"] = rec.get("txt", []) or []
    for txt in out["txt"]:
        if txt.lower().startswith("v=spf1"):
            out["spf"] = txt
    return out

def build_fingerprint(work: Path) -> dict:
    httpx_records = read_jsonl(work / "httpx.json")
    out: dict[str, Any] = {"server": None, "platform_label": None, "tech": []}
    if not httpx_records:
        return out
    rec = httpx_records[0]
    out["server"] = rec.get("webserver") or rec.get("server")

    techs_raw = rec.get("technologies", []) or rec.get("tech", []) or []
    for t in techs_raw:
        if isinstance(t, str):
            name, version = (t.split(":", 1) + [None])[:2]
            out["tech"].append({"name": name.strip(), "version": (version or "").strip() or None, "category": categorize(name)})
        elif isinstance(t, dict):
            out["tech"].append({
                "name": t.get("name"),
                "version": t.get("version"),
                "category": categorize(t.get("name", "")) or t.get("category"),
            })

    names = [t.get("name", "").lower() for t in out["tech"]]
    if "wordpress" in names and "wp.cloud" in names:
        out["platform_label"] = "WordPress on wp.cloud (Pressable)"
    elif "wordpress" in names and "wp engine" in names:
        out["platform_label"] = "WordPress on WP Engine"
    elif "wordpress" in names:
        out["platform_label"] = "WordPress"
    elif any("asp.net" in n for n in names):
        out["platform_label"] = "Microsoft .NET / IIS"
    return out

def build_waf(work: Path) -> dict:
    out = {"detected": False, "vendor": None, "confidence": "unknown"}
    waf_data = read_json(work / "wafw00f.json")
    if not waf_data:
        return out
    if isinstance(waf_data, list) and waf_data:
        first = waf_data[0]
        if first.get("detected") or first.get("firewall"):
            out["detected"] = True
            out["vendor"] = first.get("firewall") or first.get("manufacturer")
            out["confidence"] = "high"
    elif isinstance(waf_data, dict):
        if waf_data.get("detected") or waf_data.get("firewall"):
            out["detected"] = True
            out["vendor"] = waf_data.get("firewall") or waf_data.get("manufacturer")
            out["confidence"] = "high"
    return out

# ─── Build subdomain record ──────────────────────────────────────────────────

def build_probe_status(work: Path) -> dict:
    """Per-tool probe health for this host THIS scan, read from `_probe_status.json`
    ({tool: {"ok": true} | {"degraded": "<reason>"}}, written by the scanner).
    4.7 G3: lets the differ distinguish 'probes ran, item genuinely absent' (a real
    removal) from 'probes degraded, item not observed' (UNKNOWN, never removed).
    Absent file → {} → the G1 gate treats every item as observed (no suppression),
    i.e. exactly current behaviour until the scanner writes the file."""
    data = read_json(work / "_probe_status.json")
    return data if isinstance(data, dict) else {}

def build_subdomain_record(name: str, sub_work: Path, *, is_root: bool,
                           discovered_via: str, ip_cache: dict) -> dict:
    return {
        "name":    name,
        "alive":   True,                            # we only build records for live subs
        "is_root": is_root,
        "discovered_via":   discovered_via,
        "first_discovered": utc_now(),
        "last_seen":        utc_now(),
        "tags":             [],
        "reachability":     build_reachability(sub_work),
        "probe_status":     build_probe_status(sub_work),   # 4.7 G3: per-tool health
        "hosts":            build_hosts(sub_work, ip_cache),
        "services":         build_services(sub_work),
        "dns":              build_dns(sub_work),
        "fingerprint":      build_fingerprint(sub_work),
        "waf":              build_waf(sub_work),
    }

# ─── Roll-up summary across subdomains ──────────────────────────────────────

def build_summary(subdomains: list[dict]) -> dict:
    live = [s for s in subdomains if s.get("alive")]
    all_hosts = []
    all_services = []
    nearest_cert = None
    for s in subdomains:
        all_hosts.extend(s.get("hosts", []))
        all_services.extend(s.get("services", []))
        for svc in s.get("services", []):
            d = (svc.get("cert") or {}).get("days_to_expiry")
            if isinstance(d, (int, float)) and (nearest_cert is None or d < nearest_cert):
                nearest_cert = d
    # Top hosting org
    org_counts: dict[str, int] = {}
    for h in all_hosts:
        org = (h.get("asn_org") or "").strip()
        if org:
            org_counts[org] = org_counts.get(org, 0) + 1
    top_org = max(org_counts.items(), key=lambda x: x[1])[0] if org_counts else None

    # Platform labels (unique, non-null)
    platforms = sorted({s.get("fingerprint", {}).get("platform_label") for s in subdomains
                        if s.get("fingerprint", {}).get("platform_label")})

    return {
        "subdomain_count":          len(subdomains),
        "live_subdomain_count":     len(live),
        "host_count":               len({h.get("ip") for h in all_hosts if h.get("ip")}),
        "service_count":            len(all_services),
        "newest_cert_expiry_days":  nearest_cert,
        "top_hosting_org":          top_org,
        "platforms":                platforms,
    }

# ─── Delta computation (subdomain-aware) ─────────────────────────────────────

def compute_deltas(prev: dict | None, current: dict) -> dict:
    out: dict[str, Any] = {
        "since_scan": None,
        "added":   {"subdomains": [], "services": [], "hosts": []},
        "removed": {"subdomains": [], "services": [], "hosts": []},
        "changed": {"fingerprint": [], "cert": [], "reachability": []},
    }
    if not prev:
        return out
    out["since_scan"] = prev.get("scan", {}).get("id")

    # 4.7 G1/G3: a host/service that dropped out is only a REAL removal if the
    # probes that would observe it ran OK this scan. If they degraded, the item
    # is UNKNOWN — carry forward, never emit a removal. Per delta class: ports
    # need naabu; a host needs naabu OR httpx (any successful observation). A sub
    # with no probe_status (file absent) reads as fully observed → no suppression.
    _curr_by_sub = {s.get("name"): s for s in current.get("subdomains", [])}
    def _degraded(sub, tool):
        return "degraded" in ((_curr_by_sub.get(sub, {}).get("probe_status") or {}).get(tool) or {})
    def _host_unobserved(sub):   # no way to confirm the host is gone this scan
        return _degraded(sub, "naabu") and _degraded(sub, "httpx_tech")
    def _ports_unobserved(sub):  # can't confirm a port closed if the port scan failed
        return _degraded(sub, "naabu")

    prev_subs = {s["name"] for s in prev.get("subdomains", []) if s.get("alive")}
    curr_subs = {s["name"] for s in current["subdomains"] if s.get("alive")}
    out["added"]["subdomains"]   = sorted(curr_subs - prev_subs)
    out["removed"]["subdomains"] = sorted(prev_subs - curr_subs)

    def services_with_owner(record: dict) -> set[tuple]:
        bag = set()
        for s in record.get("subdomains", []):
            sub = s.get("name")
            for svc in s.get("services", []):
                bag.add((sub, svc.get("ip"), svc.get("port"), svc.get("protocol")))
        return bag
    prev_svcs = services_with_owner(prev)
    curr_svcs = services_with_owner(current)
    out["added"]["services"]   = [{"subdomain": sub, "ip": ip, "port": p, "protocol": pr}
                                  for (sub, ip, p, pr) in sorted(curr_svcs - prev_svcs)]
    out["removed"]["services"] = [{"subdomain": sub, "ip": ip, "port": p, "protocol": pr}
                                  for (sub, ip, p, pr) in sorted(prev_svcs - curr_svcs)
                                  if not _ports_unobserved(sub)]   # 4.7 G1

    def hosts_with_owner(record: dict) -> set[tuple]:
        bag = set()
        for s in record.get("subdomains", []):
            sub = s.get("name")
            for h in s.get("hosts", []):
                if h.get("ip"):
                    bag.add((sub, h["ip"]))
        return bag
    prev_hosts = hosts_with_owner(prev)
    curr_hosts = hosts_with_owner(current)
    out["added"]["hosts"]   = [{"subdomain": sub, "ip": ip} for (sub, ip) in sorted(curr_hosts - prev_hosts)]
    out["removed"]["hosts"] = [{"subdomain": sub, "ip": ip} for (sub, ip) in sorted(prev_hosts - curr_hosts)
                               if not _host_unobserved(sub)]   # 4.7 G1

    # Tech version changes per subdomain
    def tech_index(record: dict) -> dict[tuple[str, str], str | None]:
        bag = {}
        for s in record.get("subdomains", []):
            sub = s.get("name")
            for t in s.get("fingerprint", {}).get("tech", []):
                if t.get("name"):
                    bag[(sub, t["name"])] = t.get("version")
        return bag
    prev_tech = tech_index(prev)
    curr_tech = tech_index(current)
    for (sub, name), ver in curr_tech.items():
        if (sub, name) in prev_tech and prev_tech[(sub, name)] != ver:
            out["changed"]["fingerprint"].append({
                "subdomain": sub, "name": name,
                "from": prev_tech[(sub, name)], "to": ver,
            })

    # Reachability changes — track sub-level liveness transitions so the alerter
    # can fire CHANGE-based alerts ('went offline', 'came back online') instead
    # of STATE-based alerts ('still offline every scan'). Per-sub history so we
    # can detect both root-level and individual sub transitions if needed later.
    def reach_index(record: dict) -> dict[str, dict]:
        bag = {}
        for s in record.get("subdomains", []):
            sub = s.get("name")
            if not sub:
                continue
            bag[sub] = {
                "live":    s.get("reachability", {}).get("live"),
                "is_root": bool(s.get("is_root")),
            }
        return bag
    prev_reach = reach_index(prev)
    curr_reach = reach_index(current)
    for sub, curr_state in curr_reach.items():
        prev_state = prev_reach.get(sub)
        if not prev_state:
            continue  # new sub; new_subdomain alert handles that case
        if prev_state["live"] != curr_state["live"]:
            out["changed"]["reachability"].append({
                "subdomain": sub,
                "from":      prev_state["live"],
                "to":        curr_state["live"],
                "is_root":   curr_state["is_root"],
            })

    return out

# ─── Validation ──────────────────────────────────────────────────────────────

def validate(asset_json: dict) -> list[str]:
    errors = []
    required = ["schema_version", "asset", "scan", "registration", "summary",
                "subdomains", "deltas", "history"]
    for k in required:
        if k not in asset_json:
            errors.append(f"missing top-level key: {k}")
    if asset_json.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version mismatch (expected {SCHEMA_VERSION})")
    asset = asset_json.get("asset", {})
    for k in ("id", "type", "value", "owner"):
        if k not in asset:
            errors.append(f"asset.{k} missing")
    if asset.get("type") not in ("apex", "fqdn", "ip", "cidr", "asn"):
        errors.append(f"asset.type invalid: {asset.get('type')}")
    return errors

# ─── Target metadata loader ──────────────────────────────────────────────────

def load_target_metadata(targets_path: Path, target_id: str) -> dict:
    out = {"owner": "unknown", "tags": [], "notes": "", "discovered_via": "manual"}
    if not targets_path.exists():
        return out
    text = targets_path.read_text()
    in_block = False
    capture_tags = False
    for line in text.splitlines():
        s = line.rstrip()
        stripped = s.strip()
        if stripped.startswith(f"id: {target_id}") or stripped == f"id: {target_id}":
            in_block = True
            capture_tags = False
            continue
        if in_block:
            # End of block: blank line OR next list item OR un-indented
            if (stripped.startswith("- id:") or stripped.startswith("- ")) and not capture_tags:
                break
            if stripped.startswith("owner:"):
                out["owner"] = stripped.split(":", 1)[1].strip().strip('"').strip("'")
            elif stripped.startswith("notes:"):
                out["notes"] = stripped.split(":", 1)[1].strip().strip('"').strip("'")
            elif stripped.startswith("tags:"):
                inline = stripped.split(":", 1)[1].strip()
                if inline.startswith("[") and inline.endswith("]"):
                    out["tags"] = [t.strip().strip('"').strip("'") for t in inline[1:-1].split(",") if t.strip()]
                    capture_tags = False
                elif not inline:
                    capture_tags = True
                    continue
            elif capture_tags and stripped.startswith("- "):
                out["tags"].append(stripped[2:].strip().strip('"').strip("'"))
                continue
            elif capture_tags:
                capture_tags = False
            elif stripped.startswith("discovered_via:"):
                out["discovered_via"] = stripped.split(":", 1)[1].strip().strip('"').strip("'")
    return out

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-id", required=True)
    ap.add_argument("--scan-id",   required=True)
    ap.add_argument("--work-dir",  required=True)
    ap.add_argument("--targets",   required=True)
    ap.add_argument("--schema",    required=False)
    ap.add_argument("--previous",  required=False)
    ap.add_argument("--out",       required=True)
    args = ap.parse_args()

    work = Path(args.work_dir)
    if not work.exists():
        print(f"FATAL: work dir not found: {work}", file=sys.stderr)
        sys.exit(2)

    target_value = (work / "_target_value").read_text().strip()
    target_type  = (work / "_target_type").read_text().strip()
    started_at   = (work / "_started").read_text().strip()
    completed_at = (work / "_completed").read_text().strip() if (work / "_completed").exists() else utc_now()

    meta = load_target_metadata(Path(args.targets), args.target_id)

    ip_cache: dict[str, dict] = {}
    subdomains: list[dict] = []

    subs_root = work / "subs"
    if subs_root.exists() and any(subs_root.iterdir()):
        # Apex flow — per-sub directories
        for sub_dir in sorted(subs_root.iterdir()):
            if not sub_dir.is_dir():
                continue
            name = sub_dir.name
            is_root = (name == target_value)
            via = "dnsx" if is_root else "subfinder"
            subdomains.append(build_subdomain_record(
                name, sub_dir, is_root=is_root, discovered_via=via, ip_cache=ip_cache,
            ))
    else:
        # Non-apex flow (fqdn, ip, cidr) — single record from the top-level work dir
        is_root = True
        via = "manual" if target_type in ("ip", "cidr") else "dnsx"
        subdomains.append(build_subdomain_record(
            target_value, work, is_root=is_root, discovered_via=via, ip_cache=ip_cache,
        ))

    # Sort: root first, then alphabetical
    subdomains.sort(key=lambda s: (not s.get("is_root"), s.get("name", "")))

    # Whois on the apex (the top-level work dir's whois.txt)
    registration = parse_whois_domain(read_text(work / "whois.txt"))

    # Tools-run inferred from existence/non-emptiness of any sub's outputs
    tools_run_set = set()
    for d in (subs_root.iterdir() if subs_root.exists() else [work]):
        if not d.is_dir():
            continue
        for tool, path in [
            ("dnsx", "dnsx.json"), ("subfinder", "subfinder.json"),
            ("naabu", "naabu.json"), ("fingerprintx", "fingerprintx.json"),
            ("httpx", "httpx.json"), ("wafw00f", "wafw00f.json"),
            ("testssl", "testssl.json"), ("whois", "whois.txt"),
        ]:
            p = d / path
            if p.exists() and p.stat().st_size > 0:
                tools_run_set.add(tool)
    # Also check top-level work dir
    for tool, path in [
        ("subfinder", "subfinder.json"), ("whois", "whois.txt"),
    ]:
        p = work / path
        if p.exists() and p.stat().st_size > 0:
            tools_run_set.add(tool)

    try:
        d_start = datetime.strptime(started_at, "%Y-%m-%dT%H:%M:%SZ")
        d_end   = datetime.strptime(completed_at, "%Y-%m-%dT%H:%M:%SZ")
        duration = int((d_end - d_start).total_seconds())
    except Exception:
        duration = 0

    # ─── Tier 2 phantom defense — surface the DNS-gate's phantom list ────
    # asm-discover.sh splits enumerated subdomains into _resolved + _phantom
    # before the per-sub deep-scan loop runs. The resolved ones become full
    # subdomain records (above); the phantoms get carried as plain names so
    # the importer can mark them discovery_status='ct_ghost' at UPSERT time.
    # No port/cert data because we never reached them — there was nothing
    # to reach. Per Security Advisor 4.7 + Tier 2 design 2026-06-06.
    phantom_subdomains: list[str] = []
    phantom_file = work / "_phantom_subdomains.txt"
    if phantom_file.exists():
        for line in phantom_file.read_text().splitlines():
            n = line.strip()
            if n and n != target_value:
                phantom_subdomains.append(n)
        phantom_subdomains = sorted(set(phantom_subdomains))

    asset_json = {
        "schema_version": SCHEMA_VERSION,
        "asset": {
            "id":     args.target_id,
            "type":   target_type,
            "value":  target_value,
            "owner":  meta["owner"],
            "tags":   meta["tags"],
            "notes":  meta["notes"],
            "discovered_via": meta["discovered_via"],
        },
        "scan": {
            "id":               args.scan_id,
            "started_at":       started_at,
            "completed_at":     completed_at,
            "duration_seconds": duration,
            "engine_version":   ENGINE_VERSION,
            "scanner_origin":   "github-actions-ubuntu-azure",
            "tools_run":        sorted(tools_run_set),
        },
        "registration": registration,
        "summary":      build_summary(subdomains),
        "subdomains":   subdomains,
        # Plain list of hostname strings, no port/cert/tech data — by
        # definition we couldn't reach them. Importer reads this and
        # UPSERTs each as discovery_status='ct_ghost', ownership='owned'.
        "phantom_subdomains": phantom_subdomains,
        "deltas":       {},
        "history":      [],
    }

    prev = None
    if args.previous and Path(args.previous).exists():
        try:
            prev_data = json.loads(Path(args.previous).read_text())
            if prev_data.get("schema_version") == SCHEMA_VERSION:
                prev = prev_data
            else:
                print(f"INFO: previous asset is v{prev_data.get('schema_version')} — treating as fresh v3 scan", file=sys.stderr)
        except Exception as e:
            print(f"WARN: previous asset JSON unreadable: {e}", file=sys.stderr)

    asset_json["deltas"] = compute_deltas(prev, asset_json)

    # ─── History: 30-day rolling window of scan summaries + per-host port lists ─
    # Each entry captures enough state to reconstruct "what was open on which
    # host at this point in time" without needing to re-scan or dig through
    # git. Service-history view in the dashboard reads this to render the
    # ports-over-time timeline and detect flapping services.
    #
    # Retention: 120 entries = 30 days at the 6-hour scan cadence. Tweak
    # HISTORY_RETENTION_ENTRIES if cadence changes.
    HISTORY_RETENTION_ENTRIES = 120

    # Build per-sub port map: { sub_name: { ip: [sorted unique ports] } }
    # Indexing by HOSTNAME (not IP) so the dashboard timeline shows
    # 'test.commandcommcentral.com' rather than '24.38.70.8' — names are
    # stable identifiers users recognize, IPs are implementation detail.
    # Nested ip dimension preserves IP attribution so the dashboard can
    # still display 'this sub was on IP X' as a sub-label.
    ports_by_sub: dict[str, dict[str, list[int]]] = {}
    for sub in asset_json.get("subdomains", []):
        sub_name = sub.get("name")
        if not sub_name:
            continue
        ports_by_sub[sub_name] = {}
        for svc in sub.get("services", []):
            ip = svc.get("ip")
            port = svc.get("port")
            if not ip or not isinstance(port, int):
                continue
            ports_by_sub[sub_name].setdefault(ip, [])
            if port not in ports_by_sub[sub_name][ip]:
                ports_by_sub[sub_name][ip].append(port)
        for ip in ports_by_sub[sub_name]:
            ports_by_sub[sub_name][ip].sort()

    # Sorted list of subdomain names this scan saw — used by the alerter to
    # detect 'N consecutive absences' before firing 'subdomain went away'
    # alerts (avoids false positives from wordlist enum hiccups).
    subdomain_names = sorted({
        s.get("name") for s in asset_json.get("subdomains", []) if s.get("name")
    })

    # Per-scan tech version snapshot: { tech_name: version_string }.
    # Collapses all subdomain fingerprints into one canonical map so the
    # alerter can apply 2-scan-confirmation to 'tech version change' alerts
    # the same way it does to 'new subdomain/host/service' alerts. Without
    # this, single-scan flickers from detection drift (e.g. Pressable cache
    # nodes briefly disagreeing on a Yoast readme version) fire false-positive
    # alert emails. Only versions with a non-empty value are recorded —
    # tech with version=None gets dropped (we can't meaningfully alert on
    # 'unknown → unknown'). Last sub wins on collision, which is fine for
    # the typical apex+www same-install case.
    tech_versions: dict[str, str] = {}
    for sub in asset_json.get("subdomains", []):
        fp = sub.get("fingerprint") or {}
        for t in (fp.get("tech") or []):
            name = t.get("name")
            ver = t.get("version")
            if name and ver:
                tech_versions[name] = str(ver)

    prev_history = (prev.get("history", []) if prev else [])
    summary = asset_json["summary"]
    new_entry = {
        "scan_id":              args.scan_id,
        "started_at":           asset_json["scan"].get("started_at"),
        "completed_at":         asset_json["scan"].get("completed_at"),
        "subdomain_count":      summary["subdomain_count"],
        "live_subdomain_count": summary["live_subdomain_count"],
        "host_count":           summary["host_count"],
        "service_count":        summary["service_count"],
        "subdomain_names":      subdomain_names,
        "ports_by_sub":         ports_by_sub,
        "tech_versions":        tech_versions,
    }
    # Keep the last (RETENTION - 1) prior entries + this new one = RETENTION total
    asset_json["history"] = prev_history[-(HISTORY_RETENTION_ENTRIES - 1):] + [new_entry]

    errors = validate(asset_json)
    if errors:
        print("VALIDATION FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(3)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(asset_json, indent=2))
    print(f"Wrote {out_path}", file=sys.stderr)

if __name__ == "__main__":
    main()
