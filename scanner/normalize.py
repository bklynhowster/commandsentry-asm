#!/usr/bin/env python3
"""
COMMANDsentry — normalize raw tool outputs into v2 ASM asset JSON.

Reads the raw outputs that asm-discover.sh wrote into a working dir,
synthesizes them into the v2 asset schema (schemas/asset-schema.md),
computes deltas vs. the previous scan, validates, and writes
data/assets/{target-id}.json.

Pure ASM — no exposure analysis, no security posture grading. Just surface
data: who, where, what's running.

Designed to be tolerant of partial / missing tool outputs — any phase can
fail without breaking the whole normalization. Missing data goes into
nulls / empty arrays, not exceptions.
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

SCHEMA_VERSION = "2.0"
ENGINE_VERSION = "2.0.0"

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
# Multi-format. Different registrars use different field labels.

WHOIS_PATTERNS = {
    "registrar": [
        r"^(?:[Rr]egistrar|[Rr]egistrar\s*Name):\s*(.+?)\s*$",
        r"^Sponsoring\s+Registrar:\s*(.+?)\s*$",
        r"^Registry\s+Registrar:\s*(.+?)\s*$",
    ],
    "registrar_url": [
        r"^(?:[Rr]egistrar\s*URL|[Rr]egistrar\s*WWW):\s*(.+?)\s*$",
    ],
    "created": [
        r"^Creation\s*Date:\s*(.+?)(?:T|\s|$)",
        r"^Created\s*On:\s*(.+?)(?:T|\s|$)",
        r"^Domain\s*Name\s*Commencement\s*Date:\s*(.+?)(?:T|\s|$)",
        r"^[Dd]omain\s*[Rr]egistered:\s*(.+?)(?:T|\s|$)",
    ],
    "updated": [
        r"^Updated\s*Date:\s*(.+?)(?:T|\s|$)",
        r"^Last\s*Modified:\s*(.+?)(?:T|\s|$)",
    ],
    "expires": [
        r"^Registry\s+Expiry\s+Date:\s*(.+?)(?:T|\s|$)",
        r"^Registrar\s+Registration\s+Expiration\s+Date:\s*(.+?)(?:T|\s|$)",
        r"^Expir(?:y|ation)\s*Date:\s*(.+?)(?:T|\s|$)",
        r"^Renewal\s*Date:\s*(.+?)(?:T|\s|$)",
    ],
    "status": [
        r"^(?:Domain\s+)?Status:\s*([a-zA-Z]+)",
    ],
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

WHOIS_IP_PATTERNS = {
    "asn":     [r"^OriginAS:\s*(AS?\d+)", r"^origin:\s*(AS?\d+)"],
    "asn_org": [r"^OrgName:\s*(.+)", r"^org-name:\s*(.+)", r"^netname:\s*(.+)"],
    "country": [r"^Country:\s*(\w{2})", r"^country:\s*(\w{2})"],
    "city":    [r"^City:\s*(.+)"],
    "region":  [r"^StateProv:\s*(.+)"],
}

def parse_whois_ip(text: str) -> dict:
    out: dict[str, Any] = {}
    for field, patterns in WHOIS_IP_PATTERNS.items():
        for pat in patterns:
            m = re.search(pat, text, re.MULTILINE | re.IGNORECASE)
            if m:
                out[field] = m.group(1).strip()
                break
    return out

# ─── ASN / geo via free public API ────────────────────────────────────────────
# ipinfo.io free tier returns ASN org + city/country with no auth (50k/mo).
# We fall back gracefully if it fails — never block the scan on enrichment.

def lookup_ip_attribution(ip: str, cache: dict) -> dict:
    if ip in cache:
        return cache[ip]
    out: dict[str, Any] = {"ip": ip}
    try:
        req = urllib.request.Request(
            f"https://ipinfo.io/{ip}/json",
            headers={"User-Agent": "commandsentry-asm/2.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        org = data.get("org") or ""
        # ipinfo returns "AS54017 Pressable, Inc." — split into two
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

# ─── Section builders ─────────────────────────────────────────────────────────

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

def build_hosts(work: Path) -> list[dict]:
    """Resolve unique IPs from dnsx, enrich with ASN/geo via ipinfo."""
    dnsx_records = read_jsonl(work / "dnsx.json")
    ips: set[str] = set()
    for rec in dnsx_records:
        ips.update(rec.get("a", []) or [])
        ips.update(rec.get("aaaa", []) or [])

    # IP-target case: read from _resolved_ips.txt if dnsx didn't run
    resolved_file = work / "_resolved_ips.txt"
    if resolved_file.exists():
        for line in resolved_file.read_text().splitlines():
            line = line.strip()
            if line:
                ips.add(line)

    cache: dict[str, dict] = {}
    return [lookup_ip_attribution(ip, cache) for ip in sorted(ips)]

def build_services(work: Path, hosts: list[dict]) -> list[dict]:
    """
    Pair naabu open ports with fingerprintx service IDs (when available)
    and merge in TLS cert details for HTTPS ports from testssl/httpx.
    """
    services: list[dict] = []
    seen: set[tuple[str, int, str]] = set()

    naabu = read_jsonl(work / "naabu.json") or read_jsonl(work / "naabu_cidr.json")
    fpx   = read_jsonl(work / "fingerprintx.json")

    # Index fingerprintx by (host, port)
    fpx_by_key: dict[tuple[str, int], dict] = {}
    for rec in fpx:
        host = rec.get("host") or rec.get("ip") or rec.get("address")
        port = rec.get("port")
        if host and port:
            fpx_by_key[(host, int(port))] = rec

    # TLS cert extraction (best-effort) — try testssl first, fall back to httpx
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
        service_name = (
            fpx_rec.get("protocol") if fpx_rec else
            infer_service_from_port(int(port))
        )
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

PORT_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

def infer_service_from_port(port: int) -> str:
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

def build_subdomains(work: Path, target_value: str) -> list[dict]:
    subs_file = work / "_subdomains.txt"
    if not subs_file.exists():
        return [{
            "name": target_value, "alive": True,
            "first_discovered": utc_now(), "last_seen": utc_now(),
        }]
    subs = [s.strip() for s in subs_file.read_text().splitlines() if s.strip()]
    httpx_results = read_jsonl(work / "httpx_apex.json")
    alive_set = set()
    for r in httpx_results:
        if r.get("status_code"):
            url = r.get("input") or r.get("url", "")
            host = url.replace("https://", "").replace("http://", "").split("/")[0]
            alive_set.add(host)
    return [
        {
            "name": s,
            "alive": s in alive_set or s == target_value,
            "first_discovered": utc_now(),
            "last_seen": utc_now(),
        }
        for s in subs
    ]

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

def build_registration(work: Path) -> dict:
    text = read_text(work / "whois.txt")
    return parse_whois_domain(text)

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
            name = t
            version = None
            if ":" in t:
                name, version = t.split(":", 1)
            out["tech"].append({"name": name.strip(), "version": (version or "").strip() or None, "category": _categorize(name)})
        elif isinstance(t, dict):
            out["tech"].append({
                "name":     t.get("name"),
                "version":  t.get("version"),
                "category": _categorize(t.get("name", "")) or t.get("category"),
            })

    # Synthesize a friendly platform label
    names = [t.get("name", "").lower() for t in out["tech"]]
    if "wordpress" in names and "wp.cloud" in names:
        out["platform_label"] = "WordPress on wp.cloud (Pressable)"
    elif "wordpress" in names and "wp engine" in names:
        out["platform_label"] = "WordPress on WP Engine"
    elif "wordpress" in names:
        out["platform_label"] = "WordPress"
    elif "asp.net" in names or "microsoft asp.net" in names:
        out["platform_label"] = ".NET / IIS"
    return out

CATEGORY_HINTS = {
    "wordpress": "cms", "drupal": "cms", "joomla": "cms", "wpbakery": "wp-plugin",
    "yoast seo": "wp-plugin", "slider revolution": "wp-plugin",
    "wpmu dev smush": "wp-plugin", "imagely nextgen gallery": "wp-plugin",
    "elementor": "wp-plugin", "elementor pro": "wp-plugin", "oceanwp": "wp-theme",
    "bootstrap": "frontend", "jquery": "frontend", "jquery migrate": "frontend",
    "font awesome": "frontend",
    "nginx": "webserver", "apache": "webserver", "iis": "webserver",
    "cloudflare": "cdn", "wp engine": "hosting", "wp.cloud": "hosting",
    "wpcomstaging": "hosting",
    "google tag manager": "tracking",
    "php": "language", "mysql": "database",
    "asp.net": "framework", "microsoft asp.net": "framework",
    "modernizr": "frontend",
    "hsts": "security", "http/3": "transport",
    "jsdelivr": "cdn",
}

def _categorize(name: str) -> str | None:
    return CATEGORY_HINTS.get((name or "").strip().lower())

def build_waf(work: Path) -> dict:
    out = {"detected": False, "vendor": None, "confidence": "unknown"}
    waf_data = read_json(work / "wafw00f.json")
    if not waf_data:
        return out
    if isinstance(waf_data, list) and waf_data:
        first = waf_data[0]
        if first.get("detected") or first.get("firewall"):
            out["detected"]   = True
            out["vendor"]     = first.get("firewall") or first.get("manufacturer")
            out["confidence"] = "high"
    elif isinstance(waf_data, dict):
        if waf_data.get("detected") or waf_data.get("firewall"):
            out["detected"]   = True
            out["vendor"]     = waf_data.get("firewall") or waf_data.get("manufacturer")
            out["confidence"] = "high"
    return out

# ─── Delta computation ────────────────────────────────────────────────────────

def compute_deltas(prev: dict | None, current: dict) -> dict:
    out: dict[str, Any] = {
        "since_scan": None,
        "added":   {"subdomains": [], "hosts": [], "services": []},
        "removed": {"subdomains": [], "hosts": [], "services": []},
        "changed": {"fingerprint": [], "cert": []},
    }
    if not prev:
        return out
    out["since_scan"] = prev.get("scan", {}).get("id")

    prev_subs = {s["name"] for s in prev.get("subdomains", []) if s.get("alive")}
    curr_subs = {s["name"] for s in current["subdomains"] if s.get("alive")}
    out["added"]["subdomains"]   = sorted(curr_subs - prev_subs)
    out["removed"]["subdomains"] = sorted(prev_subs - curr_subs)

    prev_hosts = {h["ip"] for h in prev.get("hosts", []) if h.get("ip")}
    curr_hosts = {h["ip"] for h in current["hosts"] if h.get("ip")}
    out["added"]["hosts"]   = [{"ip": ip} for ip in sorted(curr_hosts - prev_hosts)]
    out["removed"]["hosts"] = [{"ip": ip} for ip in sorted(prev_hosts - curr_hosts)]

    def svc_key(s: dict) -> tuple:
        return (s.get("ip"), s.get("port"), s.get("protocol"))
    prev_svcs = {svc_key(s) for s in prev.get("services", [])}
    curr_svcs = {svc_key(s) for s in current["services"]}
    out["added"]["services"]   = [{"ip": ip, "port": p, "protocol": pr} for (ip, p, pr) in sorted(curr_svcs - prev_svcs)]
    out["removed"]["services"] = [{"ip": ip, "port": p, "protocol": pr} for (ip, p, pr) in sorted(prev_svcs - curr_svcs)]

    def tech_versions(record: dict) -> dict[str, str | None]:
        return {t["name"]: t.get("version") for t in (record.get("fingerprint", {}) or {}).get("tech", []) if t.get("name")}
    prev_tech = tech_versions(prev)
    curr_tech = tech_versions(current)
    for name, ver in curr_tech.items():
        if name in prev_tech and prev_tech[name] != ver:
            out["changed"]["fingerprint"].append({"name": name, "from": prev_tech[name], "to": ver})

    # Cert chain change detection (just issuer for now)
    def cert_issuers(record: dict) -> set[str]:
        return {(s.get("cert") or {}).get("issuer") for s in record.get("services", []) if (s.get("cert") or {}).get("issuer")}
    prev_iss = cert_issuers(prev)
    curr_iss = cert_issuers(current)
    if prev_iss and prev_iss != curr_iss:
        out["changed"]["cert"].append({"from": list(prev_iss), "to": list(curr_iss)})

    return out

# ─── Validation ──────────────────────────────────────────────────────────────

def validate(asset_json: dict) -> list[str]:
    errors = []
    required = ["schema_version", "asset", "scan", "reachability", "hosts",
                "services", "subdomains", "dns", "registration", "fingerprint",
                "waf", "deltas", "history"]
    for k in required:
        if k not in asset_json:
            errors.append(f"missing top-level key: {k}")
    if asset_json.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version mismatch (expected {SCHEMA_VERSION})")
    asset = asset_json.get("asset", {})
    for k in ("id", "type", "value", "owner"):
        if k not in asset:
            errors.append(f"asset.{k} missing")
    if asset.get("type") not in ("fqdn", "apex", "ip", "cidr", "asn"):
        errors.append(f"asset.type invalid: {asset.get('type')}")
    return errors

# ─── Target metadata loader (minimal YAML reader, no PyYAML dep) ─────────────

def load_target_metadata(targets_path: Path, target_id: str) -> dict:
    out = {"owner": "unknown", "tags": [], "notes": "", "discovered_via": "manual"}
    if not targets_path.exists():
        return out
    text = targets_path.read_text()
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(f"id: {target_id}") or s == f"id: {target_id}":
            in_block = True
            continue
        if in_block:
            if s.startswith("- id:") or s.startswith("- "):
                break
            if s.startswith("owner:"):
                out["owner"] = s.split(":", 1)[1].strip().strip('"').strip("'")
            elif s.startswith("notes:"):
                out["notes"] = s.split(":", 1)[1].strip().strip('"').strip("'")
            elif s.startswith("tags:"):
                inline = s.split(":", 1)[1].strip()
                if inline.startswith("[") and inline.endswith("]"):
                    out["tags"] = [t.strip().strip('"').strip("'") for t in inline[1:-1].split(",") if t.strip()]
            elif s.startswith("discovered_via:"):
                out["discovered_via"] = s.split(":", 1)[1].strip().strip('"').strip("'")
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

    hosts        = build_hosts(work)
    services     = build_services(work, hosts)
    reachability = build_reachability(work)
    subdomains   = build_subdomains(work, target_value)
    dns          = build_dns(work)
    registration = build_registration(work)
    fingerprint  = build_fingerprint(work)
    waf          = build_waf(work)

    tools_run = []
    for tool, path in [
        ("dnsx", "dnsx.json"), ("subfinder", "subfinder.json"),
        ("naabu", "naabu.json"), ("fingerprintx", "fingerprintx.json"),
        ("httpx", "httpx.json"), ("wafw00f", "wafw00f.json"),
        ("testssl", "testssl.json"), ("whois", "whois.txt"),
    ]:
        p = work / path
        if p.exists() and p.stat().st_size > 0:
            tools_run.append(tool)

    try:
        d_start = datetime.strptime(started_at, "%Y-%m-%dT%H:%M:%SZ")
        d_end   = datetime.strptime(completed_at, "%Y-%m-%dT%H:%M:%SZ")
        duration = int((d_end - d_start).total_seconds())
    except Exception:
        duration = 0

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
            "tools_run":        tools_run,
        },
        "reachability": reachability,
        "hosts":        hosts,
        "services":     services,
        "subdomains":   subdomains,
        "dns":          dns,
        "registration": registration,
        "fingerprint":  fingerprint,
        "waf":          waf,
        "deltas":       {},
        "history":      [],
    }

    prev = None
    if args.previous and Path(args.previous).exists():
        try:
            prev = json.loads(Path(args.previous).read_text())
            # Skip prev if it's v1 (incompatible structure) — first v2 scan starts fresh
            if prev.get("schema_version", "1.0") != SCHEMA_VERSION:
                print(f"INFO: previous asset is v{prev.get('schema_version')} — treating as fresh v2 scan", file=sys.stderr)
                prev = None
        except Exception as e:
            print(f"WARN: previous asset JSON unreadable: {e}", file=sys.stderr)

    asset_json["deltas"] = compute_deltas(prev, asset_json)

    prev_history = (prev.get("history", []) if prev else [])
    asset_json["history"] = prev_history[-89:] + [{
        "scan_id":         args.scan_id,
        "live":            reachability["live"],
        "host_count":      len(hosts),
        "service_count":   len(services),
        "subdomain_count": sum(1 for s in subdomains if s.get("alive")),
    }]

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
