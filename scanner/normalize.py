#!/usr/bin/env python3
"""
COMMANDsentry — normalize raw tool outputs into asset JSON.

Reads the raw outputs that asm-discover.sh wrote into a working dir,
synthesizes them into the canonical asset schema (schemas/asset-schema.md),
computes deltas vs. the previous scan, validates, and writes
data/assets/{target-id}.json.

Designed to be tolerant of partial / missing tool outputs — any phase
can fail without breaking the whole normalization. Missing data goes
into nulls/empty arrays, not exceptions.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ─── Config ───────────────────────────────────────────────────────────────────

SCHEMA_VERSION = "1.0"
ENGINE_VERSION = "1.0.0"

# Common DKIM selectors to probe (only used if dnsx didn't grab them already)
DKIM_SELECTORS = ["google", "default", "selector1", "selector2", "dkim", "k1"]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]


# ─── Utilities ────────────────────────────────────────────────────────────────

def utc_now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path: Path) -> list[dict]:
    """Read newline-delimited JSON. Tolerate empty / missing files. Only return dicts."""
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
                # Some tools emit a single JSON array on one line — flatten dict items
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


def read_tool_records(path: Path) -> list[dict]:
    """
    Smart loader for tool output that might be a JSON array OR JSONL stream.
    Used for nuclei -json-export which writes an array (single line or pretty-printed).
    Always returns a flat list of dicts.
    """
    if not path.exists() or path.stat().st_size == 0:
        return []
    txt = path.read_text(errors="replace").strip()
    if not txt:
        return []
    # Try whole-file JSON first (handles array or object)
    try:
        data = json.loads(txt)
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass
    # Fall back to JSONL
    return read_jsonl(path)


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(errors="replace")


# ─── Section builders ─────────────────────────────────────────────────────────

def build_identity(work: Path, target_value: str) -> dict:
    """Identity: IPs, reverse DNS, ASN, registrar, geo."""
    out: dict[str, Any] = {
        "ip_addresses": [],
        "reverse_dns": {},
        "asn": None,
        "asn_org": None,
        "registrar": None,
        "whois_creation": None,
        "whois_expiry": None,
        "geo": {"country": None, "city": None},
    }

    # IPs from dnsx
    dnsx_records = read_jsonl(work / "dnsx.json")
    ips: set[str] = set()
    for rec in dnsx_records:
        ips.update(rec.get("a", []) or [])
        ips.update(rec.get("aaaa", []) or [])
    out["ip_addresses"] = sorted(ips)

    # Reverse DNS file (single-IP scans)
    rdns = read_text(work / "reverse_dns.txt").strip()
    if rdns and out["ip_addresses"]:
        # crude: assume one entry maps to first IP
        out["reverse_dns"][out["ip_addresses"][0]] = rdns

    # WHOIS — best-effort regex parse
    whois_txt = read_text(work / "whois.txt")
    if whois_txt:
        for pat, key in [
            (r"^[Rr]egistrar:\s*(.+)$", "registrar"),
            (r"^[Cc]reation [Dd]ate:\s*(.+)$", "whois_creation"),
            (r"^[Rr]egistry [Ee]xpiry [Dd]ate:\s*(.+)$", "whois_expiry"),
            (r"^[Ee]xpiration [Dd]ate:\s*(.+)$", "whois_expiry"),
            (r"^OriginAS:\s*(.+)$", "asn"),
            (r"^OrgName:\s*(.+)$", "asn_org"),
            (r"^Country:\s*(.+)$", None),  # special-case below
        ]:
            m = re.search(pat, whois_txt, re.MULTILINE)
            if not m:
                continue
            val = m.group(1).strip()
            if key:
                # only set if not already set (first match wins)
                if out.get(key) in (None, ""):
                    out[key] = val
            else:
                out["geo"]["country"] = val

    return out


def build_dns(work: Path) -> dict:
    """DNS records from dnsx, plus light SPF/DMARC parsing."""
    out: dict[str, Any] = {
        "a": [], "aaaa": [], "cname": None,
        "mx": [], "ns": [], "txt": [],
        "spf": None, "dmarc": None,
        "dkim_selectors_found": [],
        "dnssec": False,
    }

    dnsx_records = read_jsonl(work / "dnsx.json")
    if not dnsx_records:
        return out

    rec = dnsx_records[0]  # first record is typically the target
    out["a"] = rec.get("a", []) or []
    out["aaaa"] = rec.get("aaaa", []) or []
    cnames = rec.get("cname", []) or []
    out["cname"] = cnames[0] if cnames else None

    # MX records: dnsx returns list of strings like ["10 aspmx.l.google.com"]
    for mx_str in rec.get("mx", []) or []:
        parts = mx_str.split(None, 1)
        if len(parts) == 2:
            try:
                out["mx"].append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
            except ValueError:
                out["mx"].append({"priority": 0, "host": mx_str})

    out["ns"] = [n.rstrip(".") for n in (rec.get("ns", []) or [])]
    out["txt"] = rec.get("txt", []) or []

    # SPF / DMARC sniffing
    for txt in out["txt"]:
        if txt.lower().startswith("v=spf1"):
            out["spf"] = txt
        elif txt.lower().startswith("v=dmarc1"):
            out["dmarc"] = txt

    return out


def build_subdomains(work: Path, target_value: str) -> list[dict]:
    """Subdomain list from subfinder + httpx liveness."""
    out: list[dict] = []
    subs_file = work / "_subdomains.txt"
    if not subs_file.exists():
        # FQDN scan — just self
        return [{
            "name": target_value,
            "alive": True,
            "discovered": utc_now(),
        }]

    subs = [s.strip() for s in subs_file.read_text().splitlines() if s.strip()]
    httpx_results = read_jsonl(work / "httpx_apex.json")
    alive_set = {r.get("input") or r.get("url", "").replace("https://", "").replace("http://", "").split("/")[0]
                 for r in httpx_results if r.get("status_code")}

    for s in subs:
        out.append({
            "name": s,
            "alive": s in alive_set or s == target_value,
            "discovered": utc_now(),
        })
    return out


def build_ports(work: Path) -> list[dict]:
    """Open ports from naabu."""
    naabu = read_jsonl(work / "naabu.json") or read_jsonl(work / "naabu_cidr.json")
    out: list[dict] = []
    seen: set[tuple[int, str]] = set()
    for rec in naabu:
        port = rec.get("port")
        proto = rec.get("protocol", "tcp")
        if port is None:
            continue
        key = (port, proto)
        if key in seen:
            continue
        seen.add(key)
        out.append({"port": port, "protocol": proto, "state": "open"})
    out.sort(key=lambda x: x["port"])
    return out


def build_services(work: Path) -> list[dict]:
    """Service fingerprints from fingerprintx."""
    fpx = read_jsonl(work / "fingerprintx.json")
    out: list[dict] = []
    seen: set[int] = set()
    for rec in fpx:
        port = rec.get("port")
        if port is None or port in seen:
            continue
        seen.add(port)
        out.append({
            "port": port,
            "service": rec.get("protocol", rec.get("transport", "unknown")),
            "banner":  rec.get("metadata", {}).get("banner") if isinstance(rec.get("metadata"), dict) else None,
            "tls":     bool(rec.get("tls", False)),
        })
    out.sort(key=lambda x: x["port"])
    return out


def build_http(work: Path) -> dict:
    """HTTP fingerprint from httpx."""
    out: dict[str, Any] = {
        "live": False, "status_code": None, "title": None,
        "server": None, "powered_by": None,
        "technologies": [],
        "headers_present": [], "headers_missing": [],
        "cookies": [],
    }
    httpx_records = read_jsonl(work / "httpx.json")
    if not httpx_records:
        return out

    rec = httpx_records[0]
    out["live"] = bool(rec.get("status_code"))
    out["status_code"] = rec.get("status_code")
    out["title"] = rec.get("title")
    out["server"] = rec.get("webserver") or rec.get("server")

    # Tech detection
    techs_raw = rec.get("technologies", []) or rec.get("tech", []) or []
    for t in techs_raw:
        if isinstance(t, str):
            out["technologies"].append({"name": t, "version": None, "category": None})
        elif isinstance(t, dict):
            out["technologies"].append({
                "name": t.get("name"),
                "version": t.get("version"),
                "category": t.get("category"),
            })

    # Header presence
    headers = rec.get("header", {}) or rec.get("headers", {}) or {}
    headers_lower = {k.lower(): v for k, v in headers.items()}
    out["headers_present"] = [h for h in SECURITY_HEADERS if h.lower() in headers_lower]
    out["headers_missing"] = [h for h in SECURITY_HEADERS if h.lower() not in headers_lower]

    # Cookies (httpx doesn't always parse — best effort)
    set_cookie = headers_lower.get("set-cookie", "")
    if set_cookie:
        for cookie_str in set_cookie.split("\n") if isinstance(set_cookie, str) else []:
            if not cookie_str.strip():
                continue
            name = cookie_str.split("=", 1)[0].strip()
            out["cookies"].append({
                "name": name,
                "secure":   "secure" in cookie_str.lower(),
                "httponly": "httponly" in cookie_str.lower(),
                "samesite": _extract_samesite(cookie_str),
            })

    return out


def _extract_samesite(cookie_str: str) -> str | None:
    m = re.search(r"SameSite=(\w+)", cookie_str, re.IGNORECASE)
    return m.group(1) if m else None


def build_tls(work: Path) -> dict:
    """TLS posture from testssl JSON output."""
    out: dict[str, Any] = {
        "issuer": None, "subject": None, "san": [],
        "not_before": None, "not_after": None, "days_until_expiry": None,
        "protocols_supported": [], "weak_ciphers": [], "self_signed": False,
    }
    testssl_data = read_json(work / "testssl.json")
    if not testssl_data:
        return out

    findings = testssl_data if isinstance(testssl_data, list) else []
    for f in findings:
        fid = f.get("id", "")
        finding_value = f.get("finding", "")
        if fid == "cert_subject":
            out["subject"] = finding_value
        elif fid == "cert_issuer":
            out["issuer"] = finding_value
        elif fid == "cert_subjectAltName":
            out["san"] = [s.strip() for s in finding_value.split() if s.strip()]
        elif fid == "cert_notBefore":
            out["not_before"] = finding_value
        elif fid == "cert_notAfter":
            out["not_after"] = finding_value
        elif fid.startswith("SSLv") or fid.startswith("TLS"):
            if "offered" in str(finding_value).lower() and "not" not in str(finding_value).lower():
                out["protocols_supported"].append(fid)
        elif "weak" in fid.lower() or fid == "cipher_negotiated":
            if "weak" in str(finding_value).lower():
                out["weak_ciphers"].append(finding_value)

    # Days until expiry
    if out["not_after"]:
        try:
            ext = datetime.strptime(out["not_after"][:24], "%b %d %H:%M:%S %Y")
            out["days_until_expiry"] = (ext - datetime.utcnow()).days
        except Exception:
            pass

    return out


def build_waf(work: Path) -> dict:
    """WAF detection from wafw00f."""
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


# ─── Exposure builder ─────────────────────────────────────────────────────────

def build_exposures(inventory: dict, work: Path, scan_id: str) -> list[dict]:
    """
    Synthesize exposure records from the inventory + nuclei output.
    Each exposure is a STATE FLAG, not a vulnerability.
    """
    exp: list[dict] = []
    counter = 1

    def add(t: str, cat: str, sev: str, title: str, detail: str, evidence: str):
        nonlocal counter
        exp.append({
            "id":          f"E-{counter:03d}",
            "type":        t,
            "category":    cat,
            "severity":    sev,        # notice | watch
            "title":       title,
            "detail":      detail,
            "evidence":    evidence,
            "first_seen":  utc_now(),
            "last_seen":   utc_now(),
            "status":      "open",
        })
        counter += 1

    # Cert expiry
    tls = inventory.get("tls", {})
    days = tls.get("days_until_expiry")
    if days is not None:
        if days < 0:
            add("cert_expired", "tls", "watch",
                "Certificate has expired",
                f"Cert not_after was {tls.get('not_after')} ({-days} days ago).",
                f"not_after: {tls.get('not_after')}")
        elif days < 7:
            add("cert_expiring_soon", "tls", "watch",
                f"Certificate expires in {days} days",
                "Renewal pipeline should be verified.",
                f"not_after: {tls.get('not_after')}")
        elif days < 30:
            add("cert_expiring_soon", "tls", "notice",
                f"Certificate expires in {days} days",
                "Within renewal window.",
                f"not_after: {tls.get('not_after')}")

    if tls.get("self_signed"):
        add("cert_self_signed", "tls", "watch",
            "Self-signed certificate on internet-facing host",
            "Browsers will warn users.",
            "Cert chain check failed")

    for proto in tls.get("protocols_supported", []):
        if proto in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            add("weak_tls_protocol", "tls", "watch",
                f"Weak TLS protocol enabled: {proto}",
                f"Disable {proto}.",
                f"testssl reported {proto} offered")

    # Email
    dns = inventory.get("dns", {})
    if not dns.get("dmarc"):
        add("missing_dmarc", "email", "notice",
            "No DMARC record published",
            "Domain remains spoofable beyond what SPF protects against.",
            "_dmarc TXT record absent")
    if not dns.get("dkim_selectors_found"):
        add("missing_dkim", "email", "notice",
            "No DKIM selector records found",
            "Outbound mail is unsigned.",
            f"Selectors probed: {', '.join(DKIM_SELECTORS)}")

    # Headers
    http = inventory.get("http", {})
    for h in http.get("headers_missing", []):
        add("missing_security_header", "headers", "notice",
            f"Missing: {h}",
            f"Response from / does not include {h}.",
            f"GET / → headers do not contain {h}")

    # Insecure cookies
    for c in http.get("cookies", []):
        if not c.get("secure"):
            add("cookie_no_secure_flag", "headers", "notice",
                f"Cookie {c['name']} missing Secure flag",
                "Cookie can be sent over HTTP if HSTS isn't enforced.",
                f"Set-Cookie: {c['name']}=...")

    # Nuclei exposure findings
    # nuclei -json-export produces a JSON array (or sometimes JSONL); use smart loader
    nuclei = read_tool_records(work / "nuclei.json")
    for n in nuclei:
        if not isinstance(n, dict):
            continue
        info = n.get("info") if isinstance(n.get("info"), dict) else {}
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        if not isinstance(tags, list):
            tags = []
        # map nuclei severity → ASM severity
        n_sev = info.get("severity", "info").lower()
        sev = "watch" if n_sev in ("medium", "high", "critical") else "notice"
        # categorize by tag heuristic
        if any(t in tags for t in ["git", "git-config"]):
            t_type = "exposed_git_dir"
        elif any(t in tags for t in ["env", "dotenv"]):
            t_type = "exposed_env_file"
        elif any(t in tags for t in ["admin", "login", "panel"]):
            t_type = "exposed_admin_panel"
        elif any(t in tags for t in ["debug", "phpinfo", "trace"]):
            t_type = "exposed_debug_endpoint"
        else:
            t_type = "exposed_debug_endpoint"

        add(t_type, "exposure", sev,
            info.get("name", "Exposure detected"),
            info.get("description", "")[:300],
            f"{n.get('matched-at', n.get('host', ''))} (template: {n.get('template-id', '')})")

    return exp


# ─── Delta computation ───────────────────────────────────────────────────────

def compute_deltas(prev: dict | None, current: dict) -> dict:
    out: dict[str, Any] = {
        "since_scan": None,
        "added":   {"subdomains": [], "ports": [], "exposures": []},
        "removed": {"subdomains": [], "ports": [], "exposures": []},
        "changed": {"tech": []},
    }
    if not prev:
        return out

    out["since_scan"] = prev.get("scan", {}).get("id")

    # Subdomains
    prev_subs = {s["name"] for s in prev.get("inventory", {}).get("subdomains", []) if s.get("alive")}
    curr_subs = {s["name"] for s in current["inventory"]["subdomains"] if s.get("alive")}
    out["added"]["subdomains"]   = sorted(curr_subs - prev_subs)
    out["removed"]["subdomains"] = sorted(prev_subs - curr_subs)

    # Ports
    def port_set(asset_inv: dict) -> set[tuple[int, str]]:
        return {(p["port"], p["protocol"]) for p in asset_inv.get("ports", [])}

    prev_ports = port_set(prev.get("inventory", {}))
    curr_ports = port_set(current["inventory"])
    out["added"]["ports"]   = [{"port": p, "protocol": pr} for p, pr in sorted(curr_ports - prev_ports)]
    out["removed"]["ports"] = [{"port": p, "protocol": pr} for p, pr in sorted(prev_ports - curr_ports)]

    # Exposures (by type+title)
    def exp_key(e: dict) -> tuple[str, str]:
        return (e.get("type", ""), e.get("title", ""))

    prev_exp = {exp_key(e): e for e in prev.get("exposures", [])}
    curr_exp = {exp_key(e): e for e in current["exposures"]}
    out["added"]["exposures"]   = [curr_exp[k]["id"] for k in curr_exp if k not in prev_exp]
    out["removed"]["exposures"] = [prev_exp[k]["id"] for k in prev_exp if k not in curr_exp]

    # Tech changes
    def tech_versions(inv: dict) -> dict[str, str | None]:
        return {t["name"]: t.get("version") for t in inv.get("http", {}).get("technologies", []) if t.get("name")}

    prev_tech = tech_versions(prev.get("inventory", {}))
    curr_tech = tech_versions(current["inventory"])
    for name, ver in curr_tech.items():
        if name in prev_tech and prev_tech[name] != ver:
            out["changed"]["tech"].append({"name": name, "from": prev_tech[name], "to": ver})

    return out


# ─── Validation ──────────────────────────────────────────────────────────────

def validate(asset_json: dict) -> list[str]:
    """Lightweight schema check. Returns list of errors (empty = valid)."""
    errors = []

    required_top = ["schema_version", "asset", "scan", "inventory", "exposures", "deltas", "history"]
    for key in required_top:
        if key not in asset_json:
            errors.append(f"missing top-level key: {key}")

    if asset_json.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version mismatch (expected {SCHEMA_VERSION})")

    # Asset
    asset = asset_json.get("asset", {})
    for key in ("id", "type", "value", "owner"):
        if key not in asset:
            errors.append(f"asset.{key} missing")
    if asset.get("type") not in ("fqdn", "apex", "ip", "cidr", "asn"):
        errors.append(f"asset.type invalid: {asset.get('type')}")

    # Exposure severities
    for e in asset_json.get("exposures", []):
        if e.get("severity") not in ("notice", "watch"):
            errors.append(f"exposure {e.get('id')} severity must be notice|watch (got {e.get('severity')})")

    return errors


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-id",   required=True)
    ap.add_argument("--scan-id",     required=True)
    ap.add_argument("--work-dir",    required=True)
    ap.add_argument("--targets",     required=True, help="path to targets.yml")
    ap.add_argument("--schema",      required=False, help="path to asset-schema.md (informational)")
    ap.add_argument("--previous",    required=False, help="path to previous asset JSON for delta")
    ap.add_argument("--out",         required=True)
    args = ap.parse_args()

    work = Path(args.work_dir)
    if not work.exists():
        print(f"FATAL: work dir not found: {work}", file=sys.stderr)
        sys.exit(2)

    target_value = (work / "_target_value").read_text().strip()
    target_type  = (work / "_target_type").read_text().strip()
    started_at   = (work / "_started").read_text().strip()
    completed_at = (work / "_completed").read_text().strip() if (work / "_completed").exists() else utc_now()

    # Load target metadata from targets.yml (best-effort, no PyYAML dep)
    targets_text = Path(args.targets).read_text()
    owner = "unknown"
    tags: list[str] = []
    notes = ""
    discovered_via = "manual"
    in_block = False
    for line in targets_text.splitlines():
        s = line.strip()
        if s.startswith(f"id: {args.target_id}") or s == f"id: {args.target_id}":
            in_block = True
            continue
        if in_block:
            if s.startswith("- id:") or s.startswith("- "):
                break
            if s.startswith("owner:"):
                owner = s.split(":", 1)[1].strip().strip('"').strip("'")
            elif s.startswith("notes:"):
                notes = s.split(":", 1)[1].strip().strip('"').strip("'")
            elif s.startswith("tags:"):
                inline = s.split(":", 1)[1].strip()
                if inline.startswith("[") and inline.endswith("]"):
                    tags = [t.strip().strip('"').strip("'") for t in inline[1:-1].split(",") if t.strip()]
            elif s.startswith("discovered_via:"):
                discovered_via = s.split(":", 1)[1].strip().strip('"').strip("'")

    # Build inventory sections
    inventory = {
        "identity":  build_identity(work, target_value),
        "dns":       build_dns(work),
        "subdomains": build_subdomains(work, target_value),
        "ports":     build_ports(work),
        "services":  build_services(work),
        "http":      build_http(work),
        "tls":       build_tls(work),
        "waf":       build_waf(work),
    }

    # Build exposure list
    exposures = build_exposures(inventory, work, args.scan_id)

    # Tools that ran (heuristic: file present and non-empty)
    tools_run = []
    for tool, path in [
        ("dnsx", "dnsx.json"),
        ("subfinder", "subfinder.json"),
        ("naabu", "naabu.json"),
        ("fingerprintx", "fingerprintx.json"),
        ("httpx", "httpx.json"),
        ("wafw00f", "wafw00f.json"),
        ("testssl", "testssl.json"),
        ("nuclei-exposure", "nuclei.json"),
        ("whois", "whois.txt"),
    ]:
        p = work / path
        if p.exists() and p.stat().st_size > 0:
            tools_run.append(tool)

    # Duration
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
            "owner":  owner,
            "tags":   tags,
            "notes":  notes,
            "discovered_via": discovered_via,
        },
        "scan": {
            "id":               args.scan_id,
            "started_at":       started_at,
            "completed_at":     completed_at,
            "duration_seconds": duration,
            "engine_version":   ENGINE_VERSION,
            "tools_run":        tools_run,
            "tool_versions":    {},   # filled by install-tools or omitted
        },
        "inventory": inventory,
        "exposures": exposures,
        "deltas":    {},
        "history":   [],
    }

    # Load previous for delta + history
    prev = None
    if args.previous and Path(args.previous).exists():
        try:
            prev = json.loads(Path(args.previous).read_text())
        except Exception as e:
            print(f"WARN: previous asset JSON unreadable: {e}", file=sys.stderr)

    asset_json["deltas"] = compute_deltas(prev, asset_json)

    # History: keep last 90 entries
    prev_history = (prev.get("history", []) if prev else [])
    asset_json["history"] = prev_history[-89:] + [{
        "scan_id":          args.scan_id,
        "live":             inventory["http"]["live"],
        "ports_open":       len(inventory["ports"]),
        "subdomains_alive": sum(1 for s in inventory["subdomains"] if s.get("alive")),
        "exposures_total":  len(exposures),
    }]

    # Validate
    errors = validate(asset_json)
    if errors:
        print("VALIDATION FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(3)

    # Write
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(asset_json, indent=2))
    print(f"Wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
