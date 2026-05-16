"""
common.py — Shared helpers used by every parser.

Defines the FindingEvent dataclass (the per-observation record each parser
produces), the canonical severity scale, severity mappers for common tool
scales, and the finding_id generator.

A FindingEvent is intentionally per-observation, not per-finding-identity.
The driver rolls events up into final Finding records by grouping on
finding_id and building the history array.

The severity scale is a hard rule (per CLAUDE.md):
    CRITICAL, HIGH, MODERATE-HIGH, MODERATE, LOW, INFO
Never compound (no LOW-MODERATE etc).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─── canonical severity scale ─────────────────────────────────────────────────
CANONICAL_SEVERITIES = ("CRITICAL", "HIGH", "MODERATE-HIGH", "MODERATE", "LOW", "INFO")


def map_severity_nuclei(value: Optional[str]) -> str:
    """Nuclei: critical/high/medium/low/info/unknown → canonical."""
    if not value:
        return "INFO"
    v = value.strip().lower()
    return {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MODERATE",
        "low": "LOW",
        "info": "INFO",
        "informational": "INFO",
        "unknown": "INFO",
    }.get(v, "INFO")


def map_severity_cvss(score: Optional[float]) -> str:
    """CVSS 3.x score → canonical. Conservative thresholds."""
    if score is None:
        return "INFO"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "INFO"
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 5.0:  # MODERATE-HIGH reserved for manual classification; tool output never auto-promotes
        return "MODERATE"
    if s >= 3.0:
        return "LOW"
    return "INFO"


# ─── identity ─────────────────────────────────────────────────────────────────
def stable_finding_id(asset_id: str, source: str, template_id: str, matched_at: str) -> str:
    """
    Deterministic finding identity.

    Format: <asset>:<source>:<template_id>:<hash7>
    where hash7 is the first 7 hex chars of sha256(matched_at).

    Two observations of the same nuclei template hitting the same URL across
    different scans produce the same finding_id — that's how history is built.
    A different URL on the same template = different finding_id (different
    instance of the same vuln pattern).
    """
    matched = matched_at or ""
    h = hashlib.sha256(matched.encode("utf-8")).hexdigest()[:7]
    return f"{asset_id}:{source}:{template_id}:{h}"


# ─── timestamps ───────────────────────────────────────────────────────────────
def to_utc_iso(ts: Optional[str]) -> Optional[str]:
    """Normalize any ISO-ish timestamp to UTC ISO-8601 with a Z suffix."""
    if not ts:
        return None
    try:
        # fromisoformat handles tz-aware inputs in 3.11+
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, AttributeError):
        return ts  # best-effort: return as-is rather than dropping


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── path helpers ─────────────────────────────────────────────────────────────
def relative_to_scan_root(path: Path | str, scan_root: Path) -> str:
    """
    Convert an absolute path to a relative-to-scan-root path so canonical
    records stay portable (don't bake in Howie's home directory).
    """
    p = Path(path).resolve()
    try:
        return str(p.relative_to(scan_root.resolve()))
    except ValueError:
        # Path is outside scan_root — fall back to the basename
        return p.name


# ─── target → asset_id mapping ────────────────────────────────────────────────
def infer_asset_id(target_dirname: str) -> str:
    """
    Map a target directory name to a canonical asset_id.

    Conventions seen on disk:
      commandcommcentral          → commandcommcentral.com
      commanddigital              → commanddigital.com
      unimacgraphics              → unimacgraphics.com
      api-commandcommcentral      → api.commandcommcentral.com
      vpn-sciimage                → vpn.sciimage.com
      email-sciimage              → email.sciimage.com
      cablenet-nodns              → ip-range:cablenet-nodns
      cablenet-test3-testapi      → testapi.commandcommcentral.com (approx — needs disambiguation)
      mail-commandweb             → mail.commandweb.com
      ftp-sciimage                → ftp.sciimage.com
      insite-sciimage             → insite.sciimage.com
      www.commandcommcentral.com  → www.commandcommcentral.com (already FQDN)
      test.commandcommcentral.com → test.commandcommcentral.com (already FQDN)
      commandcompanies            → commandcompanies.com
      commandmarketinginnovations → commandmarketinginnovations.com

    Hostname-style names with dots are taken as-is. Otherwise we apply known
    transforms. Unknown names fall back to `target:<dirname>` so we don't
    fabricate an asset identity we can't justify.
    """
    if "." in target_dirname:
        return target_dirname
    mapping = {
        "commandcommcentral":            "commandcommcentral.com",
        "commanddigital":                "commanddigital.com",
        "commandcompanies":              "commandcompanies.com",
        "commandmarketinginnovations":   "commandmarketinginnovations.com",
        "unimacgraphics":                "unimacgraphics.com",
        "api-commandcommcentral":        "api.commandcommcentral.com",
        "vpn-sciimage":                  "vpn.sciimage.com",
        "vpn2-sciimage":                 "vpn2.sciimage.com",
        "email-sciimage":                "email.sciimage.com",
        "ftp-sciimage":                  "ftp.sciimage.com",
        "insite-sciimage":               "insite.sciimage.com",
        "mail-commandweb":               "mail.commandweb.com",
        "cablenet-nodns":                "ip-range:cablenet-nodns",
        "cablenet-test3-testapi":        "testapi.commandcommcentral.com",
    }
    return mapping.get(target_dirname, f"target:{target_dirname}")


# ─── finding events ───────────────────────────────────────────────────────────
@dataclass
class FindingEvent:
    """
    One observation of a finding by one parser in one scan.

    Driver collects events, groups by finding_id, builds final Finding records
    with history arrays.
    """
    finding_id: str
    asset_id: str
    scan_id: str
    source: str                         # "nuclei", "zap", "semgrep", "manual_named", etc.
    title: str
    severity: str                       # canonical
    category: str
    observed_at: str                    # UTC ISO
    matched_at: Optional[str] = None
    description: Optional[str] = None
    cve: list[str] = field(default_factory=list)
    cwe: list[int] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    raw_excerpt: Optional[str] = None
    evidence_paths: list[str] = field(default_factory=list)  # relative to scan_root

    # Merger-prep fields (extended schema 2026-05-16). Optional, populated when
    # the parser can derive them. Enables service-centric and subdomain-centric
    # SPA views without needing a separate services table for Phase 1.
    subdomain: Optional[str] = None     # FQDN where finding observed
    host_ip: Optional[str] = None       # IP address
    port: Optional[int] = None
    protocol: Optional[str] = None      # http/https/tcp/udp/ssl/dns/smtp/imap/pop3

    # Status hint from manually-authored sources (SUMMARY.md, VERDICT.md).
    # Drives the rollup to set current_status correctly across scans.
    # None when the parser has no explicit status signal — rollup falls back
    # to count-based heuristic.
    status_hint: Optional[str] = None   # "open", "remediated", "regressed", "validated_remediated"


def event_to_dict(ev: FindingEvent) -> dict:
    return asdict(ev)


# ─── status hint mapping (SUMMARY.md author's intent → canonical status) ────
STATUS_HINT_MAP = {
    "UNPATCHED":                 "open",
    "UNCHANGED":                 "open",
    "STILL OPEN":                "open",
    "STILL-OPEN":                "open",
    "OPEN":                      "open",
    "CONFIRMED":                 "confirmed",
    "NEW":                       "detected",
    "REMEDIATED":                "remediated",
    "RESOLVED":                  "remediated",
    "FIXED":                     "remediated",
    "VALIDATED_REMEDIATED":      "validated_remediated",
    "VALIDATED REMEDIATED":      "validated_remediated",
    "REGRESSED":                 "regressed",
    "FALSE_POSITIVE":            "false_positive",
    "FALSE POSITIVE":            "false_positive",
}


def normalize_status_hint(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    return STATUS_HINT_MAP.get(raw.strip().upper())


# ─── subdomain inference from URL ─────────────────────────────────────────────
def subdomain_from_url(url: Optional[str]) -> Optional[str]:
    """Pull the FQDN from a URL. Returns None if can't determine."""
    if not url:
        return None
    import re
    m = re.match(r"^(?:https?|ssl|ftp|smtp)://([^/:?#]+)", url, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    # Sometimes nuclei records bare host:port
    m = re.match(r"^([a-z0-9.-]+)(?::\d+)?$", url, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    return None


def port_from_url(url: Optional[str]) -> Optional[int]:
    """Extract port from URL. None if not explicit (callers can default by protocol)."""
    if not url:
        return None
    import re
    m = re.match(r"^[a-z]+://[^/:]+:(\d+)", url, re.IGNORECASE)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def protocol_from_url(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    url = url.lower()
    if url.startswith("https://"): return "https"
    if url.startswith("http://"):  return "http"
    if url.startswith("ssl://"):   return "ssl"
    if url.startswith("ftp://"):   return "ftp"
    if url.startswith("smtp://"):  return "smtp"
    return None


# ─── category inference ───────────────────────────────────────────────────────
def infer_category_from_tags(tags: list[str], template_id: str = "") -> str:
    """
    Heuristic mapping from nuclei tags / template-id to canonical category.

    Conservative: when in doubt, fall back to 'other' rather than mislabeling.
    """
    t = set((tag or "").lower() for tag in tags)
    tid = (template_id or "").lower()

    if "xss" in t or "xss" in tid:
        return "xss"
    if "sqli" in t or "sql-injection" in t or "sqli" in tid:
        return "sqli"
    if "ssrf" in t:
        return "ssrf"
    if "xxe" in t:
        return "xxe"
    if "rce" in t or "code-execution" in t:
        return "rce"
    if "lfi" in t or "file-inclusion" in t:
        return "lfi"
    if "csrf" in t:
        return "csrf"
    if "redirect" in t or "open-redirect" in t:
        return "redirect"
    if "idor" in t:
        return "idor"
    if "auth" in t or "authentication" in t or "auth-bypass" in t:
        return "auth"
    if "session" in t:
        return "session"
    if "ssl" in t or "tls" in t or "cert" in t:
        return "tls"
    if "headers" in t or "missing-headers" in t or "security-headers" in t:
        return "headers"
    if "dns" in t:
        return "dns"
    if "spf" in t or "dmarc" in t or "dkim" in t:
        return "email"
    if "secret" in t or "exposure" in t or "leak" in t:
        return "secret"
    if "subdomain-takeover" in t or "takeover" in t:
        return "takeover"
    if "disclosure" in t or "info-leak" in t or "info-disclosure" in t:
        return "info_disclosure"
    if "config" in t or "misconfig" in t or "default-creds" in t:
        return "config"
    if "deprecated" in t or "eol" in t:
        return "deprecation"
    if any(x in t for x in ("cve", "wordpress", "wp", "wp-plugin", "wp-theme", "package")):
        return "supply_chain"
    return "other"
