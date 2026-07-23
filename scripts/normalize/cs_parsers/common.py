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
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─── ANSI escape stripping ────────────────────────────────────────────────────
# Tools that emit colored output (nuclei is the worst offender, wpscan too)
# can leak ANSI SGR escapes into the strings we end up storing in
# finding_id / normalized_key / title. The user-facing artifact is ugly
# (e.g. `[92mhttp-missing-security-headers[0m`) and breaks string
# comparisons for dedup. Strip them at every ingest boundary AND defensively
# bake the strip into stable_finding_id so a forgetful parser can't leak.
#
# Pattern covers both forms seen in the wild:
#   • Full ANSI: ESC[XXm  (e.g. \x1b[92m)
#   • Bare bracketed: [XXm  (the ESC byte got dropped somewhere upstream)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m|\[\d+m")


def strip_ansi(s: str) -> str:
    """Remove ANSI SGR escapes from a string. Idempotent. None-safe."""
    if not s:
        return s
    return ANSI_RE.sub("", s)


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
    # Defense in depth: strip ANSI escapes from template_id at the ID-build
    # boundary. Parsers SHOULD strip at capture (see nuclei_text.py 2026-06-02
    # fix), but this guarantees ANSI never leaks into a finding_id even if a
    # future parser forgets.
    template_id_clean = strip_ansi(template_id or "")
    h = hashlib.sha256(matched.encode("utf-8")).hexdigest()[:7]
    return f"{asset_id}:{source}:{template_id_clean}:{h}"


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

    Hostname-style names with dots are taken as-is, then run through
    canonical_asset_id() so www.X folds into X per design principle #5.
    Unknown names fall back to `target:<dirname>` so we don't fabricate an
    asset identity we can't justify.
    """
    if "." in target_dirname:
        return canonical_asset_id(target_dirname) or target_dirname
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

    # 4.7 H1/H5 (2026-07-08) — parser-native dedup key for INTRA-source class
    # collapse (e.g. nikto tech-fingerprint headers → "tech-header-disclosure").
    # Distinct from the cross-source same-fact map (run_normalize #36); when a
    # parser sets this, run_normalize honours it over the (None) cross-source lookup.
    normalized_key: Optional[str] = None

    # #2.05 (Obsidian 160 / 4.7 2026-07-23) — per-class target context for the safe-exploit
    # pipeline, persisted to findings.params (jsonb, default {}). cors: {endpoint,
    # acao_observed, acac_observed, source}. redirect/ssrf/lfi (phase 2): {endpoint,
    # param_name, param_example, discovery_source}. Shape documented as code in
    # safe_exploit.PARAMS_SCHEMAS; empty {} for every non-safe-exploit finding.
    params: dict = field(default_factory=dict)

    def __post_init__(self):
        # Title normalization happens once at construction so every parser
        # gets it for free without each one having to remember.
        #
        # 1. Strip ANSI escape sequences (some scanners leak colored output
        #    into title strings).
        # 2. Collapse any whitespace run (multiple spaces, tabs, embedded
        #    newlines) to a single space. nuclei + testssl frequently emit
        #    titles like "ssl-issuer  [Let's Encrypt]" with a double-space
        #    between the slug and the bracketed metadata; this normalizes
        #    them at ingest so the portal never has to.
        # 3. Trim leading/trailing whitespace.
        if self.title:
            cleaned = strip_ansi(self.title)
            cleaned = re.sub(r"\s+", " ", cleaned).strip()
            self.title = cleaned


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


def canonical_asset_id(fqdn: Optional[str]) -> Optional[str]:
    """
    Collapse www.X and X to the same canonical asset_id.

    The bare apex and the www subdomain are operationally the same web
    property in 99% of cases — same server, same WordPress install, same
    posture. Treating them as separate assets creates phantom 'two boxes'
    in the dashboard when there's really one. Other subdomains
    (test/api/admin/etc) are genuinely distinct and not collapsed.

    The finding's `subdomain` field still records the actual hostname that
    was scanned (www.X), so forensic drill-in shows the real URL. Only the
    asset_id grouping changes.
    """
    if not fqdn:
        return fqdn
    fqdn = fqdn.lower()
    if fqdn.startswith("www."):
        return fqdn[4:]
    return fqdn


def is_fqdn_in_scope(fqdn: Optional[str], target_asset: str) -> bool:
    """
    Returns True if fqdn is the target_asset's registrable apex or a subdomain
    of it. Used to restrict per-event asset_id overrides to in-scope FQDNs —
    keeps scan-output references to external URLs (login.microsoftonline.com,
    rdap.verisign.com, CDN endpoints) from becoming spurious assets.

    For IP-based targets, returns False (no FQDN override applies).
    """
    if not fqdn or not target_asset:
        return False
    if target_asset.startswith("ip:") or target_asset.startswith("ip-range:") or target_asset.startswith("target:"):
        return False
    fqdn = fqdn.lower()
    parts = target_asset.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else target_asset
    return fqdn == apex or fqdn.endswith("." + apex)


def resolve_finding_asset_id(target_dirname: str, *url_candidates: Optional[str]) -> str:
    """
    Decide the asset_id for a finding. Prefers the most specific FQDN we can
    derive from URL candidates (matched_at, target URL, host string), but ONLY
    if that FQDN is under the same registrable apex as the target dir's
    canonical asset.

    Why the apex restriction: scan outputs frequently reference external
    URLs (login.microsoftonline.com, rdap.verisign.com, CDN endpoints, etc.).
    Without filtering, those become spurious 'assets' in the dashboard.
    By restricting to in-scope FQDNs, we keep test/www/api etc as their own
    assets while keeping external references attributed to the target apex.

    For IP-based targets, no URL-derived override is applied — IPs stay as IPs.

    URL candidates tried in order; first valid FQDN-under-apex match wins.
    """
    target_asset = infer_asset_id(target_dirname)

    # IP-based targets: don't try to URL-derive
    if target_asset.startswith("ip:") or target_asset.startswith("ip-range:") or target_asset.startswith("target:"):
        return target_asset

    # FQDN-based target — compute the registrable-domain apex (last 2 labels
    # for .com/.net/.org-style TLDs; this is naive but works for the
    # Command-family domains and most others we encounter).
    target_parts = target_asset.split(".")
    target_apex = ".".join(target_parts[-2:]) if len(target_parts) >= 2 else target_asset

    for url in url_candidates:
        fqdn = subdomain_from_url(url) if url else None
        if not fqdn:
            continue
        fqdn = fqdn.lower()
        # Only accept if under the same registrable apex
        if fqdn == target_apex or fqdn.endswith("." + target_apex):
            return fqdn
    return target_asset


# ─── category inference ───────────────────────────────────────────────────────
# ─── cross-source semantic dedup (#36) ────────────────────────────────────────
# Curated, conservative same-fact equivalence map. When the same single fact
# is detected by multiple sources with divergent normalized_keys (or none),
# this map collapses them to a shared canonical key so the dedup view
# (v_open_findings_dedup, grouped on (asset_id, normalized_key)) sees ONE
# group instead of N.
#
# SCOPE — DO NOT BROADEN. Two classes only. Each entry must be EARNED with
# evidence that the matched (source, title) pairs describe the SAME single
# fact — not just topically related, not opposite states, not multi-issue.
#
# NEVER MERGE (and the negative-test fixture in test_cross_source_equivalence.py
# locks these in as regression guards):
#   • ciphers (LUCKY13 != CBC-enabled != obsoleted — distinct fixes)
#   • HSTS-present vs HSTS-missing (OPPOSITES — merging hides the gap)
#   • CSRF F-02 vs F-03 (distinct)
#   • nuclei `dmarc-detect` (INFO DETECTION — opposite semantic of "missing")
#
# DEFERRED: CSP, forward-secrecy.
#
# Patterns are applied case-insensitively. Pattern precision IS the
# conservatism: e.g. the DMARC entry uses the exact phrase 'no dmarc record'
# (NOT a generic 'dmarc' match) to avoid catching manual_named F-02
# "Domain Spoofing Enabled — No SPF, DMARC, or…" and L-05 "No SPF/DMARC/MX"
# which are multi-issue findings that would wrongly fold SPF/DKIM into the
# DMARC dedup group.
#
# Mirrors migration 20260618a_cross_source_dedup_dmarc_ocsp.sql exactly —
# both the (source, pattern) → canonical_key map AND the never-merge list.
# Any edit here MUST land in the SQL migration too (or the next normalize
# pass diverges from the backfilled DB state).
CROSS_SOURCE_EQUIVALENCE: list[dict] = [
    {
        "canonical_key": "dns-missing-dmarc",
        "patterns": [
            ("manual_named",        re.compile(r"no dmarc record", re.IGNORECASE)),
            ("commandsentry_light", re.compile(r"dns missing dmarc", re.IGNORECASE)),
        ],
    },
    {
        "canonical_key": "tls-ocsp-stapling-missing",
        "patterns": [
            ("manual_named", re.compile(r"no ocsp stapling", re.IGNORECASE)),
            ("testssl",      re.compile(r"ocsp stapling not enabled", re.IGNORECASE)),
        ],
    },
]


def apply_cross_source_equivalence(source: Optional[str], title: Optional[str]) -> Optional[str]:
    """
    Return the canonical normalized_key for a (source, title) pair if it
    matches a curated cross-source equivalence entry. Returns None otherwise
    (caller preserves whatever normalized_key the source originally derived,
    or leaves it NULL for sources that don't derive one — e.g. manual_named).

    Applied during rollup_findings() in run_normalize.py. Findings that don't
    match any entry keep their source-specific key (or no key), which is the
    correct conservative behavior — only same-fact equivalences earn merging.
    """
    if not source or not title:
        return None
    for entry in CROSS_SOURCE_EQUIVALENCE:
        for entry_source, pattern in entry["patterns"]:
            if entry_source == source and pattern.search(title):
                return entry["canonical_key"]
    return None


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
    if "cors" in t:                          # 4.7 Q3 (Obsidian 160 / #2.05) — CORS misconfiguration class
        return "cors"
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
