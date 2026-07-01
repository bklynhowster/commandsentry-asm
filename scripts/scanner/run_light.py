#!/usr/bin/env python3
"""
run_light.py — Phase 4a M3 Light tier scanner

Consumes a scan descriptor (produced by poll_queue.py — see M2), runs the
Light tier check suite against the asset, writes findings + raw artifacts
to Supabase, and closes out the scan_run with status='complete' (or 'failed'
if something blew up).

LIGHT TIER PHILOSOPHY:
  • Passive HTTPS only — no active payloads, no fuzzing, no auth flows
  • Fast (~30-60 sec per asset)
  • IronPort-equivalent safe — nothing here should ever trigger a WAF
  • Catches the high-signal config/posture issues:
      - TLS cert about to expire / weak signature
      - Missing security headers (HSTS, CSP, X-Frame, X-Content-Type, etc.)
      - Common dev-leak paths exposed (.git, .env, /admin, etc.)
      - DNS posture (DMARC, SPF, DKIM)
      - Tech disclosure (httpx -td)
      - HTTP methods that shouldn't be enabled (TRACE)
      - Static CSP nonces (caught CCC M-02)

CHECKS RUN (in order):
  1. tls_check         — openssl cert chain inspection
  2. headers_check     — 7 security headers presence
  3. common_paths      — 8 well-known leak paths
  4. dns_posture       — DMARC / SPF / DKIM via dig
  5. httpx_tech        — tech detection (informational)
  6. methods_check     — OPTIONS / TRACE / etc.
  7. csp_nonce_check   — static-nonce detector (NEW for Phase 4a)

USAGE:
  python scripts/scanner/run_light.py /tmp/scan_descriptor.json

ENVIRONMENT:
  SUPABASE_DSN — required (or pass --dsn)

EXIT CODES:
  0 — scan ran (findings written, scan_run closed). Findings may be 0; the
      run is still counted as 'complete'.
  1 — fatal error (DB unreachable, descriptor invalid, etc.). scan_run is
      marked 'failed' before exit so the row is never left stuck 'running'.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ─── Lazy import psycopg ────────────────────────────────────────────────
def _import_deps() -> Any:
    try:
        import psycopg
        from psycopg.rows import dict_row
        from psycopg.types.json import Json
    except ImportError:
        print(
            "error: psycopg (psycopg3) required.\n"
            "  pip install --user --break-system-packages 'psycopg[binary]'",
            file=sys.stderr,
        )
        sys.exit(2)
    return psycopg, dict_row, Json


# ─── Constants ──────────────────────────────────────────────────────────
SECURITY_HEADERS = [
    # (header_name, severity, why_it_matters_one_liner)
    ("Strict-Transport-Security",       "MODERATE",
     "Browsers may attempt HTTP connections instead of upgrading to HTTPS"),
    ("Content-Security-Policy",         "MODERATE",
     "No server-side defense against XSS / inline-script injection"),
    ("X-Frame-Options",                 "LOW",
     "Page can be framed, enabling clickjacking attacks"),
    ("X-Content-Type-Options",          "LOW",
     "Browsers may MIME-sniff responses, enabling content-type confusion attacks"),
    ("Referrer-Policy",                 "LOW",
     "Outgoing requests may leak sensitive URL information in Referer headers"),
    ("Permissions-Policy",              "LOW",
     "No restriction on which browser features the site can use"),
    ("X-Permitted-Cross-Domain-Policies", "INFO",
     "Adobe Flash / PDF cross-domain access not explicitly restricted"),
]

COMMON_PATHS = [
    # (path, severity_if_exposed, why_it_matters)
    ("/.git/HEAD",            "HIGH",
     "Full source code and commit history retrievable via .git directory exposure"),
    ("/.env",                 "HIGH",
     "Environment file commonly contains database credentials and API keys"),
    ("/.git/config",          "HIGH",
     "Git configuration exposed — confirms .git directory is web-accessible"),
    ("/wp-config.php.bak",    "HIGH",
     "WordPress config backup commonly contains database credentials"),
    ("/wp-admin/install.php", "MODERATE",
     "WordPress installation page reachable — confirms WP install path"),
    ("/admin",                "INFO",
     "Admin path reachable (200) — login gate is normal but worth knowing"),
    ("/robots.txt",           "INFO",
     "Robots.txt reachable — informational, may reveal hidden paths"),
    ("/sitemap.xml",          "INFO",
     "Sitemap reachable — informational, enumerates content surface"),
]

DANGEROUS_METHODS = {
    "TRACE":  ("MODERATE", "TRACE enabled — historically used in Cross-Site Tracing attacks"),
    "PUT":    ("HIGH",     "PUT method allowed — may enable arbitrary file upload"),
    "DELETE": ("HIGH",     "DELETE method allowed — may enable resource removal by unauthenticated callers"),
    "PATCH":  ("MODERATE", "PATCH method allowed — may enable unauthorized modification"),
}

DEFAULT_SUPABASE_URL = "https://hdygktppfvuspnumpfuq.supabase.co"


# ─── ADR-001 — Validated-SHA key (convergent edition) ───────────────────
#
# Allowlist of (intensity, scanner_version) pairs whose emissions get
# stamped validation_status='validated'. Stored in the Postgres table
# public.scanner_validations, NOT in this runner code.
#
# WHY THE TABLE — full rationale in scripts/scanner/run_medium.py's
# block. Short version: an in-code allowlist can't self-reference (the
# commit recording a validation can't BE the validated commit). Moving
# to a table means promotion = INSERT, not a code change, so the regime
# converges. Bad code is still auto-invalidated because new SHAs aren't
# in the table until a human INSERTs them.
#
# Schema: scripts/db/migrations/20260608a_scanner_validations.sql

def get_scanner_version() -> str:
    """Return the runner's git SHA from GITHUB_SHA env (GH Actions
    populates this on every workflow run) or 'unknown' if absent.
    Always full 40-char SHA — never abbreviate, the table-match
    is exact-string."""
    return os.environ.get("GITHUB_SHA") or "unknown"


def derive_validation_status(conn, intensity: str, sha: str) -> str:
    """Query public.scanner_validations. Returns 'validated' iff a row
    exists for (intensity, sha); else 'unvalidated'. Fails loud if the
    table is missing — better than silently stamping 'unvalidated' on a
    misconfigured deploy."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM public.scanner_validations "
            "WHERE intensity = %s AND scanner_version = %s",
            (intensity, sha),
        )
        return "validated" if cur.fetchone() else "unvalidated"


# ─── Finding model ──────────────────────────────────────────────────────
@dataclass
class LightFinding:
    """A single Light-tier finding ready to upsert."""
    check_name:   str           # e.g., "missing-header-hsts"
    title:        str           # human-readable
    severity:     str           # CRITICAL / HIGH / MODERATE-HIGH / MODERATE / LOW / INFO
    # category MUST be a value in the finding_category_t enum. Valid values are:
    #   sast, dast, sca, secret, recon, tls, headers, dns, email, auth, session,
    #   csrf, ssrf, xxe, xss, sqli, idor, rce, lfi, redirect, info_disclosure,
    #   takeover, typosquat, config, deprecation, supply_chain, other
    # Light tier uses: tls, headers, dns, info_disclosure (for paths + tech), config (for methods)
    category:     str
    description:  str           # 1-3 sentence scanner-side summary (enrichment expands this)
    tags:         list[str] = field(default_factory=list)
    cwe:          list[int] = field(default_factory=list)
    # CVE IDs when known. Populated by probes/checks that detect a specific
    # CVE (wpvulnerability lookups, WPS Hide Login probe, etc.). Empty for
    # findings that don't map to a CVE (CSP nonce posture, missing headers).
    # The portal groupBySharedCve() render-time dedup keys off this — so
    # wpscan-imported + manual_named + commandsentry_light findings of the
    # same CVE render as a single "N sources" row when all three populate
    # this field.
    cve:          list[str] = field(default_factory=list)
    references:   list[str] = field(default_factory=list)
    raw_excerpt:  str | None = None
    # Explicit normalized_key. When set, this WINS over the default derivation
    # at upsert time (CVE-join / check_name). Used by wpvulnerability findings
    # to force plugin-level master dedup (normalized_key = wpplugin-<slug>) so
    # every advisory for one plugin install collapses into ONE group instead
    # of one row per CVE. Without it, cve-populated wp findings key off the CVE
    # and each CVE renders as its own row (P-008 regression — the reason
    # migration 20260604c's backfill kept getting undone on re-scan).
    normalized_key_override: str | None = None


@dataclass
class ScanContext:
    descriptor:    dict
    hostname:      str
    asset_id:      str
    scan_run_id:   str
    queue_id:      str
    intensity:     str
    findings:      list[LightFinding] = field(default_factory=list)
    tools_run:     list[str] = field(default_factory=list)
    artifacts:     list[tuple[str, str, str]] = field(default_factory=list)
    # artifacts: list of (tool_name, output_format, content_string)
    # M3 revision (2026-05-29): port_scan() populates open_ports before
    # service-specific checks dispatch. asset_kind comes from the
    # descriptor when present so we can short-circuit "no need to scan
    # HTTPS on a pure mail relay" decisions.
    open_ports:    set[int] = field(default_factory=set)
    asset_kind:    str | None = None

    # S1 2026-06-09: per-tool completeness map written to
    # scan_run.tool_status at close-out. Keys match tool_run entries;
    # values are {"ok": True} or {"degraded": "<reason>"}.
    # The "degraded" reason is a stable machine-readable slug so
    # downstream reports group on it. Same framework that surfaced
    # nikto Bug E in run_medium.py — "tool failed silently" was
    # invisible until tool_status; same risk class in light's many
    # log()-only failure paths.
    tool_status:   dict[str, dict] = field(default_factory=dict)


# ─── Subprocess helper ──────────────────────────────────────────────────
def run_cmd(cmd: list[str], timeout: int = 30, input_str: str | None = None) -> tuple[int, str, str]:
    """Run a shell command. Returns (returncode, stdout, stderr).
    Never raises — failures get captured and surfaced to the caller.
    """
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_str,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired as e:
        return 124, "", f"timeout after {timeout}s: {e}"
    except FileNotFoundError as e:
        return 127, "", f"command not found: {cmd[0]} — {e}"
    except Exception as e:
        return 1, "", f"unexpected: {e!r}"


def log(msg: str) -> None:
    print(f"[run_light] {msg}", file=sys.stderr)


# ─── S1 (2026-06-09) — per-tool degraded-status framework ──────────────
# Mirrors run_medium.py's nikto/ffuf/wafw00f detectors. The unifying
# rule from S0 medium work (Howie 2026-06-07): "degraded" means tool
# FAILED in a recognized way, NEVER "tool worked within its budget."
# Detectors that cry-wolf on empty-but-healthy runs are the exact
# nuclei-empty trap we don't want to repeat.

def mark_tool_ok(ctx: ScanContext, tool_name: str) -> None:
    """Record that a tool produced real output."""
    ctx.tool_status[tool_name] = {"ok": True}


def mark_tool_degraded(ctx: ScanContext, tool_name: str, reason: str) -> None:
    """Record that a tool failed in a recognized way. `reason` is a stable
    machine-readable slug (snake_case) — downstream groups on it."""
    ctx.tool_status[tool_name] = {"degraded": reason}


def mark_tool_skipped(ctx: ScanContext, tool_name: str, reason: str) -> None:
    """Record that a tool was INTENTIONALLY SKIPPED (third state — see
    run_medium.py mark_tool_skipped docstring for full design rationale).

    Shape: {"skipped": "<reason_slug>"}. A skipped tool is NOT degraded;
    a run with only ok + skipped statuses stays scan_quality='clean'.
    Light tier currently has no skip cases wired but the helper is
    mirrored here for parity with run_medium so future light-tier
    policy skips (e.g. dns_posture on internal-only assets) have the
    helper ready.
    """
    ctx.tool_status[tool_name] = {"skipped": reason}


def tls_check_is_degraded(exception: BaseException) -> tuple[bool, str]:
    """Python ssl/socket exceptions during TLS handshake.
    Distinguishes "connection refused" (target down — degraded) from
    "TLS handshake error" (got a verdict — healthy)."""
    msg = str(exception).lower()
    # Network-layer failures: degraded
    if isinstance(exception, (ConnectionRefusedError, ConnectionResetError, TimeoutError)):
        return True, "network_unreachable"
    if "timed out" in msg or "timeout" in msg:
        return True, "network_timeout"
    if "no route to host" in msg or "name or service not known" in msg or "getaddrinfo failed" in msg:
        return True, "dns_resolution_failed"
    if "connection refused" in msg:
        return True, "network_unreachable"
    # TLS-layer failures: ALSO degraded for our purposes — we can't
    # inspect a cert if we can't complete the handshake at all.
    # Distinguishes from "got cert but it's bad" which produces findings.
    if "ssl" in msg or "handshake" in msg:
        return True, "tls_handshake_failed"
    return True, "unknown_exception"


def headers_check_is_degraded(rc: int, stdout: str, stderr: str) -> tuple[bool, str]:
    """curl -sI failure modes. rc != 0 with empty stdout = couldn't fetch
    headers. rc == 0 but empty stdout = curl thinks it worked but got
    nothing parseable (uncommon but seen)."""
    if rc != 0 and len(stdout.strip()) == 0:
        # curl's own exit code mapping for the network-level failures
        if rc in (6, 7):  # 6=resolve failed, 7=connect failed
            return True, "network_unreachable"
        if rc == 28:  # operation timed out
            return True, "network_timeout"
        if rc == 35:  # SSL handshake fail
            return True, "tls_handshake_failed"
        return True, "curl_failed"
    if rc == 0 and len(stdout.strip()) == 0:
        return True, "empty_response_body"
    return False, ""


def httpx_tech_is_degraded(rc: int, stdout: str) -> tuple[bool, str]:
    """httpx -td output is JSON. Healthy: rc=0 and at least one JSON line.
    Degraded: rc != 0, or stdout doesn't contain a parseable JSON object.
    Empty findings (no tech detected) IS healthy — httpx still emits the
    `url` line even when it didn't fingerprint anything."""
    if rc != 0:
        return True, f"rc_{rc}"
    if not stdout.strip():
        return True, "empty_output"
    # Try to parse at least one line as JSON to confirm structure
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            json.loads(line)
            return False, ""
        except json.JSONDecodeError:
            continue
    return True, "no_parseable_json"


def dns_posture_is_degraded(spf_rc: int, dmarc_rc: int) -> tuple[bool, str]:
    """dig should always succeed even on NXDOMAIN (returns empty + rc=0).
    rc != 0 means the resolver itself failed (no network, no DNS service,
    dig binary missing). NXDOMAIN-without-record findings ARE healthy
    output (we emit "dns-missing-spf" finding) — that's not degraded."""
    if spf_rc != 0 and dmarc_rc != 0:
        return True, "resolver_unreachable"
    if spf_rc != 0:
        return True, "spf_query_failed"
    if dmarc_rc != 0:
        return True, "dmarc_query_failed"
    return False, ""


def httpx_methods_is_degraded(rc: int, stdout: str) -> tuple[bool, str]:
    """methods_check uses curl OPTIONS. Same failure-mode mapping as
    headers_check — rc != 0 with empty stdout means we couldn't ask the
    server about its methods at all."""
    if rc != 0 and len(stdout.strip()) == 0:
        if rc in (6, 7):
            return True, "network_unreachable"
        if rc == 28:
            return True, "network_timeout"
        return True, "curl_failed"
    return False, ""


def wpvuln_lookup_is_degraded(reason: str | None) -> tuple[bool, str]:
    """wpvulnerability has 4 distinct early-exit reasons (3 healthy +
    1 degraded). Caller passes the reason slug; we just classify.
        - 'client_import_failed' → degraded (env bug)
        - 'homepage_fetch_failed' → degraded (network)
        - 'not_wordpress' → HEALTHY (target isn't WP, skip is correct)
        - 'no_versions_detected' → HEALTHY (WP but no version leak, skip is correct)
    """
    if reason in ("client_import_failed", "homepage_fetch_failed"):
        return True, reason
    return False, ""


def common_paths_is_degraded(probe_count: int, total_paths: int) -> tuple[bool, str]:
    """common_paths probes a fixed list. If we couldn't probe ANY of
    them (all curl calls failed), the target is unreachable. If we
    probed at least some, even if no path was exposed, the check did
    its job — that's healthy."""
    if probe_count == 0 and total_paths > 0:
        return True, "all_probes_failed"
    return False, ""


def naabu_is_degraded(rc: int, stdout: str) -> tuple[bool, str]:
    """naabu port scan. rc != 0 with no output = scanner failed.
    rc == 0 with empty stdout = legitimately no open ports (healthy).
    The difference is the rc."""
    if rc != 0 and not stdout.strip():
        if rc == 127:
            return True, "naabu_not_installed"
        return True, f"naabu_rc_{rc}"
    return False, ""


# ─── Check implementations ──────────────────────────────────────────────

def check_tls(ctx: ScanContext) -> None:
    """Inspect the TLS cert via Python's ssl module (no openssl subprocess)."""
    ctx.tools_run.append("tls_check")
    try:
        with socket.create_connection((ctx.hostname, 443), timeout=10) as sock:
            sslctx = ssl.create_default_context()
            sslctx.check_hostname = False
            sslctx.verify_mode = ssl.CERT_NONE
            with sslctx.wrap_socket(sock, server_hostname=ctx.hostname) as ssock:
                cert = ssock.getpeercert()
                der  = ssock.getpeercert(binary_form=True)
                version = ssock.version()
    except Exception as e:
        log(f"tls_check: connect/handshake failed: {e}")
        _, reason = tls_check_is_degraded(e)
        mark_tool_degraded(ctx, "tls_check", reason)
        return

    not_after_str = cert.get("notAfter", "")
    try:
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_remaining = (not_after - datetime.now(timezone.utc)).days
    except Exception:
        days_remaining = None

    artifact = {
        "subject":       cert.get("subject"),
        "issuer":        cert.get("issuer"),
        "not_before":    cert.get("notBefore"),
        "not_after":     not_after_str,
        "san":           cert.get("subjectAltName"),
        "tls_version":   version,
        "days_remaining": days_remaining,
    }
    ctx.artifacts.append(("tls_check", "json", json.dumps(artifact)))

    if days_remaining is not None:
        if days_remaining < 0:
            ctx.findings.append(LightFinding(
                check_name="tls-cert-expired",
                title=f"TLS certificate expired ({abs(days_remaining)} days ago)",
                severity="HIGH",
                category="tls",  # enum: tls
                description=f"The TLS certificate served by {ctx.hostname} expired on "
                            f"{not_after_str}. Browsers and clients will refuse to "
                            f"connect or show warnings until a fresh certificate is issued.",
                tags=["tls", "cert", "expired"],
                raw_excerpt=json.dumps(artifact, indent=2)[:2000],
            ))
        elif days_remaining < 14:
            ctx.findings.append(LightFinding(
                check_name="tls-cert-expiring-soon",
                title=f"TLS certificate expires in {days_remaining} days",
                severity="MODERATE",
                category="tls",
                description=f"The TLS certificate on {ctx.hostname} expires in "
                            f"{days_remaining} days ({not_after_str}). Schedule a "
                            f"renewal before expiry to avoid client-facing outages.",
                tags=["tls", "cert", "expiring"],
                raw_excerpt=json.dumps(artifact, indent=2)[:2000],
            ))

    if version and version.lower() in ("tlsv1", "tlsv1.0", "tlsv1.1"):
        ctx.findings.append(LightFinding(
            check_name="tls-weak-protocol",
            title=f"Deprecated TLS protocol negotiated: {version}",
            severity="MODERATE",
            category="tls",
            description=f"{ctx.hostname} negotiated {version} during handshake. "
                        f"TLS 1.0 and 1.1 are deprecated. Configure the server to "
                        f"require TLS 1.2+ (or 1.3 where supported).",
            tags=["tls", "protocol", "deprecated"],
            raw_excerpt=f"TLS protocol: {version}",
        ))

    mark_tool_ok(ctx, "tls_check")


def check_headers(ctx: ScanContext) -> None:
    """Fetch '/' and check for the standard security header set."""
    ctx.tools_run.append("headers_check")
    rc, stdout, stderr = run_cmd(
        ["curl", "-sI", "-L", "--max-time", "15",
         "-H", "User-Agent: Mozilla/5.0 (compatible; COMMANDsentry/1.0)",
         f"https://{ctx.hostname}/"],
        timeout=20,
    )
    degraded, reason = headers_check_is_degraded(rc, stdout, stderr)
    if degraded:
        log(f"headers_check: curl rc={rc}: {stderr.strip()[:200]}")
        mark_tool_degraded(ctx, "headers_check", reason)
        return

    ctx.artifacts.append(("headers_check", "txt", stdout))

    headers_lc = {}
    for line in stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers_lc[k.strip().lower()] = v.strip()

    for header_name, severity, why in SECURITY_HEADERS:
        if header_name.lower() not in headers_lc:
            slug = header_name.lower().replace("-", "_")
            ctx.findings.append(LightFinding(
                check_name=f"missing-header-{header_name.lower()}",
                title=f"Missing security header: {header_name}",
                severity=severity,
                category="headers",
                description=f"The HTTP response from {ctx.hostname} does not include "
                            f"the {header_name} header. {why}.",
                tags=["headers", "missing-header", slug],
                cwe=[693],
                raw_excerpt=stdout[:1500],
            ))

    mark_tool_ok(ctx, "headers_check")


def check_common_paths(ctx: ScanContext) -> None:
    """HEAD-probe a list of common leak paths. 200/204/206 = exposed."""
    ctx.tools_run.append("common_paths")
    results = []
    successful_probes = 0
    for path, severity, why in COMMON_PATHS:
        rc, stdout, stderr = run_cmd(
            ["curl", "-s", "-o", "/dev/null",
             "-w", "%{http_code}",
             "--max-time", "10",
             "-H", "User-Agent: Mozilla/5.0 (compatible; COMMANDsentry/1.0)",
             f"https://{ctx.hostname}{path}"],
            timeout=15,
        )
        code = stdout.strip() if rc == 0 else "err"
        if rc == 0:
            successful_probes += 1
        results.append({"path": path, "status": code})
        if code in ("200", "204", "206"):
            slug = path.lstrip("/").replace("/", "-").replace(".", "")
            ctx.findings.append(LightFinding(
                check_name=f"exposed-path-{slug}",
                title=f"Exposed path: {path} (HTTP {code})",
                severity=severity,
                category="info_disclosure",  # enum remap: 'paths' isn't a valid finding_category_t
                description=f"The path {path} on {ctx.hostname} returned HTTP {code}. {why}.",
                tags=["paths", "exposure"],
                cwe=[538],
                raw_excerpt=f"GET {path} -> HTTP {code}",
            ))

    ctx.artifacts.append(("common_paths", "json", json.dumps({"probes": results})))

    # If every single probe failed (rc != 0 for all paths), the target
    # is unreachable — mark degraded. If at least one succeeded, the
    # check did its job, regardless of whether any path was exposed.
    degraded, reason = common_paths_is_degraded(successful_probes, len(COMMON_PATHS))
    if degraded:
        mark_tool_degraded(ctx, "common_paths", reason)
    else:
        mark_tool_ok(ctx, "common_paths")


def check_dns_posture(ctx: ScanContext) -> None:
    """Use dig to check DMARC, SPF, DKIM presence."""
    ctx.tools_run.append("dns_posture")
    results: dict[str, Any] = {}

    # SPF — TXT record on the hostname
    spf_rc, stdout, _ = run_cmd(["dig", "+short", "TXT", ctx.hostname], timeout=10)
    txt_lines = [l.strip().strip('"') for l in stdout.splitlines() if l.strip()]
    spf_lines = [l for l in txt_lines if l.lower().startswith("v=spf1")]
    results["spf"] = spf_lines
    if not spf_lines:
        ctx.findings.append(LightFinding(
            check_name="dns-missing-spf",
            title="DNS missing SPF record",
            severity="MODERATE",
            category="dns",
            description=f"No SPF (v=spf1) TXT record found on {ctx.hostname}. "
                        f"Without SPF, attackers can spoof mail from this domain "
                        f"without receiving-server rejection.",
            tags=["dns", "email-auth", "spf"],
            cwe=[290],  # CWE-290 Authentication Bypass by Spoofing
            raw_excerpt=stdout[:1000],
        ))

    # DMARC — TXT on _dmarc.<hostname>
    dmarc_rc, stdout, _ = run_cmd(["dig", "+short", "TXT", f"_dmarc.{ctx.hostname}"], timeout=10)
    dmarc_lines = [l.strip().strip('"') for l in stdout.splitlines() if l.strip()]
    dmarc_records = [l for l in dmarc_lines if l.lower().startswith("v=dmarc1")]
    results["dmarc"] = dmarc_records
    if not dmarc_records:
        ctx.findings.append(LightFinding(
            check_name="dns-missing-dmarc",
            title="DNS missing DMARC record",
            severity="MODERATE",
            category="dns",
            description=f"No DMARC (v=DMARC1) TXT record found at _dmarc.{ctx.hostname}. "
                        f"DMARC instructs receiving servers what to do with mail that "
                        f"fails SPF/DKIM — without it, spoofed mail passes through.",
            tags=["dns", "email-auth", "dmarc"],
            cwe=[290],  # CWE-290 Authentication Bypass by Spoofing
            raw_excerpt=stdout[:1000],
        ))
    else:
        # Check for p=none (monitoring only — not enforcing)
        rec = dmarc_records[0]
        if "p=none" in rec.lower():
            ctx.findings.append(LightFinding(
                check_name="dns-dmarc-policy-none",
                title="DMARC policy set to p=none (monitoring only)",
                severity="LOW",
                category="dns",
                description=f"DMARC record on {ctx.hostname} is set to p=none, "
                            f"meaning receiving servers will report on spoofed mail "
                            f"but won't reject it. Move to p=quarantine once you've "
                            f"reviewed DMARC reports, then to p=reject.",
                tags=["dns", "dmarc", "policy"],
                raw_excerpt=rec,
            ))

    ctx.artifacts.append(("dns_posture", "json", json.dumps(results)))

    # Degraded only when the RESOLVER fails (dig non-zero). NXDOMAIN /
    # missing-record cases produce findings, not degradation.
    degraded, reason = dns_posture_is_degraded(spf_rc, dmarc_rc)
    if degraded:
        mark_tool_degraded(ctx, "dns_posture", reason)
    else:
        mark_tool_ok(ctx, "dns_posture")


def check_httpx_tech(ctx: ScanContext) -> None:
    """Tech detection via httpx -td. Informational only."""
    ctx.tools_run.append("httpx_tech")
    rc, stdout, stderr = run_cmd(
        ["httpx", "-u", f"https://{ctx.hostname}", "-td", "-silent", "-json", "-timeout", "15"],
        timeout=25,
    )
    degraded, reason = httpx_tech_is_degraded(rc, stdout)
    if degraded:
        log(f"httpx_tech: rc={rc}, no output: {stderr.strip()[:200]}")
        mark_tool_degraded(ctx, "httpx_tech", reason)
        return

    try:
        data = json.loads(stdout.splitlines()[0])
    except Exception as e:
        log(f"httpx_tech: JSON parse failed: {e}")
        mark_tool_degraded(ctx, "httpx_tech", "json_parse_failed")
        return

    ctx.artifacts.append(("httpx_tech", "json", json.dumps(data)))

    tech = data.get("tech") or data.get("technologies") or []
    if tech:
        ctx.findings.append(LightFinding(
            check_name="tech-disclosure",
            title=f"Detected technologies: {', '.join(tech[:5])}{'...' if len(tech) > 5 else ''}",
            severity="INFO",
            category="info_disclosure",  # enum remap: 'tech' isn't a valid finding_category_t
            description=f"Active tech fingerprinting on {ctx.hostname} identified: "
                        f"{', '.join(tech)}. This is informational — useful for asset "
                        f"profiling and CVE matching, not a defect by itself.",
            tags=["tech", "fingerprint"] + [t.lower().replace(" ", "-") for t in tech[:6]],
            raw_excerpt=json.dumps(data, indent=2)[:2000],
        ))

    mark_tool_ok(ctx, "httpx_tech")


# ─── WordPress version-CVE lookup via wpvulnerability.net (Plan C day 1) ──
#
# Closes the version → CVE detection class for WordPress targets that
# neither nuclei templates nor behavioral probes cover. Lookup-only —
# detected versions go to the API, CVEs come back. WAF-immune.

def _detect_wp_plugin_versions(html: str, hostname: str) -> dict[str, str]:
    """Parse rendered HTML for plugin slug + version pairs.

    WordPress emits referenced assets with ?ver=<version> cache-busting
    query strings. Example pattern from CMI:

      wp-content/plugins/revslider/public/css/sr7.css?ver=6.7.56
      wp-content/plugins/wpforms/.../wpforms-full.min.css?ver=1.10.1

    Yields a {slug: version} dict, picking the highest unambiguous version
    per slug if multiple assets reference different versions (e.g. when
    cache-bust hashes are mixed with semver tags).

    Versions that look like cache-bust hashes (long hex strings, or
    epoch-style integers) are skipped — they're not semver and can't be
    matched against CVE operator ranges.
    """
    # Match: wp-content/plugins/<slug>/...?ver=<version>
    # Version capture stops at quote, ampersand, or whitespace.
    pattern = r"wp-content/plugins/([a-zA-Z0-9_\-]+)/[^\"'?]+\?ver=([^\"'&\s]+)"
    matches = re.findall(pattern, html)
    slug_versions: dict[str, str] = {}
    for slug, version in matches:
        # Skip cache-bust hashes (long hex, epoch ints, MD5-shaped)
        if re.match(r"^[0-9a-fA-F]{20,}$", version):
            continue
        # Skip epoch-style integers (10+ digits)
        if re.match(r"^\d{10,}$", version):
            continue
        # Must look like at least one numeric component
        if not re.match(r"^\d+(\.\d+)*", version):
            continue
        # Keep the longest version string seen per slug (resolves
        # cases where ?ver=6.7 and ?ver=6.7.56 both appear)
        existing = slug_versions.get(slug)
        if existing is None or len(version) > len(existing):
            slug_versions[slug] = version
    return slug_versions


def _detect_wp_core_version(ctx: ScanContext) -> str | None:
    """Try several sources for the WordPress core version.

    Returns version string ('6.5.4') or None if undetectable. Pressable
    and other managed-WP hosts often strip the meta generator tag and
    readme.html headers, so this returns None more often than not — but
    when it works, it works cheaply.
    """
    BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36")

    # Source 1: meta generator on the homepage
    rc, html, _ = run_cmd(
        ["curl", "-s", "-L", "--max-time", "12",
         "-A", BROWSER_UA, f"https://{ctx.hostname}/"],
        timeout=15,
    )
    if rc == 0 and html:
        m = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([0-9.]+)',
            html, re.IGNORECASE,
        )
        if m:
            return m.group(1)
        # Inline JS often references wp_version
        m2 = re.search(r'wp_version["\']?\s*[:=]\s*["\']([0-9.]+)["\']', html)
        if m2:
            return m2.group(1)

    # Source 2: /feed/ RSS sometimes leaks WordPress version
    rc2, feed, _ = run_cmd(
        ["curl", "-s", "--max-time", "10",
         "-A", BROWSER_UA, f"https://{ctx.hostname}/feed/"],
        timeout=15,
    )
    if rc2 == 0 and feed:
        m = re.search(r'<generator>https?://wordpress\.org/\?v=([0-9.]+)</generator>', feed)
        if m:
            return m.group(1)

    return None


def check_wpvulnerability(ctx: ScanContext) -> None:
    """Detect WordPress versions on the target and query wpvulnerability.net
    for matching CVEs.

    Plan C day 1 lead — closes the version → CVE detection class for
    WordPress targets. WAF-immune because the only network calls beyond
    the target's homepage/feed go to wpvulnerability.net's API, not the
    target.

    Self-gates: bails early if the homepage doesn't look like WordPress
    (no wp-content references). Skips silently if no plugins detected
    even on a WP site.
    """
    ctx.tools_run.append("wpvulnerability")
    # Import lazily so a missing module doesn't kill the whole Light tier
    try:
        import wpvulnerability_client as wpc
    except Exception as e:
        log(f"wpvulnerability: client import failed: {e!r}")
        # Degraded: the runner can't query the API at all → silent
        # WordPress CVE blind-spot. Same risk class as nikto's Bug E.
        degraded, reason = wpvuln_lookup_is_degraded("client_import_failed")
        mark_tool_degraded(ctx, "wpvulnerability", reason)
        return

    BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36")

    # Step 1: fetch homepage
    rc, html, _ = run_cmd(
        ["curl", "-s", "-L", "--max-time", "15",
         "-A", BROWSER_UA, f"https://{ctx.hostname}/"],
        timeout=20,
    )
    if rc != 0 or not html:
        log(f"  wpvulnerability: homepage fetch rc={rc}, skipping")
        # Degraded: couldn't even reach the target homepage.
        degraded, reason = wpvuln_lookup_is_degraded("homepage_fetch_failed")
        mark_tool_degraded(ctx, "wpvulnerability", reason)
        return

    # Step 2: is this even a WordPress site?
    if "wp-content" not in html.lower():
        log(f"  wpvulnerability: no wp-content references — not a WordPress site, skipping")
        # NOT degraded — non-WP target is the correct skip path. The
        # check did its job (determined target isn't WP).
        mark_tool_ok(ctx, "wpvulnerability")
        return

    # Step 3: detect plugin slugs + versions
    plugins = _detect_wp_plugin_versions(html, ctx.hostname)
    core_version = _detect_wp_core_version(ctx)
    log(f"  wpvulnerability: detected core={core_version or '<unknown>'}, "
        f"{len(plugins)} plugin(s): {sorted(plugins.keys())}")

    if not plugins and not core_version:
        log(f"  wpvulnerability: no detectable versions, skipping API lookups")
        # NOT degraded — WP site exists but no version leak. The
        # check did its job (looked, found no version-specific data).
        mark_tool_ok(ctx, "wpvulnerability")
        return

    # Record the detection inventory as an artifact for audit
    ctx.artifacts.append(("wpvulnerability_detection", "json", json.dumps({
        "core_version": core_version,
        "plugins": plugins,
    })))

    # Step 4: API lookups
    findings_added = 0

    if core_version:
        try:
            core_vulns = wpc.lookup_core(core_version)
            for v in core_vulns:
                _wpvuln_emit_finding(ctx, v, wpc)
                findings_added += 1
        except Exception as e:
            log(f"  wpvulnerability: core lookup failed: {e!r}")

    for slug, version in sorted(plugins.items()):
        try:
            plugin_vulns = wpc.lookup_plugin(slug, version)
            for v in plugin_vulns:
                _wpvuln_emit_finding(ctx, v, wpc)
                findings_added += 1
        except Exception as e:
            log(f"  wpvulnerability: plugin {slug} lookup failed: {e!r}")

    log(f"  wpvulnerability: {findings_added} finding(s) added across "
        f"{len(plugins)} plugin(s){' + core' if core_version else ''}")
    mark_tool_ok(ctx, "wpvulnerability")


def _wpvuln_emit_finding(ctx: ScanContext, v, wpc) -> None:
    """Convert a WpVulnerability into a LightFinding and append to ctx.

    Separated out so the loop in check_wpvulnerability stays tidy and
    so each finding-emission failure is isolated.
    """
    severity = wpc.severity_from_cve_metadata(v.cve_id, v.description)
    # Stable check_name keyed on CVE ID (preferred) or UUID (fallback for
    # vulnerabilities without a CVE assignment). This lets the dedup
    # engine recognize the same vuln across multiple scans + sources.
    if v.cve_id:
        check_name = f"wpvuln-{v.cve_id.lower()}"
    elif v.uuid:
        check_name = f"wpvuln-uuid-{v.uuid[:16]}"
    else:
        check_name = f"wpvuln-{v.affected_target.replace(':', '-')}-{v.affected_version}"

    # Plugin-level master dedup (P-008, 2026-06-04): all advisories for one
    # plugin install share normalized_key = wpplugin-<slug> so they collapse
    # into a single group instead of one row per CVE. The slug comes from the
    # [slug] token the wpvulnerability.net title always carries
    # ("Slider Revolution [revslider] < 7.0.11") — the SAME derivation the
    # 20260604c / 20260701 backfill migrations use, so scanner + backfill agree.
    # Titles without a slug (e.g. WordPress core advisories) get no override
    # and fall back to the CVE/check_name key at upsert time.
    slug_match = re.search(r"\[([^\]]+)\]", v.title or "")
    normalized_key_override = (
        f"wpplugin-{slug_match.group(1).strip().lower()}"
        if slug_match and slug_match.group(1).strip()
        else None
    )

    references = []
    if v.source_link:
        references.append(v.source_link)
    if v.cve_id:
        references.append(f"https://nvd.nist.gov/vuln/detail/{v.cve_id}")

    description_lines = [
        f"{v.affected_target.replace(':', ' ').title()} detected on {ctx.hostname} "
        f"at version {v.affected_version} matches the vulnerable range {v.operator_summary}."
    ]
    if v.description:
        description_lines.append(v.description.strip()[:600])
    if v.unfixed:
        description_lines.append(
            "NOTE: wpvulnerability.net flags this as UNFIXED — no patched "
            "version is currently available. Mitigation requires WAF rules, "
            "configuration changes, or plugin removal."
        )
    description_lines.append(
        "Detection: wpvulnerability.net CVE-by-fingerprint API lookup. "
        "Cross-source dedup will merge this with wpscan-imported findings "
        "of the same CVE."
    )

    ctx.findings.append(LightFinding(
        check_name=check_name,
        title=v.title[:200],
        severity=severity,
        category="config",  # wp-plugin-cve isn't a finding_category_t value
        description="\n\n".join(description_lines),
        tags=["wordpress", "wpvulnerability", "version-cve",
              v.affected_target.split(":")[0]],
        cwe=[1395],  # CWE-1395 Dependency on Vulnerable Third-Party Component
        # CVE ID(s) when present — enables portal groupBySharedCve render-
        # time dedup so cloud (commandsentry_light) merges with wpscan-
        # imported + manual_named findings of the same CVE
        cve=[v.cve_id] if v.cve_id else [],
        references=references,
        normalized_key_override=normalized_key_override,
        raw_excerpt=(
            f"Target: {v.affected_target}\n"
            f"Detected version: {v.affected_version}\n"
            f"Vulnerable range: {v.operator_summary}\n"
            f"CVE: {v.cve_id or '(no CVE assigned)'}\n"
            f"wpvulnerability.net UUID: {v.uuid or '(none)'}\n"
            f"Unfixed: {v.unfixed}"
        )[:2000],
    ))


def check_methods(ctx: ScanContext) -> None:
    """Run OPTIONS, parse Allow header, flag dangerous methods."""
    ctx.tools_run.append("methods_check")
    rc, stdout, stderr = run_cmd(
        ["curl", "-s", "-I", "-X", "OPTIONS", "--max-time", "10",
         f"https://{ctx.hostname}/"],
        timeout=15,
    )
    degraded, reason = httpx_methods_is_degraded(rc, stdout)
    if degraded:
        log(f"methods_check: curl rc={rc}: {stderr.strip()[:200]}")
        mark_tool_degraded(ctx, "methods_check", reason)
        return

    ctx.artifacts.append(("methods_check", "txt", stdout))

    allow_line = next(
        (l for l in stdout.splitlines() if l.lower().startswith("allow:")),
        "",
    )
    if not allow_line:
        # OPTIONS responded but no Allow header — server doesn't expose
        # methods discoverably. Not degraded (the check did its job),
        # just no findings to emit.
        mark_tool_ok(ctx, "methods_check")
        return

    allowed = [m.strip().upper() for m in allow_line.split(":", 1)[1].split(",")]
    for method in allowed:
        if method in DANGEROUS_METHODS:
            severity, why = DANGEROUS_METHODS[method]
            ctx.findings.append(LightFinding(
                check_name=f"method-{method.lower()}-enabled",
                title=f"HTTP {method} method enabled",
                severity=severity,
                category="config",  # enum remap: 'methods' isn't a valid finding_category_t
                description=f"The {method} HTTP method is enabled on {ctx.hostname} "
                            f"(advertised in the OPTIONS Allow header). {why}.",
                tags=["methods", method.lower()],
                cwe=[16],
                raw_excerpt=allow_line,
            ))

    mark_tool_ok(ctx, "methods_check")


def check_csp_nonce(ctx: ScanContext) -> None:
    """Fetch / 5 times, extract CSP script-src nonce values, flag if static.
    Caught CCC M-02. This is one of the cheapest, highest-signal Light checks.
    """
    ctx.tools_run.append("csp_nonce_check")
    nonces: list[str] = []
    csp_samples: list[str] = []
    for _ in range(5):
        rc, stdout, _ = run_cmd(
            ["curl", "-s", "-I", "--max-time", "10",
             "-H", "Cache-Control: no-cache",
             "-H", "Pragma: no-cache",
             f"https://{ctx.hostname}/"],
            timeout=12,
        )
        if rc != 0:
            continue
        csp = next(
            (l for l in stdout.splitlines() if l.lower().startswith("content-security-policy:")),
            "",
        )
        csp_samples.append(csp)
        m = re.search(r"'nonce-([A-Za-z0-9+/=_-]+)'", csp)
        if m:
            nonces.append(m.group(1))

    ctx.artifacts.append(("csp_nonce_check", "json", json.dumps({
        "samples_collected": len(csp_samples),
        "nonces_extracted":  nonces,
    })))

    if len(nonces) >= 3:
        unique = set(nonces)
        if len(unique) == 1:
            ctx.findings.append(LightFinding(
                check_name="csp-static-nonce",
                title="CSP script-src nonce is static across requests",
                severity="MODERATE",
                category="headers",  # enum remap: 'csp' isn't a valid finding_category_t (CSP IS a header)
                description=f"Five consecutive requests to {ctx.hostname} returned "
                            f"identical CSP script-src nonces ('{list(unique)[0][:16]}...'). "
                            f"Static nonces defeat the purpose of nonce-based CSP — an "
                            f"attacker can predict valid nonce values across sessions. "
                            f"The server must generate a fresh cryptographically random "
                            f"nonce per response.",
                tags=["csp", "nonce", "static"],
                cwe=[330],  # CWE-330 Use of Insufficiently Random Values
                raw_excerpt="\n".join(csp_samples[:3])[:2000],
            ))


# ─── Behavioral probes (P-behavioral-probes, 2026-05-31 PM) ─────────────
#
# Targeted HTTP probes that detect bespoke / stealth / app-logic findings
# that neither nuclei templates nor version-fingerprint APIs can catch.
# Each probe is a small function that does specific HTTP requests and
# appends a LightFinding if its match conditions are satisfied.
#
# Three classes of finding this track exists to cover (advisor brief #3,
# 2026-05-31 PM):
#   1. Stealth-by-design plugins (WPS Hide Login — hides itself from
#      fingerprinting; wpvulnerability.net can't see it)
#   2. Bespoke app-logic vulns (CCC class — hardcoded keys, static
#      nonces, auth bypass) — already partially covered by check_csp_nonce
#      and check_methods, behavioral_probes is the home for new ones
#   3. HTTP-method / WAF-bypass classes (URL-encoded traversal, etc.)
#
# Design rules:
#   - Each probe self-gates: if the target doesn't look like its
#     applicable surface (e.g. non-WordPress site for a WP-specific
#     probe), the probe returns without appending a finding.
#   - Each probe is single-purpose (one finding type, one match condition).
#     Don't conflate multiple checks in one probe — makes testing painful.
#   - Probes are LOW-VOLUME (≤5 requests each). Light tier hard caps
#     total request count across all checks.
#   - Probe registry below grows over time as we accumulate the inventory
#     from Mac deep-probe-v2.sh + CCC scan history + future findings.

def probe_wps_hide_login_bypass(ctx: ScanContext) -> None:
    """CVE-2024-2473 — WPS Hide Login plugin bypass via ?action=postpass.

    REWRITTEN 2026-06-01 PM after a false-positive audit caught the
    original logic flagging any WordPress site behind any WAF.

    PRIOR LOGIC (broken — kept here as a cautionary record):
      Step 1 used a bare 'Mozilla/5.0' scanner UA and accepted 403/404
      as "hiding plugin active." But every common WAF (Cloudflare bot
      challenge, Pressable nginx, Fortinet) returns 403 to scanner UAs
      regardless of plugin presence. Step 2 accepted 302 to /wp-login.php
      as "bypass disclosure," but that's standard WordPress unauthed
      redirect behavior — every WP site does this. Net result: probe
      false-positived on every WordPress site behind any WAF.

    NEW ANCHOR: browser-UA on /wp-login.php.
      WPS Hide Login actively HIDES /wp-login.php — when configured, a
      real-browser GET returns 404 (URL is not reachable, login moved
      to a custom path). If a browser gets 200 back with the WordPress
      login form, NOTHING is hidden — CVE-2024-2473 is logically
      impossible. Definitive negative; bail immediately. Anything other
      than 200/404 (403 / 5xx / redirect / etc.) is inconclusive; bail
      rather than risk another FP class. Tightening trades false
      negatives for zero false positives — the correct tradeoff per
      Howie's standing rule.

    DETECTION (only fires when Step 1 confirms hiding is real):
      Step 2 — GET /wp-admin/?action=postpass with browser UA.
      The buggy plugin fails to apply hiding to this specific redirect,
      so the response is a 302 whose Location header still names
      /wp-login.php — disclosing the path that should have been kept
      hidden. Status 302 + 'wp-login.php' in Location = match.

    NEGATIVE FIXTURES GUARANTEE: any site whose /wp-login.php returns
    200 to a browser cannot be flagged. CMI, commanddigital, and
    unimacgraphics all confirmed clean 2026-06-01 by direct curl;
    they're wired in as negative fixtures and verify_probes.py enforces
    that this probe returns 0 findings against them on every run.

    POSITIVE FIXTURE: NONE. ⚠ POSITIVE-UNVALIDATED STATUS.
    The prior CMI positive fixture (F-10 manual finding) was itself a
    false positive — F-10's 5/04 evidence cited the same broken signals
    this rewrite eliminates (scanner-UA 403 + postpass 302 = "vuln
    present"), with no browser-UA confirmation and no plugin in the
    enumerated inventory. F-10 was assumed-true and validated the
    probe; the probe then re-amplified the assumption across the
    fleet.
    This rewrite has been proven NOT to over-fire (three negative
    fixtures, all clean). It has NOT been proven to detect a real
    WPS Hide Login ≤ 1.9.15.2 bypass. Treat any future match against
    this probe as a HYPOTHESIS pending manual verification, not a
    confirmed finding, until at least one positive fixture has been
    captured against a known-real instance.

    Why nuclei misses this: existing cve-2024-2473 template uses a POST
    to /wp-login.php?action=postpass + body match — different request
    shape. Behavioral probe complements that template when its
    conditions also hold (browser sees 404 on wp-login).
    """
    ctx.tools_run.append("probe_wps_hide_login_bypass")

    BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/131.0.0.0 Safari/537.36")

    # Step 1 — definitive hidden-or-not check via a real-browser UA.
    rc1, stdout1, _ = run_cmd(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         "--max-time", "10",
         "-A", BROWSER_UA,
         f"https://{ctx.hostname}/wp-login.php"],
        timeout=12,
    )
    if rc1 != 0:
        return
    try:
        wp_login_code = int(stdout1.strip())
    except ValueError:
        return
    if wp_login_code != 404:
        # 200 = login renders, plugin is NOT hiding → CVE impossible.
        # Anything else (403, 5xx, redirect, etc.) = inconclusive → bail.
        return

    # Step 2 — postpass bypass. With hiding confirmed by Step 1, a 302
    # whose Location names /wp-login.php is the disclosure.
    rc2, stdout2, _ = run_cmd(
        ["curl", "-s", "-I", "--max-time", "10",
         "-A", BROWSER_UA,
         f"https://{ctx.hostname}/wp-admin/?action=postpass"],
        timeout=12,
    )
    if rc2 != 0:
        return
    status_match = re.search(r"^HTTP/[\d.]+\s+(\d{3})", stdout2, re.MULTILINE)
    location_match = re.search(r"^location:\s*(\S+)", stdout2, re.IGNORECASE | re.MULTILINE)
    if not status_match or not location_match:
        return
    status_code = int(status_match.group(1))
    location = location_match.group(1)
    if status_code != 302 or "wp-login.php" not in location:
        return

    # Both steps confirmed — flag the finding.
    ctx.findings.append(LightFinding(
        check_name="wps-hide-login-bypass-cve-2024-2473",
        title="WPS Hide Login bypass — hidden login URL disclosed via ?action=postpass",
        severity="MODERATE",
        category="auth",
        description=(
            f"The WPS Hide Login plugin appears active on {ctx.hostname} "
            f"(direct /wp-login.php access returns HTTP {wp_login_code}), "
            f"but the hidden login URL is disclosed via the "
            f"/wp-admin/?action=postpass redirect bypass — the server "
            f"responded with 302 → {location[:200]}. This is CVE-2024-2473 "
            f"(WPS Hide Login ≤ 1.9.15.2). The bypass defeats the security-"
            f"through-obscurity control and enables credential stuffing / "
            f"brute force against the now-disclosed login URL. "
            f"Remediation: update WPS Hide Login to a version newer than "
            f"1.9.15.2; if already on latest and the bypass still works, "
            f"replace with proper IP-allowlist or 2FA-on-login."
        ),
        tags=["cve", "cve2024", "wordpress", "wp-plugin", "wps-hide-login",
              "disclosure", "behavioral-probe"],
        cwe=[200],  # CWE-200 Exposure of Sensitive Information
        cve=["CVE-2024-2473"],  # enables portal cross-source dedup
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2473",
            "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wps-hide-login/wps-hide-login-19152-login-page-disclosure",
        ],
        raw_excerpt=(
            f"Step 1: GET /wp-login.php → HTTP {wp_login_code}\n"
            f"Step 2: GET /wp-admin/?action=postpass → HTTP {status_code}\n"
            f"        Location: {location}"
        )[:2000],
    ))


def probe_static_csp_nonces_per_directive(ctx: ScanContext) -> None:
    """M-02 class — detect static CSP nonces, per-directive.

    The existing check_csp_nonce only captures the FIRST nonce in the
    CSP header (typically script-src). When script-src is randomized but
    other directives (style-src, etc.) keep static nonces, the first-only
    check misses the live vulnerability. Empirically verified 2026-06-01
    against test.commandcommcentral.com: script-src nonce randomizes per
    request (remediated), but style-src has 10 static 'CSS_10001'..
    'CSS_10010' nonces across every request.

    Detection logic:
      1. Fetch / 5 times with cache-busting headers
      2. Parse the Content-Security-Policy header into directives
      3. For each directive that uses nonce-based CSP (script-src,
         style-src, etc.), extract its nonce values
      4. Compare nonces of each directive across the 5 requests
      5. Flag any directive whose nonces are IDENTICAL across requests
         — that's a static nonce defeating CSP for that resource class

    Each affected directive gets its own finding so the dedup engine
    can track them independently and remediation status per-directive is
    visible in the portal.

    Why this is a behavioral probe (not just a header check):
    requires SAMPLING across multiple requests to compare nonces. Single-
    request inspection can't tell static from random.

    Architecture note: this probe runs against the homepage (the
    target's most-allowlisted endpoint), so it survives FortiGate-style
    path filtering. M-02-class findings live in response HEADERS, which
    are returned for every allowlisted-path response.
    """
    ctx.tools_run.append("probe_static_csp_nonces_per_directive")
    BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36")

    # Step 1: collect 5 samples
    samples: list[str] = []  # raw CSP header values
    for _ in range(5):
        rc, stdout, _ = run_cmd(
            ["curl", "-s", "-I", "--max-time", "10",
             "-H", "Cache-Control: no-cache",
             "-H", "Pragma: no-cache",
             "-A", BROWSER_UA,
             f"https://{ctx.hostname}/"],
            timeout=12,
        )
        if rc != 0:
            continue
        csp_line = next(
            (l for l in stdout.splitlines()
             if l.lower().startswith("content-security-policy:")),
            "",
        )
        if csp_line:
            # Strip "Content-Security-Policy:" prefix, keep value
            samples.append(csp_line.split(":", 1)[1].strip())

    if len(samples) < 3:
        # Insufficient data to compare — bail
        return

    # Step 2: parse each sample into {directive: [nonces]}
    def _parse_csp(csp: str) -> dict[str, list[str]]:
        """Split CSP into directives, extract nonces from each."""
        result: dict[str, list[str]] = {}
        # Directives are separated by ';'
        for chunk in csp.split(";"):
            chunk = chunk.strip()
            if not chunk:
                continue
            parts = chunk.split(None, 1)  # split on first whitespace
            if not parts:
                continue
            directive = parts[0].lower()
            value = parts[1] if len(parts) > 1 else ""
            nonces = re.findall(r"'nonce-([A-Za-z0-9+/=_\-]+)'", value)
            if nonces:
                result[directive] = nonces
        return result

    parsed_samples = [_parse_csp(s) for s in samples]

    # Step 3: for each directive that appears in samples, check if nonces
    # are identical across all samples (=static, =vulnerable)
    all_directives = set()
    for p in parsed_samples:
        all_directives.update(p.keys())

    ctx.artifacts.append(("csp_nonce_per_directive", "json", json.dumps({
        "samples_collected": len(samples),
        "parsed_samples": parsed_samples,
    })))

    for directive in sorted(all_directives):
        # Gather the nonce-set for this directive from each sample.
        # Use sorted tuple as the comparable hash (order shouldn't matter,
        # but we want order-independent comparison)
        directive_samples: list[tuple[str, ...]] = []
        for p in parsed_samples:
            nonces = p.get(directive)
            if nonces is not None:
                directive_samples.append(tuple(sorted(nonces)))

        # Only flag if the directive appears in ALL samples (not flaky
        # presence) AND all sample nonce-sets are identical
        if len(directive_samples) != len(samples):
            continue
        unique_sets = set(directive_samples)
        if len(unique_sets) != 1:
            continue  # nonces vary across requests = randomized = OK
        static_nonces = list(unique_sets)[0]
        if not static_nonces:
            continue

        # Live finding — flag it
        ctx.findings.append(LightFinding(
            check_name=f"csp-static-nonce-{directive.replace('-', '_')}",
            title=(f"CSP {directive} nonce is static across requests "
                   f"({len(static_nonces)} value(s) repeated)"),
            severity="MODERATE",
            category="headers",
            description=(
                f"The Content-Security-Policy {directive} directive on "
                f"{ctx.hostname} uses nonce-based CSP, but the nonce "
                f"value(s) are IDENTICAL across {len(samples)} consecutive "
                f"requests. Static nonces defeat the purpose of nonce-based "
                f"CSP — an attacker who observes one response can predict "
                f"valid nonce values for the same resource class across "
                f"every session. The server must generate a fresh "
                f"cryptographically random nonce per response for each "
                f"nonce-using directive.\n\n"
                f"Observed static {directive} nonce(s) "
                f"(first 16 chars each): "
                f"{', '.join(n[:16]+'...' for n in static_nonces[:5])}"
                f"{' (truncated)' if len(static_nonces) > 5 else ''}"
            ),
            tags=["csp", "nonce", "static", directive, "behavioral-probe"],
            cwe=[330],  # CWE-330 Use of Insufficiently Random Values
            references=[
                "https://content-security-policy.com/nonce/",
                "https://cwe.mitre.org/data/definitions/330.html",
            ],
            raw_excerpt=(
                f"Directive: {directive}\n"
                f"Samples: {len(samples)}\n"
                f"Unique nonce-sets across samples: 1 (=static)\n"
                f"Static nonce-set ({len(static_nonces)} value(s)):\n"
                + "\n".join(f"  - {n}" for n in static_nonces[:10])
                + ("\n  ..." if len(static_nonces) > 10 else "")
            )[:2000],
        ))


def probe_hardcoded_client_crypto(ctx: ScanContext) -> None:
    """Detect hardcoded crypto keys / weak crypto patterns in client-side
    JavaScript that the app actually serves.

    Architecture (matters for WAF-protected targets):
      1. GET homepage with browser UA → parse <script src=...> references
      2. For each referenced .js file, GET it (also browser UA) → grep
         response body for hardcoded-key patterns
      3. Flag a finding per high-confidence match

    Why follow app's reference chain instead of guessing /Scripts/aes.js
    style paths: FortiGate (and similar WAFs) maintain a path allowlist.
    Arbitrary file-path probes get filtered (403/Invalid Request) before
    they see the file. App-referenced asset paths are allowlisted because
    the app actually serves them — those GETs survive the WAF.

    Verified 2026-06-01 against test.commandcommcentral.com (FortiGate):
      GET /Scripts/encryption.js → 200 OK (referenced from homepage)
      GET /Scripts/jquery.js     → 403 Invalid Request (NOT referenced)
      GET /Scripts/aes.js        → 403 Invalid Request (dead-code leftover)

    The probe will correctly NOT match against test.ccc today because
    C-01 was remediated 2026-05-02 (encryption.js migrated to AES-256-GCM
    + Web Crypto API). Probe value is fleet-wide application to future
    findings of this class, not retroactive discovery on remediated assets.
    """
    ctx.tools_run.append("probe_hardcoded_client_crypto")
    BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36")

    # Step 1: fetch homepage
    rc, html, _ = run_cmd(
        ["curl", "-s", "-L", "--max-time", "15",
         "-A", BROWSER_UA,
         f"https://{ctx.hostname}/"],
        timeout=20,
    )
    if rc != 0 or not html:
        return

    # Step 2: parse script refs (relative paths only — external CDN refs
    # would 1) usually be referenced via known-clean CDNs and 2) not be
    # under our coverage scope)
    script_paths = re.findall(
        r'<script[^>]+src=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )
    # Keep only same-origin (relative or absolute-path) script refs
    same_origin = [
        p for p in script_paths
        if p.startswith("/") or (not p.startswith("http") and not p.startswith("//"))
    ]
    if not same_origin:
        return

    # Light-tier discipline: cap how many JS files we fetch per probe.
    # 12 is generous for most apps (CCC has 9).
    SCRIPT_FETCH_CAP = 12
    same_origin = same_origin[:SCRIPT_FETCH_CAP]

    # Patterns we consider high-signal for hardcoded client-side crypto.
    # Order matters — first-match wins per file (don't double-flag).
    SUSPECT_PATTERNS = [
        # Direct hardcoded passphrase strings (the literal CCC C-01 case)
        (r'pass#\d{3,}', "hardcoded-passphrase-string",
         "Plain-text passphrase literal embedded in client JS — appears "
         "to match the 'pass#NNN' pattern, indicating a hardcoded secret."),
        # CryptoJS with Hex.parse on what looks like a literal key
        (r'CryptoJS\.enc\.Hex\.parse\(["\'][0-9a-fA-F]{16,64}["\']\)',
         "hardcoded-cryptojs-hex-key",
         "CryptoJS.enc.Hex.parse called with a hardcoded hex literal "
         "(not a runtime-derived value) — indicates a baked-in encryption key."),
        # AES-CBC or ECB mode — weak crypto regardless of key handling
        (r'CryptoJS\.AES\.(encrypt|decrypt)\([^)]*mode:\s*CryptoJS\.mode\.(CBC|ECB)',
         "weak-crypto-mode-cbc-ecb",
         "CryptoJS.AES used with CBC or ECB mode. Both are vulnerable "
         "to attacks (CBC: padding oracle; ECB: pattern preservation) "
         "when used without authenticated encryption (HMAC) or in "
         "padding-sensitive contexts. Prefer GCM."),
    ]

    # Step 3: fetch + grep each referenced script
    for script_path in same_origin:
        rc_s, body, _ = run_cmd(
            ["curl", "-s", "--max-time", "10",
             "-A", BROWSER_UA,
             f"https://{ctx.hostname}{script_path}"],
            timeout=15,
        )
        if rc_s != 0 or not body:
            continue
        # Sanity cap — don't grep huge bundles, but most app JS is <200KB
        if len(body) > 1_000_000:
            continue

        for pattern, check_suffix, description in SUSPECT_PATTERNS:
            m = re.search(pattern, body)
            if m:
                excerpt_start = max(0, m.start() - 80)
                excerpt_end = min(len(body), m.end() + 80)
                excerpt = body[excerpt_start:excerpt_end]
                # Redact the actual match in the excerpt — we want to
                # surface "there's a problem here" without leaking the
                # exact key in the findings table
                redacted_excerpt = (
                    body[excerpt_start:m.start()]
                    + "<<MATCH REDACTED — see source>>"
                    + body[m.end():excerpt_end]
                )

                ctx.findings.append(LightFinding(
                    check_name=f"client-js-{check_suffix}",
                    title=(
                        f"Client-side JavaScript contains "
                        f"{check_suffix.replace('-', ' ')}"
                    ),
                    severity="MODERATE",
                    category="secret" if "passphrase" in check_suffix or "key" in check_suffix else "config",
                    description=(
                        f"{description}\n\n"
                        f"Detected in {script_path} served by {ctx.hostname}. "
                        f"Client-side crypto secrets / weak modes are visible "
                        f"to any user — the security boundary they imply (server "
                        f"can't be fooled) doesn't actually exist. Recommendation: "
                        f"move crypto operations server-side, or use the browser's "
                        f"Web Crypto API with session-derived keys and authenticated "
                        f"encryption (AES-GCM)."
                    ),
                    tags=["secret", "client-js", "crypto", "behavioral-probe",
                          check_suffix],
                    cwe=[798] if "passphrase" in check_suffix or "key" in check_suffix else [327],
                    references=[
                        "https://cwe.mitre.org/data/definitions/798.html",
                        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
                    ],
                    raw_excerpt=(
                        f"File: {script_path}\n"
                        f"Match pattern: {check_suffix}\n"
                        f"Context (key/secret redacted):\n"
                        f"...{redacted_excerpt}..."
                    )[:2000],
                ))
                break  # one finding per file, move on


# Probe registry. Each entry is a (name, function) tuple. New probes are
# appended here; check_behavioral_probes iterates the whole list.
#
# Naming: probe_<vuln_class_short>. Function signature is (ctx) -> None
# (probe appends LightFinding to ctx.findings on match, returns nothing).
BEHAVIORAL_PROBES = [
    ("wps_hide_login_bypass",            probe_wps_hide_login_bypass),
    ("hardcoded_client_crypto",          probe_hardcoded_client_crypto),
    ("static_csp_nonces_per_directive",  probe_static_csp_nonces_per_directive),
]

# Per-probe fixtures (P-PROBE-FIXTURES).
#
# Each probe carries TWO lists:
#   • positive: hosts where the probe MUST produce at least one finding.
#     0 findings = probe is STALE (target's response shape changed, or
#     vuln was remediated). Triage: probe stale first, vuln gone second.
#   • negative: known-clean hosts where the probe MUST produce ZERO
#     findings. 1+ findings = probe is FALSE-POSITIVE. Catches the kind
#     of bug we just shipped in wps_hide_login_bypass — a probe that
#     fires on any WordPress site behind any WAF.
#
# verify_probes.py runs BOTH lists every time it's invoked. Either
# failure aborts (exit 1).
#
# IMPORTANT — manual_named findings are NOT automatically ground truth.
# F-10 (WPS Hide Login on CMI) was used as the WPS probe's positive
# fixture and was itself a false positive — same broken signals,
# scaled. A manual baseline qualifies as a fixture ONLY when its
# evidence is re-verifiable from current state (e.g. browser-UA curl
# returns the expected response shape, the plugin is enumerated in
# tech_profile, the host appears in a CVE database, etc.). Audit any
# manual finding before depending on it.
#
# Schema (2026-06-01 PM rewrite — supersedes the flat list-only form):
#   { probe_name: {"positive": [hosts], "negative": [hosts]} }
PROBE_FIXTURES: dict[str, dict[str, list[str]]] = {
    "wps_hide_login_bypass": {
        # NONE currently — prior CMI positive removed 2026-06-01 after FP
        # audit confirmed CMI's /wp-login.php returns 200 to a browser UA
        # (page renders normally → nothing is hidden → CVE not present).
        # Add a positive when a real WPS Hide Login ≤ 1.9.15.2 target
        # turns up.
        "positive": [],
        # All three Command WP sites empirically confirmed clean
        # 2026-06-01: browser-UA GET /wp-login.php returns 200 with the
        # standard WordPress login page. CVE-2024-2473 is logically
        # impossible on any of them; probe must not fire.
        "negative": [
            "commandmarketinginnovations.com",
            "www.commanddigital.com",
            "unimacgraphics.com",
        ],
    },
    "hardcoded_client_crypto": {
        # CCC's C-01 was remediated 2026-05-02 (encryption.js migrated to
        # AES-256-GCM + Web Crypto API). No live positive in inventory.
        "positive": [],
        # commanddigital and unimacgraphics serve WordPress pages with no
        # hardcoded-key crypto in their JS — probe must stay quiet.
        # (CMI deliberately omitted while we still don't know its full JS
        # surface; add it as a negative after one clean scan confirms it.)
        "negative": [
            "www.commanddigital.com",
            "unimacgraphics.com",
        ],
    },
    "static_csp_nonces_per_directive": {
        # M-02 verified LIVE on test.ccc 2026-06-01: script-src nonce
        # randomized, style-src has 10 static 'CSS_10001'..'CSS_10010'
        # nonces across every request.
        "positive": ["test.commandcommcentral.com"],
        # commanddigital + CMI don't set static CSP nonces in their
        # responses; probe must not fire. (If a cached-page edge case
        # ever does cause a FP here, it'll surface at the next
        # verify_probes run — which is the point.)
        "negative": [
            "www.commanddigital.com",
            "commandmarketinginnovations.com",
        ],
    },
}


def check_behavioral_probes(ctx: ScanContext) -> None:
    """Run all registered behavioral probes against the target.

    Each probe is responsible for its own surface-applicability gating
    (e.g. a WordPress-specific probe should bail early if the target
    isn't WordPress). This check just iterates the registry and catches
    per-probe failures so one broken probe doesn't kill the whole step.
    """
    ctx.tools_run.append("behavioral_probes")
    for name, probe_fn in BEHAVIORAL_PROBES:
        try:
            log(f"  → {name}")
            probe_fn(ctx)
        except Exception as e:
            log(f"  ✗ behavioral probe {name} failed: {e!r}")


# ─── Port scan + per-service checks (M3 revision, 2026-05-29) ──────────
#
# The original Light tier was HTTPS-only — useless for SSH/SMTP/FTP/mail-
# relay assets (Howie's design call 2026-05-28 night). M3 revision:
#   1. port_scan() does naabu top-100 to discover what's actually open
#   2. HTTPS suite stays unchanged but only fires when port 443 is open
#      (or as a fallback when port scan returns nothing — covers
#      firewalled environments where naabu can't reach)
#   3. New per-service checks fire when their respective ports are open:
#        check_ssh    on 22, 2222
#        check_smtp   on 25, 465, 587, 2525
#        check_ftp    on 21
#   4. asset_kind from the descriptor can force checks even when the
#      port wasn't seen — e.g. "mail-relay" kind always runs SMTP
#      probing on 25/587 regardless of scan result.
# ────────────────────────────────────────────────────────────────────────

# Port-to-service mappings. Conservative: only ports we have actual
# check implementations for. Other interesting ports (RDP 3389, MySQL
# 3306, etc.) get a generic "exposed service" INFO finding later.
SSH_PORTS  = {22, 2222}
SMTP_PORTS = {25, 465, 587, 2525}
FTP_PORTS  = {21}


def port_scan(ctx: ScanContext) -> set[int]:
    """
    naabu top-100 TCP port scan against the asset's hostname. Returns
    the set of open ports. Empty set on failure (network errors, naabu
    missing, etc.) — callers should treat empty as "we don't know" and
    fall back to HTTPS-only behavior.
    """
    ctx.tools_run.append("naabu")
    rc, stdout, stderr = run_cmd(
        ["naabu",
         "-host", ctx.hostname,
         "-top-ports", "100",
         "-silent",
         "-timeout", "5000",
         "-retries", "1"],
        timeout=180,
    )
    if rc != 0:
        log(f"naabu rc={rc}: {stderr[:200]}")
        # Capture the failure as an artifact so we have evidence why
        # service-specific checks didn't fire.
        ctx.artifacts.append((
            "naabu",
            "text",
            f"naabu exited {rc}\n\nstderr:\n{stderr[:2000]}",
        ))
        _, reason = naabu_is_degraded(rc, stdout)
        mark_tool_degraded(ctx, "naabu", reason)
        return set()

    open_ports: set[int] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if ":" in line:
            try:
                port = int(line.rsplit(":", 1)[1])
                open_ports.add(port)
            except ValueError:
                continue

    log(f"naabu open ports: {sorted(open_ports)}")
    ctx.artifacts.append((
        "naabu",
        "text",
        f"hostname: {ctx.hostname}\nopen ports: {sorted(open_ports)}\n\n"
        f"raw stdout:\n{stdout[:2000]}",
    ))
    mark_tool_ok(ctx, "naabu")
    return open_ports


def check_ssh(ctx: ScanContext, port: int) -> None:
    """
    SSH service detection + protocol-version check. Banner format is
    "SSH-2.0-OpenSSH_X.Y" — parse the OpenSSH version and flag old
    builds known to be missing security patches.
    """
    ctx.tools_run.append(f"ssh-banner:{port}")

    import socket
    try:
        sock = socket.create_connection((ctx.hostname, port), timeout=5)
        sock.settimeout(5)
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        try:
            sock.close()
        except Exception:
            pass
    except Exception as e:
        log(f"ssh banner-grab {ctx.hostname}:{port} failed: {e}")
        return

    if not banner.startswith("SSH-"):
        log(f"port {port} did not return SSH banner: {banner[:50]}")
        return

    # INFO: service detected. Always emit so the asset's open-services
    # surface is fully indexed.
    ctx.findings.append(LightFinding(
        check_name=f"ssh-service-on-port-{port}",
        title=f"SSH service exposed on port {port}",
        severity="INFO",
        category="recon",
        description=(
            f"An SSH service is responding on TCP port {port} of "
            f"{ctx.hostname}. Banner: {banner[:120]}. Confirm this "
            f"endpoint is intentionally internet-facing; if not, restrict "
            f"to source-IP allow-lists."
        ),
        tags=["ssh", "exposed-service"],
        raw_excerpt=banner,
    ))

    # Parse OpenSSH version if banner identifies it.
    if banner.startswith("SSH-2.0-OpenSSH_"):
        soft_part = banner[len("SSH-2.0-OpenSSH_"):].split()[0]
        try:
            tokens = soft_part.split(".")
            major = int("".join(c for c in tokens[0] if c.isdigit()))
            minor = int("".join(c for c in (tokens[1] if len(tokens) > 1 else "0") if c.isdigit()) or 0)
            # OpenSSH < 7.4 has CVE-2016-10009/0777 and several other
            # documented issues. < 8.0 lacks modern crypto defaults.
            if (major, minor) < (7, 4):
                ctx.findings.append(LightFinding(
                    check_name=f"ssh-outdated-on-port-{port}",
                    title=f"Outdated OpenSSH on port {port} (OpenSSH_{soft_part})",
                    severity="MODERATE",
                    category="deprecation",
                    description=(
                        f"OpenSSH {soft_part} predates 7.4 and is missing "
                        f"published security patches. CVEs include "
                        f"CVE-2016-10009 (agent local privilege escalation) "
                        f"and CVE-2016-0777 (information disclosure)."
                    ),
                    tags=["ssh", "outdated", "openssh"],
                    references=["https://www.openssh.com/security.html"],
                    raw_excerpt=banner,
                ))
            elif (major, minor) < (8, 0):
                ctx.findings.append(LightFinding(
                    check_name=f"ssh-aging-on-port-{port}",
                    title=f"Aging OpenSSH on port {port} (OpenSSH_{soft_part})",
                    severity="LOW",
                    category="deprecation",
                    description=(
                        f"OpenSSH {soft_part} predates 8.0 and is missing "
                        f"modern key-exchange defaults and security hardening. "
                        f"Upgrading is recommended."
                    ),
                    tags=["ssh", "aging", "openssh"],
                    raw_excerpt=banner,
                ))
        except (ValueError, IndexError):
            pass


def check_smtp(ctx: ScanContext, port: int) -> None:
    """
    SMTP service detection + STARTTLS support check. Connects, reads
    banner, sends EHLO, looks for STARTTLS capability in response.
    Missing STARTTLS = mail can transit unencrypted.
    """
    ctx.tools_run.append(f"smtp-banner:{port}")

    import socket
    try:
        sock = socket.create_connection((ctx.hostname, port), timeout=5)
        sock.settimeout(5)
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
    except Exception as e:
        log(f"smtp banner-grab {ctx.hostname}:{port} failed: {e}")
        return

    if not banner.startswith("220"):
        log(f"port {port} did not return SMTP 220 banner: {banner[:50]}")
        try:
            sock.close()
        except Exception:
            pass
        return

    # EHLO probe — get the capability list
    ehlo_text = ""
    try:
        sock.send(b"EHLO commandsentry.scanner\r\n")
        buf = b""
        for _ in range(8):
            try:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                buf += chunk
                # SMTP multiline response ends when a line starts "250 " (with
                # space, not dash) — at that point the last line came through.
                lines = buf.decode("utf-8", errors="replace").splitlines()
                if any(l.startswith("250 ") for l in lines):
                    break
            except socket.timeout:
                break
        ehlo_text = buf.decode("utf-8", errors="replace")
        try:
            sock.send(b"QUIT\r\n")
        except Exception:
            pass
        sock.close()
    except Exception as e:
        log(f"smtp EHLO failed: {e}")
        ehlo_text = ""

    # INFO: service detected
    ctx.findings.append(LightFinding(
        check_name=f"smtp-service-on-port-{port}",
        title=f"SMTP service exposed on port {port}",
        severity="INFO",
        category="recon",
        description=(
            f"An SMTP service is responding on TCP port {port} of "
            f"{ctx.hostname}. Banner: {banner[:120]}."
        ),
        tags=["smtp", "exposed-service"],
        raw_excerpt=(banner + "\n\nEHLO response:\n" + ehlo_text)[:1500],
    ))

    # STARTTLS check — port 465 is implicit TLS so doesn't need STARTTLS.
    # Ports 25, 587, 2525 should advertise STARTTLS if they handle real mail.
    if port != 465 and ehlo_text:
        if "STARTTLS" not in ehlo_text.upper():
            ctx.findings.append(LightFinding(
                check_name=f"smtp-no-starttls-on-port-{port}",
                title=f"SMTP server does not advertise STARTTLS on port {port}",
                severity="MODERATE",
                category="tls",
                description=(
                    f"The SMTP server at {ctx.hostname}:{port} did not include "
                    f"STARTTLS in its EHLO capability list. Mail transmitted "
                    f"to/from this endpoint may travel in plaintext, exposing "
                    f"message contents and credentials to network observers. "
                    f"Either enable STARTTLS or restrict the endpoint to "
                    f"implicit-TLS port 465."
                ),
                tags=["smtp", "starttls", "plaintext", "tls"],
                cwe=[319],  # Cleartext Transmission of Sensitive Information
                raw_excerpt=ehlo_text[:1500],
            ))


def check_ftp(ctx: ScanContext, port: int) -> None:
    """
    FTP service detection + anonymous-login test. If anonymous login
    succeeds, that's HIGH — anyone on the internet can read (potentially
    write) files via this endpoint without auth.
    """
    ctx.tools_run.append(f"ftp-check:{port}")

    import socket
    try:
        sock = socket.create_connection((ctx.hostname, port), timeout=5)
        sock.settimeout(5)
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
    except Exception as e:
        log(f"ftp banner-grab {ctx.hostname}:{port} failed: {e}")
        return

    if not banner.startswith("220"):
        log(f"port {port} did not return FTP 220 banner: {banner[:50]}")
        try:
            sock.close()
        except Exception:
            pass
        return

    # INFO: service detected
    ctx.findings.append(LightFinding(
        check_name=f"ftp-service-on-port-{port}",
        title=f"FTP service exposed on port {port}",
        severity="INFO",
        category="recon",
        description=(
            f"An FTP service is responding on TCP port {port} of "
            f"{ctx.hostname}. Banner: {banner[:120]}. FTP transmits "
            f"credentials in plaintext and is generally discouraged for "
            f"public-facing endpoints in favor of SFTP."
        ),
        tags=["ftp", "exposed-service"],
        raw_excerpt=banner,
    ))

    # Anonymous login attempt
    transcript: list[str] = [f"banner: {banner}"]
    try:
        sock.send(b"USER anonymous\r\n")
        user_resp = sock.recv(1024).decode("utf-8", errors="replace").strip()
        transcript.append(f"USER anonymous → {user_resp}")
        sock.send(b"PASS commandsentry@scanner.local\r\n")
        pass_resp = sock.recv(1024).decode("utf-8", errors="replace").strip()
        transcript.append(f"PASS *** → {pass_resp}")
        try:
            sock.send(b"QUIT\r\n")
        except Exception:
            pass
        sock.close()

        # Code 230 = User logged in. 530 = Not logged in.
        if pass_resp.startswith("230"):
            ctx.findings.append(LightFinding(
                check_name=f"ftp-anonymous-login-on-port-{port}",
                title=f"FTP anonymous login enabled on port {port}",
                severity="HIGH",
                category="auth",
                description=(
                    f"The FTP server at {ctx.hostname}:{port} accepted an "
                    f"anonymous login. Anyone on the public internet can "
                    f"connect and read files (and potentially write, depending "
                    f"on filesystem permissions) without any credentials. "
                    f"Disable anonymous access unless this is an intentional "
                    f"public file-distribution endpoint."
                ),
                tags=["ftp", "anonymous", "authentication", "exposed"],
                cwe=[287],  # Improper Authentication
                raw_excerpt="\n".join(transcript)[:1500],
            ))
    except Exception as e:
        log(f"ftp anon login attempt failed: {e}")


# ─── Findings upsert ────────────────────────────────────────────────────

#
# 2026-06-07 ADR-001: writes validation_status + scanner_version +
# validated_at on every emission. Heal logic identical to run_medium —
# upgrade-only on validation_status, always-overwrite on scanner_version
# (informational), set-once on validated_at. See run_medium.py for the
# design notes.
#
UPSERT_FINDING_SQL = """
INSERT INTO public.findings (
    finding_id, asset_id, title, severity, category, description,
    cwe, cve, normalized_key, "references", current_status, first_detected_at,
    last_observed_at, source, tags,
    validation_status, scanner_version, validated_at
)
VALUES (%(finding_id)s, %(asset_id)s, %(title)s, %(severity)s, %(category)s,
        %(description)s, %(cwe)s, %(cve)s, %(normalized_key)s,
        %(references)s, 'detected',
        now(), now(), %(source)s, %(tags)s,
        %(validation_status)s, %(scanner_version)s,
        CASE WHEN %(validation_status)s = 'validated' THEN now() ELSE NULL END)
ON CONFLICT (finding_id) DO UPDATE SET
    title             = EXCLUDED.title,
    category          = EXCLUDED.category,
    description       = EXCLUDED.description,
    -- Backfill cve on re-detection. Only OVERWRITE when EXCLUDED.cve is
    -- non-empty — never blow away a populated array with NULL/[] from a
    -- subsequent emission of the same finding via a code path that
    -- doesn't carry the CVE list.
    cve = CASE
      WHEN EXCLUDED.cve IS NOT NULL AND array_length(EXCLUDED.cve, 1) > 0
        THEN EXCLUDED.cve
      ELSE findings.cve
    END,
    -- Same protection for normalized_key — only overwrite when EXCLUDED is
    -- non-NULL. Going forward all cloud emissions populate this, but a
    -- legacy code path or a manual SQL UPDATE backfill should never get
    -- blown away by a subsequent scanner pass.
    normalized_key = COALESCE(EXCLUDED.normalized_key, findings.normalized_key),
    -- Status-downgrade guard (same pattern as import_jsonl.py):
    -- re-detecting an issue does NOT reopen a closed finding.
    current_status = CASE
      WHEN findings.current_status IN (
             'remediated', 'validated_remediated',
             'false_positive', 'wont_fix', 'accepted_risk'
           )
        THEN findings.current_status
      ELSE 'detected'
    END,
    -- Severity downgrade protection:
    severity = CASE
      WHEN (CASE findings.severity
             WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
             WHEN 'MODERATE-HIGH' THEN 3 WHEN 'MODERATE' THEN 4
             WHEN 'LOW' THEN 5 WHEN 'INFO' THEN 6 ELSE 9 END)
         > (CASE EXCLUDED.severity
             WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
             WHEN 'MODERATE-HIGH' THEN 3 WHEN 'MODERATE' THEN 4
             WHEN 'LOW' THEN 5 WHEN 'INFO' THEN 6 ELSE 9 END)
        THEN findings.severity
      ELSE EXCLUDED.severity
    END,
    first_detected_at = LEAST(findings.first_detected_at, EXCLUDED.first_detected_at),
    last_observed_at  = EXCLUDED.last_observed_at,
    tags              = EXCLUDED.tags,
    -- ADR-001 upgrade-only heal: never downgrade from 'validated'.
    validation_status = CASE
      WHEN EXCLUDED.validation_status = 'validated'
        THEN 'validated'
      ELSE findings.validation_status
    END,
    -- Always record the latest emitter SHA for forensic context.
    scanner_version   = EXCLUDED.scanner_version,
    -- Stamp validated_at the FIRST time the status transitions to
    -- 'validated'; never touch it again afterward.
    validated_at = CASE
      WHEN EXCLUDED.validation_status = 'validated'
       AND findings.validation_status <> 'validated'
        THEN now()
      ELSE findings.validated_at
    END
RETURNING (xmax = 0) as inserted;
"""


INSERT_ARTIFACT_SQL = """
INSERT INTO public.scan_run_artifacts (
    scan_run_id, tool_name, output_format, size_bytes, content_jsonb
)
VALUES (%(scan_run_id)s, %(tool_name)s, %(output_format)s, %(size_bytes)s, %(content_jsonb)s);
"""


# psycopg3 rejects multi-statement strings in execute() — split each pair
# into individual single-statement queries. Caller runs both inside the open
# transaction so the close-out remains atomic.

CLOSE_SCAN_RUN_SQL = """
UPDATE public.scan_run
SET status            = 'complete',
    completed_at      = now(),
    duration_seconds  = EXTRACT(EPOCH FROM (now() - started_at))::int,
    tools_run         = %(tools_run)s,
    findings_added    = %(findings_added)s,
    findings_updated  = %(findings_updated)s,
    -- S1 2026-06-09: per-tool completeness map.
    -- {tool_name: {"ok": True} | {"degraded": "reason"}}
    tool_status       = %(tool_status)s
WHERE scan_run_id     = %(scan_run_id)s;
"""

CLOSE_SCAN_QUEUE_SQL = """
UPDATE public.scan_queue
SET status            = 'complete',
    completed_at      = now(),
    duration_seconds  = EXTRACT(EPOCH FROM (now() - started_at))::int,
    findings_count    = %(findings_count)s
WHERE queue_id        = %(queue_id)s;
"""


FAIL_SCAN_RUN_SQL = """
UPDATE public.scan_run
SET status           = 'failed',
    completed_at     = now(),
    duration_seconds = EXTRACT(EPOCH FROM (now() - started_at))::int,
    error_message    = %(error)s
WHERE scan_run_id    = %(scan_run_id)s;
"""

FAIL_SCAN_QUEUE_SQL = """
UPDATE public.scan_queue
SET status           = 'failed',
    completed_at     = now(),
    duration_seconds = EXTRACT(EPOCH FROM (now() - started_at))::int,
    error_message    = %(error)s
WHERE queue_id       = %(queue_id)s;
"""


def write_findings_and_artifacts(conn, ctx: ScanContext, Json) -> tuple[int, int]:
    """Upsert findings + insert artifacts. Returns (inserted, updated)."""
    inserted = 0
    updated  = 0
    # ADR-001: stamp every emission with the runner's SHA + validation
    # status. validation_status is computed by querying the
    # scanner_validations table (NOT an in-code allowlist — see
    # derive_validation_status() docstring for the convergence rationale).
    scanner_version = get_scanner_version()
    validation_status = derive_validation_status(conn, ctx.intensity, scanner_version)
    log(f"  ADR-001: scanner_version={scanner_version[:12]} "
        f"validation_status={validation_status}")

    with conn.cursor() as cur:
        for f in ctx.findings:
            finding_id = f"{ctx.asset_id}:light:{f.check_name}"
            # Compute normalized_key at write time using the same rule as
            # migration 20260601a's rule 2b/2c:
            #   - If cve populated → sorted, lowercased, comma-joined
            #   - Else → check_name slug (which is finding_id's :light:<slug>)
            # Cloud probes that want explicit cross-source mapping (e.g.
            # behavioral probes that should merge with a specific manual_named
            # finding) should ensure their check_name matches the migration's
            # 2a target slug.
            if f.normalized_key_override:
                # Explicit key (e.g. wpplugin-<slug> for WP plugin vulns) —
                # forces plugin-level master dedup regardless of CVE. MUST win
                # over the CVE-join below, otherwise cve-populated wp findings
                # key off the CVE and re-split into one row per CVE on every
                # re-scan (the P-008 regression migration 20260604c fought).
                normalized_key = f.normalized_key_override
            elif f.cve:
                normalized_key = ",".join(sorted(c.lower() for c in f.cve))
            else:
                normalized_key = f.check_name

            params = {
                "finding_id":     finding_id,
                "asset_id":       ctx.asset_id,
                "title":          f.title,
                "severity":       f.severity,
                "category":       f.category,
                "description":    f.description,
                "cwe":            f.cwe,
                "cve":            f.cve,
                "normalized_key": normalized_key,
                "references":     f.references,
                # Source is derived from ctx.intensity so this same upsert
                # path is reusable by run_medium.py / run_heavy.py without
                # forking the function. All three values were added to
                # finding_source_t in migration 20260528b.
                "source":      f"commandsentry_{ctx.intensity}",
                "tags":        f.tags,
                # ADR-001 validated-SHA key — see top-of-file derive_validation_status.
                "validation_status": validation_status,
                "scanner_version":   scanner_version,
            }
            cur.execute(UPSERT_FINDING_SQL, params)
            row = cur.fetchone()
            if row and row["inserted"]:
                inserted += 1
            else:
                updated += 1

        for tool_name, output_format, content_str in ctx.artifacts:
            try:
                content_obj = json.loads(content_str)
            except Exception:
                content_obj = {"raw": content_str}
            cur.execute(INSERT_ARTIFACT_SQL, {
                "scan_run_id":   ctx.scan_run_id,
                "tool_name":     tool_name,
                "output_format": output_format,
                "size_bytes":    len(content_str.encode("utf-8")),
                "content_jsonb": Json(content_obj),
            })

    return inserted, updated


def close_out(conn, ctx: ScanContext, inserted: int, updated: int, Json) -> None:
    """Mark scan_run + scan_queue as 'complete'. Writes per-tool
    completeness map (S1 2026-06-09) so downstream reports can see
    which tools genuinely worked vs. silently degraded."""
    with conn.cursor() as cur:
        params = {
            "tools_run":        ctx.tools_run,
            "findings_added":   inserted,
            "findings_updated": updated,
            "findings_count":   inserted + updated,
            "scan_run_id":      ctx.scan_run_id,
            "queue_id":         ctx.queue_id,
            # S1: wrap with Json so psycopg writes proper jsonb. Use {}
            # if no tools registered status — better than NULL for
            # downstream queries.
            "tool_status":      Json(ctx.tool_status or {}),
        }
        cur.execute(CLOSE_SCAN_RUN_SQL, params)
        cur.execute(CLOSE_SCAN_QUEUE_SQL, params)


def fail_out(conn, ctx: ScanContext, error: str) -> None:
    with conn.cursor() as cur:
        params = {
            "error":       error,
            "scan_run_id": ctx.scan_run_id,
            "queue_id":    ctx.queue_id,
        }
        cur.execute(FAIL_SCAN_RUN_SQL, params)
        cur.execute(FAIL_SCAN_QUEUE_SQL, params)


# ─── Main ───────────────────────────────────────────────────────────────
def derive_hostname(asset: dict) -> str:
    """Pick the scan target from the asset row. Prefer name, fall back to asset_id."""
    name = (asset.get("name") or "").strip()
    if name and " " not in name:
        return name
    return asset["asset_id"]


def run(descriptor_path: str, dsn: str) -> int:
    psycopg, dict_row, Json = _import_deps()

    log(f"reading descriptor: {descriptor_path}")
    try:
        descriptor = json.loads(Path(descriptor_path).read_text())
    except Exception as e:
        log(f"descriptor read/parse failed: {e}")
        return 1

    if descriptor.get("intensity") != "light":
        log(f"WARNING: descriptor intensity is '{descriptor.get('intensity')}', not 'light'. Proceeding anyway.")

    asset = descriptor["asset"]
    ctx = ScanContext(
        descriptor=descriptor,
        hostname=derive_hostname(asset),
        asset_id=descriptor["asset_id"],
        scan_run_id=descriptor["scan_run_id"],
        queue_id=descriptor["queue_id"],
        intensity=descriptor["intensity"],
        asset_kind=asset.get("kind"),
    )
    log(f"asset_id={ctx.asset_id} hostname={ctx.hostname} kind={ctx.asset_kind} scan_run_id={ctx.scan_run_id}")

    try:
        conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
    except Exception as e:
        log(f"DB connect failed: {e}")
        return 1

    try:
        # ─── Port scan preflight (M3 revision) ─────────────────────────
        # Discover what's actually listening before dispatching checks.
        # An empty result means naabu couldn't reach the host (firewall,
        # no DNS, etc.) — fall back to the legacy HTTPS-only behavior so
        # we don't silently scan less than we used to.
        log("→ port_scan")
        ctx.open_ports = port_scan(ctx)
        no_scan_data = len(ctx.open_ports) == 0

        # ─── HTTPS suite ───────────────────────────────────────────────
        # Fires when port 443 was found OR we have no scan data
        # (fallback to legacy behavior). Skipped for assets where 443 is
        # definitely closed.
        run_https = (443 in ctx.open_ports) or no_scan_data

        # Kind-aware override — some kinds expect HTTPS regardless of
        # what the port scan saw. Belt-and-suspenders for cases where
        # the port scan is being filtered.
        if ctx.asset_kind in ("portal", "marketing", "vpn-endpoint", "web-app"):
            run_https = True

        if run_https:
            log("→ HTTPS suite")
            log("  → check_tls")
            check_tls(ctx)
            log("  → check_headers")
            check_headers(ctx)
            log("  → check_common_paths")
            check_common_paths(ctx)
            log("  → check_httpx_tech")
            check_httpx_tech(ctx)
            log("  → check_methods")
            check_methods(ctx)
            log("  → check_csp_nonce")
            check_csp_nonce(ctx)
            log("  → check_wpvulnerability")
            check_wpvulnerability(ctx)
            log("→ check_behavioral_probes")
            check_behavioral_probes(ctx)
        else:
            log(f"HTTPS suite SKIPPED — port 443 not in open_ports={sorted(ctx.open_ports)}, kind={ctx.asset_kind}")

        # ─── DNS posture (always, not HTTP-specific) ───────────────────
        log("→ check_dns_posture")
        check_dns_posture(ctx)

        # ─── Per-service checks ────────────────────────────────────────
        # Iterate sorted for deterministic finding order.
        for port in sorted(ctx.open_ports):
            if port in SSH_PORTS:
                log(f"→ check_ssh (port {port})")
                check_ssh(ctx, port)
            elif port in SMTP_PORTS:
                log(f"→ check_smtp (port {port})")
                check_smtp(ctx, port)
            elif port in FTP_PORTS:
                log(f"→ check_ftp (port {port})")
                check_ftp(ctx, port)

        # ─── Kind-aware fallbacks ──────────────────────────────────────
        # If the asset is a known mail-relay kind, try SMTP on the
        # standard ports even if port scan didn't see them — naabu may
        # have been firewalled. Same for the other common kinds.
        if ctx.asset_kind == "mail-relay":
            for port in (25, 587):
                if port not in ctx.open_ports:
                    log(f"→ check_smtp (kind-forced, port {port})")
                    check_smtp(ctx, port)

        log(f"checks complete; {len(ctx.findings)} finding(s), {len(ctx.artifacts)} artifact(s)")

        inserted, updated = write_findings_and_artifacts(conn, ctx, Json)
        # Pass Json so close_out can wrap tool_status as proper jsonb.
        log(f"upserted findings: {inserted} new, {updated} existing")

        close_out(conn, ctx, inserted, updated, Json)
        conn.commit()
        log("scan_run + scan_queue closed out successfully")
        return 0

    except Exception as e:
        log(f"FATAL: {e!r}")
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            fail_out(conn, ctx, f"run_light fatal: {e!r}")
            conn.commit()
        except Exception as e2:
            log(f"fail_out also failed: {e2!r}")
        return 1
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 4a Light tier scanner. Consumes a descriptor from "
                    "poll_queue.py and runs the Light check suite.",
    )
    parser.add_argument(
        "descriptor",
        help="Path to the JSON descriptor file produced by poll_queue.py",
    )
    parser.add_argument(
        "--dsn",
        default=os.environ.get("SUPABASE_DSN"),
        help="Postgres DSN (or set SUPABASE_DSN).",
    )
    args = parser.parse_args()

    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN required", file=sys.stderr)
        sys.exit(2)

    sys.exit(run(args.descriptor, args.dsn))


if __name__ == "__main__":
    main()
