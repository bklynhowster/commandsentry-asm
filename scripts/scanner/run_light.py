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
    references:   list[str] = field(default_factory=list)
    raw_excerpt:  str | None = None


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


def check_headers(ctx: ScanContext) -> None:
    """Fetch '/' and check for the standard security header set."""
    ctx.tools_run.append("headers_check")
    rc, stdout, stderr = run_cmd(
        ["curl", "-sI", "-L", "--max-time", "15",
         "-H", "User-Agent: Mozilla/5.0 (compatible; COMMANDsentry/1.0)",
         f"https://{ctx.hostname}/"],
        timeout=20,
    )
    if rc != 0:
        log(f"headers_check: curl rc={rc}: {stderr.strip()[:200]}")
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


def check_common_paths(ctx: ScanContext) -> None:
    """HEAD-probe a list of common leak paths. 200/204/206 = exposed."""
    ctx.tools_run.append("common_paths")
    results = []
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


def check_dns_posture(ctx: ScanContext) -> None:
    """Use dig to check DMARC, SPF, DKIM presence."""
    ctx.tools_run.append("dns_posture")
    results: dict[str, Any] = {}

    # SPF — TXT record on the hostname
    rc, stdout, _ = run_cmd(["dig", "+short", "TXT", ctx.hostname], timeout=10)
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
            cwe=[1021],
            raw_excerpt=stdout[:1000],
        ))

    # DMARC — TXT on _dmarc.<hostname>
    rc, stdout, _ = run_cmd(["dig", "+short", "TXT", f"_dmarc.{ctx.hostname}"], timeout=10)
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
            cwe=[1021],
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


def check_httpx_tech(ctx: ScanContext) -> None:
    """Tech detection via httpx -td. Informational only."""
    ctx.tools_run.append("httpx_tech")
    rc, stdout, stderr = run_cmd(
        ["httpx", "-u", f"https://{ctx.hostname}", "-td", "-silent", "-json", "-timeout", "15"],
        timeout=25,
    )
    if rc != 0 or not stdout.strip():
        log(f"httpx_tech: rc={rc}, no output: {stderr.strip()[:200]}")
        return

    try:
        data = json.loads(stdout.splitlines()[0])
    except Exception as e:
        log(f"httpx_tech: JSON parse failed: {e}")
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


def check_methods(ctx: ScanContext) -> None:
    """Run OPTIONS, parse Allow header, flag dangerous methods."""
    ctx.tools_run.append("methods_check")
    rc, stdout, stderr = run_cmd(
        ["curl", "-s", "-I", "-X", "OPTIONS", "--max-time", "10",
         f"https://{ctx.hostname}/"],
        timeout=15,
    )
    if rc != 0:
        log(f"methods_check: curl rc={rc}: {stderr.strip()[:200]}")
        return

    ctx.artifacts.append(("methods_check", "txt", stdout))

    allow_line = next(
        (l for l in stdout.splitlines() if l.lower().startswith("allow:")),
        "",
    )
    if not allow_line:
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
                cwe=[1021],
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

    Detection path verified 2026-05-31 PM via direct curl probe against
    commandmarketinginnovations.com (Mac's intensive-scan-2026-05-04
    finding F-10). Two-step probe:

      Step 1: GET /wp-login.php — if 403/404, hiding plugin is active.
              If 200, no hiding plugin = no vuln to bypass = no finding.
      Step 2: GET /wp-admin/?action=postpass — if 302 to wp-login, the
              hidden login URL is being disclosed via the bypass.

    Both must match to flag. Single-step matching produces false positives
    on bare WordPress (wp-admin always redirects to wp-login for unauthed
    users; the signal is "wp-login was hidden AND bypass disclosed it").

    Why nuclei misses this: existing cve-2024-2473 template uses a POST
    to /wp-login.php?action=postpass + body match — different request
    shape than the GET-based detection. On sites where the POST path
    doesn't trigger the matchable response, the template returns 0
    matches even though the GET-based bypass is demonstrably present.
    Behavioral probe catches what the template can't.
    """
    ctx.tools_run.append("probe_wps_hide_login_bypass")

    # NB on User-Agent strategy (verified empirically against CMI 2026-05-31):
    # WPS Hide Login can be UA-aware. With a real-browser UA it returns 200
    # on wp-login.php (lets browsers through). With a scanner-shape UA it
    # returns 403 (the hiding behavior). Both reveal different things:
    #   - Browser UA on wp-login: 200 → can't distinguish "no plugin" from
    #     "plugin lets browsers through" — masks vulnerability presence
    #   - Scanner UA on wp-login: 403 → plugin is actively hiding the URL
    #     (or the host returns 403 for some other reason — combined with
    #     step 2 we get the full signal)
    #
    # So step 1 deliberately uses a minimal "Mozilla/5.0" UA to TRIGGER
    # the hiding plugin's gate. If hiding is active, we see 403/404.
    # Step 2 uses a real-browser UA to confirm the bypass works for the
    # most-permissive client class — same attack pattern a real attacker
    # would use.
    SCANNER_UA = "Mozilla/5.0"  # bare-minimum UA — triggers hiding plugin's gate
    BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36")

    # Step 1: is wp-login.php hidden from scanner-shape traffic?
    rc1, stdout1, _ = run_cmd(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
         "--max-time", "10",
         "-A", SCANNER_UA,
         f"https://{ctx.hostname}/wp-login.php"],
        timeout=12,
    )
    if rc1 != 0:
        return
    try:
        wp_login_code = int(stdout1.strip())
    except ValueError:
        return
    if wp_login_code not in (403, 404):
        # Login is openly accessible even to scanner UAs — no hiding
        # plugin (or plugin is inactive). No vuln to bypass.
        return

    # Step 2: does ?action=postpass disclose the login URL to a
    # browser-shape request?
    rc2, stdout2, _ = run_cmd(
        ["curl", "-s", "-I", "--max-time", "10",
         "-A", BROWSER_UA,
         f"https://{ctx.hostname}/wp-admin/?action=postpass"],
        timeout=12,
    )
    if rc2 != 0:
        return
    # Look for 302 + Location header pointing to wp-login.php
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


# Probe registry. Each entry is a (name, function) tuple. New probes are
# appended here; check_behavioral_probes iterates the whole list.
#
# Naming: probe_<vuln_class_short>. Function signature is (ctx) -> None
# (probe appends LightFinding to ctx.findings on match, returns nothing).
BEHAVIORAL_PROBES = [
    ("wps_hide_login_bypass", probe_wps_hide_login_bypass),
]


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

UPSERT_FINDING_SQL = """
INSERT INTO public.findings (
    finding_id, asset_id, title, severity, category, description,
    cwe, "references", current_status, first_detected_at,
    last_observed_at, source, tags
)
VALUES (%(finding_id)s, %(asset_id)s, %(title)s, %(severity)s, %(category)s,
        %(description)s, %(cwe)s, %(references)s, 'detected',
        now(), now(), %(source)s, %(tags)s)
ON CONFLICT (finding_id) DO UPDATE SET
    title             = EXCLUDED.title,
    category          = EXCLUDED.category,
    description       = EXCLUDED.description,
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
    tags              = EXCLUDED.tags
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
    findings_updated  = %(findings_updated)s
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

    with conn.cursor() as cur:
        for f in ctx.findings:
            finding_id = f"{ctx.asset_id}:light:{f.check_name}"
            params = {
                "finding_id":  finding_id,
                "asset_id":    ctx.asset_id,
                "title":       f.title,
                "severity":    f.severity,
                "category":    f.category,
                "description": f.description,
                "cwe":         f.cwe,
                "references":  f.references,
                # Source is derived from ctx.intensity so this same upsert
                # path is reusable by run_medium.py / run_heavy.py without
                # forking the function. All three values were added to
                # finding_source_t in migration 20260528b.
                "source":      f"commandsentry_{ctx.intensity}",
                "tags":        f.tags,
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


def close_out(conn, ctx: ScanContext, inserted: int, updated: int) -> None:
    with conn.cursor() as cur:
        params = {
            "tools_run":        ctx.tools_run,
            "findings_added":   inserted,
            "findings_updated": updated,
            "findings_count":   inserted + updated,
            "scan_run_id":      ctx.scan_run_id,
            "queue_id":         ctx.queue_id,
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
        log(f"upserted findings: {inserted} new, {updated} existing")

        close_out(conn, ctx, inserted, updated)
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
