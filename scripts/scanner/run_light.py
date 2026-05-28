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
                # 'commandsentry_light' added to finding_source_t in migration
                # 20260528b_phase4a_source_enum_extension.sql
                "source":      "commandsentry_light",
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
    )
    log(f"asset_id={ctx.asset_id} hostname={ctx.hostname} scan_run_id={ctx.scan_run_id}")

    try:
        conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
    except Exception as e:
        log(f"DB connect failed: {e}")
        return 1

    try:
        log("→ check_tls")
        check_tls(ctx)
        log("→ check_headers")
        check_headers(ctx)
        log("→ check_common_paths")
        check_common_paths(ctx)
        log("→ check_dns_posture")
        check_dns_posture(ctx)
        log("→ check_httpx_tech")
        check_httpx_tech(ctx)
        log("→ check_methods")
        check_methods(ctx)
        log("→ check_csp_nonce")
        check_csp_nonce(ctx)

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
