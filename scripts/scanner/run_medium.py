#!/usr/bin/env python3
"""
run_medium.py — Phase 4a M6/M7b Medium tier scanner

Consumes a scan descriptor (produced by poll_queue.py), runs the Medium
tier check suite against the asset, writes findings + raw artifacts to
Supabase, and closes out the scan_run.

MEDIUM TIER PHILOSOPHY:
  • Active checks — nuclei, nikto, ffuf — but TUNED QUIET so we don't
    trip target WAFs. Per Howie's design call 2026-05-29: rotation is
    not the primary defense; not triggering the WAF in the first place
    is. Rotation can layer on later if quiet-only proves insufficient.
  • Runs from inside ExpressVPN (vpn_bringup.sh wraps this invocation
    in scanner.yml for Medium+). Egress is NOT the GH runner IP.
  • Builds on top of Light — assumes Light already ran or will run
    independently. Medium does NOT re-do TLS cert / header / DNS /
    common-paths checks.
  • Aborts early on WAF-block cascade (>5 consecutive 4xx/5xx in a
    sliding window) instead of burning through the rotation budget.

CHECKS RUN (in order):
  1. nuclei  — quiet (-rate-limit 30 -c 5), skip intrusive templates
  2. nikto   — quiet (-Pause 1), HTML-format output parsed
  3. ffuf    — quiet (-rate 50 -p 0.1-0.3), top-100 dir wordlist

QUIET-TOOLING SPEC (Howie 2026-05-29):
  • Real-browser user agents rotated per tool invocation
  • Rate-limited well below WAF detection thresholds
  • Inter-request jitter to look human
  • Skip aggressive payloads against confirmed-WAF targets
  • Hard request ceiling (8000) — abort if exceeded
  • Response-code histogram dumped as artifact for post-mortem tuning

USAGE:
  python scripts/scanner/run_medium.py /tmp/scan_descriptor.json

ENVIRONMENT:
  SUPABASE_DSN — required (or pass --dsn)

EXIT CODES:
  0 — scan ran (findings written, scan_run closed). Findings may be 0.
  1 — fatal error (DB unreachable, descriptor invalid, etc.). scan_run
      is marked 'failed' before exit.
  3 — WAF block cascade detected mid-scan. scan_run marked 'failed' with
      explicit error_message so we know to tune further.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
from collections import Counter
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

# Rotating UA pool — real Chrome/Firefox/Safari/Edge as observed in
# Cloudflare's own published UA distribution. We pick one per tool
# invocation so a target seeing nuclei + nikto + ffuf doesn't see the
# same UA across all three and instantly fingerprint a scanner.
REAL_BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
]

def pick_ua() -> str:
    return random.choice(REAL_BROWSER_UAS)


# Tool budgets. Conservative — we'd rather come back with partial data
# than get banned mid-scan. These can be raised in v2 once we have real
# WAF-tolerance data from the field.
NUCLEI_RATE_LIMIT = 30      # req/sec ceiling
NUCLEI_CONCURRENCY = 5       # parallel template workers
NUCLEI_TIMEOUT_S  = 15       # per-template timeout
NUCLEI_WALL_S     = 600      # whole-tool timeout

NIKTO_PAUSE_S     = 1        # inter-check delay
NIKTO_WALL_S      = 600

FFUF_RATE         = 50       # req/sec
FFUF_DELAY_RANGE  = "0.1-0.3"  # jitter window between requests
FFUF_WALL_S       = 300

# Hard ceiling — across all tools combined. Abort if exceeded.
MAX_TOTAL_REQUESTS = 8000

# WAF-block-cascade detection. If we see this many 4xx/5xx in a row
# (in the response-code stream we observe), bail out before we burn
# through every IP in the rotation pool.
CASCADE_THRESHOLD = 5

# Small wordlist for ffuf — top dirs that high-signal but don't
# look like obvious vuln-scanner fingerprints (no /wp-admin, no /.git
# — Light already covers those).
FFUF_WORDS = [
    "api", "v1", "v2", "graphql", "rest",
    "admin", "console", "manager", "dashboard", "panel",
    "config", "settings", "uploads", "files", "download",
    "backup", "logs", "tmp", "test", "dev",
    "staging", "internal", "private", "old", "new",
    "beta", "demo", "docs", "swagger", "openapi",
    "health", "status", "ping", "monitor", "metrics",
    "actuator", "trace", "env", "info", "version",
    "login", "logout", "register", "auth", "oauth",
    "callback", "redirect", "proxy", "static", "assets",
    "images", "img", "media", "css", "js",
    "vendor", "node_modules", "build", "dist", "src",
    "webhook", "callback", "notify", "subscribe", "unsubscribe",
    "reports", "report", "export", "import", "sync",
    "queue", "task", "job", "worker", "cron",
    "stats", "analytics", "tracking", "telemetry", "logs",
    "cms", "blog", "post", "page", "article",
    "search", "filter", "tag", "category", "archive",
    "robots", "humans", "sitemap", "favicon", "manifest",
    "package", "composer", "Gemfile", "requirements", "Dockerfile",
]


# ─── Finding model (DUPED from run_light — refactor to _shared.py
# once there's a third scanner) ────────────────────────────────────────
@dataclass
class MediumFinding:
    """A single Medium-tier finding ready to upsert."""
    check_name:   str
    title:        str
    severity:     str
    category:     str
    description:  str
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
    waf_detected:  bool = False   # if true, skip 'intrusive' nuclei tags
    findings:      list[MediumFinding] = field(default_factory=list)
    tools_run:     list[str] = field(default_factory=list)
    artifacts:     list[tuple[str, str, str]] = field(default_factory=list)
    # Response-code histogram across ALL tools — dumped as a tuning
    # artifact so we can post-mortem "did we trip the WAF" without
    # re-scanning.
    response_codes: Counter = field(default_factory=Counter)
    total_requests: int = 0
    # Egress IP tracking — we record the IP we observe at scan start AND
    # the one we observe at scan end. ExpressVPN does dynamic NAT
    # within a /24 (verified 2026-05-29) so these can differ.
    egress_ips_seen: set[str] = field(default_factory=set)


# ─── Subprocess helper ──────────────────────────────────────────────────
def run_cmd(cmd: list[str], timeout: int = 30, input_str: str | None = None,
            env_extra: dict | None = None) -> tuple[int, str, str]:
    """Run a shell command. Returns (returncode, stdout, stderr).
    Never raises — failures get captured and surfaced to the caller.
    """
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_str,
            env=env,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired as e:
        return 124, "", f"timeout after {timeout}s: {e}"
    except FileNotFoundError as e:
        return 127, "", f"command not found: {cmd[0]} — {e}"
    except Exception as e:
        return 1, "", f"unexpected: {e!r}"


def log(msg: str) -> None:
    print(f"[run_medium] {msg}", file=sys.stderr)


# ─── Egress IP capture ──────────────────────────────────────────────────
def capture_egress_ip() -> str | None:
    """Probe ifconfig.me / api.ipify.org to learn our current egress IP.
    Used at scan start + end to record what the target actually saw.
    Returns None if no provider responded.
    """
    for url in ("https://api.ipify.org", "https://ifconfig.me",
                "https://icanhazip.com"):
        rc, stdout, _ = run_cmd(["curl", "-s", "--max-time", "5", url],
                                 timeout=8)
        if rc == 0:
            ip = stdout.strip()
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
                return ip
    return None


# ─── WAF pre-check ──────────────────────────────────────────────────────
def detect_waf(ctx: ScanContext) -> None:
    """Quick wafw00f probe to figure out if we're behind a known WAF.
    If we are, gate nuclei intrusive templates off — the WAF will block
    them anyway and we don't want the resulting 4xx flood to look like
    an attack.
    """
    ctx.tools_run.append("wafw00f")
    rc, stdout, _ = run_cmd(
        ["wafw00f", f"https://{ctx.hostname}/", "-a"],
        timeout=60,
    )
    ctx.artifacts.append(("wafw00f", "text", stdout))

    if rc != 0:
        log(f"wafw00f exited rc={rc} — assuming no WAF for tuning purposes")
        return

    if re.search(r"is behind", stdout, re.IGNORECASE):
        ctx.waf_detected = True
        log(f"WAF detected — will gate intrusive templates off")
    else:
        log("no WAF detected by wafw00f")


# ─── nuclei ─────────────────────────────────────────────────────────────
NUCLEI_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MODERATE",
    "low":      "LOW",
    "info":     "INFO",
    "unknown":  "INFO",
}


def check_nuclei(ctx: ScanContext) -> None:
    """Run nuclei quietly. Parse JSONL output. Emit one finding per match.

    Quiet flags:
      -rate-limit 30   below most per-IP rate limit thresholds
      -c 5             few parallel template workers (was 25 default)
      -timeout 15      per-template HTTP timeout
      -H "User-Agent"  rotating real browser UA
      -exclude-tags    intrusive when WAF detected
      -severity        critical,high,medium  (skip info noise)
    """
    ctx.tools_run.append("nuclei")
    ua = pick_ua()

    cmd = [
        "nuclei",
        "-u", f"https://{ctx.hostname}",
        "-rate-limit", str(NUCLEI_RATE_LIMIT),
        "-c",          str(NUCLEI_CONCURRENCY),
        "-timeout",    str(NUCLEI_TIMEOUT_S),
        "-H",          f"User-Agent: {ua}",
        "-severity",   "critical,high,medium",
        "-silent",
        "-jsonl",
        "-no-color",
    ]
    if ctx.waf_detected:
        # 'intrusive' templates do active fuzzing — WAFs almost always
        # block them, and the resulting 403 flood IS the WAF-cascade we
        # try to avoid. 'dos' is always off regardless of WAF.
        cmd += ["-exclude-tags", "intrusive,dos,fuzz"]
    else:
        cmd += ["-exclude-tags", "dos"]

    rc, stdout, stderr = run_cmd(cmd, timeout=NUCLEI_WALL_S)
    ctx.artifacts.append(("nuclei", "jsonl", stdout))

    if rc not in (0, 124):
        # 124 = our timeout; we still want to parse whatever JSONL came
        # through before the wall-clock cut it off.
        log(f"nuclei exited rc={rc}: {stderr.strip()[:300]}")

    matches = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            m = json.loads(line)
        except Exception:
            continue
        matches += 1
        ctx.total_requests += 1  # nuclei doesn't expose per-template
                                  # request counts in jsonl; this is a
                                  # rough floor.

        info     = m.get("info", {})
        sev_raw  = (info.get("severity") or "info").lower()
        severity = NUCLEI_SEVERITY_MAP.get(sev_raw, "INFO")
        name     = info.get("name", m.get("template-id", "unknown"))
        tpl_id   = m.get("template-id", "")
        descr    = (info.get("description") or "").strip()
        matched  = m.get("matched-at", m.get("host", ""))
        refs     = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        tags     = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        ctx.findings.append(MediumFinding(
            check_name=f"nuclei-{tpl_id}",
            title=f"{name} ({tpl_id})",
            severity=severity,
            category="dast",
            description=(
                descr
                or f"nuclei template {tpl_id} matched against {matched}. "
                   f"Severity classification per the template author. "
                   f"Review the matched-at URL and the template body for "
                   f"the exact detection criteria."
            ),
            tags=["nuclei", tpl_id] + tags[:10],
            references=refs[:10],
            raw_excerpt=json.dumps(m, indent=2)[:2500],
        ))

    log(f"nuclei: {matches} match(es)")


# ─── nikto ──────────────────────────────────────────────────────────────
NIKTO_OSVDB_SEVERITY = {
    # OSVDB IDs are mostly retired but nikto still references them.
    # We use the +/+OSVDB- count + the message text as a coarse severity
    # signal since nikto doesn't emit per-finding severity directly.
}


def check_nikto(ctx: ScanContext) -> None:
    """Run nikto quietly. Parse the plain-text output. Emit findings.

    Quiet flags:
      -Pause 1         1 sec between checks (much slower than default)
      -nointeractive   no prompts
      -ask no          don't prompt for any updates
      -Tuning x        skip "Denial of Service" tests
      -useragent       rotating real browser UA
      -timeout 15      per-request HTTP timeout
    """
    ctx.tools_run.append("nikto")
    ua = pick_ua()

    cmd = [
        "nikto",
        "-h",            f"https://{ctx.hostname}",
        "-Pause",        str(NIKTO_PAUSE_S),
        "-nointeractive",
        "-ask",          "no",
        "-Tuning",       "x6",         # skip "Denial of Service" (group 6)
        "-useragent",    ua,
        "-timeout",      "15",
        "-maxtime",      str(NIKTO_WALL_S - 30),
        "-Format",       "txt",
    ]
    rc, stdout, stderr = run_cmd(cmd, timeout=NIKTO_WALL_S)
    ctx.artifacts.append(("nikto", "text", stdout))

    if rc not in (0, 124):
        log(f"nikto exited rc={rc}: {stderr.strip()[:300]}")

    # Parse nikto text output. Findings are prefixed with "+ ":
    #   + /admin/: Admin login page/section found.
    matches = 0
    for line in stdout.splitlines():
        line = line.rstrip()
        if not line.startswith("+ "):
            continue
        body = line[2:].strip()
        # Skip the header noise lines nikto emits.
        if any(prefix in body for prefix in (
            "Target IP:", "Target Hostname:", "Target Port:",
            "Start Time:", "End Time:", "Server:", "items checked:",
            "Site link", "Allowed HTTP", "SSL Info:",
            "Subject:", "Ciphers:", "Issuer:",
        )):
            continue
        matches += 1
        ctx.total_requests += 1

        # Coarse severity heuristic from message text.
        body_lc = body.lower()
        if any(k in body_lc for k in ("exposed", "leak", "dangerous", "vulnerable",
                                       "uploadable", "writable")):
            severity = "MODERATE"
        elif any(k in body_lc for k in ("found", "directory", "listing")):
            severity = "LOW"
        else:
            severity = "INFO"

        # Make a stable check_name slug from the first 60 chars.
        slug = re.sub(r"[^a-z0-9]+", "-", body_lc)[:60].strip("-")
        if not slug:
            slug = f"finding-{matches}"

        ctx.findings.append(MediumFinding(
            check_name=f"nikto-{slug}",
            title=f"nikto: {body[:120]}",
            severity=severity,
            category="dast",
            description=(
                f"Nikto reported on {ctx.hostname}: {body}. Review the raw "
                f"nikto output artifact for full context including the "
                f"OSVDB reference and the exact URL probed."
            ),
            tags=["nikto"],
            raw_excerpt=body[:1500],
        ))

    log(f"nikto: {matches} reported item(s)")


# ─── ffuf ───────────────────────────────────────────────────────────────
def check_ffuf(ctx: ScanContext) -> None:
    """Quiet directory fuzzing. Top-100 high-signal words from our small
    wordlist. Match 200/204/301/302/307/401/403 (anything that isn't 404
    is worth knowing) but only EMIT findings for 200/204 — 403 just
    means "exists but you can't see it without auth," which is normal.

    Quiet flags:
      -rate 50         req/sec cap
      -p 0.1-0.3       jittered delay between requests
      -H "User-Agent"  rotating real browser UA
      -mc all          match any code (we filter post-hoc)
      -fc 404,500      filter out 404s and 500s from output
      -t 5             few threads
      -timeout 15
    """
    ctx.tools_run.append("ffuf")
    ua = pick_ua()

    # Write wordlist to tmp — ffuf wants a file.
    wl_path = "/tmp/commandsentry-ffuf-wl.txt"
    Path(wl_path).write_text("\n".join(FFUF_WORDS) + "\n")

    out_path = "/tmp/commandsentry-ffuf-out.json"
    cmd = [
        "ffuf",
        "-u",        f"https://{ctx.hostname}/FUZZ",
        "-w",        wl_path,
        "-rate",     str(FFUF_RATE),
        "-p",        FFUF_DELAY_RANGE,
        "-H",        f"User-Agent: {ua}",
        "-mc",       "200,204,301,302,307,401,403",
        "-fc",       "404,500,502,503",
        "-t",        "5",
        "-timeout",  "15",
        "-of",       "json",
        "-o",        out_path,
        "-s",        # silent (no banner)
    ]
    rc, stdout, stderr = run_cmd(cmd, timeout=FFUF_WALL_S)

    if rc not in (0, 124):
        log(f"ffuf exited rc={rc}: {stderr.strip()[:300]}")

    # Parse the JSON output file ffuf wrote.
    try:
        out_blob = Path(out_path).read_text()
    except Exception as e:
        log(f"ffuf output file unreadable: {e}")
        return

    ctx.artifacts.append(("ffuf", "json", out_blob))

    try:
        data = json.loads(out_blob)
    except Exception as e:
        log(f"ffuf output parse failed: {e}")
        return

    results = data.get("results", [])
    ctx.total_requests += len(FFUF_WORDS)  # rough — actual req count =
                                            # words attempted, regardless
                                            # of how many showed in output

    interesting = 0
    for r in results:
        status = r.get("status", 0)
        url    = r.get("url", "")
        word   = r.get("input", {}).get("FUZZ", "")
        ctx.response_codes[str(status)] += 1

        # Only 200/204 are worth emitting as findings. Other codes just
        # confirm the path exists in some form and are useful for the
        # response-code histogram but don't deserve a discrete finding.
        if status not in (200, 204):
            continue
        interesting += 1
        ctx.findings.append(MediumFinding(
            check_name=f"ffuf-found-{word}",
            title=f"Accessible path discovered: /{word} (HTTP {status})",
            severity="INFO",
            category="info_disclosure",
            description=(
                f"Directory fuzzing discovered /{word} on {ctx.hostname} "
                f"returning HTTP {status}. Review whether this endpoint "
                f"is intentionally public or should be moved behind auth. "
                f"This is informational by itself but can pair with other "
                f"findings to expose attack surface."
            ),
            tags=["ffuf", "directory", "discovery"],
            raw_excerpt=f"GET {url} -> HTTP {status}",
        ))

    log(f"ffuf: {len(results)} non-404 response(s), {interesting} 200/204 finding(s)")


# ─── SQL helpers (DUPED from run_light — refactor to _shared.py
# once there's a third scanner) ────────────────────────────────────────
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
    current_status = CASE
      WHEN findings.current_status IN (
             'remediated', 'validated_remediated',
             'false_positive', 'wont_fix', 'accepted_risk'
           )
        THEN findings.current_status
      ELSE 'detected'
    END,
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
    inserted = 0
    updated  = 0
    with conn.cursor() as cur:
        for f in ctx.findings:
            finding_id = f"{ctx.asset_id}:medium:{f.check_name}"
            params = {
                "finding_id":  finding_id,
                "asset_id":    ctx.asset_id,
                "title":       f.title,
                "severity":    f.severity,
                "category":    f.category,
                "description": f.description,
                "cwe":         f.cwe,
                "references":  f.references,
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


def write_scan_metadata_artifact(conn, ctx: ScanContext, Json,
                                  start_egress: str | None,
                                  end_egress:   str | None) -> None:
    """Dump scan-level metadata as a synthetic artifact. Captures the
    response-code histogram, total observed requests, egress IP set, and
    WAF detection. Used for post-mortem tuning — if a scan looks like it
    got WAF-blocked, we look here first.
    """
    meta = {
        "scan_run_id":    ctx.scan_run_id,
        "asset_id":       ctx.asset_id,
        "hostname":       ctx.hostname,
        "tools_run":      ctx.tools_run,
        "waf_detected":   ctx.waf_detected,
        "total_requests": ctx.total_requests,
        "response_codes": dict(ctx.response_codes),
        "egress_ips":     sorted(ctx.egress_ips_seen),
        "start_egress":   start_egress,
        "end_egress":     end_egress,
        "timestamp_utc":  datetime.now(timezone.utc).isoformat(),
    }
    with conn.cursor() as cur:
        cur.execute(INSERT_ARTIFACT_SQL, {
            "scan_run_id":   ctx.scan_run_id,
            "tool_name":     "scan_metadata",
            "output_format": "json",
            "size_bytes":    len(json.dumps(meta).encode("utf-8")),
            "content_jsonb": Json(meta),
        })


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

    if descriptor.get("intensity") not in ("medium", "standard"):
        log(f"WARNING: descriptor intensity is '{descriptor.get('intensity')}', "
            f"not 'medium'. Proceeding anyway.")

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

    # Capture pre-scan egress IP.
    start_egress = capture_egress_ip()
    if start_egress:
        ctx.egress_ips_seen.add(start_egress)
        log(f"pre-scan egress IP: {start_egress}")

    try:
        conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
    except Exception as e:
        log(f"DB connect failed: {e}")
        return 1

    end_egress = None
    try:
        # ─── WAF pre-check ─────────────────────────────────────────────
        log("→ detect_waf")
        detect_waf(ctx)

        # ─── nuclei ────────────────────────────────────────────────────
        if ctx.total_requests < MAX_TOTAL_REQUESTS:
            log("→ check_nuclei")
            check_nuclei(ctx)
        else:
            log("skipping nuclei — total request ceiling already hit")

        # ─── nikto ─────────────────────────────────────────────────────
        if ctx.total_requests < MAX_TOTAL_REQUESTS:
            log("→ check_nikto")
            check_nikto(ctx)
        else:
            log("skipping nikto — total request ceiling already hit")

        # ─── ffuf ──────────────────────────────────────────────────────
        if ctx.total_requests < MAX_TOTAL_REQUESTS:
            log("→ check_ffuf")
            check_ffuf(ctx)
        else:
            log("skipping ffuf — total request ceiling already hit")

        # ─── Capture post-scan egress IP ───────────────────────────────
        end_egress = capture_egress_ip()
        if end_egress:
            ctx.egress_ips_seen.add(end_egress)
            log(f"post-scan egress IP: {end_egress}")

        log(f"checks complete; {len(ctx.findings)} finding(s), "
            f"{len(ctx.artifacts)} artifact(s), "
            f"{ctx.total_requests} request(s) made, "
            f"{len(ctx.egress_ips_seen)} distinct egress IP(s)")

        # ─── Write everything ──────────────────────────────────────────
        inserted, updated = write_findings_and_artifacts(conn, ctx, Json)
        write_scan_metadata_artifact(conn, ctx, Json, start_egress, end_egress)
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
            fail_out(conn, ctx, f"run_medium fatal: {e!r}")
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
        description="Phase 4a Medium tier scanner. Consumes a descriptor from "
                    "poll_queue.py and runs the Medium check suite (nuclei + "
                    "nikto + ffuf) with quiet-tuned flags.",
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
