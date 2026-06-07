#!/usr/bin/env python3
"""
run_medium.py — Phase 4a M6/M7b Medium tier scanner

Consumes a scan descriptor (produced by poll_queue.py), runs the Medium
tier check suite against the asset, writes findings + raw artifacts to
Supabase, and closes out the scan_run.

MEDIUM TIER PHILOSOPHY (refined 2026-05-30):
  • Active checks — nuclei, nikto, ffuf — quiet-tuned so we don't
    trip target WAFs as the PRIMARY defense.
  • Runs from inside Mullvad VPN egress (scanner.yml wraps the
    invocation with vpn_bringup.sh + vpn_teardown.sh for Medium+).
  • Builds on top of Light — assumes Light already ran or will run
    independently. Medium does NOT re-do TLS cert / header / DNS /
    common-paths checks.

AGGRESSIVE ROTATION LAYER (new in this version):
  Mullvad's atomic region-swap is effectively free (1-2s, verified
  drill #10). We leverage it to rotate egress IP between tool chunks,
  so each chunk runs from a different exit IP. This means:
    - Single-IP WAF reputation never accumulates enough to ban us
    - If a chunk DOES get banned mid-flight, the next chunk's already
      on a new IP — bounded loss
    - Rotation cost ~1-2s × ~10 rotations = 10-20s overhead in a
      15-min scan (<3%)

  Four protection layers against WAF bans:
    1. Pre-chunk healthcheck (curl baseline before scanner starts)
    2. Small chunks (30-50 URLs each) so mid-chunk ban damage is bounded
    3. Rewind window — when ban detected, mark recent N seconds of
       'completed' URLs as suspect for re-scan on the next chunk
    4. Kill + rotate + requeue — bounded recovery, finding-upsert
       handles dedup automatically

CHECKS RUN (in order):
  1. wafw00f      — WAF pre-check, gates intrusive nuclei templates
  2. nuclei       — chunked, quiet (-rate-limit 30 -c 5)
  3. ffuf         — chunked, quiet (-rate 50 -p 0.1-0.3), top dirs
  4. nikto        — single pass, no chunking (incompatible)

USAGE:
  python scripts/scanner/run_medium.py /tmp/scan_descriptor.json

ENVIRONMENT:
  SUPABASE_DSN — required (or pass --dsn)

EXIT CODES:
  0 — scan ran (findings written, scan_run closed). Findings may be 0.
  1 — fatal error (DB unreachable, descriptor invalid, etc.). scan_run
      is marked 'failed' before exit.
  3 — WAF block cascade detected and no rotation recovered. scan_run
      marked 'failed' with explicit error_message.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
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

# Real-browser user agents rotated per tool invocation. Picked from
# Cloudflare's published UA distribution to look like ordinary traffic.
REAL_BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
]

def pick_ua() -> str:
    if STEALTH_UA:
        # Pin the single Chrome/131 UA — match the Mac stringent script
        # exactly so FortiGate sees identical fingerprint across requests.
        return STEALTH_FIXED_UA
    return random.choice(REAL_BROWSER_UAS)


# Tool budgets (per-chunk, not whole-scan).
NUCLEI_RATE_LIMIT = 30
NUCLEI_CONCURRENCY = 5
NUCLEI_TIMEOUT_S = 15
NUCLEI_CHUNK_WALL_S = 180      # each chunk caps at ~3min (was 90s — too short for real targets)
NUCLEI_URLS_PER_CHUNK = 40     # ~30-50s of work per chunk

NIKTO_PAUSE_S = 1
NIKTO_WALL_S = 600

FFUF_RATE = 50
FFUF_DELAY_RANGE = "0.1-0.3"
FFUF_CHUNK_WALL_S = 60
FFUF_WORDS_PER_CHUNK = 25

# Mid-scan ban-detection / rewind tuning.
REWIND_SECONDS = 30             # rewind window for soft-ban paranoia
MAX_REQUESTS_TOTAL = 8000        # hard ceiling across all tools
BAN_HTTP_CODES = {403, 429, 503, 521, 522, 523}  # WAF/CDN ban signals


# ─── ADR-001 — Validated-SHA key ────────────────────────────────────────
#
# Per-tier allowlist of scanner SHAs whose findings can be stamped as
# 'validated' instead of the default 'unvalidated'. Starts empty:
# no SHA is validated until ADR-001 Step 5 promotes the first one,
# AFTER Bug D (nikto invocation) is fixed and the silent-tool-failure
# detector is in place, AND the proving run on demo.testfire.net
# confirms all expected findings land with all tools producing real
# output (not help-text, not empty stdout from a WAF ban).
#
# Promotion mechanics:
#   - Add the full 40-char GITHUB_SHA of the proving commit to the
#     appropriate tier's set below.
#   - Re-fire that commit's runner once; subsequent inserts get
#     validation_status='validated' automatically.
#   - Older legacy/unvalidated rows that get re-emitted by a validated
#     SHA are upgraded by the UPSERT heal logic.
#
# Demotion is impossible by design. Once a SHA is in the allowlist
# its findings stay validated forever — if a SHA is later found to
# produce bad output, REMOVE it from the allowlist but do NOT
# retroactively flip rows; that's the role of remediated/false_positive
# on current_status, not the validation regime.
#
# See migration scripts/db/migrations/20260607a_findings_validation_key.sql
# and the project log [[75 - Session Log 2026-06-07]] for the rationale.

VALIDATED_VERSIONS: dict[str, set[str]] = {
    "light":  set(),
    "medium": set(),
    "heavy":  set(),
}


def get_scanner_version() -> str:
    """Return the runner's git SHA from GITHUB_SHA env (GH Actions
    populates this on every workflow run) or 'unknown' if absent.
    Always full 40-char SHA — never abbreviate, the allowlist match
    is exact-string."""
    return os.environ.get("GITHUB_SHA") or "unknown"


def derive_validation_status(intensity: str, sha: str) -> str:
    """Return 'validated' iff (intensity, sha) is in the allowlist;
    'unvalidated' otherwise. Never returns 'legacy' — that's reserved
    for rows that existed before ADR-001 (migration 20260607a)."""
    if sha in VALIDATED_VERSIONS.get(intensity, set()):
        return "validated"
    return "unvalidated"

# Rotation regions are now loaded DYNAMICALLY from /etc/wireguard/*.conf
# at script startup. Pool size went from 12 → 205 after Howie's "All
# cities / All servers" Mullvad download 2026-05-31 — way more rotation
# headroom + no code edits needed when the pool changes.
#
# Earlier reasoning preserved for the record:
# - Threshold probe #82 showed bans hit at every rate tested
# - Cross-IP propagation burned Chicago without scanning it
# - Phoenix is on Tzulo ASN; most others are M247 / DataPacket
# - With 205 IPs we can rotate per-chunk (and eventually per-N-requests)
#   without ever waiting for cooldowns
def _load_rotation_regions(conf_dir: str = "/etc/wireguard",
                           shuffle: bool = True) -> list[str]:
    """Discover the rotation pool from .conf files in conf_dir.

    Returns the region names (filename without .conf), SHUFFLED by
    default so each scan uses a different subset of the (large) pool.
    Falls back to the original 5-region pool if the dir is missing.

    `shuffle=False` gives sorted/deterministic order (useful for tests).
    """
    try:
        names = sorted(p.stem for p in Path(conf_dir).glob("*.conf"))
        if names:
            if shuffle:
                random.shuffle(names)
            return names
    except Exception:
        pass
    # Fallback for local dev / when /etc/wireguard isn't populated
    return ["us-nyc", "us-chi", "us-atl", "us-dal", "us-lax"]

ROTATION_REGIONS = _load_rotation_regions()

# ─── Threshold probe mode ───────────────────────────────────────────────
# When THRESHOLD_PROBE_MODE=true in env, the scan runs in calibration mode:
# nuclei uses a per-chunk rate ladder (instead of fixed NUCLEI_RATE_LIMIT),
# and after each chunk completes we run a healthcheck on the SAME egress
# IP (before rotating) to detect whether that rate triggered a ban. nikto
# and ffuf are skipped — we're isolating the nuclei rate variable.
#
# Output: ctx.threshold_probe_results list with per-chunk
#   {chunk, rate, egress_ip, pre_chunk_code, post_chunk_code,
#    matches, rc, banned}
# logged to scan_metadata artifact for analysis.
#
# Fire via:  -e THRESHOLD_PROBE_MODE=true ./scripts/scanner/run_medium.py ...
# Or set as a step env var in scanner.yml's "Run Medium tier" step.
THRESHOLD_PROBE_MODE = os.environ.get("THRESHOLD_PROBE_MODE", "").lower() in ("true", "1", "yes")

# When THRESHOLD_PROBE_SAFE_ONLY=true (only meaningful WITH probe mode on),
# all 5 chunks use the `medium,tech` template tag — the one chunk that
# survived scans #82 + #87 without banning its IP. Confirms that the
# template content is the trigger, not rate or fingerprint. If all 5
# chunks come back HTTP 200 post-chunk, we have the smoking gun.
THRESHOLD_PROBE_SAFE_ONLY = os.environ.get("THRESHOLD_PROBE_SAFE_ONLY", "").lower() in ("true", "1", "yes")

# Per-chunk rate ladder when probe mode is active. Brackets the current
# default (30) below and above so a single scan maps the threshold curve.
THRESHOLD_PROBE_RATE_LADDER = [5, 15, 30, 50, 100]

# ─── Patient mode ──────────────────────────────────────────────────────
# Mirrors Howie's Mac runbook (RUNBOOK-CCC-Triple-Scan-2026-05-12) which
# runs the FULL nuclei template battery against FortiGate-protected targets
# and survives via patience: rate-limit 10, 5-sec delays between phases,
# wait 30 min before rotating egress when banned. Scans take 60-90 min
# but stay alive.
#
# Hypothesis: bans are velocity-driven, not source-IP-class-driven.
# Test by replicating the Mac tuning in cloud and seeing if broad-template
# scans survive on Mullvad IPs.
PATIENT_MODE = os.environ.get("PATIENT_MODE", "").lower() in ("true", "1", "yes")

# Seconds to sleep after a post-chunk healthcheck shows BANNED, before
# rotating to the next region. Mac runbook = 1800 (30 min). Tunable
# for faster experiments. Only used when PATIENT_MODE is true.
PATIENT_BAN_COOLDOWN_S = int(os.environ.get("PATIENT_BAN_COOLDOWN_S", "1800"))

# Seconds to sleep between chunks regardless of ban state. Mac runbook
# uses 5s between phases. Only used when PATIENT_MODE is true.
PATIENT_INTER_CHUNK_DELAY_S = int(os.environ.get("PATIENT_INTER_CHUNK_DELAY_S", "5"))

# Rate-limit override when PATIENT_MODE is true. Matches Mac runbook.
PATIENT_RATE_LIMIT = int(os.environ.get("PATIENT_RATE_LIMIT", "10"))

# ─── Softened rate (Plan A2 + B, 2026-05-31 PM) ────────────────────────
# Gentler nuclei rate for non-FortiGate targets that nevertheless have a
# WAF or are running WordPress. FortiGate gets full PATIENT (cooldowns
# + rotation recovery). These targets just need slower probing so the
# WAF doesn't silently 403-filter scanner-shaped requests.
#
# Origin: Scan B (CMI) 2026-05-31 PM. Default rate 30 against Pressable
# (which has generic WAF — 403s on attack strings, doesn't ban IPs).
# 0 new findings on a site with 44 known existing findings. Mac runbook
# uses --rate-limit 2 + per-phase delays against the same target and
# finds the WP plugin CVEs cleanly. Cloud rate of 5 is a defensive
# middle ground between cloud's broken 30 and Mac's gentle 2.
SOFTENED_RATE_LIMIT = int(os.environ.get("SOFTENED_RATE_LIMIT", "5"))

# ─── Stealth UA mode (advisor-brief audit fallout, 2026-05-31 PM) ──────
# Mirrors the Mac stringent script line 94: "Browser-like headers —
# looks authenticated, not like a scanner." Pins User-Agent to a single
# Chrome/131 string (vs our randomized pool) and drops nuclei rate to 2
# (vs PATIENT's 10, vs default 30). Step 1 of the two-step diagnostic
# test — Howie's refinement of my one-step proposal so we can isolate
# UA-vs-rate-vs-content as the surviving lever instead of flipping
# multiple variables at once.
STEALTH_UA = os.environ.get("STEALTH_UA", "").lower() in ("true", "1", "yes")
STEALTH_RATE_LIMIT = int(os.environ.get("STEALTH_RATE_LIMIT", "2"))
# Pinned UA matches the Mac runbook test-stringent-retest-2026-05-14.sh
# line 95 exactly. If we want to vary later, env-override-able.
STEALTH_FIXED_UA = os.environ.get(
    "STEALTH_FIXED_UA",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
)

# ─── Crawl-first mode (step 2 of the two-step diagnostic) ──────────────
# When true, runs katana to crawl the target FIRST, captures the URL
# list, then invokes nuclei with -list against the crawled URLs instead
# of -u target. Skips template-driven path enumeration entirely — the
# scanner never requests /wp-login, /admin, /.env, etc. unless katana
# discovered them via real links. This is what the Mac stringent script
# actually does (line: `Pass 1: critical+high only, rps=2, c=1, against
# 529 URLs`). Composable with STEALTH_UA — typical use is both together.
CRAWL_FIRST_MODE = os.environ.get("CRAWL_FIRST_MODE", "").lower() in ("true", "1", "yes")
# katana depth cap. Mac uses default (3). Bound it to keep crawl quick.
CRAWL_DEPTH = int(os.environ.get("CRAWL_DEPTH", "3"))
# katana wall (seconds). Crawl runs once at scan start, so budget enough.
CRAWL_WALL_S = int(os.environ.get("CRAWL_WALL_S", "300"))
# Match the regions for which we've shipped WireGuard configs in the
# vpn-tools GH release. Add more by generating + uploading more confs.

# Small high-signal wordlist for ffuf — top dirs that high-signal but
# don't look like obvious vuln-scanner fingerprints (no /wp-admin, no
# /.git — Light already covers those).
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
    "stats", "analytics", "tracking", "telemetry",
    "cms", "blog", "post", "page", "article",
    "search", "filter", "tag", "category", "archive",
    "robots", "humans", "sitemap", "favicon", "manifest",
    "package", "composer", "Gemfile", "requirements", "Dockerfile",
]


# ─── Data classes ───────────────────────────────────────────────────────
@dataclass
class MediumFinding:
    check_name: str
    title: str
    severity: str
    category: str
    description: str
    tags: list[str] = field(default_factory=list)
    cwe: list[int] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    raw_excerpt: str | None = None


@dataclass
class ScanContext:
    descriptor: dict
    hostname: str
    asset_id: str
    scan_run_id: str
    queue_id: str
    intensity: str
    waf_detected: bool = False
    waf_kind: str | None = None  # 'fortiweb', 'cloudflare', 'akamai', etc. — from wafw00f
    tech_stack: set[str] = field(default_factory=set)  # lowercased techs from httpx -td
    findings: list[MediumFinding] = field(default_factory=list)
    tools_run: list[str] = field(default_factory=list)
    artifacts: list[tuple[str, str, str]] = field(default_factory=list)
    response_codes: Counter = field(default_factory=Counter)
    total_requests: int = 0
    egress_ips_seen: list[str] = field(default_factory=list)
    rotation_count: int = 0
    ban_events: list[dict] = field(default_factory=list)  # log of detected bans
    region_idx: int = 0  # cursor into ROTATION_REGIONS
    # Threshold probe (only populated when THRESHOLD_PROBE_MODE=true).
    # One dict per nuclei chunk: rate, egress_ip, pre/post HTTP code, banned bool.
    threshold_probe_results: list[dict] = field(default_factory=list)
    # ADR-001 Step 4 — per-tool completeness map. After each tool runs,
    # a narrow predicate decides whether the tool actually produced real
    # output. {tool_name: {"ok": True} | {"degraded": "<reason_slug>"}}.
    # Written to scan_run.tool_status at close-out.
    tool_status: dict[str, dict] = field(default_factory=dict)


# ─── Tool-status helpers (ADR-001 Step 4) ───────────────────────────────
#
# A degraded flag means "tool FAILED," NEVER "tool worked, found nothing."
# Only wire detectors that key on unambiguous failure (help-banner-on-bad-args,
# parse-error, absence-of-verdict-line). Do NOT wire empty-output detectors
# on tools where empty is a healthy outcome (e.g. nuclei against a clean
# stack legitimately returns empty stdout). Per Howie 2026-06-07: a detector
# that cries wolf on healthy runs trains the team to ignore 'degraded' and
# defeats the regime.
#
# Each detector is named `tool_is_degraded(...)` and returns
# (False, "")  if the tool's output looks like a real scan
# (True,  "<reason>") if a failure shape is recognized.


def mark_tool_ok(ctx: ScanContext, tool_name: str) -> None:
    """Record that a tool produced real output."""
    ctx.tool_status[tool_name] = {"ok": True}


def mark_tool_degraded(ctx: ScanContext, tool_name: str, reason: str) -> None:
    """Record that a tool failed in a recognized way. reason is a stable
    machine-readable slug (snake_case) — downstream reports group on it."""
    ctx.tool_status[tool_name] = {"degraded": reason}


def nikto_is_degraded(stdout: str, rc: int) -> tuple[bool, str]:
    """Bug D detector. nikto prints its short usage banner on ambiguous
    arg or unknown flag. Look for the exact phrases nikto's help text
    emits — narrow enough that real scan output never matches."""
    if "Note: This is the short help output" in stdout:
        return True, "help_text_returned"
    if "Use -H for full help text" in stdout:
        return True, "help_text_returned"
    return False, ""


def ffuf_is_degraded(out_blob: str | None, parsed: dict | None) -> tuple[bool, str]:
    """ffuf is degraded only when the OUTPUT FILE can't be read (handled
    inline as 'unreadable') or the JSON has no `results` key at all.
    `results == []` is healthy — it just means no path in the chunk matched.
    Per Howie's rule: NEVER flag empty-found as degraded."""
    if out_blob is None:
        return True, "output_unreadable"
    if parsed is None:
        return True, "parse_failed"
    if "results" not in parsed:
        return True, "results_key_missing"
    return False, ""


def wafw00f_is_degraded(stdout: str, rc: int) -> tuple[bool, str]:
    """wafw00f always emits either a '[+] ' positive verdict line or
    '[-] No WAF detected by the generic detection'. If neither is in
    the output, something went wrong (network failure, unsupported
    target, etc.). rc != 0 with no verdict is also degraded — but
    rc==1 with a clean 'No WAF' verdict is healthy (wafw00f exits 1
    when no WAF found, weirdly)."""
    if "[+] " in stdout:
        return False, ""
    if "No WAF detected by the generic detection" in stdout:
        return False, ""
    if "is behind a" in stdout or "is behind " in stdout:
        # Older wafw00f phrasing — still a positive identification
        return False, ""
    return True, "no_verdict"


# ─── Subprocess helpers ─────────────────────────────────────────────────
def run_cmd(cmd: list[str], timeout: int = 30, input_str: str | None = None,
            env_extra: dict | None = None) -> tuple[int, str, str]:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            input=input_str, env=env,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", f"command not found: {cmd[0]} — {e}"
    except Exception as e:
        return 1, "", f"unexpected: {e!r}"


def log(msg: str) -> None:
    print(f"[run_medium] {msg}", file=sys.stderr)


# ─── Egress IP + VPN rotation ──────────────────────────────────────────
def capture_egress_ip() -> str | None:
    for url in ("https://api.ipify.org", "https://ifconfig.me",
                "https://icanhazip.com"):
        rc, stdout, _ = run_cmd(["curl", "-s", "--max-time", "5", url], timeout=8)
        if rc == 0:
            ip = stdout.strip()
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip):
                return ip
    return None


def rotate_vpn(ctx: ScanContext) -> bool:
    """Rotate to the next region in ROTATION_REGIONS. Best-effort —
    returns True on success, False on failure. Failures are non-fatal:
    the scan continues on the current tunnel.
    """
    ctx.region_idx = (ctx.region_idx + 1) % len(ROTATION_REGIONS)
    region = ROTATION_REGIONS[ctx.region_idx]
    log(f"→ rotating VPN to {region}")

    # The vpn_rotate.sh script is shipped alongside this scanner in
    # scripts/scanner/. Resolve its path relative to this file.
    script = Path(__file__).parent / "vpn_rotate.sh"
    if not script.exists():
        log(f"  vpn_rotate.sh not found at {script} — rotation disabled")
        return False

    rc, stdout, stderr = run_cmd([str(script), region], timeout=120)
    if rc == 0:
        ctx.rotation_count += 1
        new_ip = capture_egress_ip()
        if new_ip and new_ip not in ctx.egress_ips_seen:
            ctx.egress_ips_seen.append(new_ip)
        log(f"  ✓ rotated to {new_ip or '<unknown>'}")
        return True
    else:
        log(f"  ✗ rotation failed (rc={rc}): {stderr.strip()[:200]}")
        return False


# ─── Healthcheck — IP-banned detection ─────────────────────────────────
def healthcheck(ctx: ScanContext) -> tuple[bool, int]:
    """Probe the target with a benign HTTP request. Returns (healthy, http_code).
    'healthy' = the IP is NOT showing ban signals (4xx WAF block, captcha, etc).
    """
    ua = pick_ua()
    rc, stdout, _ = run_cmd(
        ["curl", "-s", "-o", "/dev/null",
         "-w", "%{http_code}",
         "--max-time", "10",
         "-H", f"User-Agent: {ua}",
         f"https://{ctx.hostname}/"],
        timeout=15,
    )
    if rc != 0:
        return False, 0

    try:
        code = int(stdout.strip())
    except ValueError:
        return False, 0

    healthy = code in (200, 301, 302, 303, 307, 308, 401)  # 401 = auth-gated but reachable
    return healthy, code


def ensure_healthy_egress(ctx: ScanContext, max_rotations: int = 2) -> bool:
    """Healthcheck + rotate-on-fail loop. Returns True if we ended up
    with a healthy IP. Returns False if even after `max_rotations`
    rotations we're still banned everywhere.
    """
    for attempt in range(max_rotations + 1):
        healthy, code = healthcheck(ctx)
        if healthy:
            if attempt > 0:
                log(f"healthcheck: recovered on attempt {attempt + 1} (HTTP {code})")
            return True
        log(f"healthcheck: unhealthy (HTTP {code}) on attempt {attempt + 1}")
        if attempt < max_rotations:
            ctx.ban_events.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "pre_chunk_unhealthy",
                "http_code": code,
            })
            rotate_vpn(ctx)
    return False


# ─── WAF pre-check ──────────────────────────────────────────────────────
def detect_waf(ctx: ScanContext) -> None:
    """Run wafw00f. Sets ctx.waf_detected + ctx.waf_kind on hit.

    Two detection paths:
      (1) Named-signature match — "is behind <Name>" with a known WAF
          identifier like FortiWeb, Cloudflare, Akamai, etc.
      (2) Generic detection — wafw00f sees attack-string requests get
          403'd but can't ID the WAF by signature. Common for Pressable,
          smaller managed-host WAFs, and bespoke FortiGate configs.

    Previously only (1) set waf_detected=True. (2) was logged as 'no WAF'
    which caused the cloud scanner to fire broad templates at rate 30
    against Pressable (commandmarketinginnovations.com 2026-05-31 PM),
    triggering silent 403-filtering by Pressable's WAF and returning
    0 findings against a site we knew had real findings.
    """
    ctx.tools_run.append("wafw00f")
    rc, stdout, _ = run_cmd(
        ["wafw00f", f"https://{ctx.hostname}/", "-a"],
        timeout=60,
    )
    ctx.artifacts.append(("wafw00f", "text", stdout))
    # ADR-001 Step 4 — completeness check: either a verdict line is
    # present or the tool failed.
    is_degraded, reason = wafw00f_is_degraded(stdout, rc)
    if is_degraded:
        mark_tool_degraded(ctx, "wafw00f", reason)
    else:
        mark_tool_ok(ctx, "wafw00f")
    if rc != 0:
        log(f"wafw00f rc={rc} — assuming no WAF for tuning purposes")
        return
    # Path 1: named-signature match. "is behind FortiWeb (Fortinet Inc.)"
    m = re.search(r"is behind\s+([A-Za-z][A-Za-z0-9_\-]+)", stdout)
    if m:
        ctx.waf_detected = True
        ctx.waf_kind = m.group(1).lower()
        log(f"WAF detected: {ctx.waf_kind} — will gate intrusive templates off")
        return
    # Path 2: generic detection. "seems to be behind a WAF or some sort
    # of security solution" — wafw00f's response-code-heuristic firing
    # without a signature match. Set waf_kind='generic' so downstream
    # softening kicks in even though we don't know the specific WAF.
    if re.search(r"seems to be behind", stdout, re.IGNORECASE):
        ctx.waf_detected = True
        ctx.waf_kind = "generic"
        log("WAF detected: generic (wafw00f generic detection — kind unknown)")
        return
    log("no WAF detected by wafw00f")


# ─── Tech stack detection (P2.5) ───────────────────────────────────────
def detect_tech_stack(ctx: ScanContext) -> None:
    """Run httpx -td against the target, populate ctx.tech_stack.

    Tech names httpx emits include: 'WordPress', 'Nginx', 'Apache',
    'IIS', 'ASP.NET', 'PHP', 'jQuery', 'Cloudflare', etc. Lowercased
    for downstream matching against the chunk-plan stack keys.
    """
    ctx.tools_run.append("httpx[-td]")
    rc, stdout, stderr = run_cmd(
        [
            "httpx",
            "-u", f"https://{ctx.hostname}",
            "-td",
            "-silent",
            "-json",
            "-timeout", "10",
            "-no-color",
        ],
        timeout=30,
    )
    if rc != 0:
        log(f"httpx tech-detect rc={rc} — skipping (chunk plan stays default)")
        log(f"  stderr: {stderr[:200]}")
        return
    # httpx -json emits one JSON object per line; we asked for a single URL
    line = stdout.strip().splitlines()[0] if stdout.strip() else ""
    if not line:
        log("httpx tech-detect: no output")
        return
    try:
        data = json.loads(line)
        techs = data.get("tech") or data.get("technologies") or []
        ctx.tech_stack = {t.lower() for t in techs if isinstance(t, str)}
        ctx.artifacts.append(("httpx_tech", "json", line))
        log(f"tech detected: {sorted(ctx.tech_stack) if ctx.tech_stack else '<none>'}")
    except Exception as e:
        log(f"httpx tech-detect parse failed: {e!r}")


# ─── Target routing — FortiGate detection (P1) ─────────────────────────
# Hostname allowlist for known FortiGate-protected vhosts. wafw00f
# detection is the primary signal, but a permissively-configured
# FortiGate may not announce itself in headers. The allowlist is the
# defensive fallback so we apply safe-only + patient defaults reliably.
#
# Source-of-truth: CLAUDE.md "Command hosting topology" memory +
# 2026-05-31 audit. Update when new Command vhosts come into scope or
# move between hosting tiers.
FORTIGATE_HOSTNAMES: set[str] = {
    "test.commandcommcentral.com",
    "www.commandcommcentral.com",
    "api.commandcommcentral.com",  # Monitor mode, but still FortiGate
    "sciimage.com",
    "www.sciimage.com",
    "vpn.sciimage.com",
    "ftp.sciimage.com",
}

# Apex domains where every subdomain is on Command's FortiGate. Cheaper
# than enumerating every vhost; safer than relying only on wafw00f.
FORTIGATE_APEXES: set[str] = {
    "commandcommcentral.com",
    "sciimage.com",
}


def is_fortigate_target(ctx: ScanContext) -> bool:
    """True if the scan target sits behind Command's FortiGate.

    Order of evidence:
      1. wafw00f said so (ctx.waf_kind contains 'forti')
      2. exact hostname match against FORTIGATE_HOSTNAMES
      3. apex domain match against FORTIGATE_APEXES
    """
    if ctx.waf_kind and "forti" in ctx.waf_kind:
        return True
    if ctx.hostname in FORTIGATE_HOSTNAMES:
        return True
    # Apex / subdomain match
    parts = ctx.hostname.split(".")
    for i in range(len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in FORTIGATE_APEXES:
            return True
    return False


# ─── Chunk plan builder (P1 + P2.5 combined) ───────────────────────────
def build_chunk_plan(ctx: ScanContext) -> list[tuple[str, str | None, str]]:
    """Return the list of (severity_filter, tag_filter, description) for
    this target's nuclei chunks.

    Routing logic:
      • THRESHOLD_PROBE_MODE+SAFE_ONLY → 5x medium,tech (existing behavior)
      • is_fortigate_target → 5x medium,tech (safe-only, proven survives)
      • Otherwise → stack-aware plan:
          - Always: critical+high (broad), medium CVE, exposure/config,
            tech baseline
          - WordPress detected → +medium,wordpress,cms
          - IIS/.NET detected → +medium,iis,asp,aspnet,dotnet
          - PHP detected → +medium,php
          - Drupal detected → +medium,drupal,cms
          - Joomla detected → +medium,joomla,cms
    """
    # PROBE+SAFE_ONLY still has its own plan
    if THRESHOLD_PROBE_MODE and THRESHOLD_PROBE_SAFE_ONLY:
        return [
            ("medium", "tech", f"tech-stack (safe-only probe #{i+1}/5)")
            for i in range(5)
        ]

    # P1: FortiGate → safe-only. Broad templates proven to ban every
    # time on these targets regardless of patience/UA/crawl-first; only
    # medium,tech reliably completes. Five identical safe chunks rotate
    # IPs for breadth-via-rotation rather than breadth-via-templates.
    if is_fortigate_target(ctx):
        log(f"  target_class=FortiGate (waf_kind={ctx.waf_kind}, "
            f"hostname_match={ctx.hostname in FORTIGATE_HOSTNAMES}) → safe-only plan")
        return [
            ("medium", "tech", f"FortiGate safe-only chunk {i+1}/5")
            for i in range(5)
        ]

    # P2.5: stack-aware plan for non-FortiGate targets
    stack = ctx.tech_stack
    chunks: list[tuple[str, str | None, str]] = [
        ("critical,high", None,            "critical + high severity (broad)"),
        ("medium",        "cve",           "medium CVE templates"),
    ]
    # Stack-specific chunks — only fire templates that could possibly match
    if any(t in stack for t in ("wordpress", "wp")):
        chunks.append(("medium", "wordpress,cms", "WordPress/CMS misconfig"))
    if any(t in stack for t in ("iis", "asp.net", "aspnet", "asp", "dotnet", ".net", "microsoft-iis")):
        chunks.append(("medium", "iis,asp,aspnet,dotnet,microsoft,windows", "IIS/.NET stack"))
    if "php" in stack:
        chunks.append(("medium", "php", "PHP stack"))
    if "drupal" in stack:
        chunks.append(("medium", "drupal,cms", "Drupal/CMS misconfig"))
    if "joomla" in stack:
        chunks.append(("medium", "joomla,cms", "Joomla/CMS misconfig"))
    # Always-on closers
    chunks.append(("medium", "exposure,config", "config + secret exposure"))
    chunks.append(("medium", "tech",            "tech-stack-specific"))
    log(f"  target_class=standard (stack={sorted(stack) or '<unknown>'}) → "
        f"{len(chunks)}-chunk plan")
    return chunks


def is_effective_patient_mode(ctx: ScanContext) -> bool:
    """Patient mode auto-on for FortiGate targets even if workflow input
    is false. Operator can still disable via PATIENT_MODE_OFF=true env.
    """
    if os.environ.get("PATIENT_MODE_OFF", "").lower() in ("true", "1", "yes"):
        return False
    return PATIENT_MODE or is_fortigate_target(ctx)


def needs_softened_rate(ctx: ScanContext) -> bool:
    """True if the target deserves a gentler nuclei rate but doesn't
    need full PATIENT mode (no cooldowns, no rotation recovery — just
    slower probing so the WAF doesn't silently filter scanner traffic).

    Triggers:
    - Any WAF detected (FortiGate already covered by PATIENT)
    - WordPress in tech_stack (Mac runbook treats WP gently regardless
      of WAF detection — managed WP hosts often filter scanner-shape
      traffic without announcing themselves)

    FortiGate targets get PATIENT instead, which already includes the
    slower rate plus cooldowns and inter-chunk delays. Don't double up.
    """
    if is_fortigate_target(ctx):
        return False
    if ctx.waf_detected:
        return True
    # Substring match on tech_stack — httpx -td sometimes emits plugin
    # names like "email encoder for wordpress" rather than clean tokens.
    if any("wordpress" in t or t == "wp" for t in ctx.tech_stack):
        return True
    return False


# ─── nuclei (chunked) ──────────────────────────────────────────────────
NUCLEI_SEVERITY_MAP = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MODERATE",
    "low": "LOW", "info": "INFO", "unknown": "INFO",
}


def discover_target_urls(ctx: ScanContext) -> list[str]:
    """Build the URL list nuclei will be chunked across.

    For a single-host Medium scan, nuclei is typically run against the
    BASE URL and nuclei itself fans out across templates. So the "URLs
    to chunk" are really TEMPLATE CHUNKS, not URL chunks.

    Strategy: split nuclei's template severity classes into chunks so
    each chunk is bounded:
      - critical+high severity templates
      - medium severity templates split into N batches by tag
    """
    # For the initial Medium tier implementation, we just run nuclei
    # against the root URL once per chunk with different template
    # filters. Future enhancement: discover sub-paths via katana/ffuf
    # first and feed those as the chunked URL list.
    base = f"https://{ctx.hostname}"
    return [base]


def run_katana_crawl(ctx: ScanContext, base_url: str) -> str | None:
    """Run katana against the target ONCE at scan start to produce a URL
    list. Used by CRAWL_FIRST_MODE to scope nuclei to crawled URLs only
    (no template-driven path enumeration that would hit /wp-login,
    /admin, /.env and trip FortiGate bot-trap signatures).

    Returns the path to a file containing one URL per line, or None on
    failure (caller falls back to template-driven scanning).
    """
    ctx.tools_run.append("katana")
    ua = pick_ua()
    out_file = f"/tmp/katana_urls_{ctx.scan_run_id}.txt"
    cmd = [
        "katana",
        "-u", base_url,
        "-d", str(CRAWL_DEPTH),
        "-H", f"User-Agent: {ua}",
        "-silent",
        "-jc",  # include javascript-discovered endpoints
        "-o", out_file,
    ]
    # Pace the crawl on FortiGate targets — STEALTH_UA + auto-patient
    # for FortiGate-hostnames both imply gentleness.
    if STEALTH_UA or is_effective_patient_mode(ctx):
        cmd += ["-rate-limit", "10"]
    log(f"crawl-first: katana crawling {base_url} (depth={CRAWL_DEPTH}, wall={CRAWL_WALL_S}s)")
    rc, stdout, stderr = run_cmd(cmd, timeout=CRAWL_WALL_S)
    if rc != 0:
        log(f"  katana rc={rc} — crawl failed, falling back to template-driven mode")
        log(f"  stderr: {stderr[:300]}")
        return None
    # Count URLs discovered + log a preview
    try:
        with open(out_file) as f:
            urls = [u.strip() for u in f if u.strip()]
        log(f"  katana discovered {len(urls)} URL(s)")
        if len(urls) == 0:
            log("  empty crawl — falling back to template-driven mode")
            return None
        # Persist as artifact for forensics
        ctx.artifacts.append(("katana", "text", "\n".join(urls)))
        return out_file
    except Exception as e:
        log(f"  could not read katana output: {e}")
        return None


def run_nuclei_chunk(ctx: ScanContext, target_url: str,
                     severity_filter: str, tag_filter: str | None,
                     rate_override: int | None = None,
                     url_list_file: str | None = None) -> tuple[int, int, list[int]]:
    """Run one nuclei chunk. Returns (rc, match_count, response_codes_observed).

    response_codes_observed is populated from nuclei's stats output if
    we can parse it; otherwise it's empty.

    rate_override: if set, used instead of NUCLEI_RATE_LIMIT. Threshold
    probe mode passes a per-chunk rate from the ladder.

    url_list_file: if set, nuclei runs with -list <file> against the
    crawled URLs instead of -u target_url. CRAWL_FIRST_MODE uses this
    to avoid template-driven path enumeration on WAF-sensitive targets.
    """
    ctx.tools_run.append(f"nuclei[{severity_filter}{':'+tag_filter if tag_filter else ''}]")
    ua = pick_ua()
    if rate_override is not None:
        effective_rate = rate_override
    elif STEALTH_UA:
        effective_rate = STEALTH_RATE_LIMIT
    else:
        effective_rate = NUCLEI_RATE_LIMIT

    cmd = ["nuclei"]
    if url_list_file:
        cmd += ["-list", url_list_file]
    else:
        cmd += ["-u", target_url]
    cmd += [
        "-rate-limit", str(effective_rate),
        "-c", str(NUCLEI_CONCURRENCY),
        "-timeout", str(NUCLEI_TIMEOUT_S),
        "-H", f"User-Agent: {ua}",
        "-severity", severity_filter,
        "-silent", "-jsonl", "-no-color",
    ]
    if tag_filter:
        cmd += ["-tags", tag_filter]
    if ctx.waf_detected:
        cmd += ["-exclude-tags", "intrusive,dos,fuzz"]
    else:
        cmd += ["-exclude-tags", "dos"]

    rc, stdout, stderr = run_cmd(cmd, timeout=NUCLEI_CHUNK_WALL_S)
    ctx.artifacts.append((
        f"nuclei[{severity_filter}{':'+tag_filter if tag_filter else ''}]",
        "jsonl", stdout,
    ))

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
        ctx.total_requests += 1

        info = m.get("info", {})
        sev_raw = (info.get("severity") or "info").lower()
        severity = NUCLEI_SEVERITY_MAP.get(sev_raw, "INFO")
        name = info.get("name", m.get("template-id", "unknown"))
        tpl_id = m.get("template-id", "")
        descr = (info.get("description") or "").strip()
        matched = m.get("matched-at", m.get("host", ""))
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        ctx.findings.append(MediumFinding(
            check_name=f"nuclei-{tpl_id}",
            title=f"{name} ({tpl_id})",
            severity=severity,
            category="dast",
            description=(
                descr or
                f"nuclei template {tpl_id} matched against {matched}. "
                f"Severity per the template author. Review the matched-at URL."
            ),
            tags=["nuclei", tpl_id] + tags[:10],
            references=refs[:10],
            raw_excerpt=json.dumps(m, indent=2)[:2500],
        ))

    return rc, matches, []


def run_nuclei_chunked(ctx: ScanContext) -> None:
    """Run nuclei in multiple chunks, rotating VPN between each.

    Chunks defined by severity + tag combinations so each chunk runs a
    bounded subset of templates against the target.

    When THRESHOLD_PROBE_MODE is active, the rate is overridden per
    chunk from THRESHOLD_PROBE_RATE_LADDER, and a post-chunk healthcheck
    is run on the SAME egress IP before rotating away — so we can map
    rate-to-ban behavior in a single scan.
    """
    # Effective mode resolution. PATIENT_MODE may be inherited from the
    # workflow input OR auto-enabled by target class (FortiGate → on).
    patient_effective = is_effective_patient_mode(ctx)
    if THRESHOLD_PROBE_MODE:
        if THRESHOLD_PROBE_SAFE_ONLY:
            log("→ nuclei (THRESHOLD PROBE MODE — SAFE-ONLY: all 5 chunks use medium,tech)")
            log(f"  rate ladder: {THRESHOLD_PROBE_RATE_LADDER} req/s (one per chunk)")
            log("  isolating template-content variable — if all 5 chunks pass post-check,")
            log("  template paths are confirmed as the ban trigger (not rate / not fingerprint)")
        else:
            log("→ nuclei (THRESHOLD PROBE MODE — rate ladder per chunk)")
            log(f"  rate ladder: {THRESHOLD_PROBE_RATE_LADDER} req/s (one per chunk)")
    elif patient_effective:
        why = "workflow input" if PATIENT_MODE else f"auto-on for FortiGate target"
        log(f"→ nuclei (PATIENT MODE — {why} — mirrors Mac runbook tuning)")
        log(f"  rate-limit: {PATIENT_RATE_LIMIT} req/s (vs default {NUCLEI_RATE_LIMIT})")
        log(f"  inter-chunk delay: {PATIENT_INTER_CHUNK_DELAY_S}s")
        log(f"  ban cooldown: {PATIENT_BAN_COOLDOWN_S}s ({PATIENT_BAN_COOLDOWN_S//60} min) before rotating")
        log(f"  expected runtime: ~{(NUCLEI_CHUNK_WALL_S * 5 + PATIENT_INTER_CHUNK_DELAY_S * 4) // 60} min baseline,")
        log(f"  up to ~{((NUCLEI_CHUNK_WALL_S * 5 + PATIENT_BAN_COOLDOWN_S * 4) // 60)} min if every chunk bans")
    else:
        log("→ nuclei (chunked with mid-scan rotation)")
    if STEALTH_UA:
        log(f"  STEALTH_UA on: pinned UA + rate {STEALTH_RATE_LIMIT} req/s "
            f"(overrides chunk rate unless probe-mode active)")
    base_url = f"https://{ctx.hostname}"

    # CRAWL_FIRST_MODE: run katana once at scan start, then pass the URL
    # list to every nuclei chunk via -list. Skips template-driven path
    # enumeration entirely. Step 2 of Howie's two-step diagnostic.
    url_list_file = None
    if CRAWL_FIRST_MODE:
        log("→ CRAWL_FIRST_MODE on — running katana preflight to build URL list")
        url_list_file = run_katana_crawl(ctx, base_url)
        if url_list_file:
            log(f"  nuclei chunks will run against -list {url_list_file}")
        else:
            log("  katana failed or empty — chunks will fall back to -u target_url")

    # P1 + P2.5: target-class + stack-aware chunk plan. See build_chunk_plan()
    # for routing logic. PROBE+SAFE_ONLY still gets its diagnostic-specific
    # 5-chunk plan inside the builder.
    chunks = build_chunk_plan(ctx)

    for i, (sev, tag, desc) in enumerate(chunks):
        # Layer 1: pre-chunk healthcheck
        # Rate resolution: PROBE ladder always wins (it's a diagnostic test).
        # Otherwise, "most conservative rate wins" across all active modes.
        # Bug fix 2026-05-31 PM: previously PATIENT_MODE's rate (10) silently
        # overrode STEALTH_UA's rate (2) when both were enabled. Cost ~10 min
        # of a banned scan before catching it.
        if THRESHOLD_PROBE_MODE and i < len(THRESHOLD_PROBE_RATE_LADDER):
            rate_for_chunk = THRESHOLD_PROBE_RATE_LADDER[i]
            mode_label = f"PROBE @ {rate_for_chunk}"
        else:
            candidates = [NUCLEI_RATE_LIMIT]
            active_modes = []
            if patient_effective:
                candidates.append(PATIENT_RATE_LIMIT)
                # Distinguish auto-on from workflow-input for log clarity
                active_modes.append("PATIENT" if PATIENT_MODE else "PATIENT-auto")
            if STEALTH_UA:
                candidates.append(STEALTH_RATE_LIMIT)
                active_modes.append("STEALTH")
            if needs_softened_rate(ctx):
                candidates.append(SOFTENED_RATE_LIMIT)
                reason = "waf" if ctx.waf_detected else "wp"
                active_modes.append(f"SOFTENED-{reason}")
            rate_for_chunk = min(candidates)
            mode_label = f"{'+'.join(active_modes) or 'DEFAULT'} @ {rate_for_chunk}"
        if active_modes_or_probe := (THRESHOLD_PROBE_MODE or patient_effective or STEALTH_UA or needs_softened_rate(ctx)):
            log(f"chunk {i+1}/{len(chunks)} [{mode_label} req/s]: {desc}")
        else:
            log(f"chunk {i+1}/{len(chunks)}: {desc}")

        if not ensure_healthy_egress(ctx, max_rotations=2):
            log("  ✗ target unreachable from any rotated IP — skipping chunk")
            ctx.ban_events.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "chunk_skipped_unreachable",
                "chunk": f"{sev}:{tag or '<all>'}",
            })
            if THRESHOLD_PROBE_MODE:
                ctx.threshold_probe_results.append({
                    "chunk_index": i + 1, "rate": rate_for_chunk,
                    "egress_ip": ctx.egress_ips_seen[-1] if ctx.egress_ips_seen else None,
                    "pre_chunk_code": 0, "post_chunk_code": None,
                    "matches": 0, "rc": None, "banned": True,
                    "note": "skipped — already unreachable before chunk",
                })
            continue

        # PROBE/PATIENT: capture the egress IP we're about to scan from +
        # a baseline health code RIGHT BEFORE the chunk runs.
        probe_egress_ip = ctx.egress_ips_seen[-1] if ctx.egress_ips_seen else None
        pre_code = None
        if THRESHOLD_PROBE_MODE or patient_effective:
            _, pre_code = healthcheck(ctx)
            tag_lbl = "PROBE" if THRESHOLD_PROBE_MODE else "PATIENT"
            log(f"  {tag_lbl} pre-chunk healthcheck on {probe_egress_ip}: HTTP {pre_code}")

        # Layer 2: run the chunk
        rc, matches, _ = run_nuclei_chunk(
            ctx, base_url, sev, tag,
            rate_override=rate_for_chunk if (THRESHOLD_PROBE_MODE or patient_effective or STEALTH_UA or needs_softened_rate(ctx)) else None,
            url_list_file=url_list_file,
        )
        log(f"  chunk {i+1} done: {matches} match(es), rc={rc}")

        # PROBE/PATIENT: healthcheck on the SAME tunnel BEFORE rotating.
        # In PROBE mode this is data-gathering. In PATIENT mode it gates
        # whether we trigger the ban-cooldown sleep before rotating.
        post_banned = False
        if THRESHOLD_PROBE_MODE or patient_effective:
            _, post_code = healthcheck(ctx)
            post_banned = post_code not in (200, 301, 302, 303, 307, 308, 401)
            tag_lbl = "PROBE" if THRESHOLD_PROBE_MODE else "PATIENT"
            log(f"  {tag_lbl} post-chunk healthcheck on {probe_egress_ip}: HTTP {post_code} → "
                f"{'BANNED' if post_banned else 'still reachable'}")
            if THRESHOLD_PROBE_MODE:
                ctx.threshold_probe_results.append({
                    "chunk_index": i + 1,
                    "rate": rate_for_chunk,
                    "egress_ip": probe_egress_ip,
                    "pre_chunk_code": pre_code,
                    "post_chunk_code": post_code,
                    "matches": matches,
                    "rc": rc,
                    "banned": post_banned,
                })

        # PATIENT: if the post-check showed a ban, sleep the cooldown
        # before rotating — mirrors Mac runbook's "wait 30 min, rotate
        # egress, resume" pattern. The hypothesis is that immediate
        # rotation accelerates cross-IP reputation tracking.
        if patient_effective and post_banned and i < len(chunks) - 1:
            log(f"  PATIENT: banned IP detected — sleeping {PATIENT_BAN_COOLDOWN_S}s "
                f"({PATIENT_BAN_COOLDOWN_S//60} min) before rotation")
            ctx.ban_events.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "patient_mode_cooldown",
                "chunk": f"{sev}:{tag or '<all>'}",
                "egress_ip": probe_egress_ip,
                "cooldown_s": PATIENT_BAN_COOLDOWN_S,
            })
            time.sleep(PATIENT_BAN_COOLDOWN_S)

        # Layer 3 + 4: planned rotation between chunks
        if i < len(chunks) - 1:
            rotate_vpn(ctx)
            # PATIENT: short delay regardless of ban state — mirrors
            # the 5-second WAF_DELAY between phases in deep-probe-v2.sh
            if patient_effective:
                log(f"  PATIENT: {PATIENT_INTER_CHUNK_DELAY_S}s inter-chunk delay")
                time.sleep(PATIENT_INTER_CHUNK_DELAY_S)

        # Ceiling check
        if ctx.total_requests >= MAX_REQUESTS_TOTAL:
            log(f"hit hard request ceiling ({MAX_REQUESTS_TOTAL}) — stopping nuclei")
            break

    # PROBE: print the final threshold table
    if THRESHOLD_PROBE_MODE and ctx.threshold_probe_results:
        log("")
        log("═══ THRESHOLD PROBE RESULTS ═══")
        log(f"{'Chunk':<6}{'Rate':<8}{'Egress IP':<20}{'Pre':<6}{'Post':<6}{'Banned?':<10}")
        for r in ctx.threshold_probe_results:
            log(f"{r['chunk_index']:<6}{r['rate']:<8}{(r['egress_ip'] or '?'):<20}"
                f"{r['pre_chunk_code']:<6}{r['post_chunk_code'] or '?':<6}"
                f"{'YES' if r['banned'] else 'no':<10}")
        # Identify the threshold band
        clean_rates = [r['rate'] for r in ctx.threshold_probe_results if not r['banned']]
        banned_rates = [r['rate'] for r in ctx.threshold_probe_results if r['banned']]
        if clean_rates and banned_rates:
            log(f"  → highest clean rate: {max(clean_rates)} req/s")
            log(f"  → lowest banned rate: {min(banned_rates)} req/s")
            log(f"  → THRESHOLD is between {max(clean_rates)} and {min(banned_rates)} req/s")
        elif clean_rates:
            log(f"  → all rates clean (no bans across {clean_rates}) — rate is NOT the trigger")
        elif banned_rates:
            log(f"  → all rates banned ({banned_rates}) — even lowest tested rate trips WAF; not pure rate")


# ─── nikto (single pass) ────────────────────────────────────────────────
def run_nikto(ctx: ScanContext) -> None:
    """Single nikto pass on a fresh IP. nikto doesn't chunk well; if
    it gets banned mid-run, we accept the loss for this pass.
    """
    log("→ nikto (single pass)")

    if not ensure_healthy_egress(ctx, max_rotations=2):
        log("  ✗ target unreachable — skipping nikto entirely")
        return

    ctx.tools_run.append("nikto")
    ua = pick_ua()
    # Bug D fix (2026-06-07 PM, ADR-001 Step 3):
    # nikto uses Perl Getopt::Long with prefix matching. "-h" is ambiguous —
    # it prefix-matches BOTH "-host" (target host, requires value) AND
    # "-Help" (extended help, no value). nikto's behavior on ambiguous
    # prefix is to print the short usage banner and exit immediately.
    #
    # Symptom (silently present from before 2026-05-30 through testfire
    # run 59ad6a13 on 2026-06-07): nikto artifact is 1256 bytes of help
    # text instead of real scan output. status='complete'. findings_added
    # from nikto = 0. Bug invisible because the runner closes out cleanly.
    # The 14 prior CMI/test.ccc medium runs all carry the same
    # 1256-byte help-text artifact — verify post-fix that the testfire
    # re-fire produces real scan output.
    #
    # Fix: use the full "-host" flag, which is unambiguous.
    cmd = [
        "nikto",
        "-host", f"https://{ctx.hostname}",
        "-Pause", str(NIKTO_PAUSE_S),
        "-nointeractive", "-ask", "no",
        "-Tuning", "x6",
        "-useragent", ua,
        "-timeout", "15",
        "-maxtime", str(NIKTO_WALL_S - 30),
        "-Format", "txt",
    ]
    # input_str="" — pre-empt any future prompt from hanging the runner
    # (defensive; not the cause of the current arg-rejection bug, but cheap
    # insurance for the "tool waits on stdin" class of silent failures).
    rc, stdout, stderr = run_cmd(cmd, timeout=NIKTO_WALL_S, input_str="")
    ctx.artifacts.append(("nikto", "text", stdout))
    # ADR-001 Step 4 — Bug D detector. If nikto bailed to its help banner
    # (which is exactly what happened across 14+ prior medium runs because
    # of the '-h' ambiguity), mark degraded. Otherwise: stdout is real
    # scan output. The detector is narrow — only flags the literal help
    # banner phrases, never a legitimate empty/short scan output.
    is_degraded, reason = nikto_is_degraded(stdout, rc)
    if is_degraded:
        mark_tool_degraded(ctx, "nikto", reason)
    else:
        mark_tool_ok(ctx, "nikto")
    # UNCONDITIONAL stderr log. nikto's short-help bail is often rc=0
    # (the gated `if rc not in (0,124)` block below swallowed it on the
    # 2026-06-07 PM testfire re-fire after the -host fix). Perl
    # Getopt::Long prints "Unknown option: X" or "Option X is ambiguous"
    # on stderr just before the usage banner — that line names the
    # exact rejected flag, which is the only thing we need to identify
    # the next bug in the cmd. Logging unconditionally closes this
    # blind spot for every future nikto failure too.
    if stderr.strip():
        log(f"  nikto stderr ({len(stderr)}B): {stderr.strip()[:400]}")
    if rc not in (0, 124):
        log(f"  nikto rc={rc}")

    matches = 0
    for line in stdout.splitlines():
        line = line.rstrip()
        if not line.startswith("+ "):
            continue
        body = line[2:].strip()
        if any(prefix in body for prefix in (
            "Target IP:", "Target Hostname:", "Target Port:",
            "Start Time:", "End Time:", "Server:", "items checked:",
            "Site link", "Allowed HTTP", "SSL Info:",
            "Subject:", "Ciphers:", "Issuer:",
        )):
            continue
        matches += 1
        ctx.total_requests += 1

        body_lc = body.lower()
        if any(k in body_lc for k in ("exposed", "leak", "dangerous",
                                       "vulnerable", "uploadable", "writable")):
            severity = "MODERATE"
        elif any(k in body_lc for k in ("found", "directory", "listing")):
            severity = "LOW"
        else:
            severity = "INFO"

        slug = re.sub(r"[^a-z0-9]+", "-", body_lc)[:60].strip("-") or f"finding-{matches}"
        ctx.findings.append(MediumFinding(
            check_name=f"nikto-{slug}",
            title=f"nikto: {body[:120]}",
            severity=severity,
            category="dast",
            description=(
                f"Nikto reported on {ctx.hostname}: {body}. Review the raw "
                f"nikto output artifact for full context including OSVDB ref "
                f"and the exact URL probed."
            ),
            tags=["nikto"],
            raw_excerpt=body[:1500],
        ))

    log(f"  nikto: {matches} reported item(s)")


# ─── ffuf (chunked) ─────────────────────────────────────────────────────
def run_ffuf_chunk(ctx: ScanContext, words: list[str]) -> int:
    """Run one ffuf chunk against a wordlist subset. Returns count of
    findings emitted (any -mc-matched status: 200/204/301/302/307/401/403).

    Pre-2026-06-07 PM: this function hard-filtered to 200/204 only, silently
    discarding 30x/401/403. The 2026-06-07 demo.testfire.net validation
    (scan_run 59ad6a13) surfaced the bug — ffuf discovered /admin, /swagger,
    /static, /images (all 302→/login.jsp on a Java/Tomcat target), the
    parser correctly populated `results`, but the 200/204 filter dropped
    all 4 findings and findings_added=0. End-to-end runner proof failed
    on a real positive-control target.

    Un-filtered now — ffuf's `-mc` allowlist is the trusted source of
    truth, the Python side trusts it. All -mc-matched statuses produce
    findings, titles vary per status class so the human triage signal
    isn't homogenized.

    NOT YET FLOOD-SAFE FOR WAF-FRONTED ASSETS. The un-filter is correct
    on no-WAF targets like testfire (4 hits → 4 findings). On Cloudflare/
    FortiGate-fronted assets (cc/cmi/unimac/ccc) where 403/302 is the
    norm, this could emit dozens of low-signal findings per scan and
    re-flood the dashboard we just spent today de-phantoming. Land the
    per-scan cap + WAF-rollup logic (see Tasks #3 + #4) BEFORE medium
    runs against any owned WAF-fronted asset.

    Also pending — severity tuning (Task #5): blanket-INFO buries
    high-signal hits (401 on /admin, 200 on /.env or /.git) in the
    noise floor. Sensitive-path detection + status-aware severity
    should be the next layer once the flood guard is in.
    """
    ctx.tools_run.append(f"ffuf[{len(words)}w]")
    ua = pick_ua()

    wl_path = f"/tmp/commandsentry-ffuf-wl-{random.randint(1000,9999)}.txt"
    Path(wl_path).write_text("\n".join(words) + "\n")

    out_path = f"/tmp/commandsentry-ffuf-out-{random.randint(1000,9999)}.json"
    cmd = [
        "ffuf",
        "-u", f"https://{ctx.hostname}/FUZZ",
        "-w", wl_path,
        "-rate", str(FFUF_RATE),
        "-p", FFUF_DELAY_RANGE,
        "-H", f"User-Agent: {ua}",
        "-mc", "200,204,301,302,307,401,403",
        "-fc", "404,500,502,503",
        "-t", "5", "-timeout", "15",
        "-of", "json", "-o", out_path, "-s",
    ]
    rc, stdout, stderr = run_cmd(cmd, timeout=FFUF_CHUNK_WALL_S)
    if rc not in (0, 124):
        log(f"  ffuf chunk rc={rc}: {stderr.strip()[:200]}")

    try:
        out_blob = Path(out_path).read_text()
    except Exception as e:
        log(f"  ffuf output unreadable: {e}")
        # ADR-001 Step 4 — output file missing. Across multiple chunks
        # this would flap; the LAST chunk's status wins (the closed scan
        # records the worst-recently-seen state). Sufficient signal for now.
        mark_tool_degraded(ctx, "ffuf", "output_unreadable")
        return 0

    ctx.artifacts.append(("ffuf", "json", out_blob))

    try:
        data = json.loads(out_blob)
    except Exception as e:
        log(f"  ffuf output parse failed: {e}")
        mark_tool_degraded(ctx, "ffuf", "parse_failed")
        return 0

    # ADR-001 Step 4 — structure check. results==[] is healthy ("no
    # matched paths in this chunk"); only the absence of the key entirely
    # signals a real failure.
    is_degraded, reason = ffuf_is_degraded(out_blob, data)
    if is_degraded:
        mark_tool_degraded(ctx, "ffuf", reason)
    else:
        mark_tool_ok(ctx, "ffuf")

    results = data.get("results", [])
    ctx.total_requests += len(words)

    interesting = 0
    for r in results:
        status = r.get("status", 0)
        url = r.get("url", "")
        word = r.get("input", {}).get("FUZZ", "")
        redirect_to = r.get("redirectlocation", "") or ""
        ctx.response_codes[str(status)] += 1

        # Title + description per status class. Trust ffuf -mc as the
        # promotion gate; don't second-guess on the Python side.
        if status in (200, 204):
            title_kind = "Accessible path"
            desc_action = (
                "Review whether this endpoint is intentionally public "
                "or should be moved behind auth."
            )
        elif status in (301, 302, 307):
            title_kind = (f"Path exists (redirect → {redirect_to})"
                          if redirect_to else "Path exists (redirect)")
            desc_action = (
                f"Path /{word} responded with redirect "
                f"({redirect_to or 'unspecified location'}) — endpoint is "
                "reachable. Review whether the redirect chain leaks "
                "information about internal structure or auth flow."
            )
        elif status == 401:
            title_kind = "Auth-required endpoint"
            desc_action = (
                "Endpoint exists and requires authentication. Inventory "
                "which path is gated by which mechanism — important "
                "context for AuthN/AuthZ posture review."
            )
        elif status == 403:
            title_kind = "Forbidden endpoint"
            desc_action = (
                "Endpoint exists but is denied. Often signals "
                "misconfigured access controls or a real endpoint locked "
                "at the WAF/server layer rather than removed."
            )
        else:
            title_kind = "Path responded"
            desc_action = "Review the response."

        raw = f"GET {url} -> HTTP {status}"
        if redirect_to:
            raw += f" (Location: {redirect_to})"

        interesting += 1
        ctx.findings.append(MediumFinding(
            check_name=f"ffuf-found-{word}",
            title=f"{title_kind}: /{word} (HTTP {status})",
            severity="INFO",
            category="info_disclosure",
            description=(
                f"Directory fuzzing discovered /{word} on {ctx.hostname} "
                f"returning HTTP {status}. {desc_action}"
            ),
            tags=["ffuf", "directory", "discovery", f"status_{status}"],
            raw_excerpt=raw,
        ))

    return interesting


def run_ffuf_chunked(ctx: ScanContext) -> None:
    """Run ffuf in chunks of FFUF_WORDS_PER_CHUNK words each, rotating
    VPN between chunks.
    """
    log("→ ffuf (chunked with mid-scan rotation)")

    # Slice the wordlist
    chunks = [FFUF_WORDS[i:i+FFUF_WORDS_PER_CHUNK]
              for i in range(0, len(FFUF_WORDS), FFUF_WORDS_PER_CHUNK)]

    for i, words in enumerate(chunks):
        log(f"chunk {i+1}/{len(chunks)}: {len(words)} words")
        if not ensure_healthy_egress(ctx, max_rotations=2):
            log("  ✗ target unreachable — skipping ffuf chunk")
            continue

        interesting = run_ffuf_chunk(ctx, words)
        log(f"  chunk {i+1} done: {interesting} 200/204 finding(s)")

        if i < len(chunks) - 1:
            rotate_vpn(ctx)

        if ctx.total_requests >= MAX_REQUESTS_TOTAL:
            log(f"hit hard request ceiling — stopping ffuf")
            break


# ─── SQL helpers (DUPED from run_light — TODO: refactor) ───────────────
#
# 2026-06-07 ADR-001: writes validation_status + scanner_version +
# validated_at on every emission. UPSERT heal logic is upgrade-only —
# once a finding is 'validated' it stays validated; an 'unvalidated'
# re-emission cannot demote it. scanner_version always records the
# latest emission's SHA (informational). validated_at is set the FIRST
# time validation_status transitions to 'validated' and stays put.
#
UPSERT_FINDING_SQL = """
INSERT INTO public.findings (
    finding_id, asset_id, title, severity, category, description,
    cwe, "references", current_status, first_detected_at,
    last_observed_at, source, tags,
    validation_status, scanner_version, validated_at
)
VALUES (%(finding_id)s, %(asset_id)s, %(title)s, %(severity)s, %(category)s,
        %(description)s, %(cwe)s, %(references)s, 'detected',
        now(), now(), %(source)s, %(tags)s,
        %(validation_status)s, %(scanner_version)s,
        CASE WHEN %(validation_status)s = 'validated' THEN now() ELSE NULL END)
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

CLOSE_SCAN_RUN_SQL = """
UPDATE public.scan_run
SET status            = 'complete',
    completed_at      = now(),
    duration_seconds  = EXTRACT(EPOCH FROM (now() - started_at))::int,
    tools_run         = %(tools_run)s,
    findings_added    = %(findings_added)s,
    findings_updated  = %(findings_updated)s,
    -- ADR-001 Step 4 — per-tool completeness map.
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
    inserted = 0
    updated = 0
    # ADR-001: stamp every emission with the runner's SHA + validation
    # status. validation_status defaults to 'unvalidated' until the SHA
    # is in VALIDATED_VERSIONS[ctx.intensity] (empty until ADR-001
    # Step 5 promotes the first proving SHA).
    scanner_version = get_scanner_version()
    validation_status = derive_validation_status(ctx.intensity, scanner_version)
    log(f"  ADR-001: scanner_version={scanner_version[:12]} "
        f"validation_status={validation_status}")
    with conn.cursor() as cur:
        for f in ctx.findings:
            finding_id = f"{ctx.asset_id}:medium:{f.check_name}"
            params = {
                "finding_id": finding_id,
                "asset_id": ctx.asset_id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "cwe": f.cwe,
                "references": f.references,
                "source": f"commandsentry_{ctx.intensity}",
                "tags": f.tags,
                "validation_status": validation_status,
                "scanner_version": scanner_version,
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
                "scan_run_id": ctx.scan_run_id,
                "tool_name": tool_name,
                "output_format": output_format,
                "size_bytes": len(content_str.encode("utf-8")),
                "content_jsonb": Json(content_obj),
            })
    return inserted, updated


def write_scan_metadata_artifact(conn, ctx: ScanContext, Json,
                                   start_egress: str | None,
                                   end_egress: str | None) -> None:
    meta = {
        "scan_run_id": ctx.scan_run_id,
        "asset_id": ctx.asset_id,
        "hostname": ctx.hostname,
        "tools_run": ctx.tools_run,
        "waf_detected": ctx.waf_detected,
        "waf_kind": ctx.waf_kind,
        "tech_stack": sorted(ctx.tech_stack),
        "target_class": "fortigate" if is_fortigate_target(ctx) else "standard",
        "patient_mode_effective": is_effective_patient_mode(ctx),
        "softened_rate_effective": needs_softened_rate(ctx),
        "total_requests": ctx.total_requests,
        "response_codes": dict(ctx.response_codes),
        "rotation_count": ctx.rotation_count,
        "egress_ips_seen": ctx.egress_ips_seen,
        "ban_events": ctx.ban_events,
        "start_egress": start_egress,
        "end_egress": end_egress,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        # Threshold probe results (empty list if not in probe mode).
        "threshold_probe_mode": THRESHOLD_PROBE_MODE,
        "threshold_probe_results": ctx.threshold_probe_results,
        # ADR-001 Step 4 — per-tool completeness map (Bug D + class).
        "tool_status": ctx.tool_status,
    }
    with conn.cursor() as cur:
        cur.execute(INSERT_ARTIFACT_SQL, {
            "scan_run_id": ctx.scan_run_id,
            "tool_name": "scan_metadata",
            "output_format": "json",
            "size_bytes": len(json.dumps(meta).encode("utf-8")),
            "content_jsonb": Json(meta),
        })


def close_out(conn, ctx: ScanContext, inserted: int, updated: int, Json) -> None:
    with conn.cursor() as cur:
        params = {
            "tools_run": ctx.tools_run,
            "findings_added": inserted,
            "findings_updated": updated,
            "findings_count": inserted + updated,
            "scan_run_id": ctx.scan_run_id,
            "queue_id": ctx.queue_id,
            # ADR-001 Step 4 — wrap with Json so psycopg writes proper jsonb.
            "tool_status": Json(ctx.tool_status or {}),
        }
        cur.execute(CLOSE_SCAN_RUN_SQL, params)
        cur.execute(CLOSE_SCAN_QUEUE_SQL, params)


def fail_out(conn, ctx: ScanContext, error: str) -> None:
    with conn.cursor() as cur:
        params = {
            "error": error,
            "scan_run_id": ctx.scan_run_id,
            "queue_id": ctx.queue_id,
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
        log(f"WARNING: descriptor intensity is '{descriptor.get('intensity')}', not 'medium'")

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

    start_egress = capture_egress_ip()
    if start_egress:
        ctx.egress_ips_seen.append(start_egress)
        log(f"pre-scan egress IP: {start_egress}")

    # DB connection deferred until write phase. Scan #35 (2026-05-30)
    # showed Supabase closes idle connections after 7+ min, and we
    # used to open at scan-start which idled the whole Medium tier.
    # Now we open right before the writes.
    conn = None

    end_egress = None
    try:
        # ─── Phase 1: WAF detection ─────────────────────────────────
        log("→ detect_waf")
        detect_waf(ctx)
        log("→ detect_tech_stack")
        detect_tech_stack(ctx)

        # ─── Phase 2: nuclei (chunked + rotation) ──────────────────
        if ctx.total_requests < MAX_REQUESTS_TOTAL:
            run_nuclei_chunked(ctx)
        else:
            log("skipping nuclei — total request ceiling already hit")

        if THRESHOLD_PROBE_MODE:
            log("THRESHOLD PROBE MODE — skipping nikto + ffuf (isolating nuclei rate variable)")
        else:
            # Rotate before nikto (single-pass tool gets a fresh IP)
            rotate_vpn(ctx)

            # ─── Phase 3: nikto (single pass) ──────────────────────────
            if ctx.total_requests < MAX_REQUESTS_TOTAL:
                run_nikto(ctx)
            else:
                log("skipping nikto — total request ceiling already hit")

            # Rotate before ffuf
            rotate_vpn(ctx)

            # ─── Phase 4: ffuf (chunked + rotation) ────────────────────
            if ctx.total_requests < MAX_REQUESTS_TOTAL:
                run_ffuf_chunked(ctx)
            else:
                log("skipping ffuf — total request ceiling already hit")

        # ─── Phase 5: capture end egress + write ───────────────────
        end_egress = capture_egress_ip()
        if end_egress and end_egress not in ctx.egress_ips_seen:
            ctx.egress_ips_seen.append(end_egress)
            log(f"final egress IP: {end_egress}")

        log(f"checks complete; {len(ctx.findings)} finding(s), "
            f"{len(ctx.artifacts)} artifact(s), "
            f"{ctx.total_requests} request(s), "
            f"{ctx.rotation_count} rotation(s), "
            f"{len(ctx.egress_ips_seen)} distinct egress IP(s), "
            f"{len(ctx.ban_events)} ban event(s)")

        # DB write phase — lazy-open + retry-once-on-failure.
        # Layer 1: lazy connection (eliminates the 7-min idle problem)
        # Layer 2: retry once with fresh conn if write fails mid-phase
        #          (handles transient network blips, Supabase reboots,
        #          mid-write connection drops)
        # Howie 2026-05-30: "I love the lazy approach, but I think
        # there's a need for both" — belt and suspenders.
        inserted = 0
        updated = 0
        MAX_WRITE_ATTEMPTS = 2
        for attempt in range(1, MAX_WRITE_ATTEMPTS + 1):
            try:
                log(f"opening DB connection (attempt {attempt}/{MAX_WRITE_ATTEMPTS})")
                conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
                inserted, updated = write_findings_and_artifacts(conn, ctx, Json)
                write_scan_metadata_artifact(conn, ctx, Json, start_egress, end_egress)
                close_out(conn, ctx, inserted, updated, Json)
                conn.commit()
                log(f"upserted findings: {inserted} new, {updated} existing")
                log("scan_run + scan_queue closed out successfully")
                return 0
            except (psycopg.OperationalError, psycopg.InterfaceError) as db_err:
                log(f"DB write attempt {attempt} failed: {db_err!r}")
                try:
                    if conn:
                        conn.close()
                except Exception:
                    pass
                conn = None
                if attempt == MAX_WRITE_ATTEMPTS:
                    log("write retries exhausted — re-raising for fail_out")
                    raise
                # Backoff before retry: 3s, 6s
                backoff = 3 * attempt
                log(f"retrying after {backoff}s...")
                time.sleep(backoff)

    except Exception as e:
        log(f"FATAL: {e!r}")
        # Try to mark the run failed even if the FATAL happened mid-scan.
        # Open a fresh DB connection if we don't have one yet.
        if conn is None:
            try:
                conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
            except Exception as e2:
                log(f"could not open DB to mark scan failed: {e2!r}")
                return 1
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
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 4a Medium tier scanner with mid-scan VPN rotation.",
    )
    parser.add_argument("descriptor",
                        help="Path to JSON descriptor from poll_queue.py")
    parser.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN"),
                        help="Postgres DSN (or set SUPABASE_DSN)")
    args = parser.parse_args()

    if not args.dsn:
        print("error: --dsn or SUPABASE_DSN required", file=sys.stderr)
        sys.exit(2)

    sys.exit(run(args.descriptor, args.dsn))


if __name__ == "__main__":
    main()
