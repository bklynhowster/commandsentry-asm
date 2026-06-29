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

# Scanner degradation primitives — fail-closed on "we didn't actually scan."
# See SPEC_SCANNER_DEGRADATION_HARDENING.md. 2026-06-12.
from degradation import (
    DegradedRunError,
    MAX_BAN_EVENTS,
    MAX_HEALTHCHECK_FAILURES,
    POST_ROTATE_SETTLE_ATTEMPTS,
    POST_ROTATE_SETTLE_DELAY_S,
    PRE_ROTATE_RETRY_ATTEMPTS,
    PRE_ROTATE_RETRY_DELAY_S,
    VALIDATION_TARGETS,
    assert_tool_status_invariant,
    assert_validate_mode_target_allowed,
    cap_aware_append_ban,
    cap_aware_append_healthcheck_failure,
    delta_close_eligible,
    egress_failure_reason,
    healthcheck_with_retry,
    is_tool_output_degraded,
)


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


# ─── ADR-001 — Validated-SHA key (convergent edition) ───────────────────
#
# Allowlist of (intensity, scanner_version) pairs whose emissions get
# stamped validation_status='validated'. Stored in the Postgres table
# public.scanner_validations, NOT here in the runner code.
#
# WHY THE TABLE INSTEAD OF AN IN-CODE DICT:
# Earlier draft (commit eebc45a, reverted before push 2026-06-08)
# tried VALIDATED_VERSIONS as an in-code set. That never converges:
# the commit that ADDS a SHA to the in-code list is itself a new commit
# with a new SHA. When that new commit runs, GITHUB_SHA = its_own_sha,
# which is NOT in the allowlist (only the old proven SHA is). So every
# future run writes 'unvalidated' — backfill stamps one run, then
# nothing validates again. Silent no-op.
#
# Moving the allowlist out of hashed code breaks the self-reference:
# validating a SHA is an INSERT, not a commit. HEAD doesn't move. The
# running SHA can validate itself. Real code changes still produce new
# SHAs that run 'unvalidated' until proven AND explicitly INSERTed —
# auto-invalidation is preserved.
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
    exists for (intensity, sha) AND that row is NOT retracted; else
    'unvalidated'.

    NEVER returns 'legacy' — that's reserved for rows that existed
    before migration 20260607a backfilled them.

    Trust-layer fix Part 2 (2026-06-13): added `retracted_at IS NULL`
    filter. Before this column existed (migration 20260613a), retraction
    was a notes-edit; this query would still return 'validated' for
    findings stamped with a retracted SHA. After the migration +
    this filter, the invariant is enforced AT WRITE TIME — no validated
    row can be stamped under a retracted SHA, and any subsequent
    re-emit demotes via UPSERT_FINDING_SQL's derive-on-write semantics.

    Fails loud if the table is missing (migration 20260608a not
    applied). Better to error than silently stamp everything
    'unvalidated' on a misconfigured deploy."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM public.scanner_validations "
            "WHERE intensity = %s "
            "  AND scanner_version = %s "
            "  AND retracted_at IS NULL",
            (intensity, sha),
        )
        return "validated" if cur.fetchone() else "unvalidated"

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


# ─── S3 Part 2 (2026-06-18) — ffuf path-sensitivity classification ────────
#
# Curated, anchored — earn each entry, same discipline as #36 cross-source
# dedup. Never substring-broad: a wordlist hit on /env (no dot) is generic
# (already in FFUF_WORDS); only the literal `.env` (dotfile) is a secret.
# Adding an entry requires evidence that the path-class semantics are
# unambiguous — when in doubt, leave it out (it stays INFO under the
# generic case, which is the safe under-classify direction).
#
# Two tiers consumed by classify_ffuf_severity():
#   SECRET_PATHS  — exposure of these = serious (secrets / config /
#                   repo-private content reachable to anyone). 200 → HIGH.
#   ADMIN_PATHS   — privileged surface reachable to anyone. 200 → MODERATE.
# A 401/403 on EITHER tier downgrades to LOW (the path exists but is
# gated — inventory value, not active exposure). Redirects stay INFO.
#
# Matched case-insensitively against the fuzzed `word` (the wordlist entry,
# typically a single path component, occasionally nested like `.git/config`
# or `manager/html`). Anchored: matches the full word OR the trailing
# path component after a slash — never a substring inside another word.
# Examples (positive):    .env  ·  path/.env  ·  admin  ·  foo/admin
# Examples (negative):    myenv ·  .envrc ·  administrative ·  admin-panel

SECRET_PATHS_PATTERNS = (
    r"\.env",
    r"\.git",
    r"\.svn",
    r"\.hg",
    r"\.sql",
    r"\.bak",
    r"\.backup",
    r"dump\.sql",
    r"\.htpasswd",
    r"wp-config\.php",
    r"config\.php",
    r"id_rsa",
    r"\.aws/credentials",
    r"\.npmrc",
    r"\.pem",
    r"web\.config",
    r"\.DS_Store",
    r"backup\.zip",
    r"database\.yml",
    r"\.dockercfg",
)

ADMIN_PATHS_PATTERNS = (
    r"admin",
    r"administrator",
    r"manager/html",
    r"phpmyadmin",
    r"console",
    r"wp-admin",
    # .git/config is the specific config file — distinct from .git directory
    # (in SECRET above). On a host that exposes the whole .git, the SECRET
    # entry catches the directory; on a host that only exposes /.git/config
    # via a more narrow probe, this entry catches the file.
    r"\.git/config",
    r"actuator",
    r"swagger",
    r"api-docs",
)

# Build the anchored matchers. `^(?:.*/)?<pat>/?$` anchors to either the
# whole word OR the trailing path component after a slash. The optional
# trailing slash tolerates ffuf words with directory-style suffixes.
SECRET_PATH_RE = re.compile(
    r"^(?:.*/)?(?:" + "|".join(SECRET_PATHS_PATTERNS) + r")/?$",
    re.IGNORECASE,
)
ADMIN_PATH_RE = re.compile(
    r"^(?:.*/)?(?:" + "|".join(ADMIN_PATHS_PATTERNS) + r")/?$",
    re.IGNORECASE,
)


def classify_ffuf_severity(word: str, url: str, status: int) -> str:
    """S3 Part 2 (2026-06-18) — assign severity by (path-sensitivity × status).
    Replaces the blanket `severity='INFO'` at the ffuf per-path emit site,
    so a real hit on /.env (HIGH) or /admin (MODERATE) surfaces above the
    INFO noise floor.

    Matrix:
      path class       200/204         401/403          301/302/307
      SECRET_PATH      HIGH            LOW              INFO
      ADMIN_PATH       MODERATE        LOW              INFO
      generic          INFO            INFO             INFO

    Other statuses default to INFO. Anchored regex match on `word` —
    substring matches inside other words (e.g. `myenv` matching `.env`,
    `administrative` matching `admin`) are excluded. Empty word → INFO.

    SECRET wins on overlap: if a word somehow matches both tiers (rare
    today; reserved for edge cases like a new entry being mis-classified),
    the higher classification applies.

    The `url` parameter is currently unused — kept in the signature so a
    future enrichment that checks the response URL (e.g. for path traversal
    in the redirect) can land without a call-site change.

    Pure function — testable without subprocess. The matrix lives entirely
    in the call site of the helper; promotion logic isn't smeared across
    multiple decision points.
    """
    if not word:
        return "INFO"
    # Redirects: stay INFO regardless of path class. The catch-all-redirect
    # case (#33) is suppressed before reaching here; a non-catch-all 30x is
    # low signal (target exists, intentionally redirects elsewhere — not a
    # direct exposure or privileged-surface hit).
    if status in (301, 302, 307):
        return "INFO"

    is_secret = bool(SECRET_PATH_RE.match(word))
    is_admin = bool(ADMIN_PATH_RE.match(word))

    if status in (200, 204):
        if is_secret:
            return "HIGH"
        if is_admin:
            return "MODERATE"
        return "INFO"

    if status in (401, 403):
        if is_secret or is_admin:
            return "LOW"
        return "INFO"

    # Any other status (404 shouldn't be in ffuf -mc, but defensive; 500s
    # could appear if ffuf -mc is widened later) → INFO.
    return "INFO"


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
    # Scanner-degradation forensics (SPEC_SCANNER_DEGRADATION_HARDENING.md
    # 2026-06-12 — Bug C). Populated by run_medium.py and written to
    # scan_run.{egress_ip, vpn_config_used, rotation_log} at close-out
    # OR degraded_out. Survives forensics queries instead of forcing
    # every "why didn't this find X" to re-read the GH Actions log.
    egress_ip_initial: str | None = None     # first egress observed post-bringup
    vpn_config_used: str | None = None       # initial WireGuard region/config
    healthcheck_failures: list[dict] = field(default_factory=list)
    rotation_storm: bool = False             # tripped when ban_events or
                                             # healthcheck_failures hits 500 cap
    # Batch 2 step c (SPEC_SCANNER_DEGRADATION_HARDENING.md Part 3):
    # set True when SKIP_VPN env was passed (validate-mode run, no
    # Mullvad tunnel). rotate_vpn short-circuits when True (no tunnel
    # to rotate). ensure_healthy_egress overrides max_rotations to 0
    # so any health failure aborts immediately — the validate run is
    # PRISTINE-or-NOTHING, never "rotated to find another path."
    validate_mode: bool = False
    # Live scan progress (note 103 2026-06-24). Set in run() once we have
    # the DSN. flush_progress() opens its OWN short-lived autocommit conn
    # per call (the main scan conn is deferred until close_out per the
    # 2026-05-30 idle-close lesson, and we don't want progress writes to
    # interact with the main scan transaction). dsn=None → flush_progress
    # is a no-op (validate-mode runs + unit tests).
    dsn: str | None = None
    # planned_steps — expected phase list, written ONCE after Phase 1 so
    # build_chunk_plan can produce the actual nuclei chunk names. Honest
    # about auth_gated skips (ffuf/nikto/non-tech nuclei excluded when
    # auth_gated). None = not yet computed; portal renders without a
    # total ("Scanning…") until it lands.
    planned_steps: list[str] | None = None
    # #33 (2026-06-16) — ffuf catch-all redirect calibration. Set at the
    # start of run_ffuf_chunked by detect_ffuf_catchall_redirect(): if the
    # target redirects a known-random path with 301/302/307, the redirect
    # Location is the catch-all baseline. Per-path ffuf findings whose
    # redirect_to == this baseline get suppressed at emit time (they all
    # mean the same fact: "this host redirects everything here") and
    # collapsed into one summary INFO finding. EXACT-equality match —
    # distinct redirects and 200/204/401/403 matches still emit
    # individually as before. None = no catch-all detected → suppression
    # is a no-op, per-path emission unchanged.
    ffuf_catchall_redirect: str | None = None
    # Count of per-path ffuf findings suppressed because they matched the
    # catch-all baseline. Drives the collapsed summary finding at end of
    # run_ffuf_chunked.
    ffuf_catchall_count: int = 0
    # S3 Part 1 (2026-06-18) — ffuf catch-all STATUS calibration. Generalizes
    # #33's redirect-only catch-all to also capture a blanket non-discriminating
    # status (403 from a FortiGate-fronted asset, 401 from a uniformly
    # auth-gated host, 200 from a SPA / soft-404 host). detect_ffuf_catchall
    # probes 2 random paths; if BOTH return the same non-404 status, that
    # status is the catch-all baseline. Per-path ffuf findings matching the
    # baseline get suppressed at emit time (one fact, not N phantoms) and
    # collapsed into ONE summary finding at end of run_ffuf_chunked.
    # EXACT-status-equality only — distinct statuses still emit individually
    # (a real signal that survives a blanket-deny host). None = no catch-all
    # status detected → suppression is a no-op, per-path emission unchanged.
    ffuf_catchall_status: int | None = None
    # Count of per-path ffuf findings suppressed because their status matched
    # ffuf_catchall_status. Drives the collapsed status summary finding at
    # end of run_ffuf_chunked.
    ffuf_catchall_status_count: int = 0
    # #32 (2026-06-16) — set True the FIRST time any tool successfully
    # gets a real HTTP response from the target (wafw00f verdict
    # parsed / httpx tech-detect parsed / nuclei chunk completed with
    # rc=0). Used by ensure_healthy_egress as a prior-tool-success
    # short-circuit: if a later pre-chunk gate fails its retries +
    # rotations, and we already PROVED target reachability earlier in
    # this run, the gate bypasses to healthy instead of skipping the
    # chunk. Per advisor 2026-06-16: 'uses same-run ground truth.'
    # Downside: assumes reachability persisted — won't catch a real
    # mid-scan block; that's what the httpx-based probe re-test in
    # ensure_healthy_egress is for. Layered defense, not either-or.
    target_proven_reachable: bool = False
    # #24 Phase 2 (2026-06-15): read from asset_surface.auth_gated at
    # scan start. True if the asset is fronted by an identity provider
    # login (Entra / Okta / Auth0 / Cognito / B2C / etc) — derived by
    # import_asm_to_surface.py's compute_auth_gated() via title +
    # cert-SAN AND-gate. When True, skip nikto + ffuf entirely + skip
    # non-tech nuclei chunks (the unauth attack surface doesn't exist
    # — only the IdP login page does). Keep wafw00f + httpx +
    # nuclei[tech] (fingerprint the IdP infra cleanly). A skipped tool
    # is recorded via mark_tool_skipped — NOT degraded, NOT ok. Run
    # stays scan_quality='clean' (skipped is a third state). Fail-safe
    # default: False (run everything) when the asset_surface read fails
    # or no row exists.
    auth_gated: bool = False


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


# ─── Live scan progress (note 103, 2026-06-24) ─────────────────────────
#
# Three helpers + ctx fields make scan_run.tool_status / tools_run /
# updated_at observable mid-run. The portal polls scan_run every ~4s and
# renders a "N/M steps · current tool" bar that advances on REAL tool
# completion (no fake timer). close_out remains the authoritative final
# write — these flushes are additive and best-effort: any DB failure is
# logged and swallowed so the scan continues regardless.
#
# Architectural note: flush_progress opens its OWN short-lived autocommit
# connection per call from ctx.dsn. The main scan conn is deferred until
# close_out (per the 2026-05-30 Supabase idle-close lesson — scan #35
# discovered idle conns get dropped after 7 min and we used to open at
# scan-start which broke long scans). A separate per-call conn keeps
# progress writes orthogonal to the main scan transaction's lifecycle
# AND inherits the same best-effort discipline (connection-refused →
# log + continue, never raise).


def _open_progress_conn(ctx: "ScanContext"):
    """Open a short-lived autocommit conn for a single progress write.
    Returns the live conn or None on any failure (best-effort).

    Defensive on ctx.dsn — test fixtures may use minimal mock contexts
    that don't carry the live-progress fields. getattr keeps the
    best-effort hook from breaking those tests.
    """
    dsn = getattr(ctx, "dsn", None)
    if not dsn:
        return None
    try:
        psycopg, dict_row, _Json = _import_deps()
        return psycopg.connect(
            dsn, row_factory=dict_row, autocommit=True, connect_timeout=5
        )
    except Exception as e:  # pragma: no cover — connection-time failures
        log(f"  progress flush: connect failed (non-fatal): "
            f"{type(e).__name__}: {e}")
        return None


def flush_progress(ctx: "ScanContext") -> None:
    """Best-effort incremental progress flush — UPDATE scan_run with the
    current tool_status + tools_run + updated_at=now(). Called after each
    mark_tool_ok / mark_tool_skipped / mark_tool_degraded so the portal's
    ScanProgress poller sees per-step completion as it happens.

    GUARANTEES (per note 103 §Part 1):
      - Opens its OWN short-lived autocommit conn (does not interfere
        with the main scan transaction, which doesn't even exist yet
        during tool runs — deferred-conn pattern per 2026-05-30).
      - ALL failures swallowed (try/except, log, continue). A failed
        progress write MUST NOT fail the scan.
      - No-op if ctx.dsn is not set (validate-mode + unit tests).
      - Touches ONLY tool_status + tools_run + updated_at. Never status /
        completed_at / findings_added — close_out remains the
        authoritative final write of those columns.
      - scan_run_id cast `::uuid` (load-bearing per note 103 trap list;
        matches the #35 `aa7c98f` cast pattern).
    """
    if not getattr(ctx, "dsn", None):
        return
    conn = _open_progress_conn(ctx)
    if conn is None:
        return
    try:
        _psycopg, _dict_row, Json = _import_deps()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE public.scan_run "
                "SET tool_status = %s, "
                "    tools_run   = %s, "
                "    updated_at  = now() "
                "WHERE scan_run_id = %s::uuid",
                (
                    Json(ctx.tool_status or {}),
                    list(ctx.tools_run),
                    str(ctx.scan_run_id),
                ),
            )
    except Exception as e:
        log(f"  progress flush failed (non-fatal): "
            f"{type(e).__name__}: {e}")
    finally:
        try:
            conn.close()
        except Exception:  # pragma: no cover
            pass


def flush_planned_steps(ctx: "ScanContext") -> None:
    """Best-effort one-shot write of ctx.planned_steps to scan_run.
    Called once after Phase 1 (detect_waf + detect_tech_stack) when
    build_chunk_plan can produce the actual nuclei chunk names and
    auth_gated is known so ffuf/nikto inclusion is honest.

    Same best-effort discipline as flush_progress: own conn, swallow
    failures, no-op if dsn not set or planned_steps not computed.
    """
    if not getattr(ctx, "dsn", None) or getattr(ctx, "planned_steps", None) is None:
        return
    conn = _open_progress_conn(ctx)
    if conn is None:
        return
    try:
        _psycopg, _dict_row, Json = _import_deps()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE public.scan_run "
                "SET planned_steps = %s, updated_at = now() "
                "WHERE scan_run_id = %s::uuid",
                (Json(list(ctx.planned_steps)), str(ctx.scan_run_id)),
            )
    except Exception as e:
        log(f"  planned_steps flush failed (non-fatal): "
            f"{type(e).__name__}: {e}")
    finally:
        try:
            conn.close()
        except Exception:  # pragma: no cover
            pass


def build_planned_steps(ctx: "ScanContext") -> list[str]:
    """Compute the expected phase/tool list for a medium run, given the
    current ctx (tech_stack + auth_gated populated from Phase 1). Mirrors
    the actual run() dispatch order in scripts/scanner/run_medium.py so
    the portal denominator matches reality.

    auth_gated DROPS ffuf + nikto + non-tech nuclei chunks (those won't
    really attempt a scan — they get marked skipped at runtime). The
    spec called for "reflect the real plan, not a fixed 12."

    THRESHOLD_PROBE_MODE skips nikto + ffuf (the run() flow already
    short-circuits them under probe mode).

    Pure function — no side effects on ctx. Safe to call repeatedly or
    in tests.
    """
    steps: list[str] = ["wafw00f", "httpx[-td]"]
    if CRAWL_FIRST_MODE:
        steps.append("katana")

    # nuclei chunks — only the chunk names that'll actually attempt a scan.
    # build_chunk_plan returns (sev, tag, desc) tuples; chunk_name must
    # match the per-chunk format used in run_nuclei_chunked (L2005):
    #   f"nuclei[{sev}{':'+tag if tag else ''}]"
    nuclei_chunks = build_chunk_plan(ctx)
    for sev, tag, _desc in nuclei_chunks:
        # Mirror the auth_gated per-chunk skip (run_medium L2018):
        # auth_gated targets only run the medium:tech chunk; everything
        # else is intentionally skipped from the plan.
        if ctx.auth_gated and tag != "tech":
            continue
        chunk_name = f"nuclei[{sev}{':'+tag if tag else ''}]"
        steps.append(chunk_name)

    if THRESHOLD_PROBE_MODE:
        return steps

    # nikto — single tool; auth_gated skips it from the plan entirely.
    if not ctx.auth_gated:
        steps.append("nikto")

    # ffuf — chunked wordlist; auth_gated skips the whole tool from the
    # plan. Chunk names match the format in run_ffuf_chunked (L2421):
    #   f"ffuf[{len(words)}w]#{i+1}"
    # Slice EXACTLY the same way the runner does so the names don't
    # drift (the last chunk has fewer words than the rest).
    if not ctx.auth_gated:
        ffuf_chunks = [
            FFUF_WORDS[i:i + FFUF_WORDS_PER_CHUNK]
            for i in range(0, len(FFUF_WORDS), FFUF_WORDS_PER_CHUNK)
        ]
        for i, words in enumerate(ffuf_chunks):
            steps.append(f"ffuf[{len(words)}w]#{i+1}")

    return steps


def mark_tool_ok(ctx: ScanContext, tool_name: str) -> None:
    """Record that a tool produced real output."""
    ctx.tool_status[tool_name] = {"ok": True}
    # Live scan progress (note 103): best-effort flush so the portal's
    # ScanProgress poller sees this step complete. No-op if ctx.dsn unset.
    flush_progress(ctx)


# Cap on stderr captured into ctx.artifacts (per Howie A′ design 2026-06-15)
# 64KB is generous for tool-specific error output (nikto's longest
# observed stderr is ~250B; the cap mostly protects against a runaway
# tool that floods stderr with thousands of error lines). The GH-log
# tail (the "belt-and-suspenders" half) caps lower (4KB) — log lines
# stay readable. If a real failure ever exceeds 64KB, that's diagnostic
# in itself (rotation storm of errors → revisit the cap then).
MARK_DEGRADED_STDERR_ARTIFACT_CAP_BYTES = 64 * 1024  # 64KB
MARK_DEGRADED_STDERR_LOG_CAP_BYTES = 4 * 1024        # 4KB


def mark_tool_skipped(ctx: ScanContext, tool_name: str, reason: str) -> None:
    """Record that a tool was INTENTIONALLY SKIPPED (not run, not degraded).

    Third state alongside {"ok": True} and {"degraded": "<slug>"}:
        {"skipped": "<reason_slug>"}

    Examples of reasons:
        "auth_gated"  — target is an IdP login page, no unauth attack surface
        (future)      — other policy-based skip classes

    LOAD-BEARING distinction: a SKIPPED tool is NOT degraded. The scan
    correctly chose not to run it because it cannot produce useful output
    against this target class. Routing skipped to degraded would re-create
    the "degraded flag means tool worked within its budget" anti-pattern
    (see nikto_is_degraded docstring on the target_error_limit split).
    The 2026-06-15 [1] fix established three states for accurate
    forensics; this 2026-06-15 #24 fix extends that to the skip case.

    Set-equality invariant: callers MUST append to tools_run BEFORE
    calling this (same lockstep as mark_tool_degraded). assert_tool_
    status_invariant is value-blind on the set check, so "skipped"
    entries satisfy it as long as the key is present.

    scan_quality semantics: a run with only ok + skipped statuses stays
    scan_quality='clean'. degraded_out is only triggered by raise
    DegradedRunError, which mark_tool_skipped DOES NOT raise. Therefore
    findings from auth-gated runs (wafw00f + httpx + nuclei[tech])
    remain validatable, which is correct — those tools' output IS clean,
    we just chose not to run the others.

    NO stderr kwarg (unlike mark_tool_degraded) — skipped tools didn't
    execute, there's no stderr to capture.
    """
    ctx.tool_status[tool_name] = {"skipped": reason}
    # Live scan progress (note 103): best-effort flush.
    flush_progress(ctx)


def mark_tool_degraded(
    ctx: ScanContext,
    tool_name: str,
    reason: str,
    *,
    stderr: str | None = None,
) -> None:
    """Record that a tool failed in a recognized way. reason is a stable
    machine-readable slug (snake_case) — downstream reports group on it.

    2026-06-15 (Howie A′ design): optional `stderr=` kwarg captures the
    failed tool's stderr to two surfaces:
      1. ctx.artifacts as ('<tool>_stderr', 'text', stderr[:cap]) — flushed
         to scan_run_artifacts via the existing flush loops (clean path
         at write_findings_and_artifacts and degraded path at degraded_out
         via flush_artifacts_to_db). No 3-tuple → 4-tuple refactor needed.
      2. log(stderr[:cap]) — lands in GH Actions log too, so forensics
         survive even if the DB write fails.

    Capped at MARK_DEGRADED_STDERR_ARTIFACT_CAP_BYTES (artifact) and
    MARK_DEGRADED_STDERR_LOG_CAP_BYTES (log) to prevent a chatty tool
    from bloating scan_run_artifacts or the GH log tail.

    Keyword-only + Optional → backward-compatible. Existing ~25 call
    sites across run_light + run_medium continue to work unchanged;
    sites with stderr in scope can opt in one line at a time.

    Surfaced by myordersauth prod (d0cbe39e) + test (bd2cef8f) 2026-06-14:
    both degraded as nikto runtime_error but the actual `+ ERROR:` line
    that triggered the detector lives in nikto stderr, which was
    captured in no surface anywhere — not GH logs (line 1602's
    'unconditional' log is gated behind the success branch), not the DB
    (ctx.artifacts only carries stdout, and degraded path discards it
    via rollback even when present). [1] diagnosis was dead-end without
    this capture path.
    """
    ctx.tool_status[tool_name] = {"degraded": reason}
    # Live scan progress (note 103): best-effort flush. Done BEFORE
    # the stderr capture below so the portal sees the degraded status
    # ASAP even if stderr serialization is slow.
    flush_progress(ctx)
    if stderr:
        # Truncate at cap; full stderr is preserved upstream in run_cmd's
        # return value if anything else wants the full bytes.
        capped_artifact = stderr[:MARK_DEGRADED_STDERR_ARTIFACT_CAP_BYTES]
        ctx.artifacts.append(
            (f"{tool_name}_stderr", "text", capped_artifact)
        )
        # Smaller cap for the log — GH log lines stay readable. The
        # full bytes are in the artifact; this is the eyeball-in-CI view.
        capped_log = stderr[:MARK_DEGRADED_STDERR_LOG_CAP_BYTES]
        log(f"{tool_name} stderr ({len(stderr)}B, "
            f"showing first {len(capped_log)}B): {capped_log}")


def nikto_is_degraded(stdout: str, stderr: str, rc: int) -> tuple[bool, str]:
    """Bug D + Bug E detector. Reads BOTH stdout AND stderr.

    Catches two recognized failure shapes:

    1. **help_text_returned** (original Bug D, 2026-06-07 AM): nikto
       prints its short usage banner on Getopt::Long flag rejection
       or ambiguity. Keys on the EXACT phrases in nikto's short help.
       Banner can land on either stream depending on nikto version.

    2. **runtime_error** (Bug E, added 2026-06-07 PM after scan_run
       c14e2fe2 exposed the blind spot): nikto can scan the target,
       print a valid header, and THEN crash in a plugin (e.g. report
       plugin failing to open the -output file). The header-presence
       check would falsely read healthy. Keys instead on any
       `+ ERROR:` line — nikto's own error-line convention.

       IMPORTANT — nikto routes `+ ERROR:` lines to STDERR (verified
       on scan_run c14e2fe2: stderr was 221B starting with
       "+ ERROR: Unable to open '' for write:" while stdout was only
       136B and contained no error). The detector MUST inspect both
       streams; reading stdout alone false-negatived c14e2fe2 the
       first time this detector was written.

       Explicitly excludes `+ ERROR: Host maximum execution time` —
       that's routine time-boxing (the `-maxtime` cap doing its job)
       and would cry-wolf on every capped run, repeating the
       nuclei-empty mistake. Per Howie's rule: a degraded flag must
       mean tool FAILED, never "tool worked within its budget."

       Does NOT key on `rc` alone. `-maxtime` can set rc != 0 even
       when the scan was healthy.

    3. **module_not_found / no_scan_output** (added 2026-06-10 after
       scan_run 47bbdbff): upstream nikto dies AT STARTUP when a
       required Perl module is missing, printing bare
       `ERROR: Required module not found: JSON` lines — note: NO
       leading `+ `, so the `+ ERROR:` check (shape 2) never fires.
       This is exactly the failure the advisor warned about when the
       apt→upstream binary swap landed ("detector tuned against apt
       2.1.5 — verify still fires on upstream"): it stamped ok:true
       on runs a981526e (6/9, the 0864fd3 mint evidence) and 47bbdbff
       (6/10) where nikto scanned NOTHING. Durations told the truth:
       apt-nikto testfire runs ~1040-1060s; both upstream runs ~485s
       — a real nikto pass had silently vanished from the runtime.

       Two checks close the class:
       a. exact-phrase `Required module not found` → module_not_found
       b. positive-evidence fallback: rc != 0 AND no "Nikto v" banner
          in stdout → nikto never even started → no_scan_output.
          Cry-wolf safe: maxtime-capped runs print the banner before
          rc goes non-zero; healthy runs have rc == 0.

    4. **target_error_limit** (added 2026-06-15 after scan_run
       78a94f11): nikto has its own internal 20-consecutive-errors
       budget. When the TARGET (not nikto's own machinery) rejects 20
       requests in a row, nikto emits TWO specific stderr lines and
       quits gracefully with partial coverage:
         + ERROR: *** Error limit (20) reached for host, giving up. ***
         + ERROR: *** Consider using mitmproxy to avoid TLS fingerprinting. ***
       Surfaced on myordersauth-test (Azure App Service + Entra) — nikto
       ran 444s, reached ~5% coverage, hit the error limit, terminated
       with partial findings ("3 errors and 4 items reported").

       DESIGN NOTE (advisor 2026-06-15, important): this is its OWN
       degraded reason — NOT runtime_error, NOT 'ok'. Three states:
         - 'ok'                 → tool worked within OUR budget
         - 'runtime_error'      → tool CRASHED (Bug E class)
         - 'target_error_limit' → TARGET blocked us partway through
       Tempting trap: route error-limit to the maxtime-style exclude
       list and mark clean. WRONG. maxtime = "worked within OUR -maxtime
       budget" (clean is honest). error-limit = "target blocked us at
       5% coverage" (incomplete is honest). Per this detector's docstring
       rule: 'a degraded flag must mean tool FAILED, never tool worked
       within its budget.' A target-blocked partial-coverage run with
       5% reach is NOT "worked within budget" — it's incomplete because
       of an external denial. Treating it as 'ok' would re-create the
       success-shaped-lie class.

       Implementation: priority order matters. Check error-limit FIRST
       (more specific), then fall through to the generic `+ ERROR:`
       runtime_error catch. The error-limit pattern is two distinct
       lines that appear together; matching either marks the run.

    Verified post-fix against stored fixtures (all in scan_run history):
      - 7f8b18e8 / 1256B help banner (pre-Bug-D-fix) → help_text_returned
      - c14e2fe2 / rc=2 write-crash (stderr 221B)   → runtime_error
      - 7bd3bbf9 / healthy 1595B scan output         → ok
      - 47bbdbff / rc=1 module-not-found (85B stderr) → module_not_found
      - synthesized maxtime-only run (header + items + Host max exec
        ERROR + clean End Time) → ok (cry-wolf guard)
      - 78a94f11 / 148B "Error limit (20) reached" stderr → target_error_limit
    """
    combined = stdout + "\n" + stderr
    if "Note: This is the short help output" in combined:
        return True, "help_text_returned"
    if "Use -H for full help text" in combined:
        return True, "help_text_returned"
    if "Required module not found" in combined:
        return True, "module_not_found"
    # target_error_limit takes precedence over runtime_error — more
    # specific reason. Two stderr lines that appear together when
    # nikto's 20-consecutive-error budget is exhausted by the target.
    # Either line alone is sufficient evidence (defensive — nikto could
    # add/remove the secondary mitmproxy hint in a future version, the
    # primary "Error limit" is the load-bearing signal).
    if "Error limit (" in combined and "reached for host" in combined:
        return True, "target_error_limit"
    if "Consider using mitmproxy to avoid TLS fingerprinting" in combined:
        return True, "target_error_limit"
    for line in combined.splitlines():
        s = line.strip()
        if s.startswith("+ ERROR:"):
            # Skip the benign maxtime-cap line. Match generously on
            # the literal "Host maximum execution time" phrase so
            # cosmetic phrasing changes (different numbers, etc.) all
            # match.
            if "Host maximum execution time" in s:
                continue
            # target_error_limit is handled above as its own reason —
            # don't double-fire here. The earlier checks already
            # returned if either pattern matched.
            return True, "runtime_error"
    if rc != 0 and "Nikto v" not in stdout:
        # Non-zero exit AND nikto never printed its banner → it died
        # before scanning anything (startup crash class). The banner
        # check keeps maxtime-capped runs (banner present, rc != 0)
        # out of this bucket.
        return True, "no_scan_output"
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


def capture_vpn_config_used() -> str | None:
    """Return the active WireGuard interface name (e.g. 'us-atl-wg-001') by
    asking the wg tool. Used by run() to populate ctx.vpn_config_used so
    scan_run.vpn_config_used isn't NULL when VPN is up (Bug C).

    Returns None on any error — caller falls back gracefully.
    """
    rc, stdout, _ = run_cmd(["wg", "show", "interfaces"], timeout=5)
    if rc != 0:
        return None
    iface = stdout.strip().split()[0] if stdout.strip() else ""
    return iface or None


def note_ban_event(ctx: ScanContext, event: dict) -> None:
    """Append a ban event with the 500-entry cap (advisor ruling Q2).

    When the cap is hit, flips ctx.rotation_storm=True and stops
    appending. rotation_storm is independent evidence of severe
    degradation and is surfaced in rotation_log."""
    hit = cap_aware_append_ban(ctx.ban_events, ctx.rotation_storm, event)
    if hit:
        ctx.rotation_storm = True
        log(f"  rotation storm: ban_events cap hit "
            f"({MAX_BAN_EVENTS}) — further events dropped")


def note_healthcheck_failure(ctx: ScanContext, event: dict) -> None:
    """Same shape as note_ban_event but for healthcheck failures."""
    hit = cap_aware_append_healthcheck_failure(
        ctx.healthcheck_failures, ctx.rotation_storm, event
    )
    if hit:
        ctx.rotation_storm = True
        log(f"  rotation storm: healthcheck_failures cap hit "
            f"({MAX_HEALTHCHECK_FAILURES}) — further events dropped")


def build_rotation_log(ctx: ScanContext) -> dict:
    """Build the scan_run.rotation_log jsonb payload from ctx state.

    Schema: {count, distinct_egress_ips, ban_events, healthcheck_failures,
             rotation_storm}. See migration 20260612a column COMMENT.
    """
    return {
        "count": ctx.rotation_count,
        "distinct_egress_ips": list(ctx.egress_ips_seen),
        "ban_events": list(ctx.ban_events),
        "healthcheck_failures": list(ctx.healthcheck_failures),
        "rotation_storm": ctx.rotation_storm,
    }


def rotate_vpn(ctx: ScanContext) -> bool:
    """Rotate to the next region in ROTATION_REGIONS. Best-effort —
    returns True on success, False on failure. Failures are non-fatal:
    the scan continues on the current tunnel.

    Validate-mode short-circuit (batch 2 step c): when ctx.validate_mode
    is True (SKIP_VPN env was set, runner is on direct GH Actions egress
    with no Mullvad tunnel), there's no tunnel to rotate. Return False
    immediately so the caller treats it as a failed rotation. Combined
    with the max_rotations=0 cap in ensure_healthy_egress, this means
    any health failure in validate-mode aborts on first detect — no
    pointless rotation attempts against a tunnel-less interface, no
    cosmetic noise in the log.
    """
    if ctx.validate_mode:
        log("rotate_vpn: validate_mode — rotation suppressed (no tunnel to rotate)")
        return False

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
# Codes that warrant rotating egress: the WAF/host is refusing THIS client
# (ban / throttle) or the path to origin is down.
#   403       — WAF block page (FortiGate / Cloudflare deny)
#   429       — rate-limit / throttle
#   503       — FortiWeb's DEFAULT deny page (sciimage tier) — also covers
#               origin-overwhelmed, where backing off is correct anyway
#   502, 504  — upstream path down; rotation won't fix it, but the
#               rotate→skip outcome is right (don't fire tools at a dead path)
#
# Anything else that speaks HTTP is proof the origin answered this IP.
# Task #31 (2026-06-10): the old allowlist (200/3xx/401) treated 404 as
# "unreachable", which skipped every probe against API-style hosts —
# api.commandcommcentral.com legitimately returns 404 on '/' because an
# API root has no page. An IP ban looks like 403/429/503/timeout — never
# a clean origin 404. Same trap-shape as NODATA-vs-SERVFAIL: two responses
# that look alike but mean opposite things.
BAN_OR_PATH_DOWN_CODES = (403, 429, 502, 503, 504)


def healthcheck(ctx: ScanContext) -> tuple[bool, int]:
    """Probe the target via the Go httpx client. Returns (healthy, http_code).
    'healthy' = origin answered with a non-block response.
    code 0 = no HTTP response at all (timeout / refused / reset).

    #32 (2026-06-16): switched from curl to httpx. nuclei + httpx share
    the Go ProjectDiscovery retryablehttp + Go TLS stack; curl uses
    libcurl + system OpenSSL/BoringSSL. Targets that fingerprint TLS
    or specific header shapes can reject curl while accepting the Go
    stack — that's exactly what scan_run 1dd0891f hit on
    ftp.sciimage.com (wafw00f + httpx ok on egress 45.134.140.132,
    curl healthcheck got 0 on the same IP, scan declared
    egress_unstable across 3 Mullvad rotations even though the actual
    scan-tool stack could reach).

    httpx output (with -silent -status-code -no-color):
        https://<host>/ [200]
    Parsing keys on the bracketed integer to handle stdin/proto noise.
    """
    ua = pick_ua()
    rc, stdout, _ = run_cmd(
        ["httpx",
         "-silent", "-status-code", "-no-color",
         "-timeout", "10",
         "-H", f"User-Agent: {ua}",
         "-u", f"https://{ctx.hostname}/"],
        timeout=15,
    )
    if rc != 0:
        return False, 0

    # Parse "https://<host>/ [200]" → 200. Tolerate extra lines / noise.
    m = re.search(r"\[(\d{3})\]", stdout)
    if not m:
        return False, 0
    code = int(m.group(1))
    healthy = code not in BAN_OR_PATH_DOWN_CODES
    return healthy, code


def should_suppress_ffuf_redirect(
    redirect_to: str, baseline: str | None
) -> bool:
    """#33 (2026-06-16) suppression predicate. True iff the ffuf result's
    redirect Location matches the calibrated catch-all baseline EXACTLY.

    Empty redirect or no baseline → False (no suppression). EXACT-equality
    only — this is the load-bearing safety vs. the 59ad6a13 regression
    that hid real /admin findings under a blanket -fc/-fs filter.
    Distinct redirects (≠ baseline) and any non-redirect status
    (200/204/401/403) → no suppression → emit per-path as today.

    Pure function — testable without subprocess. Pins the EXACT-equality
    semantic so a future "helpful" refactor to startswith / substring /
    URL-normalized match trips a test immediately.
    """
    return bool(redirect_to and baseline and redirect_to == baseline)


def should_suppress_ffuf_status(
    status: int, baseline: int | None, redirect_to: str
) -> bool:
    """S3 Part 1 (2026-06-18) suppression predicate. True iff this ffuf
    result's status matches the calibrated catch-all status EXACTLY and the
    result is NOT a redirect (those go through should_suppress_ffuf_redirect
    instead — never double-suppress).

    No baseline (None) → False (no suppression — calibration didn't detect
    a catch-all status). Status 0 / falsy → False (defensive: don't suppress
    on no-response rows that ffuf shouldn't have emitted anyway).

    EXACT-equality only — this is the load-bearing safety vs. the 59ad6a13
    regression (blanket -fc/-fs/-fr ffuf args that hid real /admin findings).
    Distinct statuses (e.g. /admin returning 200 on a 403-blanket host) still
    emit per-path. Pure function — testable without subprocess.

    The not-redirect clause: if a row IS a redirect, the redirect-suppress
    runs first (#33). A status-suppress here would be either redundant
    (redirect already suppressed → continue already hit) or wrong (the
    redirect didn't match the baseline → should emit). Excluding redirects
    here keeps the two suppression paths orthogonal.
    """
    if not baseline or not status:
        return False
    if redirect_to:
        return False
    return status == baseline


def emit_ffuf_catchall_status_summary(ctx: ScanContext) -> None:
    """S3 Part 1 collapsed STATUS-catchall summary emit. If the calibration
    probe detected a host-wide non-discriminating status (403/401/200/etc)
    AND ffuf saw N per-path matches collapsed into it, emit ONE finding
    summarizing the count. Idempotent: no-op if no catchall status detected
    or count is 0.

    Severity:
      - 403, 401 → LOW. A host that blanket-403/401s every path is a weak
        posture signal worth one LOW finding (uniform deny across the
        wordlist is a real story, just not per-path noise).
      - 200, 302, anything else → INFO. SPA / soft-404 / catch-all redirect
        are lower-signal — collapse to a single informational row.

    Called once at end of run_ffuf_chunked AFTER all chunks complete, beside
    the existing emit_ffuf_catchall_summary. The per-path findings are NOT
    in ctx.findings (suppressed at emit time inside the loop); this is the
    single replacement finding.
    """
    if ctx.ffuf_catchall_status_count <= 0 or ctx.ffuf_catchall_status is None:
        return
    status = ctx.ffuf_catchall_status
    severity = "LOW" if status in (401, 403) else "INFO"
    ctx.findings.append(MediumFinding(
        check_name=f"ffuf-catchall-status-{status}",
        title=(
            f"Host returns HTTP {status} to {ctx.ffuf_catchall_status_count} "
            f"paths uniformly"
        ),
        severity=severity,
        category="info_disclosure",
        description=(
            f"{ctx.ffuf_catchall_status_count} wordlist paths on "
            f"{ctx.hostname} uniformly return HTTP {status} regardless of "
            f"existence — directory discovery is not discriminating on this "
            f"host (WAF blanket-deny / soft-404 / SPA). Per-path results "
            f"suppressed as non-discriminating; distinct statuses still "
            f"emit individually."
        ),
        tags=["ffuf", "directory", "discovery", "catchall_status"],
        raw_excerpt=(
            f"Calibration probe: 2 random paths → HTTP {status}\n"
            f"Suppressed per-path matches: {ctx.ffuf_catchall_status_count}"
        ),
    ))


def emit_ffuf_catchall_summary(ctx: ScanContext) -> None:
    """#33 collapsed summary emit. If the calibration probe detected a
    host-wide redirect AND ffuf saw N per-path matches collapsed into
    it, emit ONE INFO finding summarizing the count. Idempotent: no-op
    if no catchall detected or count is 0.

    Called once at end of run_ffuf_chunked AFTER all chunks complete.
    The per-path findings are NOT in ctx.findings (suppressed at emit
    time inside the loop); this is the single replacement finding.
    """
    if ctx.ffuf_catchall_count <= 0 or not ctx.ffuf_catchall_redirect:
        return
    # Slug derived from the redirect URL for stable finding_id semantics
    # — same finding re-emerges across re-scans with the same redirect,
    # so the row matches on re-detect rather than fragmenting into new
    # finding_ids.
    slug = re.sub(r"[^a-z0-9]+", "-",
                  ctx.ffuf_catchall_redirect.lower())[:60].strip("-") \
           or "catchall-redirect"
    ctx.findings.append(MediumFinding(
        check_name=f"ffuf-catchall-redirect-{slug}",
        title=(
            f"Catch-all redirect → {ctx.ffuf_catchall_redirect} "
            f"({ctx.ffuf_catchall_count} paths)"
        ),
        severity="INFO",
        category="info_disclosure",
        description=(
            f"{ctx.ffuf_catchall_count} wordlist paths on "
            f"{ctx.hostname} uniformly redirect to "
            f"{ctx.ffuf_catchall_redirect} regardless of existence — "
            f"directory discovery is not meaningful on this host "
            f"(likely a self-hosted login/auth gate). Per-path "
            f"results suppressed as non-discriminating. Distinct "
            f"redirects and 200/204/401/403 responses still emit "
            f"individually."
        ),
        tags=["ffuf", "directory", "discovery", "catchall_redirect"],
        raw_excerpt=(
            f"Calibration probe: random path → "
            f"{ctx.ffuf_catchall_redirect}\n"
            f"Suppressed per-path matches: {ctx.ffuf_catchall_count}"
        ),
    ))


def _probe_calibration_path(ctx: ScanContext) -> tuple[int, str | None]:
    """Single calibration probe — fetch a known-random path and return
    (status_code, redirect_location). Helper for detect_ffuf_catchall.

    Returns (0, None) on any failure (rc != 0, no stdout, JSON parse error)
    so callers can treat failure as "no catch-all detected" without raising.
    Same httpx invocation as the pre-S3 detect_ffuf_catchall_redirect.
    """
    import uuid as _uuid
    random_path = f"cs-calib-{_uuid.uuid4().hex[:12]}"
    rc, stdout, _ = run_cmd(
        ["httpx",
         "-silent", "-status-code", "-location", "-json", "-no-color",
         "-timeout", "10",
         "-H", f"User-Agent: {pick_ua()}",
         "-u", f"https://{ctx.hostname}/{random_path}"],
        timeout=15,
    )
    if rc != 0:
        return 0, None
    line = stdout.strip().splitlines()[0] if stdout.strip() else ""
    if not line:
        return 0, None
    try:
        data = json.loads(line)
    except Exception:
        return 0, None
    status_code = int(data.get("status_code", 0) or 0)
    # httpx field names for redirect Location vary slightly across versions.
    # Try the most likely candidates. "location" is the canonical Location
    # header (relative or absolute). "final_url" is set with -follow-redirects
    # (we don't use it, but defensive). Anything truthy wins.
    location = data.get("location") or data.get("final_url")
    location_str = str(location).strip() if location else None
    return status_code, (location_str or None)


def detect_ffuf_catchall(
    ctx: ScanContext,
) -> tuple[str | None, int | None]:
    """S3 Part 1 (2026-06-18) ffuf catch-all calibration. Generalizes #33's
    redirect-only catch-all to also detect a uniform non-discriminating
    STATUS (403/401/200/etc) that ffuf would otherwise mint N findings for.

    Probes TWO known-random paths. Catch-all is detected only if BOTH probes
    return the same non-404 signal — defends against transient flukes that
    a single probe couldn't distinguish from a real catch-all.

    Returns:
        (redirect_location, status) — both can be None.
          - redirect_location: set if BOTH probes returned 301/302/307 with
            the same Location. The catch-all redirect baseline (#33 path).
          - status: set if BOTH probes returned the same non-404 status
            AND neither was a redirect. The catch-all status baseline
            (S3 Part 1 path).
          - (None, None): real discrimination on this host — per-path
            emission unchanged from pre-#33 behavior.

    Uses httpx (same Go stack ffuf runs — no probe-vs-tool TLS fingerprint
    divergence). Best-effort: any failure on either probe → (None, None).

    NOT a tool registration. Does NOT touch ctx.tools_run, ctx.tool_status,
    or the trust-layer invariant. Calibration is auxiliary emit-time state;
    its success/failure has no bearing on scan_quality.
    """
    status1, redirect1 = _probe_calibration_path(ctx)
    if status1 == 0:
        return None, None
    status2, redirect2 = _probe_calibration_path(ctx)
    if status2 == 0:
        return None, None

    # Redirect catch-all (#33 path): both probes 30x AND same Location.
    if (
        status1 in (301, 302, 307)
        and status2 in (301, 302, 307)
        and redirect1
        and redirect1 == redirect2
    ):
        return redirect1, None

    # Status catch-all (S3 Part 1): both probes same non-404 non-redirect
    # status. 404 is the expected response to a random path, so it indicates
    # the host IS discriminating — not a catch-all.
    if (
        status1 == status2
        and status1 != 404
        and status1 not in (301, 302, 307)
    ):
        return None, status1

    # Otherwise: discrimination present (different responses across probes,
    # or 404 = real not-found behavior). No catch-all.
    return None, None


def detect_ffuf_catchall_redirect(ctx: ScanContext) -> str | None:
    """#33 backward-compatible thin wrapper around detect_ffuf_catchall.
    Returns only the redirect Location, dropping the status component.
    Preserved for any external/test caller still using the old name.
    """
    redirect, _ = detect_ffuf_catchall(ctx)
    return redirect


def ensure_healthy_egress(
    ctx: ScanContext, max_rotations: int = 2
) -> tuple[bool, str]:
    """Healthcheck + rotate-on-fail loop with #30 (2026-06-16) hardening.

    Returns (healthy, reason). On success → (True, ""). On failure →
    (False, "<reason_slug>") distinguishing:
      - "egress_unstable"           — rotated but no tunnel ever settled
                                      enough to make target reachable.
                                      A tunnel-side problem; rotation
                                      ran but didn't help.
      - "skipped_target_unreachable" — target itself not answering after
                                      a confirmed-healthy egress (or no
                                      rotation happened and target won't
                                      answer). The original reason.

    #30 hardening over the original first-fail-rotates loop:
      1. PRE-ROTATE RETRY — before rotating on an unhealthy check, do
         PRE_ROTATE_RETRY_ATTEMPTS probes with PRE_ROTATE_RETRY_DELAY_S
         between. Only rotate if ALL fail. Filters transient curl
         timeouts that tore down working tunnels on scan_run 57a79615.
      2. POST-ROTATE SETTLE — after rotate_vpn returns, do
         POST_ROTATE_SETTLE_ATTEMPTS probes with POST_ROTATE_SETTLE_
         DELAY_S between (~15s total). wireguard-go's first handshake-
         to-target often isn't routing for several seconds after
         bringup; single immediate probe would false-negative.

    Validate-mode override (batch 2 step c, SPEC Part 3): when
    ctx.validate_mode is True, force `max_rotations=0`. The validate
    run is PRISTINE-or-NOTHING for ROTATION — no rotation, no
    pool-swapping. RETRIES still apply (per #30 2026-06-16 follow-up):
    pre-rotate retry filters transient curl blips; that's NOT
    laundering a real degradation event, that's filtering network
    noise. The "no laundering" discipline is about not letting a
    DEGRADED scan look CLEAN — a transient timeout that gets retried
    successfully isn't degradation, it's a healthy run with a noisy
    network. Validate mode = retry-but-don't-rotate.
    """
    if ctx.validate_mode and max_rotations > 0:
        log(f"ensure_healthy_egress: validate_mode — overriding "
            f"max_rotations {max_rotations} → 0 (retry-but-don't-rotate)")
        max_rotations = 0

    bind_healthcheck = lambda: healthcheck(ctx)
    # Collect every probe's HTTP code across pre-rotate + post-rotate
    # cycles. Fed to egress_failure_reason() at end of loop to decide
    # egress_unstable vs skipped_target_unreachable. Any code > 0
    # anywhere = egress worked (even if response was a ban code); all
    # zeroes = tunnel never settled.
    probe_codes: list[int] = []

    # First pass — pre-rotate retry to filter transient blips.
    healthy, code = healthcheck_with_retry(
        bind_healthcheck,
        attempts=PRE_ROTATE_RETRY_ATTEMPTS,
        delay_s=PRE_ROTATE_RETRY_DELAY_S,
    )
    probe_codes.append(code)
    if healthy:
        return True, ""
    log(f"healthcheck: unhealthy after {PRE_ROTATE_RETRY_ATTEMPTS} probes "
        f"(last HTTP {code}) — initiating rotation if allowed")

    # Rotation loop with post-rotate settle.
    for rot_idx in range(max_rotations):
        ctx.ban_events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "pre_chunk_unhealthy",
            "http_code": code,
        })
        rotate_ok = rotate_vpn(ctx)
        if not rotate_ok:
            # Couldn't rotate (vpn_rotate.sh failed, validate_mode short-
            # circuit, etc). No point probing again — break out.
            break

        # Post-rotate settle — give the new tunnel time to start
        # passing target traffic before declaring it unhealthy.
        healthy, code = healthcheck_with_retry(
            bind_healthcheck,
            attempts=POST_ROTATE_SETTLE_ATTEMPTS,
            delay_s=POST_ROTATE_SETTLE_DELAY_S,
        )
        probe_codes.append(code)
        if healthy:
            log(f"healthcheck: recovered after rotation {rot_idx + 1} "
                f"(HTTP {code})")
            return True, ""
        log(f"healthcheck: still unhealthy after rotation {rot_idx + 1} "
            f"(last HTTP {code})")

    # #32 (2026-06-16) — prior-tool-success short-circuit. If any earlier
    # tool in this run already got a real HTTP response from the target
    # (wafw00f / httpx / nuclei chunk), we have same-run ground truth
    # that the path WAS reachable. Probe failure here is more likely a
    # transient blip OR a probe-vs-tool mismatch (different request
    # shape) than a real egress problem. Log loudly + bypass to healthy
    # rather than rotate/skip — let the chunk's own tool encounter any
    # real failure with its own per-tool detector + stderr.
    #
    # Won't catch a real mid-scan block (the prior success was earlier
    # in time), but the httpx-based healthcheck change (also #32) is
    # the primary fix for the request-shape false-negative. This is
    # the layered safety net.
    if ctx.target_proven_reachable:
        log(f"  ⚑ prior-tool-success bypass — target already proved "
            f"reachable this run (probes: {probe_codes}); proceeding "
            f"despite gate failure")
        return True, ""

    # All paths exhausted. Classification logic in egress_failure_reason()
    # (degradation.py) — unit-tested independently of this loop.
    return False, egress_failure_reason(probe_codes)


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
    # 2026-06-15: capture stderr instead of `_` so the A′ stderr-into-
    # mark_tool_degraded path (run_medium.py:445) has it available.
    rc, stdout, stderr = run_cmd(
        ["wafw00f", f"https://{ctx.hostname}/", "-a"],
        timeout=60,
    )
    ctx.artifacts.append(("wafw00f", "text", stdout))
    # ADR-001 Step 4 — completeness check: either a verdict line is
    # present or the tool failed.
    is_degraded, reason = wafw00f_is_degraded(stdout, rc)
    if is_degraded:
        mark_tool_degraded(ctx, "wafw00f", reason, stderr=stderr)
    else:
        mark_tool_ok(ctx, "wafw00f")
        # #32 — wafw00f successfully verdict-parsed → target answered at
        # least one of its probes. Establishes target reachability for
        # the prior-tool-success short-circuit in ensure_healthy_egress.
        ctx.target_proven_reachable = True
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
    # Per-chunk B1 wiring lockstep (2026-06-13, advisor note 2): every tool
    # appended to tools_run gets a detector-driven stamp. httpx is
    # single-shot; pre/post health assumed True (detect_waf just ran
    # successfully, so the target was reachable a moment ago — extra
    # healthcheck here is bandwidth without added signal).
    b1_reason = is_tool_output_degraded(
        tool="httpx[-td]",
        stdout=stdout, stderr=stderr, rc=rc,
        pre_health=True, post_health=True,
    )
    if b1_reason:
        mark_tool_degraded(ctx, "httpx[-td]", b1_reason, stderr=stderr)
        raise DegradedRunError(b1_reason, "httpx[-td]")
    mark_tool_ok(ctx, "httpx[-td]")

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
        # #32 — httpx tech-detect produced parseable JSON → got a real
        # HTTP response from target. Strong evidence the target is
        # reachable via the Go stack nuclei shares. Establishes
        # target_proven_reachable for the prior-tool-success
        # short-circuit in ensure_healthy_egress.
        ctx.target_proven_reachable = True
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

    # Per-chunk B1 wiring lockstep (2026-06-13, advisor note 2): every tool
    # appended to tools_run gets a detector-driven stamp. katana is
    # single-shot. Only fires in CRAWL_FIRST_MODE today but the lockstep
    # invariant means it MUST stamp tool_status either way.
    b1_reason = is_tool_output_degraded(
        tool="katana",
        stdout=stdout, stderr=stderr, rc=rc,
        pre_health=True, post_health=True,
    )
    if b1_reason:
        mark_tool_degraded(ctx, "katana", b1_reason, stderr=stderr)
        raise DegradedRunError(b1_reason, "katana")
    mark_tool_ok(ctx, "katana")

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
                     url_list_file: str | None = None
                     ) -> tuple[int, int, list[int], str, str]:
    """Run one nuclei chunk. Returns (rc, match_count, response_codes_observed,
    stdout, stderr).

    response_codes_observed is populated from nuclei's stats output if
    we can parse it; otherwise it's empty.

    stdout/stderr returned 2026-06-13 (batch 2 per-chunk B1 wiring) so
    the caller can pass them to is_tool_output_degraded for the
    Layer 2 unreachable-pattern backstop.

    rate_override: if set, used instead of NUCLEI_RATE_LIMIT. Threshold
    probe mode passes a per-chunk rate from the ladder.

    url_list_file: if set, nuclei runs with -list <file> against the
    crawled URLs instead of -u target_url. CRAWL_FIRST_MODE uses this
    to avoid template-driven path enumeration on WAF-sensitive targets.

    NOTE: tools_run.append moved to the chunked caller 2026-06-13 so
    every chunk-name in tools_run has a matching tool_status entry
    stamped at the same call site. Required for the close_out set-
    equality invariant (B2).
    """
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

    return rc, matches, [], stdout, stderr


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

        # Chunk name — must match the success-path format below
        # (`nuclei[<sev>]` or `nuclei[<sev>:<tag>]`). Naming consistency
        # fix 2026-06-13 (advisor batch 2 per-chunk B1 wiring): the
        # abort-path previously used `nuclei[<sev>:<all>]` for null-tag
        # chunks, but the success-path tools_run.append used `nuclei[<sev>]`
        # (no `:<all>` suffix). With per-chunk stamping in tool_status now
        # required to set-equality-match tools_run, the two paths must
        # produce IDENTICAL chunk names.
        chunk_name = f"nuclei[{sev}{':'+tag if tag else ''}]"

        # #24 Phase 2 — auth-gated per-chunk skip. Only the medium:tech
        # chunk is value-additive on auth-gated targets (fingerprints
        # the IdP infra cleanly — Microsoft IIS / Azure App Service /
        # etc). Everything else (critical+high attack templates,
        # medium:cve, medium:exposure,config, medium:wordpress,cms,
        # medium:iis,asp,..., medium:php, medium:drupal,cms,
        # medium:joomla,cms) fires templates that 401/redirect to the
        # IdP login uniformly — zero signal. Stamp the chunk as skipped
        # to preserve set-equality + the forensic "we considered this
        # and intentionally skipped" record, then continue to the next
        # chunk WITHOUT running this one.
        if ctx.auth_gated and tag != "tech":
            log(f"  ⊘ skip chunk {chunk_name} — auth_gated + non-tech (no unauth attack surface)")
            ctx.tools_run.append(chunk_name)
            mark_tool_skipped(ctx, chunk_name, "auth_gated")
            continue

        healthy, egress_reason = ensure_healthy_egress(ctx, max_rotations=2)
        if not healthy:
            # #30 (2026-06-16) — reason from ensure_healthy_egress now
            # distinguishes egress_unstable (rotated, never settled)
            # from skipped_target_unreachable (target not answering
            # after confirmed-healthy egress). Stamp the chunk with
            # whichever applies.
            log(f"  ✗ pre-chunk healthy gate failed ({egress_reason}) — ABORT ({chunk_name})")
            note_ban_event(ctx, {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "chunk_skipped_unreachable",
                "chunk": f"{sev}:{tag or '<all>'}",
                "reason": egress_reason,
            })
            if THRESHOLD_PROBE_MODE:
                ctx.threshold_probe_results.append({
                    "chunk_index": i + 1, "rate": rate_for_chunk,
                    "egress_ip": ctx.egress_ips_seen[-1] if ctx.egress_ips_seen else None,
                    "pre_chunk_code": 0, "post_chunk_code": None,
                    "matches": 0, "rc": None, "banned": True,
                    "note": f"skipped — {egress_reason} before chunk",
                })
            if chunk_name not in ctx.tools_run:
                ctx.tools_run.append(chunk_name)
            mark_tool_degraded(ctx, chunk_name, egress_reason)
            raise DegradedRunError(
                egress_reason,
                f"{chunk_name} after {ctx.rotation_count} rotations",
            )

        # PROBE/PATIENT: capture the egress IP we're about to scan from +
        # a baseline health code RIGHT BEFORE the chunk runs.
        probe_egress_ip = ctx.egress_ips_seen[-1] if ctx.egress_ips_seen else None
        pre_code = None
        if THRESHOLD_PROBE_MODE or patient_effective:
            _, pre_code = healthcheck(ctx)
            tag_lbl = "PROBE" if THRESHOLD_PROBE_MODE else "PATIENT"
            log(f"  {tag_lbl} pre-chunk healthcheck on {probe_egress_ip}: HTTP {pre_code}")

        # Layer 2: run the chunk.
        # tools_run.append moved out of run_nuclei_chunk (2026-06-13 per-chunk
        # B1 wiring): append BEFORE the run so the abort-path's tool_status
        # stamp lines up with what's already in tools_run; pre_health is True
        # by induction (we just passed ensure_healthy_egress above).
        ctx.tools_run.append(chunk_name)
        pre_healthy = True
        rc, matches, _, chunk_stdout, chunk_stderr = run_nuclei_chunk(
            ctx, base_url, sev, tag,
            rate_override=rate_for_chunk if (THRESHOLD_PROBE_MODE or patient_effective or STEALTH_UA or needs_softened_rate(ctx)) else None,
            url_list_file=url_list_file,
        )
        log(f"  chunk {i+1} done: {matches} match(es), rc={rc}")

        # Per-chunk B1 detector (batch 2, advisor approved 2026-06-13).
        # Unconditional post-chunk healthcheck — NEW behavior in NORMAL mode
        # (previously only ran in PROBE/PATIENT). First time the post-check
        # path is exercised in NORMAL mode is on testfire; a flaky check
        # there would surface as a healthcheck-unreachable degradation.
        post_chunk_healthy, _ = healthcheck(ctx)
        b1_reason = is_tool_output_degraded(
            tool=chunk_name,
            stdout=chunk_stdout,
            stderr=chunk_stderr,
            rc=rc,
            pre_health=pre_healthy,
            post_health=post_chunk_healthy,
        )
        # Priority per advisor 2026-06-13 Q3:
        #   Layer 2 health authority > Layer 1 tool-specific > Layer 2 stderr backstop.
        # nuclei has no Layer 1 detector today (separate item), so priority
        # collapses to "any non-None b1_reason aborts; else mark ok."
        if b1_reason:
            mark_tool_degraded(ctx, chunk_name, b1_reason, stderr=chunk_stderr)
            raise DegradedRunError(b1_reason, chunk_name)
        mark_tool_ok(ctx, chunk_name)
        # #32 — chunk completed cleanly → tool reached target. Establishes
        # target_proven_reachable for the prior-tool-success short-circuit.
        ctx.target_proven_reachable = True

        # PROBE/PATIENT: healthcheck on the SAME tunnel BEFORE rotating.
        # In PROBE mode this is data-gathering. In PATIENT mode it gates
        # whether we trigger the ban-cooldown sleep before rotating.
        post_banned = False
        if THRESHOLD_PROBE_MODE or patient_effective:
            # Task #31: use healthcheck()'s own verdict instead of a second
            # inline copy of the code allowlist (which had drifted into the
            # same 404-means-banned bug).
            post_healthy, post_code = healthcheck(ctx)
            post_banned = not post_healthy
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
# ─── nikto parser (#28 — 2026-06-15) ───────────────────────────────────
#
# Promote ONLY canonical nikto finding shape:
#   + [<digits>] /path: description
#
# Drops scaffolding (Target IP:, Platform:, Server:, etc.) AND footer
# (Scan terminated, item(s) reported, host(s) tested) at the shape gate.
# Replaces the prior denylist-of-prefixes + natural-language-keyword
# severity map that produced 4-of-6 noise findings on the FortiWeb run
# (scan_run 14714f2f). Sharpens by FILTER rather than blacklist: shape
# match is unambiguous; non-matches are policy-dropped without enumerating
# every nikto meta-line variant.

NIKTO_FINDING_RE = re.compile(r"^\[(\d+)\]\s+(\S+?):\s+(.+)$")

# #28 Q1 — drop nikto's "Suggested security header missing:" lines.
# headers_check (light tier) is canonical for HTTP security headers and
# runs on every asset. nikto's medium-tier rehash adds zero value and
# pollutes the dashboard with duplicate findings. Clean ownership
# boundary: each tool owns its slice; medium nikto = OS/CGI/server-config
# issues, not header checks already done in light.
NIKTO_HEADER_DEDUP_PATTERN = "Suggested security header missing"

# #28 footer guard — parse nikto's "N items reported" summary line.
# Log warning if shape-matched count diverges from footer count
# (indicates parser drift — nikto changed its finding-line format or
# we missed an [ID] range edge case). Doesn't fail the scan; just
# surfaces a clear maintenance signal.
#
# 2026-06-15 #28 follow-up: original regex required literal "item(s)"
# but real nikto v2.6.0 emits "items" (bare plural). Advisor verified
# against scan_run 14714f2f's stored stdout — synthesized fixture
# diverged from real output on exactly this string, which hid the
# dead guard. Broadened to match three forms: bare "item", plural
# "items", and the parenthesized "item(s)" some nikto versions use.
# Real data is the test surface — the regression fixture is now the
# verbatim stored stdout, not a from-memory synthesis.
NIKTO_FOOTER_COUNT_RE = re.compile(r"(\d+)\s+item(?:s|\(s\))?\s+reported")


def _nikto_severity_for_id(nikto_id: str) -> str:
    """#28 Q2 — severity off nikto's ID range, NOT natural-language
    keywords (which mis-fired on negatives like 'No CGI Directories FOUND'
    → LOW). nikto NEVER self-assigns MODERATE+ — it's a low-fidelity
    source; real severity comes from nuclei/CVE/manual. Conservative
    LOW default for real findings; INFO for nikto's documented
    informational range (999xxx).

    Per advisor 2026-06-15 (Q2 correction): do NOT generalize OSVDB IDs
    (013xxx etc.) to severity buckets — OSVDB IDs do not encode severity
    semantically. 999xxx is documented as nikto's informational range;
    treat everything else as LOW with a conservative default.
    """
    return "INFO" if nikto_id.startswith("999") else "LOW"


def parse_nikto_findings(
    stdout: str, hostname: str
) -> tuple[list[MediumFinding], int, int]:
    """#28 parser — canonical-shape + Q1 dedup + Q2 ID-bucket severity.

    Returns (findings, nikto_emitted, we_promoted):
      nikto_emitted = items that pass the canonical shape gate
                      (+ [<digits>] /path: description)
      we_promoted   = items we kept (passed Q1 header-dedup drop)

    Caller compares `nikto_emitted` to the footer count via
    extract_nikto_footer_count(); divergence logs a parser-drift warning.
    """
    findings: list[MediumFinding] = []
    nikto_emitted = 0
    we_promoted = 0

    for line in stdout.splitlines():
        line = line.rstrip()
        if not line.startswith("+ "):
            continue
        body = line[2:].strip()

        # Canonical shape gate — drops every line without a [<digits>] ID.
        # Catches Platform:, No CGI Directories, Target/Server scaffolding,
        # Scan terminated/End Time/host(s) tested footers, etc. — all without
        # an explicit denylist (denylist was lossy; shape gate is total).
        m = NIKTO_FINDING_RE.match(body)
        if not m:
            continue
        nikto_id, _path, description = m.group(1), m.group(2), m.group(3)
        nikto_emitted += 1

        # Q1 — drop header-missing rehash. headers_check owns this slice.
        if NIKTO_HEADER_DEDUP_PATTERN in description:
            continue

        severity = _nikto_severity_for_id(nikto_id)
        we_promoted += 1

        # Slug derived from the full body for stable finding_id semantics.
        # Preserves existing finding identity across the parser refactor —
        # rows already in the DB (whether marked detected, remediated, or
        # the post-#28 false_positive flips) match on re-detect rather
        # than fragmenting into new finding_ids.
        body_lc = body.lower()
        slug = re.sub(r"[^a-z0-9]+", "-", body_lc)[:60].strip("-") or \
               f"finding-{we_promoted}"
        findings.append(MediumFinding(
            check_name=f"nikto-{slug}",
            title=f"nikto: {body[:120]}",
            severity=severity,
            category="dast",
            description=(
                f"Nikto reported on {hostname}: {body}. Review the raw "
                f"nikto output artifact for full context including OSVDB ref "
                f"and the exact URL probed."
            ),
            tags=["nikto"],
            raw_excerpt=body[:1500],
        ))

    return findings, nikto_emitted, we_promoted


def extract_nikto_footer_count(stdout: str) -> int | None:
    """Extract 'N item(s) reported' from nikto's footer.
    Returns None if absent (older nikto versions, truncated output, etc.).
    """
    m = NIKTO_FOOTER_COUNT_RE.search(stdout)
    return int(m.group(1)) if m else None


def run_nikto(ctx: ScanContext) -> None:
    """Single nikto pass on a fresh IP. nikto doesn't chunk well; if
    it gets banned mid-run, we accept the loss for this pass.
    """
    log("→ nikto (single pass)")

    # #24 Phase 2 — auth-gated skip. nikto crawls attack paths against
    # the root, all of which 401/redirect to the IdP login on auth-gated
    # targets. Wastes ~7 min producing zero signal + hits target's own
    # error budget (target_error_limit). Skip explicitly: tools_run +
    # tool_status get the skipped stamp (set-equality holds), no
    # execution, no degradation. Run stays scan_quality='clean'.
    if ctx.auth_gated:
        log("  ⊘ skip nikto — asset is auth_gated (no unauth attack surface)")
        ctx.tools_run.append("nikto")
        mark_tool_skipped(ctx, "nikto", "auth_gated")
        return

    healthy, egress_reason = ensure_healthy_egress(ctx, max_rotations=2)
    if not healthy:
        # #30 reason taxonomy: egress_unstable vs skipped_target_unreachable.
        log(f"  ✗ pre-nikto healthy gate failed ({egress_reason}) — ABORT")
        note_ban_event(ctx, {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "chunk_skipped_unreachable",
            "chunk": "nikto",
            "reason": egress_reason,
        })
        if "nikto" not in ctx.tools_run:
            ctx.tools_run.append("nikto")
        mark_tool_degraded(ctx, "nikto", egress_reason)
        raise DegradedRunError(
            egress_reason,
            f"nikto after {ctx.rotation_count} rotations",
        )

    ctx.tools_run.append("nikto")
    # Bug D root cause was "crusty apt nikto fighting modern arg semantics."
    # Closed 2026-06-09 by Task #6: upstream sullo/nikto installed in the
    # scanner image (replaces apt's nikto 2.1.5 from 2014). Upstream takes
    # -useragent natively, no Getopt::Long prefix ambiguity.
    #
    # UA spoofing is LOAD-BEARING for medium-on-WAF. nikto's default UA
    # contains literal "Nikto/2.x" — instant WAF tell. Spoofing to a
    # realistic browser UA is the minimum Stage-3 guardrail before firing
    # against any owned WAF-fronted asset (cc/cmi/unimac/ccc/sciimage).
    #
    # ⚠️ NOT A FULL WAF SOLVE. If the WAF blocks on TLS/JA3 fingerprint
    # or behavior rather than signature/UA, the spoofed UA does nothing.
    # That's the open Experiment-C question (note 61): signature/UA-based
    # WAFs → this fix lands; fingerprint-based WAFs → still need
    # Playwright/real-browser path. Watch the first fire against
    # api.commandcommcentral.com (FortiGate-lenient): if it still eats a
    # 403 with this clean browser UA, the WAF trigger was never UA-based.
    # That's a finding, not a failure of Task #6.
    BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/131.0.0.0 Safari/537.36")
    cmd = [
        "nikto",
        "-host", f"https://{ctx.hostname}",
        "-Pause", str(NIKTO_PAUSE_S),
        "-nointeractive", "-ask", "no",
        "-Tuning", "x6",
        # Restored by Task #6. Works on upstream nikto; apt 2.1.5 rejected this.
        "-useragent", BROWSER_UA,
        "-timeout", "15",
        "-maxtime", str(NIKTO_WALL_S - 30),
        # Bug E (2026-06-07 PM, scan_run c14e2fe2): -Format requires
        # -output FILE; without it, nikto's report plugin tries to write
        # to '' and dies at /var/lib/nikto/plugins/nikto_report_text.plugin
        # line 41 with "Unable to open '' for write:" rc=2. This is a
        # nikto config-rule (-Format pairs with -output), same on Mac/apt/
        # upstream — not an Ubuntu quirk, so the tripwire correctly
        # didn't fire. Dropping -Format restores nikto's default
        # human-readable stdout output, which is the format the runner's
        # parser at the bottom of this function already reads
        # (filters '+ '-prefixed lines, skips Target/Server/etc. headers,
        # promotes the rest as findings).
    ]
    # input_str="" — pre-empt any future prompt from hanging the runner
    # (defensive; not the cause of the current arg-rejection bug, but cheap
    # insurance for the "tool waits on stdin" class of silent failures).
    rc, stdout, stderr = run_cmd(cmd, timeout=NIKTO_WALL_S, input_str="")
    ctx.artifacts.append(("nikto", "text", stdout))
    # ADR-001 Step 4 — Bug D + Bug E detector. Now reads BOTH stdout AND
    # stderr because nikto routes its `+ ERROR:` lines to stderr (verified
    # via scan_run c14e2fe2). The narrow detector only flags the literal
    # help banner phrases (Bug D) or non-maxtime "+ ERROR:" lines (Bug E),
    # never a legitimate empty/short scan output.
    # Two-layer detector (advisor 2026-06-13). Layer 1 (nikto-specific) catches
    # startup/help-banner failures unique to nikto. Layer 2 (B1 unified) catches
    # connect-refused stderr patterns that Layer 1 doesn't model.
    #
    # Priority per advisor Q3: Layer 2 health authority > Layer 1 tool-specific
    # > Layer 2 stderr backstop. nikto is single-shot (no chunk loop), so the
    # health authority signal isn't captured here — pre/post = True (assumed
    # reachable; nikto follows wafw00f + httpx + 4 nuclei chunks already
    # confirmed reachable). The stderr backstop is what matters here.
    is_degraded, reason = nikto_is_degraded(stdout, stderr, rc)
    if is_degraded:
        # Layer 1 wins — explicit tool-specific failure detected.
        # A′ (2026-06-15): pass stderr so mark_tool_degraded captures it
        # to scan_run_artifacts + GH log. This closes the [1] diagnostic
        # gap — runtime_error keys on `+ ERROR:` lines that live in
        # stderr (per Bug E comment at line 1620-1623), which was
        # captured in NO surface before A′.
        mark_tool_degraded(ctx, "nikto", reason, stderr=stderr)
        raise DegradedRunError("nikto_specific_degradation",
                               f"nikto: {reason}")

    # Layer 2 backstop — catches connect-refused noise in stderr that
    # Layer 1 didn't pattern-match. With health = True, only the stderr
    # backstop cell of is_tool_output_degraded can fire here.
    b1_reason = is_tool_output_degraded(
        tool="nikto", stdout=stdout, stderr=stderr, rc=rc,
        pre_health=True, post_health=True,
    )
    if b1_reason:
        mark_tool_degraded(ctx, "nikto", b1_reason, stderr=stderr)
        raise DegradedRunError(b1_reason, "nikto")

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

    # #28 — parser extracted to parse_nikto_findings helper (see module-
    # level docstring near line 1497 for the design). Pre-#28 the
    # promotion loop was a denylist-of-prefixes + natural-language-keyword
    # severity map; that produced 4-of-6 noise findings on FortiWeb run
    # 14714f2f (Platform: + No-CGI-found promoted as findings; nikto's own
    # footer reported 4 items, parser stored 6). The shape-gate rewrite +
    # Q1 header dedup + Q2 ID-bucket severity collapses noise without
    # losing real signal.
    findings, nikto_emitted, we_promoted = parse_nikto_findings(
        stdout, ctx.hostname
    )
    ctx.findings.extend(findings)
    ctx.total_requests += we_promoted

    # Footer guard — log warning if shape-matched count diverges from
    # nikto's own footer "N item(s) reported." Catches future parser
    # drift without failing the scan (the run already produced output).
    footer_count = extract_nikto_footer_count(stdout)
    if footer_count is not None and footer_count != nikto_emitted:
        log(f"  ⚠ nikto parser drift: footer says {footer_count} item(s), "
            f"shape-matched {nikto_emitted}. Investigate parse_nikto_findings.")

    log(f"  nikto: {nikto_emitted} reported, {we_promoted} promoted "
        f"({nikto_emitted - we_promoted} dropped by policy)")


# ─── ffuf (chunked) ─────────────────────────────────────────────────────
def run_ffuf_chunk(ctx: ScanContext, words: list[str],
                   chunk_name: str) -> tuple[int, str | None, dict | None, str]:
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

    2026-06-13 (batch 2 per-chunk B1 wiring):
      - tools_run.append moved to caller (run_ffuf_chunked) so the
        chunk_name with #index uniqueness lands consistently.
      - chunk_name parameter threads through: existing Layer 1
        mark_tool_degraded calls now stamp chunk_name (not "ffuf") AND
        raise DegradedRunError so Bug A's first-skip-aborts discipline
        holds for tool-specific failures too.
      - Return shape extended to (interesting, out_blob, parsed, stderr)
        so the caller can run Layer 2 is_tool_output_degraded with
        proper post-tool signals.
    """
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
        # Layer 1 (tool-specific). 2026-06-13: stamp the chunk_name (not
        # generic "ffuf") so the set-equality invariant in close_out is
        # satisfied AND raise per Bug A's first-skip-aborts discipline.
        # Previously stamped "ffuf" and returned 0 — was both the wrong
        # tool_status key AND a silent continuation that violated Bug A.
        mark_tool_degraded(ctx, chunk_name, "output_unreadable", stderr=stderr)
        raise DegradedRunError("ffuf_specific_degradation",
                               f"{chunk_name}: output_unreadable: {e!r}")

    ctx.artifacts.append(("ffuf", "json", out_blob))

    try:
        data = json.loads(out_blob)
    except Exception as e:
        log(f"  ffuf output parse failed: {e}")
        mark_tool_degraded(ctx, chunk_name, "parse_failed", stderr=stderr)
        raise DegradedRunError("ffuf_specific_degradation",
                               f"{chunk_name}: parse_failed: {e!r}")

    # ADR-001 Step 4 — structure check. results==[] is healthy ("no
    # matched paths in this chunk"); only the absence of the key entirely
    # signals a real failure. NOTE: mark_tool_ok deferred to the caller —
    # it runs the Layer 2 B1 check BEFORE deciding ok-vs-degraded, so we
    # only stamp ok at the end of the whole per-chunk pipeline.
    is_degraded, reason = ffuf_is_degraded(out_blob, data)
    if is_degraded:
        mark_tool_degraded(ctx, chunk_name, reason, stderr=stderr)
        raise DegradedRunError("ffuf_specific_degradation",
                               f"{chunk_name}: {reason}")

    results = data.get("results", [])
    ctx.total_requests += len(words)

    interesting = 0
    for r in results:
        status = r.get("status", 0)
        url = r.get("url", "")
        word = r.get("input", {}).get("FUZZ", "")
        redirect_to = r.get("redirectlocation", "") or ""
        ctx.response_codes[str(status)] += 1

        # #33 (2026-06-16) — catch-all redirect suppression. If the
        # baseline calibration at run_ffuf_chunked start detected a
        # host-wide redirect (every random path → same Location), each
        # per-path 302→same-L is non-discriminating noise. Count it
        # but don't emit a per-path finding; the collapsed summary at
        # end-of-chunked-loop emits ONE INFO covering all of them.
        # EXACT-equality semantic is locked in should_suppress_ffuf_redirect.
        if should_suppress_ffuf_redirect(redirect_to, ctx.ffuf_catchall_redirect):
            ctx.ffuf_catchall_count += 1
            continue

        # S3 Part 1 (2026-06-18) — catch-all STATUS suppression. Generalizes
        # the redirect path to any uniform non-discriminating status (403 on
        # a FortiGate-blanket-deny host, 401 on a uniformly auth-gated host,
        # 200 on a SPA / soft-404 host). Same EXACT-equality safety:
        # distinct statuses (real signal) still emit per-path. The collapsed
        # summary at end-of-chunked-loop emits ONE finding for all of them
        # (LOW for 403/401, INFO for 200/302). Locked in
        # should_suppress_ffuf_status.
        if should_suppress_ffuf_status(
            status, ctx.ffuf_catchall_status, redirect_to
        ):
            ctx.ffuf_catchall_status_count += 1
            continue

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

        # S3 Part 2 (2026-06-18) — kill blanket INFO. Severity by
        # (path-sensitivity × status) via curated SECRET_PATHS /
        # ADMIN_PATHS matchers + the matrix in classify_ffuf_severity.
        # A real hit on /.env (HIGH) or /admin (MODERATE) now surfaces
        # above the INFO noise floor; gated sensitive paths land at
        # LOW; generic + redirects stay INFO. UPSERT_FINDING_SQL's
        # max-severity ratchet (~L2543) keeps elevated rows elevated
        # across re-scans; #35 delta-close still closes on
        # last_seen_scan_run mismatch independent of severity (verified
        # in test_classify_ffuf_severity_does_not_interfere_with_close).
        severity = classify_ffuf_severity(word, url, status)

        interesting += 1
        ctx.findings.append(MediumFinding(
            check_name=f"ffuf-found-{word}",
            title=f"{title_kind}: /{word} (HTTP {status})",
            severity=severity,
            category="info_disclosure",
            description=(
                f"Directory fuzzing discovered /{word} on {ctx.hostname} "
                f"returning HTTP {status}. {desc_action}"
            ),
            tags=["ffuf", "directory", "discovery", f"status_{status}"],
            raw_excerpt=raw,
        ))

    # Per-chunk B1 wiring (2026-06-13) — return shape extended from
    # bare `interesting` to (interesting, out_blob, data, stderr) so the
    # caller can run Layer 2 is_tool_output_degraded. data is the parsed
    # JSON (None if parse failed — but that path raised above).
    return interesting, out_blob, data, stderr


def run_ffuf_chunked(ctx: ScanContext) -> None:
    """Run ffuf in chunks of FFUF_WORDS_PER_CHUNK words each, rotating
    VPN between chunks.
    """
    log("→ ffuf (chunked with mid-scan rotation)")

    # Slice the wordlist
    chunks = [FFUF_WORDS[i:i+FFUF_WORDS_PER_CHUNK]
              for i in range(0, len(FFUF_WORDS), FFUF_WORDS_PER_CHUNK)]

    # #24 Phase 2 — auth-gated skip. ffuf wordlist (/api, /admin, /v1,
    # /login, etc.) would 401/redirect uniformly on auth-gated targets
    # — zero discrimination signal. Skip ALL chunks (not just some), but
    # stamp each one as skipped to preserve set-equality + forensic record.
    if ctx.auth_gated:
        log("  ⊘ skip ffuf (all chunks) — asset is auth_gated (no unauth path surface)")
        for i, words in enumerate(chunks):
            chunk_name = f"ffuf[{len(words)}w]#{i+1}"
            ctx.tools_run.append(chunk_name)
            mark_tool_skipped(ctx, chunk_name, "auth_gated")
        return

    # #33 + S3 Part 1 (2026-06-16/18) — ffuf catch-all calibration. Probe
    # 2 random paths BEFORE the chunk loop. Two outcomes (one or the other
    # may fire; never both — calibration is hierarchical):
    #   (a) #33 — both probes 301/302/307 to same Location → catch-all
    #       redirect baseline. Per-path 302→same-L is non-discriminating
    #       noise, gets suppressed and collapsed to ONE INFO summary.
    #   (b) S3 Part 1 — both probes same non-404 non-redirect status (403
    #       on FortiGate-blanket-deny, 401 on uniform-auth, 200 on SPA /
    #       soft-404) → catch-all status baseline. Per-path matching status
    #       gets suppressed and collapsed to ONE LOW (403/401) or INFO
    #       (200/etc) summary.
    # Calibration is chunk-agnostic — single baseline applied across all
    # chunks via ctx.ffuf_catchall_{redirect,status}. Suppression logic in
    # run_ffuf_chunk emit loop; collapsed summaries at end of this function.
    # See detect_ffuf_catchall docstring for safety analysis vs. the
    # 59ad6a13 regression (blanket -fc/-fs/-fr filter that hid real
    # /admin/swagger). Both suppression paths use EXACT-equality, never
    # blanket filtering — distinct statuses (real signal) always survive.
    ctx.ffuf_catchall_redirect, ctx.ffuf_catchall_status = (
        detect_ffuf_catchall(ctx)
    )
    if ctx.ffuf_catchall_redirect:
        log(f"  ffuf catch-all calibration: host redirects random paths "
            f"→ {ctx.ffuf_catchall_redirect} (per-path matches will be "
            f"suppressed + collapsed into one summary INFO)")
    elif ctx.ffuf_catchall_status is not None:
        log(f"  ffuf catch-all calibration: host returns HTTP "
            f"{ctx.ffuf_catchall_status} uniformly to random paths "
            f"(per-path matches at that status will be suppressed + "
            f"collapsed into one summary)")
    else:
        log("  ffuf catch-all calibration: no host-wide redirect or status "
            "catch-all detected (per-path emission unchanged)")

    for i, words in enumerate(chunks):
        # 2026-06-13: chunk_name uses #index to disambiguate ffuf[25w]#1
        # vs ffuf[25w]#2 vs ffuf[25w]#3 — duplicate-word-count chunks
        # would collapse in set(tools_run) otherwise and break the
        # close_out invariant. Naming matches the abort-path convention
        # from batch 1.
        chunk_name = f"ffuf[{len(words)}w]#{i+1}"
        log(f"chunk {i+1}/{len(chunks)}: {len(words)} words ({chunk_name})")

        healthy, egress_reason = ensure_healthy_egress(ctx, max_rotations=2)
        if not healthy:
            # #30 reason taxonomy: egress_unstable vs skipped_target_unreachable.
            log(f"  ✗ pre-chunk healthy gate failed ({egress_reason}) — ABORT ({chunk_name})")
            note_ban_event(ctx, {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "chunk_skipped_unreachable",
                "chunk": chunk_name,
                "reason": egress_reason,
            })
            if chunk_name not in ctx.tools_run:
                ctx.tools_run.append(chunk_name)
            mark_tool_degraded(ctx, chunk_name, egress_reason)
            raise DegradedRunError(
                egress_reason,
                f"{chunk_name} after {ctx.rotation_count} rotations",
            )

        # Per-chunk B1 wiring (2026-06-13). tools_run.append moved out
        # of run_ffuf_chunk; happens here BEFORE the run so the abort
        # path inside run_ffuf_chunk (output_unreadable / parse_failed /
        # ffuf_is_degraded) has the chunk_name already in tools_run.
        ctx.tools_run.append(chunk_name)
        pre_healthy = True  # we just passed ensure_healthy_egress
        interesting, out_blob, parsed, chunk_stderr = run_ffuf_chunk(
            ctx, words, chunk_name
        )
        log(f"  chunk {i+1} done: {interesting} 200/204 finding(s)")

        # Layer 2: unconditional post-chunk healthcheck + B1 detector.
        # Layer 1 (ffuf_is_degraded) ran inside run_ffuf_chunk and
        # raised on failure — if we reach here, Layer 1 cleared.
        post_chunk_healthy, _ = healthcheck(ctx)
        b1_reason = is_tool_output_degraded(
            tool=chunk_name,
            stdout=out_blob or "",
            stderr=chunk_stderr,
            rc=0,  # we'd have raised if rc had triggered Layer 1
            pre_health=pre_healthy,
            post_health=post_chunk_healthy,
        )
        if b1_reason:
            mark_tool_degraded(ctx, chunk_name, b1_reason, stderr=chunk_stderr)
            raise DegradedRunError(b1_reason, chunk_name)
        mark_tool_ok(ctx, chunk_name)
        # #32 — chunk completed cleanly → tool reached target. Establishes
        # target_proven_reachable for the prior-tool-success short-circuit.
        ctx.target_proven_reachable = True

        if i < len(chunks) - 1:
            rotate_vpn(ctx)

        if ctx.total_requests >= MAX_REQUESTS_TOTAL:
            log(f"hit hard request ceiling — stopping ffuf")
            break

    # #33 (2026-06-16) — collapsed catch-all redirect summary. Helper does
    # the emit + idempotency check. See emit_ffuf_catchall_summary docstring.
    if ctx.ffuf_catchall_count > 0 and ctx.ffuf_catchall_redirect:
        log(f"  ffuf catch-all summary: {ctx.ffuf_catchall_count} per-path "
            f"matches collapsed into 1 INFO (all → {ctx.ffuf_catchall_redirect})")
    emit_ffuf_catchall_summary(ctx)

    # S3 Part 1 (2026-06-18) — collapsed catch-all status summary. Helper
    # does the emit + idempotency check. Severity LOW for 403/401, INFO for
    # 200/etc. See emit_ffuf_catchall_status_summary docstring.
    if ctx.ffuf_catchall_status_count > 0 and ctx.ffuf_catchall_status is not None:
        log(f"  ffuf catch-all status summary: "
            f"{ctx.ffuf_catchall_status_count} per-path matches collapsed "
            f"into 1 finding (all → HTTP {ctx.ffuf_catchall_status})")
    emit_ffuf_catchall_status_summary(ctx)


# ─── SQL helpers (DUPED from run_light — TODO: refactor) ───────────────
#
# 2026-06-07 ADR-001: writes validation_status + scanner_version +
# validated_at on every emission.
#
# 2026-06-13 trust-layer fix (Parts 3 + 4 + Bug D):
#   • Part 3 — DERIVE-ON-WRITE semantics. The old upgrade-only CASE
#     ("once validated, stays validated") let a finding remain
#     'validated' even after the SHA it pointed at was retracted, or
#     after an unvalidated re-emit. The invariant we want everywhere is
#     simpler: validation_status follows the CURRENT scanner_version's
#     active-set membership. Re-emit at retracted/unvalidated SHA →
#     demote to 'unvalidated' + NULL validated_at. Re-emit at validated
#     SHA → promote to 'validated' + stamp validated_at=now(). This
#     keeps the implication chain airtight: derive_validation_status
#     (Part 2) filters retracted SHAs out at read-time; this UPSERT
#     re-derives at write-time; degraded_out (Part 4) demotes on
#     scan-quality flip; the re-sweep (Part 5) heals any historical
#     drift. Advisor leans 1+2 approved 2026-06-13.
#   • Bug D — populate first_detected_scan on INSERT, PRESERVE on
#     UPDATE. Before this fix the column was NEVER written by the
#     runner (only by manual backfills), which made the ce47fc27
#     scan-keyed backfill match 0 rows and turned Part 4's degraded_out
#     update keyed on `first_detected_scan = scan_run_id` into a no-op.
#     The COALESCE protects existing rows: a re-detect by a newer
#     scan_run never clobbers the original first-detection scan_run_id
#     (paired with first_detected_at LEAST semantics).
#
UPSERT_FINDING_SQL = """
INSERT INTO public.findings (
    finding_id, asset_id, title, severity, category, description,
    cwe, "references", current_status, first_detected_at,
    last_observed_at, source, tags,
    validation_status, scanner_version, validated_at,
    first_detected_scan, last_seen_scan_run
)
VALUES (%(finding_id)s, %(asset_id)s, %(title)s, %(severity)s, %(category)s,
        %(description)s, %(cwe)s, %(references)s, 'detected',
        now(), now(), %(source)s, %(tags)s,
        %(validation_status)s, %(scanner_version)s,
        CASE WHEN %(validation_status)s = 'validated' THEN now() ELSE NULL END,
        %(scan_run_id)s, %(scan_run_id)s)
ON CONFLICT (finding_id) DO UPDATE SET
    title             = EXCLUDED.title,
    category          = EXCLUDED.category,
    description       = EXCLUDED.description,
    current_status = CASE
      WHEN findings.current_status IN (
             'remediated', 'validated_remediated',
             'false_positive', 'wont_fix', 'accepted_risk',
             -- Note 129 round 7 — `regressed` is now sticky while open.
             -- Pre-round-7 a re-observation flipped regressed → detected
             -- via the ELSE branch, erasing the "this was fixed and
             -- came back" signal one scan after the regress fn set it
             -- (the cert_chain_of_trust churn 4.8 caught on
             -- ftp.sciimage.com #800 → #801). The regress fn is gated
             -- on current_status IN (remediated, validated_remediated)
             -- so it can't re-flip a sticky-regressed row → no churn
             -- in the other direction either. Regressed exits via the
             -- same paths remediated does: note-127 auto-closer (when
             -- the producer stops re-observing) or admin queue.
             'regressed'
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
    -- Trust-layer Part 3 — derive-on-write (replaces upgrade-only CASE).
    -- validation_status follows the CURRENT scanner_version's active-set
    -- membership. Promote AND demote. Re-validation on a different
    -- emit happens naturally on the next re-detect by a validated SHA.
    validation_status = EXCLUDED.validation_status,
    -- Always record the latest emitter SHA for forensic context.
    scanner_version   = EXCLUDED.scanner_version,
    -- Trust-layer Part 3 — validated_at follows validation_status.
    -- Promote (any→validated): stamp now().
    -- Demote (validated→unvalidated): NULL the field (advisor lean 2).
    -- No transition: preserve existing value.
    validated_at = CASE
      WHEN EXCLUDED.validation_status = 'validated'
       AND findings.validation_status <> 'validated'
        THEN now()
      WHEN EXCLUDED.validation_status <> 'validated'
       AND findings.validation_status =  'validated'
        THEN NULL
      ELSE findings.validated_at
    END,
    -- Bug D — preserve original first_detected_scan. COALESCE protects
    -- against re-detect by a different scan_run clobbering the lineage.
    -- Same one-way semantics as first_detected_at (LEAST). New INSERTs
    -- get %(scan_run_id)s; subsequent UPDATEs keep the original.
    first_detected_scan = COALESCE(findings.first_detected_scan, EXCLUDED.first_detected_scan),
    -- #35 — stamp the observing scan_run on EVERY observation (EXCLUDED, not
    -- COALESCE — unlike first_detected_scan). This is the signal delta-close
    -- keys on: a finding NOT re-stamped by the current run wasn't re-observed.
    last_seen_scan_run = EXCLUDED.last_seen_scan_run
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
    tool_status       = %(tool_status)s,
    -- SPEC_SCANNER_DEGRADATION_HARDENING.md (Bug C, 2026-06-12) — VPN
    -- forensics columns. Populated for clean AND degraded scans so
    -- every "why didn't this find X" investigation reads here instead
    -- of the GH Actions log.
    egress_ip         = %(egress_ip)s,
    vpn_config_used   = %(vpn_config_used)s,
    rotation_log      = %(rotation_log)s
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

# SPEC_SCANNER_DEGRADATION_HARDENING.md Bug A + Bug C — degraded close-out.
# Distinct from FAIL (which is operational/code error). Reads as
# "ran but didn't really scan the target."
# Migration 20260612a added 'degraded' to scan_run_status_t + scan_status_t
# and extended trg_scan_queue_sync_on_scan_run_terminal to fire on it.
DEGRADED_SCAN_RUN_SQL = """
UPDATE public.scan_run
SET status            = 'degraded',
    completed_at      = now(),
    duration_seconds  = EXTRACT(EPOCH FROM (now() - started_at))::int,
    tools_run         = %(tools_run)s,
    findings_added    = %(findings_added)s,
    findings_updated  = %(findings_updated)s,
    tool_status       = %(tool_status)s,
    error_message     = %(error)s,
    egress_ip         = %(egress_ip)s,
    vpn_config_used   = %(vpn_config_used)s,
    rotation_log      = %(rotation_log)s
WHERE scan_run_id     = %(scan_run_id)s;
"""

DEGRADED_SCAN_QUEUE_SQL = """
UPDATE public.scan_queue
SET status            = 'degraded',
    completed_at      = now(),
    duration_seconds  = EXTRACT(EPOCH FROM (now() - started_at))::int,
    findings_count    = %(findings_count)s,
    error_message     = %(error)s
WHERE queue_id        = %(queue_id)s;
"""

# Flip scan_quality on any findings already written by this scan_run.
# Idempotent. Belt + suspenders even though the trigger sync alone is
# sufficient at the scan_run level — finding-level scan_quality is what
# the re-validation UPSERT actually reads to refuse laundering.
#
# Trust-layer fix Part 4 (2026-06-13): also demote validation_status →
# 'unvalidated' and NULL validated_at. The two columns move together
# because the invariant treats them as one assertion: "this finding
# was emitted by a clean scan_run under a validated SHA." If the run
# turned degraded, that assertion no longer holds — validation_status
# must follow scan_quality. Without this, a degraded run that detected
# new findings under a validated SHA would leave those rows
# (validation_status='validated' AND scan_quality='degraded') — the
# exact contradiction class the acceptance gate is supposed to catch.
#
# Scope note: keyed on first_detected_scan = %(scan_run_id)s — touches
# ONLY the findings this scan_run first detected. Existing findings
# re-detected by this degraded run keep their prior status (a degraded
# re-detect should not retroactively degrade a prior clean detection;
# advisor scope note on #4). Pairs with Bug D fix above — before Bug D
# the column was always NULL and this query matched zero rows.
STAMP_FINDINGS_DEGRADED_SQL = """
UPDATE public.findings
   SET scan_quality      = 'degraded',
       validation_status = 'unvalidated',
       validated_at      = NULL
 WHERE first_detected_scan = %(scan_run_id)s
   AND (
         scan_quality      = 'clean'
      OR validation_status = 'validated'
       );
"""


def write_findings_and_artifacts(conn, ctx: ScanContext, Json) -> tuple[int, int]:
    inserted = 0
    updated = 0
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
                # Bug D fix (paired with trust-layer Part 4) — populate
                # first_detected_scan so degraded_out's update keyed on
                # `first_detected_scan = scan_run_id` actually matches
                # rows, and so forensics queries can join findings to
                # the scan_run that first detected them. COALESCE in
                # the UPSERT preserves the original on re-detects.
                "scan_run_id": ctx.scan_run_id,
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


# ─── finding_history writer (note 129 round 7) ──────────────────────────
#
# After all transition logic runs (UPSERT + delta_close + regress in
# medium; UPSERT + regress in heavy), stamp one finding_history row
# per finding the scan re-emitted. Status captured is the FINAL
# current_status — so a finding that was flipped to 'remediated' by
# delta_close, or to 'regressed' by regress_observed_for_scan_run,
# gets that final value recorded in history (not the intermediate
# status the UPSERT wrote pre-flip).
#
# WHERE last_seen_scan_run = scan_run_id scopes the write to
# findings this scan actually re-emitted — same signal delta_close
# and regress use. ON CONFLICT (finding_id, scan_id) DO NOTHING
# guarantees idempotency: re-running the close-out (e.g., transient
# commit failure + retry) doesn't write duplicates.
#
# scan_id = scan_run_id::text is now safe because the FK to
# legacy scans was dropped in migration 20260629b. Free-text column
# accepts either an offline-import scan_id (existing rows) or a
# scan_run UUID-as-text (new rows from live runs).
#
# CLEAN PATH ONLY. Caller chooses when to invoke this — typically
# from close_out (medium) or run() clean branch (heavy) AFTER all
# status flips have landed. Calling from a degraded close-out would
# stamp history rows whose status field can't be trusted (a degraded
# scan's last_seen stamps are partial / inconsistent), so the
# convention is: don't.

INSERT_FINDING_HISTORY_FOR_SCAN_RUN_SQL = """
INSERT INTO public.finding_history
    (finding_id, scan_id, observed_at, status, severity_at_scan, notes)
SELECT
    f.finding_id,
    %(scan_run_id)s,
    now(),
    -- Round 7 follow-up #2: EXPLICIT enum → text → target-enum cast.
    -- findings.current_status is finding_status_t; finding_history.status
    -- is history_status_t — two distinct enum types with no direct
    -- cast between them. Postgres ALSO has no IMPLICIT text → enum
    -- assignment cast (live #811 proved my round-7-follow-up
    -- assumption wrong); the target column required an explicit
    -- cast. The double-cast pattern is the supported idiom:
    --   source_enum::text::target_enum
    -- Migration 20260629c made sure every finding_status_t label
    -- exists in history_status_t so the text → history_status_t
    -- cast cannot fail on a valid input.
    -- ('absent' is history-only — write_finding_history never emits
    -- it; it's reserved for offline reconciliation paths.)
    f.current_status::text::history_status_t,
    -- severity_at_scan is enum severity_t — SAME type as
    -- findings.severity — so no cast needed (would be a no-op
    -- round-trip if added).
    f.severity,
    %(notes)s
  FROM public.findings f
 WHERE f.last_seen_scan_run = %(scan_run_id)s
ON CONFLICT (finding_id, scan_id) DO NOTHING;
"""


def write_finding_history_for_scan_run(
    conn, scan_run_id: str, notes: str | None = None,
) -> int:
    """Stamp finding_history with one row per finding re-emitted this
    scan. status = the FINAL current_status (post-close, post-regress).
    Returns the count of rows actually inserted (ON CONFLICT DO NOTHING
    will not count collisions). Safe to call multiple times — second
    call inserts nothing because of the unique constraint.

    Note 129 round 7 (FINDING_HISTORY_FIX_SPEC.md). Both heavy and
    medium call this from their clean-path close-out so the per-
    finding observation timeline keeps growing on every re-scan.
    """
    with conn.cursor() as cur:
        cur.execute(
            INSERT_FINDING_HISTORY_FOR_SCAN_RUN_SQL,
            {"scan_run_id": scan_run_id, "notes": notes},
        )
        # psycopg's rowcount reflects the rows actually inserted;
        # ON CONFLICT skips are not counted (good — we want the
        # post-dedup count for forensics).
        return cur.rowcount if cur.rowcount is not None else 0


def close_out(conn, ctx: ScanContext, inserted: int, updated: int, Json) -> None:
    # SPEC_SCANNER_DEGRADATION_HARDENING.md Bug B2 (ruling ⑦): set-equality
    # invariant. Every tool in tools_run must have a tool_status entry.
    # This raises DegradedRunError("tool_status_invariant", ...) if it
    # fails, which the top-level run() catches and routes to degraded_out
    # — silent-skipped tools never make it past this gate.
    assert_tool_status_invariant(ctx.tools_run, ctx.tool_status)

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
            # Bug C — VPN forensics (SPEC_SCANNER_DEGRADATION_HARDENING.md).
            "egress_ip": ctx.egress_ip_initial,
            "vpn_config_used": ctx.vpn_config_used,
            "rotation_log": Json(build_rotation_log(ctx)),
        }
        cur.execute(CLOSE_SCAN_RUN_SQL, params)
        cur.execute(CLOSE_SCAN_QUEUE_SQL, params)

        # #35 — live-path delta-close. Called ONLY from close_out (the clean
        # exit); degraded_out NEVER calls it, so a degraded scan can't close
        # anything — the structural safety guard against false-remediation.
        # Finer gate: ALL tools must be 'ok'. A skipped/degraded tool means a
        # partial scan that must NOT close (it didn't re-run everything). The
        # live medium writes one source per scan (commandsentry_{intensity}),
        # so one ineligible tool blocks the whole scan's closing — the safe
        # side. Runs AFTER CLOSE_SCAN_RUN_SQL (scan_run.completed_at now set =
        # remediated_at) and in the SAME txn — committed together by run().
        eligible = delta_close_eligible(ctx.tool_status)
        if eligible:
            # Pass the EXACT source the writes used (f"commandsentry_{intensity}")
            # so the close scopes to write-source by construction — not re-derived
            # from scan_run.intensity (avoids any standard/medium normalization gap).
            cur.execute(
                "SELECT delta_close_for_scan_run(%s, %s) AS n_closed",
                (ctx.scan_run_id, f"commandsentry_{ctx.intensity}"),
            )
            # conn is dict_row — read the aliased column by NAME, not [0]
            # (indexing a dict-row with 0 raises KeyError(0)).
            _dc_row = cur.fetchone()
            n_closed = (_dc_row["n_closed"] if _dc_row else 0) or 0
            if n_closed:
                log(f"delta-close: {n_closed} finding(s) marked remediated "
                    f"(open, not re-observed this clean scan)")
            else:
                log("delta-close: 0 closed (nothing went stale this scan)")

            # Note 129 round 6 — sibling reopen path. delta_close handles
            # "open + not seen → remediated"; regress_observed_for_scan_run
            # handles the inverse "remediated + seen → regressed" (notes
            # 126 invariant: remediated_at cleared on the flip). Disjoint
            # WHERE clauses (open-set vs remediated-set, <> vs =) so
            # order-independent and idempotent — once regressed, subsequent
            # scans skip the row. Same source token + clean-path gate as
            # the close above.
            cur.execute(
                "SELECT regress_observed_for_scan_run(%s, %s) AS n_regressed",
                (ctx.scan_run_id, f"commandsentry_{ctx.intensity}"),
            )
            _rg_row = cur.fetchone()
            n_regressed = (_rg_row["n_regressed"] if _rg_row else 0) or 0
            if n_regressed:
                log(f"regress-on-observed: {n_regressed} previously-remediated "
                    f"finding(s) re-emitted → flipped to 'regressed', "
                    f"remediated_at cleared (audit rows in admin_audit_log)")
            else:
                log("regress-on-observed: 0 flipped (no returned remediated findings)")

            # Note 129 round 7 — finding_history per re-emitted finding.
            # Runs AFTER delta_close + regress so the recorded status is
            # FINAL for this scan (remediated/regressed/whatever).
            # Same eligibility gate as close + regress (delta_close_
            # eligible) — degraded/skipped tool blocks all three.
            n_history = write_finding_history_for_scan_run(
                conn, ctx.scan_run_id,
                notes=f"observed by run_medium scan_run {ctx.scan_run_id}",
            )
            if n_history:
                log(f"finding-history: {n_history} observation row(s) "
                    f"written (scan_id={ctx.scan_run_id})")
            else:
                log("finding-history: 0 rows written (no re-emitted findings)")
        else:
            log("delta-close + regress-on-observed + finding-history: skipped "
                "— scan not fully clean (a tool degraded/skipped); neither "
                "close, reopen, nor observation history will fire on partial "
                "evidence")


def fail_out(conn, ctx: ScanContext, error: str) -> None:
    with conn.cursor() as cur:
        params = {
            "error": error,
            "scan_run_id": ctx.scan_run_id,
            "queue_id": ctx.queue_id,
        }
        cur.execute(FAIL_SCAN_RUN_SQL, params)
        cur.execute(FAIL_SCAN_QUEUE_SQL, params)


def flush_artifacts_to_db(conn, ctx: ScanContext, Json) -> int:
    """Write any artifacts collected in ctx.artifacts to scan_run_artifacts.

    Used by degraded_out (and safe to call from any path that needs to
    flush partial artifacts after an abort). Returns the number of
    artifacts successfully written.

    Per-artifact try/except — a single bad blob does NOT kill the whole
    flush. This is critical in degraded_out where the caller is already
    in error-handling mode: a raise mid-flush would lose the entire
    scan_run / scan_queue degraded-stamping path and leave the queue
    row stuck at 'running'.

    2026-06-15 (Task #21 [1b]): added to plug the forensics gap surfaced
    by myordersauth prod (d0cbe39e) + test (bd2cef8f) 2026-06-14. Before
    this, raise DegradedRunError → conn.rollback() discarded every
    ctx.artifacts row written pre-abort, and degraded_out never re-wrote
    them. Result: scan_run_artifacts had 0 rows for every degraded
    scan_run despite wafw00f / httpx / nuclei chunks / etc. having
    appended their outputs to ctx.artifacts. The runs we most need to
    debug had zero stored forensics.

    NOT called from write_findings_and_artifacts — the clean path uses
    its own inline loop because all-or-nothing semantics there are
    correct (if an artifact insert fails clean-path, we WANT close_out
    to fail-and-degrade, which routes us here, which then per-artifact
    retries). Don't unify the two — different correctness models.
    """
    written = 0
    with conn.cursor() as cur:
        for tool_name, output_format, content_str in ctx.artifacts:
            try:
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
                written += 1
            except Exception as e:
                # Per-artifact insulation. log + continue. degraded_out
                # CANNOT raise mid-flush or we lose the scan_run /
                # scan_queue stamping (queue row sticks at 'running',
                # partial unique index blocks future scans on the asset).
                log(f"flush_artifacts: skipped {tool_name!r} due to {e!r}")
    return written


def reconcile_tool_status_invariant(ctx: ScanContext) -> None:
    """Force set(tools_run) == set(tool_status.keys()) on ctx, in place.

    Called from degraded_out BEFORE the persist write so the persisted
    scan_run row is always invariant-clean regardless of which abort
    path fired. assert_tool_status_invariant only runs in close_out (the
    clean path); the degraded path used to skip it entirely, which let
    set-equality gaps persist silently (see scan_run
    648313cd-d734-4b7f-b639-1f272dfdb48e, 2026-06-13: tools_run had 3
    entries, tool_status had 4 keys, no error surfaced).

    Reconciles, does NOT raise (we're already degrading; raising a
    second time wouldn't add signal). Two directions:

      1. tool_status-only keys → append to tools_run. The stamp is
         already there (probably from a pre-chunk gate that aborted
         BEFORE the per-chunk tools_run.append); we trust the stamp
         and let tools_run catch up.

      2. tools_run-only entries → stamp `degraded:no_status_recorded`.
         These are tools that ran but the post-run mark_tool_ok /
         mark_tool_degraded never landed (interrupted between append
         and stamp — rare, but possible). Marking degraded preserves
         the launder-block lock: any finding from this scan_run is
         already scan_quality=degraded via STAMP_FINDINGS_DEGRADED_SQL,
         and the tool_status reflects that we don't fully trust its
         output.

    Fix A (line ~1351, nuclei pre-chunk abort) makes case 1 not happen
    in steady state, so this reconcile is the safety net not the
    workhorse. Belt + suspenders, advisor-approved 2026-06-13.
    """
    tools_set  = set(ctx.tools_run)
    status_set = set(ctx.tool_status.keys())

    # Case 1: stamped but not in tools_run → append to tools_run.
    for missing_in_tools in (status_set - tools_set):
        ctx.tools_run.append(missing_in_tools)

    # Case 2: in tools_run but not stamped → stamp degraded:no_status_recorded.
    for missing_in_status in (tools_set - status_set):
        mark_tool_degraded(ctx, missing_in_status, "no_status_recorded")


def degraded_out(conn, ctx: ScanContext, error: str,
                 inserted: int, updated: int, Json) -> None:
    """Stamp scan_run.status='degraded', scan_queue.status='degraded',
    AND flip findings.scan_quality='degraded' for any findings already
    written by this scan_run.

    Spec: SPEC_SCANNER_DEGRADATION_HARDENING.md. Distinct from fail_out
    (which is operational error). Reads as "ran but didn't really scan."

    Caller (run() top-level) catches DegradedRunError, then either:
      (a) finishes the write phase up to this point (any partial
          findings get written THEN flipped to scan_quality=degraded), OR
      (b) skips the write phase entirely and calls this directly.

    Either way, the re-validation UPSERT in scanner_validations land
    will refuse to flip these findings to validated because the
    `WHERE scan_quality='clean'` filter excludes them.

    2026-06-13: pre-persist invariant reconcile. Forces
    set(tools_run) == set(tool_status.keys()) before the row hits the
    DB so the degraded scan_run row is always set-consistent regardless
    of which abort path fired. Cheap safety net behind Fix A. See
    reconcile_tool_status_invariant docstring for the full rationale.
    """
    # Pre-persist reconcile — forces the invariant on ctx BEFORE the
    # row is persisted. Reconciles instead of raising (we're already
    # degrading) so the abort path can't leave inconsistent state.
    reconcile_tool_status_invariant(ctx)

    # Task #21 [1b] — flush forensic artifacts collected pre-abort.
    # Before this, raise DegradedRunError → conn.rollback() discarded
    # every ctx.artifacts row, and degraded scan_runs had 0 rows in
    # scan_run_artifacts. nikto stdout, wafw00f, httpx, nuclei chunk
    # output — all lost. Now we re-flush from ctx (in-memory list, not
    # affected by rollback) before stamping the degraded state. Best-
    # effort: per-artifact try/except in flush_artifacts_to_db means
    # one bad blob doesn't crash the stamping that follows.
    artifacts_written = flush_artifacts_to_db(conn, ctx, Json)
    log(f"degraded_out: flushed {artifacts_written}/{len(ctx.artifacts)} "
        f"forensic artifact(s) before stamping")

    with conn.cursor() as cur:
        params = {
            "error": error,
            "tools_run": ctx.tools_run,
            "findings_added": inserted,
            "findings_updated": updated,
            "findings_count": inserted + updated,
            "scan_run_id": ctx.scan_run_id,
            "queue_id": ctx.queue_id,
            "tool_status": Json(ctx.tool_status or {}),
            "egress_ip": ctx.egress_ip_initial,
            "vpn_config_used": ctx.vpn_config_used,
            "rotation_log": Json(build_rotation_log(ctx)),
        }
        cur.execute(DEGRADED_SCAN_RUN_SQL, params)
        cur.execute(DEGRADED_SCAN_QUEUE_SQL, params)
        # Belt + suspenders: flip scan_quality on any partial findings.
        cur.execute(STAMP_FINDINGS_DEGRADED_SQL,
                    {"scan_run_id": ctx.scan_run_id})


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

    # ─── ROE / ownership pull-time gate (S3 safety interlock) ───────────
    # MUST run before ANY target-bound network op (no DNS, no curl, no
    # tool — nothing). Catches direct-REST + SQL-Editor inserts that
    # bypassed the portal-side helper. Fails closed on any uncertainty
    # (db error / missing asset / unknown ownership / NULL → BLOCK).
    #
    # On block: stamps scan_run + scan_queue to failed with
    # error_message='roe_block: ownership=...', best-effort SendGrid
    # alert via portal /api/roe-block-alert. Caller exit code splits on
    # GateResult.is_routine_refusal():
    #   - True (ownership_not_allowed) → exit 0. The scanner correctly
    #     refused the request — that's success, not failure. Routine
    #     refusals shouldn't fire "Scanner: All jobs have failed."
    #   - False (asset_not_found, db_error, gate exception) → exit 1.
    #     Gate failed closed because something was broken; the GH
    #     Actions run should go RED so we notice.
    #
    # The DB stamp + SendGrid alert happen in BOTH cases — those are the
    # durable audit + visibility surfaces and don't depend on exit code.
    #
    # Site rationale: descriptor parse + intensity check are local-only;
    # ScanContext construction below is in-memory; capture_egress_ip
    # hits a third-party (ifconfig.me) NOT the scan target — but to
    # keep the gate the first thing that happens after we know what
    # asset we're being asked to scan, we run it here, before any
    # network op of any kind.
    try:
        from roe_gate import check_ownership_or_block
    except ImportError as e:
        log(f"FATAL: roe_gate module not importable: {e!r} — aborting (fail-closed, exit 1)")
        return 1
    # Open a transient DB connection just for the gate. We can't use the
    # main run-phase connection (it's lazy-opened at write time, post-scan).
    gate_conn = None
    try:
        gate_conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
        gh_url = os.environ.get("GITHUB_SERVER_URL") and os.environ.get("GITHUB_REPOSITORY") and os.environ.get("GITHUB_RUN_ID")
        gh_run_url = (
            f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
            if gh_url
            else None
        )
        # Surface the actual ingress in the alert: read scan_queue.source
        # so "Triggered via: workflow_dispatch" / "manual" is meaningful
        # instead of the generic "Likely causes" list. Best-effort — if
        # this lookup fails, the alert still fires with queue_source=None
        # and the template falls back gracefully.
        queue_source = None
        try:
            with gate_conn.cursor() as cur:
                cur.execute(
                    "SELECT source FROM public.scan_queue WHERE queue_id = %s",
                    (descriptor["queue_id"],),
                )
                qrow = cur.fetchone()
                if qrow is not None:
                    queue_source = qrow["source"] if isinstance(qrow, dict) else qrow[0]
        except Exception as e:
            log(f"[gate] could not read scan_queue.source for alert enrichment: {e!r}")

        block = check_ownership_or_block(
            conn=gate_conn,
            asset_id=descriptor["asset_id"],
            intensity=descriptor["intensity"],
            scan_run_id=descriptor["scan_run_id"],
            queue_id=descriptor["queue_id"],
            github_run_url=gh_run_url,
            queue_source=queue_source,
        )
    except Exception as e:
        log(f"FATAL: ROE gate raised: {e!r} — aborting (fail-closed, exit 1)")
        try:
            if gate_conn is not None:
                gate_conn.close()
        except Exception:
            pass
        return 1
    finally:
        try:
            if gate_conn is not None:
                gate_conn.close()
        except Exception:
            pass

    if block is not None:
        log(
            f"ROE BLOCK — asset={block.asset_id} intensity={block.intensity} "
            f"ownership={block.ownership!r} reason={block.reason}"
        )
        log(f"  message: {block.message}")
        log("  zero target-bound tools ran. scan_run + scan_queue stamped failed.")
        if block.is_routine_refusal():
            # Policy-compliant refusal — DB stamp + alert fired; workflow
            # goes GREEN so routine blocks don't pollute the failure-email
            # signal. Real failures (asset_not_found, db_error) still go
            # RED via the else branch.
            log("  routine refusal — exit 0 (workflow stays green).")
            return 0
        log("  gate failed closed on uncertainty — exit 1 (workflow goes red).")
        return 1

    # ─── Gate cleared — proceed with normal medium scan ─────────────────
    asset = descriptor["asset"]
    ctx = ScanContext(
        descriptor=descriptor,
        hostname=derive_hostname(asset),
        asset_id=descriptor["asset_id"],
        scan_run_id=descriptor["scan_run_id"],
        queue_id=descriptor["queue_id"],
        intensity=descriptor["intensity"],
        # Live scan progress (note 103) — flush_progress reads this to
        # open its short-lived autocommit conn per call. None elsewhere
        # (validate-mode + tests) → flush_progress is a no-op.
        dsn=dsn,
    )
    log(f"asset_id={ctx.asset_id} hostname={ctx.hostname} scan_run_id={ctx.scan_run_id}")

    # ─── #24 Phase 2 — read auth_gated from asset_surface ────────────────
    # Local-only DB query (no target-bound op) — fine to run before the
    # validate-mode pre-flight. Transient connection, mirrors ROE gate
    # pattern. Fail-safe: any failure or missing row → False (run all
    # tools). NEVER silently skip when uncertain — defaulting to "skip
    # everything" on a read error would erase scan coverage.
    try:
        auth_conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=True)
        try:
            with auth_conn.cursor() as cur:
                cur.execute(
                    "SELECT auth_gated FROM public.asset_surface WHERE asset_id = %s",
                    (ctx.asset_id,),
                )
                row = cur.fetchone()
                if row is not None:
                    ctx.auth_gated = bool(
                        row["auth_gated"] if isinstance(row, dict) else row[0]
                    )
        finally:
            auth_conn.close()
    except Exception as e:
        log(f"auth_gated read failed (defaulting to False — fail-safe): {e!r}")
    if ctx.auth_gated:
        log(f"asset is auth_gated — will SKIP nikto + ffuf + nuclei attack/cve/"
            f"exposure/wordpress/iis/php/drupal/joomla chunks. Keep wafw00f + "
            f"httpx + nuclei[medium:tech]. Recommend authenticated DAST.")

    # ─── Validate-mode flag read — actual assert deferred until inside `try` below ─
    # If skip_vpn=true was set on the workflow_dispatch input, the runner
    # is NOT on Mullvad and would scan from the GH Actions datacenter
    # egress. That's only safe against allowlisted public training
    # targets. Anything else → DegradedRunError, status='degraded',
    # exit 1. Fires BEFORE capture_egress_ip + any tool call.
    #
    # Negative-test fix 2026-06-12 (post first negative-test run):
    # The assert call MUST run INSIDE the `try` block so DegradedRunError
    # is caught by the `except DegradedRunError` handler and routed to
    # degraded_out (which stamps scan_run.status='degraded' + scan_queue
    # via trigger + scan_quality on any findings). Without that, the
    # exception escapes, Python crashes with a traceback, and the
    # always() cleanup stamps the row as generic 'failed' — which loses
    # the validate-mode signal AND undermines the launder-block lock.
    # First negative test exposed exactly this bookkeeping bug.
    skip_vpn = os.environ.get("SKIP_VPN", "").lower() in ("true", "1", "yes")
    # Batch 2 step c — tie ctx.validate_mode to the same SKIP_VPN env so
    # rotate_vpn + ensure_healthy_egress can't diverge from the interlock.
    # Single source of truth: SKIP_VPN env reaches BOTH the allowlist
    # interlock AND the rotation/retry suppression. Setting one without
    # the other would either (a) try to rotate a non-existent tunnel
    # during a legit validate run, or (b) skip rotation during a normal
    # run — neither is acceptable.
    ctx.validate_mode = skip_vpn
    if skip_vpn:
        log(f"validate_mode active — skip_vpn={skip_vpn}; "
            f"VALIDATION_TARGETS={sorted(VALIDATION_TARGETS)}; "
            f"rotation SUPPRESSED, health retries = 0 "
            f"(no rotation against tunnel-less direct egress)")

    start_egress = capture_egress_ip()
    if start_egress:
        ctx.egress_ips_seen.append(start_egress)
        log(f"pre-scan egress IP: {start_egress}")
        # SPEC_SCANNER_DEGRADATION_HARDENING.md Bug C — persist the
        # initial egress + VPN config so scan_run.egress_ip and
        # vpn_config_used aren't NULL when VPN is up. Previously
        # captured locally only; now stored on ctx for close_out /
        # degraded_out to write.
        ctx.egress_ip_initial = start_egress
    ctx.vpn_config_used = capture_vpn_config_used()
    if ctx.vpn_config_used:
        log(f"vpn config in use: {ctx.vpn_config_used}")

    # DB connection deferred until write phase. Scan #35 (2026-05-30)
    # showed Supabase closes idle connections after 7+ min, and we
    # used to open at scan-start which idled the whole Medium tier.
    # Now we open right before the writes.
    conn = None

    end_egress = None
    try:
        # ─── Phase 0: validate-mode safety interlock (batch 2 step a) ──
        # Runs INSIDE the try block so DegradedRunError lands in the
        # `except DegradedRunError` handler below and routes cleanly to
        # degraded_out (which stamps scan_run.status='degraded' +
        # propagates to scan_queue via the 20260612b trigger). Placed
        # BEFORE detect_waf — the first target-bound op.
        #
        # ALWAYS call the assert — when skip_vpn=False it short-circuits
        # without checking the allowlist. Single safety primitive,
        # single source of truth, no caller-side conditionals to drift.
        assert_validate_mode_target_allowed(ctx.hostname, skip_vpn)
        if skip_vpn:
            log(f"validate_mode pre-flight OK — {ctx.hostname!r} in allowlist")

        # ─── Phase 1: WAF detection ─────────────────────────────────
        log("→ detect_waf")
        detect_waf(ctx)
        log("→ detect_tech_stack")
        detect_tech_stack(ctx)

        # ─── Live scan progress (note 103) — write planned_steps ────
        # Now that Phase 1 has populated tech_stack + waf_detected, and
        # auth_gated was read at descriptor-load time, build_chunk_plan
        # produces the actual nuclei chunk names. Write once — drives
        # the portal denominator. Best-effort: write failure logs +
        # continues (planned_steps stays NULL on scan_run, portal
        # renders "Scanning…" without a total — graceful degrade).
        ctx.planned_steps = build_planned_steps(ctx)
        log(f"planned_steps ({len(ctx.planned_steps)} total): "
            f"{ctx.planned_steps}")
        flush_planned_steps(ctx)

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

    except DegradedRunError as e:
        # SPEC_SCANNER_DEGRADATION_HARDENING.md Bug A / B / C.
        # Distinct from the generic FATAL path: degradation means the
        # runner correctly detected "we're not actually scanning the
        # target." Stamp scan_run.status='degraded' (NOT 'failed'),
        # flip findings.scan_quality='degraded' on any partial writes,
        # exit 1 so the GH Actions run goes RED. Workflow exit 1 is
        # the right signal: degradation IS a failure of the scan even
        # though the runner didn't crash.
        log(f"DEGRADED: {e.reason} — {e.context}")
        log(f"  tools_run at abort: {ctx.tools_run}")
        log(f"  tool_status keys:    {sorted(ctx.tool_status.keys())}")
        log(f"  rotation_count:      {ctx.rotation_count}")
        log(f"  ban_events:          {len(ctx.ban_events)}"
            f"{' (capped — rotation storm)' if ctx.rotation_storm else ''}")
        if conn is None:
            try:
                conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
            except Exception as e2:
                log(f"could not open DB to mark scan degraded: {e2!r}")
                return 1
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            # No partial-write commit here — degraded scans don't produce
            # trusted findings. inserted=0 / updated=0 reflects what is
            # PERSISTED to the DB after the txn rollback above (line 2301
            # `conn.rollback()` discards any uncommitted findings from
            # write_findings_and_artifacts when the close-out invariant
            # raised mid-write). Three of the four raise sites (the
            # chunk-skip aborts at 1244/1370/1684) happen pre-write, so
            # there's nothing to roll back for those. The fourth — the
            # assert_tool_status_invariant call inside close_out (line
            # 1991) — fires AFTER write_findings_and_artifacts BUT the
            # rollback above is what discards those rows; do NOT remove
            # that rollback in a future cleanup or junk findings start
            # committing on invariant failures.
            degraded_out(conn, ctx, f"degraded: {e.reason}: {e.context}",
                         inserted=0, updated=0, Json=Json)
            conn.commit()
            log(f"scan_run + scan_queue stamped degraded; "
                f"findings.scan_quality flipped if any.")
        except Exception as e2:
            log(f"degraded_out also failed: {e2!r}")
        return 1
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
