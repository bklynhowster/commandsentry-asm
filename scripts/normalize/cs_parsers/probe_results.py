"""
probe_results.py — Parse phase04 backup/config-file probe results into
FindingEvents.

The intensive-scan script does a `curl -sI` sweep of ~40 sensitive paths
(wp-config*, .env*, .git/*, backup.zip, debug.log, readme.html, etc.)
and dumps the result table to `probe-results.txt`. Format (whitespace-
separated, three columns):

    403       146B  /wp-config.php
    403       146B  /.env
    200      7425B  /readme.html
    200     19903B  /license.txt
    200      1443B  /wp-admin/upgrade.php
    404     55815B  /backup.zip
    301         0B  /sitemap.xml

We emit a finding for each row where the HTTP status was 2xx AND the
path is on our "interesting" list. 4xx/5xx mean the WAF or framework
properly denied access — those are good and we don't emit findings for
them. Redirects (3xx) are noisy and rarely useful.

Severity logic:
  - .git/, .env, wp-config.php variants leaking content → CRITICAL (but
    these almost always return 403 against modern hosts; if they DO
    leak, that's a real disaster)
  - phpinfo.php, info.php, test.php exposing PHP info → HIGH
  - readme.html, license.txt, wp-config-sample.php → INFO (fingerprint)
  - wp-admin/upgrade.php, install.php exposed → MODERATE (allows
    forcing an upgrade prompt or hint at admin endpoint)
  - Directory listing on /wp-content/plugins/<name>/ → LOW (info
    disclosure of installed plugins; common but flaggable)
  - Anything else 200 OK on the watch list → LOW
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from .common import (
    FindingEvent,
    infer_asset_id,
    now_iso,
    relative_to_scan_root,
    stable_finding_id,
    to_utc_iso,
)


# Match rows like "  200      7425B  /readme.html"
ROW_RE = re.compile(
    r"^\s*(\d{3})\s+(\d+)B?\s+(\S+)\s*$"
)

# Paths that are public by design and should NEVER generate findings even
# when reachable. The probe script tests these as sanity controls; their
# 200 response is the expected outcome, not a leak.
PUBLIC_BY_DESIGN = {
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/wp-sitemap.xml",
    "/humans.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/favicon.ico",
}


def _classify(path: str, size_bytes: int) -> tuple[str, str, str]:
    """
    Return (severity, category, reason) for a 2xx-returning path.
    `reason` becomes the human-readable finding title segment.

    NOTE: `category` MUST be one of the values in the DB's
    `finding_category_t` enum (sast/dast/sca/secret/recon/tls/headers/dns/
    email/auth/session/csrf/ssrf/xxe/xss/sqli/idor/rce/lfi/redirect/
    info_disclosure/takeover/typosquat/config/deprecation/supply_chain/
    other). We map our detailed semantic categories onto this vocabulary;
    the human-readable `reason` carries the specifics into the title.
    """
    p = path.lower()

    # Disaster tier — sensitive files NEVER want to be reachable
    if any(p.startswith(x) for x in ("/.git/", "/.svn/", "/.hg/")):
        return ("CRITICAL", "secret", "VCS metadata exposed")
    if p in ("/.env", "/.env.bak", "/.env.local", "/.env.production"):
        return ("CRITICAL", "secret", ".env file exposed")
    if p.startswith("/wp-config.php") and size_bytes > 100:
        return ("CRITICAL", "secret", "wp-config.php content exposed")
    if p in ("/db.sql", "/database.sql", "/backup.sql"):
        return ("CRITICAL", "secret", "Database dump exposed")

    # PHP info / test endpoints
    if p in ("/phpinfo.php", "/info.php", "/test.php") and size_bytes > 500:
        return ("HIGH", "info_disclosure", "PHP info page exposed")

    # WP admin endpoints — exposed but not necessarily exploitable
    if p == "/wp-admin/install.php":
        return ("MODERATE", "config", "WordPress install page exposed")
    if p == "/wp-admin/upgrade.php":
        return ("MODERATE", "config", "WordPress upgrade page exposed")

    # Backup files actually returning content
    if any(p.endswith(x) for x in (".zip", ".tar", ".tar.gz", ".sql.gz")) and size_bytes > 1024:
        return ("HIGH", "secret", "Backup archive accessible")
    if p == "/wp-content/debug.log" and size_bytes > 100:
        return ("HIGH", "info_disclosure", "WordPress debug log exposed")

    # Fingerprint / info disclosure
    if p == "/readme.html":
        return ("INFO", "info_disclosure", "WordPress readme.html exposed")
    if p == "/license.txt":
        return ("INFO", "info_disclosure", "WordPress license.txt exposed")
    if p == "/wp-config-sample.php":
        return ("LOW", "config", "wp-config-sample.php exposed")
    if "/.ds_store" in p:
        return ("LOW", "info_disclosure", ".DS_Store exposed")

    # Plugin/theme directory listings — Apache "Index of" pages
    if p.startswith("/wp-content/plugins/") or p.startswith("/wp-content/themes/"):
        return ("LOW", "info_disclosure", "Plugin/theme directory listing")
    if p.startswith("/wp-content/mu-plugins/"):
        return ("LOW", "info_disclosure", "MU-plugins directory listing")

    return ("LOW", "info_disclosure", f"Sensitive path returned 2xx: {path}")


def parse_probe_results_file(
    txt_path: Path,
    asset_id: str,
    scan_id: str,
    scan_root: Path,
    fallback_observed_at: Optional[str],
) -> list[FindingEvent]:
    try:
        text = txt_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    rel_evidence = relative_to_scan_root(txt_path, scan_root)
    observed_at = to_utc_iso(fallback_observed_at) or now_iso()

    events: list[FindingEvent] = []
    for line in text.splitlines():
        m = ROW_RE.match(line)
        if not m:
            continue
        try:
            status = int(m.group(1))
            size_bytes = int(m.group(2))
            path = m.group(3)
        except (TypeError, ValueError):
            continue

        # We only care about 2xx — 4xx means WAF / framework denied (good)
        if not (200 <= status < 300):
            continue
        # Skip clearly-empty bodies; many 200/0B are framework no-ops
        if size_bytes == 0 and path not in ("/wp-content/plugins/akismet/", "/wp-content/mu-plugins/"):
            continue
        # Skip paths that are public by design (robots.txt, sitemaps, etc.)
        if path in PUBLIC_BY_DESIGN:
            continue

        severity, category, reason = _classify(path, size_bytes)

        title = f"{reason}: {path}"
        template_id = f"probe-results:{category}:{path}"
        matched_at = f"{asset_id}{path}"

        description = (
            f"Path **{path}** returned HTTP {status} ({size_bytes} bytes) "
            f"during the backup/config-file sweep.\n\n"
            f"This means the path exists and is reachable. "
            f"Expected behavior is 403 (WAF block) or 404 (not present). "
            f"A 2xx response indicates content is being served to anonymous callers."
        )

        events.append(
            FindingEvent(
                finding_id=stable_finding_id(asset_id, "probe_results", template_id, matched_at),
                asset_id=asset_id,
                scan_id=scan_id,
                # source must match finding_source_t enum. `other` is the
                # honest fit for a curl-based path probe sweep — it's not
                # produced by any of the named tools in the enum.
                source="other",
                title=title,
                severity=severity,
                category=category,
                observed_at=observed_at,
                matched_at=matched_at,
                description=description,
                cve=[],
                cwe=[200],  # CWE-200 Information Exposure (general)
                references=[],
                raw_excerpt=line.strip(),
                evidence_paths=[rel_evidence],
            )
        )

    return events


def parse(target_entry: dict, scan_entry: dict, scan_root: Path) -> list[FindingEvent]:
    target = target_entry["target"]
    asset_id = infer_asset_id(target)

    scan_run_dir = scan_entry["scan_run_dir"]
    if scan_run_dir.startswith("(target-root") or scan_run_dir == "_target_root":
        scan_id = f"{target}__synthetic_root"
    else:
        scan_id = f"{target}__{scan_run_dir}"

    scan_run_abs = Path(scan_entry["absolute_path"])
    fallback_ts = scan_entry.get("inferred_started_at")

    events: list[FindingEvent] = []
    for tool in scan_entry.get("tools_detected", []):
        if tool.get("parser") != "probe_results":
            continue
        for rel_file in tool.get("files", []):
            events.extend(
                parse_probe_results_file(
                    txt_path=scan_run_abs / rel_file,
                    asset_id=asset_id,
                    scan_id=scan_id,
                    scan_root=scan_root,
                    fallback_observed_at=fallback_ts,
                )
            )
    return events
