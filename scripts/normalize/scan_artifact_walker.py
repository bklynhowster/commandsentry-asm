#!/usr/bin/env python3
"""
scan_artifact_walker.py — Path C enrichment

Mines structured data from the per-target scan output folders sitting on disk
under ~/Downloads/ISMS Procedures/Vulnerability Scanning/{target}/, and back-
fills the structured columns on existing findings rows in Supabase.

What it parses:
  - plugin_versions.txt   — explicit plugin_slug: version mappings
  - nuclei_results.txt    — tech detection, plugin slugs, matched URLs
  - wpscan.txt            — WordPress version, plugin enumeration
  - nikto_results.txt.txt — OSVDB references, server banners
  - testssl.json          — TLS version + cipher detail

What it writes (non-destructive merge):
  - affected_component                — only if currently NULL
  - affected_component_version        — only if currently NULL
  - matched_url                       — only if currently NULL
  - tags                              — union with existing
  - cve                               — union (additive)

Why "walker" and not just another synth pass:
  - Deterministic. No LLM cost. Same input always produces same output.
  - Authoritative. The data IS in the scan files — no inference, no guess.
  - Cheap. Half a second per finding. ~5 minutes for the whole fleet.

Usage:
  # Dry-run on every supported scan folder
  python scripts/normalize/scan_artifact_walker.py --dry-run

  # Real run on every folder
  python scripts/normalize/scan_artifact_walker.py

  # Real run on a single target folder
  python scripts/normalize/scan_artifact_walker.py \\
    --folder ~/Downloads/ISMS\\ Procedures/Vulnerability\\ Scanning/unimacgraphics/www-deep

Environment:
  SUPABASE_URL                — from .env
  SUPABASE_SERVICE_ROLE_KEY   — from .env
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ─── Config ─────────────────────────────────────────────────────────────────

DEFAULT_SUPABASE_URL = "https://hdygktppfvuspnumpfuq.supabase.co"

# Default base for per-target scan folders on Howie's Mac.
DEFAULT_SCAN_ROOT = Path.home() / "Downloads" / "ISMS Procedures" / "Vulnerability Scanning"

# Map per-target scan-folder names to the asset_id used in the findings table.
# This is the bridge between "what's in the filesystem" and "what's in the DB".
# Add new mappings here as new targets get scanned.
FOLDER_TO_ASSET: dict[str, str] = {
    # filesystem folder name           → DB asset_id
    "unimacgraphics":                    "unimacgraphics.com",
    "commanddigital":                    "commanddigital.com",
    "commandcompanies":                  "commandcompanies.com",
    "commandcommcentral":                "commandcommcentral.com",
    "commandmarketinginnovations":       "commandmarketinginnovations.com",
    # Aliases — some folders contain a "www" or "www-deep" subdir; the
    # walker handles those automatically. These are the top-level folder
    # names that map to assets.
}


# ─── Plugin-slug normalization ──────────────────────────────────────────────
# Scanner outputs use various slug formats (mega_main_menu, MegaMainMenu,
# "Mega Main Menu"). We normalize to a canonical "slug form" for matching
# finding titles against scanner data.

def normalize_slug(s: str) -> str:
    """Lowercase, replace separators with single space, collapse whitespace."""
    if not s:
        return ""
    out = re.sub(r"[_\-\.\s]+", " ", s.lower()).strip()
    return out


# Friendly name table — used when populating affected_component. Maps
# canonical slug → display name. Falls back to title-case of the slug.
PLUGIN_DISPLAY_NAMES: dict[str, str] = {
    "mega main menu":           "Mega Main Menu",
    "email encoder bundle":     "Email Encoder Bundle",
    "nextgen gallery":          "NextGen Gallery",
    "nextgen gallery pro":      "NextGen Gallery Pro",
    "revslider":                "Slider Revolution",
    "slider revolution":        "Slider Revolution",
    "js composer":              "WPBakery Page Builder",
    "wpbakery":                 "WPBakery Page Builder",
    "wp smushit":               "WP Smush",
    "wpfront scroll top":       "WPFront Scroll Top",
    "toolset":                  "Toolset",
    "toolset blocks":           "Toolset Blocks",
    "wordpress seo":            "Yoast SEO",
    "yoast":                    "Yoast SEO",
    "wordfence":                "Wordfence",
    "akismet":                  "Akismet",
    "jetpack":                  "Jetpack",
    "wpforms":                  "WPForms",
    "userway accessibility widget": "UserWay Accessibility Widget",
    "elementor":                "Elementor",
    "elementor pro":            "Elementor Pro",
    "oceanwp":                  "OceanWP",
}

# Reverse alias map — friendly names / common variations → canonical slug
# the scanner actually emits. Lets a finding titled "Slider Revolution
# Outdated" match the scanner-emitted "revslider" plugin record. Keys are
# normalize_slug() form.
SLUG_ALIASES: dict[str, str] = {
    "slider revolution":        "revslider",
    "wpbakery":                 "js composer",
    "wpbakery page builder":    "js composer",
    "visual composer":          "js composer",
    "yoast seo":                "wordpress seo",
    "yoast":                    "wordpress seo",
    "wp smush":                 "wp smushit",
    "smush":                    "wp smushit",
}


def display_name_for(slug: str) -> str:
    """Best-effort display name for a plugin slug."""
    norm = normalize_slug(slug)
    if norm in PLUGIN_DISPLAY_NAMES:
        return PLUGIN_DISPLAY_NAMES[norm]
    # Fallback — title-case each word
    return " ".join(w.capitalize() for w in norm.split())


# ─── Scan-output parsers ────────────────────────────────────────────────────

@dataclass
class PluginRecord:
    slug: str
    version: Optional[str]
    matched_url: Optional[str]
    source: str                          # which scanner reported this


@dataclass
class ArtifactIndex:
    """In-memory index built from one target's scan output folder."""
    target_folder: Path
    asset_id: str
    plugins: list[PluginRecord] = field(default_factory=list)
    wp_version: Optional[str] = None
    themes: list[PluginRecord] = field(default_factory=list)
    waf: Optional[str] = None
    server_banner: Optional[str] = None
    tls_versions: list[str] = field(default_factory=list)
    extra_tags: set[str] = field(default_factory=set)

    def find_plugin(self, *keywords: str) -> Optional[PluginRecord]:
        """Return the first plugin whose canonical slug matches any keyword.
        Keywords are normalized to slug form before comparison, then resolved
        through the alias table so finding-title friendly names ("Slider
        Revolution") match scanner-emitted slugs ("revslider").
        Substring match is bidirectional but only counts when the shorter
        side is >= 4 characters to avoid spurious "wp" → "wpforms" hits."""
        targets = []
        for k in keywords:
            n = normalize_slug(k)
            if not n:
                continue
            targets.append(n)
            if n in SLUG_ALIASES:
                targets.append(SLUG_ALIASES[n])
        # Try the MOST SPECIFIC target first (longest = more specific) so
        # "nextgen gallery pro" wins over "nextgen gallery" even when the
        # base plugin happens to appear earlier in self.plugins.
        sorted_targets = sorted(set(targets), key=len, reverse=True)

        # Pass 1: exact match
        for t in sorted_targets:
            for p in self.plugins:
                if t and t == normalize_slug(p.slug):
                    return p
        # Pass 2: substring (longer side >= 4 chars on both)
        for t in sorted_targets:
            for p in self.plugins:
                ns = normalize_slug(p.slug)
                if t and len(t) >= 4 and len(ns) >= 4 and (t in ns or ns in t):
                    return p
        return None


def parse_plugin_versions(path: Path) -> list[PluginRecord]:
    """
    Parse the homepage-fallback section of plugin_versions.txt:

        === Homepage ver= Fallback ===
        email-encoder-bundle: 2 (homepage ver=)
        js_composer: 8.7.2 (homepage ver=)
        mega_main_menu: 2.2.1 (homepage ver=)
    """
    out: list[PluginRecord] = []
    if not path.exists():
        return out
    in_fallback = False
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if "Homepage ver= Fallback" in line:
            in_fallback = True
            continue
        if in_fallback and line and ":" in line and not line.startswith("="):
            # "slug: version (homepage ver=)" or "slug: BLOCKED (403)"
            slug, rest = line.split(":", 1)
            rest = rest.strip()
            if rest.startswith("BLOCKED"):
                continue
            # Strip trailing "(homepage ver=)" parenthetical
            version = re.sub(r"\s*\(.*\)\s*$", "", rest).strip()
            if version:
                out.append(PluginRecord(
                    slug=slug.strip(),
                    version=version,
                    matched_url=None,
                    source="plugin_versions.txt",
                ))
    return out


# Match nuclei lines like:
#   [wordpress-plugin-detect:wp-smushit] [http] [info] https://... [...metadata...]
NUCLEI_PLUGIN_DETECT_RE = re.compile(
    r"\[wordpress-plugin-detect:([\w\-\.]+)\]\s+\[http\]\s+\[\w+\]\s+(\S+)",
)
# Match version-bearing URLs like /wp-content/plugins/{slug}/...?ver={version}
NUCLEI_VER_URL_RE = re.compile(
    r"/wp-content/plugins/([\w\-\.]+)/[^\"\s]*?\?ver=([\w\.\-]+)",
)
# Match nuclei wordpress-detect:version_by_js
NUCLEI_WP_VERSION_RE = re.compile(
    r"\[wordpress-detect:version_by_js\][^\"]*\[\"([\d\.]+)\"\]",
)
# Match nuclei waf-detect
NUCLEI_WAF_RE = re.compile(r"\[waf-detect:([\w\-\.]+)\]")
# Match nuclei passive plugin slug list:
#   [wordpress-passive-detection:plugin_slug] [http] [info] URL ["slug","slug",...]
NUCLEI_PASSIVE_SLUGS_RE = re.compile(
    r"\[wordpress-passive-detection:plugin_slug\][^\[]+\[(.+?)\]",
)


def parse_nuclei(path: Path) -> tuple[list[PluginRecord], Optional[str], Optional[str], set[str]]:
    """Parse nuclei_results.txt → (plugin records, wp_version, waf, tags)"""
    plugins: dict[str, PluginRecord] = {}
    wp_version: Optional[str] = None
    waf: Optional[str] = None
    tags: set[str] = set()

    if not path.exists():
        return [], None, None, tags

    for raw in path.read_text(errors="replace").splitlines():
        # WordPress version
        m = NUCLEI_WP_VERSION_RE.search(raw)
        if m:
            wp_version = m.group(1)
            tags.add("wordpress")
            tags.add(f"wp-{m.group(1)}")

        # WAF
        m = NUCLEI_WAF_RE.search(raw)
        if m:
            waf = m.group(1)
            tags.add(f"waf-{m.group(1)}")

        # Plugin slugs explicitly detected
        m = NUCLEI_PLUGIN_DETECT_RE.search(raw)
        if m:
            slug = m.group(1)
            url = m.group(2)
            if slug not in plugins:
                plugins[slug] = PluginRecord(slug=slug, version=None, matched_url=url, source="nuclei")
            tags.add(slug.replace("_", "-"))

        # Versioned plugin URLs — better source for affected_component_version
        for vm in NUCLEI_VER_URL_RE.finditer(raw):
            slug = vm.group(1)
            ver = vm.group(2)
            if slug in plugins:
                if not plugins[slug].version:
                    plugins[slug].version = ver
                if not plugins[slug].matched_url:
                    plugins[slug].matched_url = f"/wp-content/plugins/{slug}/"
            else:
                plugins[slug] = PluginRecord(
                    slug=slug,
                    version=ver,
                    matched_url=f"/wp-content/plugins/{slug}/",
                    source="nuclei-ver-url",
                )

        # Passive-detection slug list
        m = NUCLEI_PASSIVE_SLUGS_RE.search(raw)
        if m:
            for slug in re.findall(r'"([^"]+)"', m.group(1)):
                if slug not in plugins:
                    plugins[slug] = PluginRecord(
                        slug=slug, version=None, matched_url=None, source="nuclei-passive",
                    )
                tags.add(slug.replace("_", "-"))

        # Tech-detect tags (nginx, php, etc.)
        m = re.search(r"\[tech-detect:([\w\-]+)\]", raw)
        if m:
            tags.add(m.group(1))

    return list(plugins.values()), wp_version, waf, tags


def parse_wpvuln_jsons(target_folder: Path) -> list[PluginRecord]:
    """Parse all wpvuln-<slug>.json files found anywhere under the target.

    These files are produced by intensive-scan-*.sh at
    `phase02-versions/wpvuln-<slug>.json` and contain the
    wpvulnerability.net response for that plugin including
    `installed_version`. That's the most-authoritative version source
    we have — it's what the scanner actually detected on disk at the
    plugin's readme/changelog endpoint, not a cachebuster `?ver=` query
    string.

    Search strategy: `target_folder` is usually a specific scan-run dir
    (e.g. commandmarketinginnovations/www-deep). Intensive-scan wpvuln
    files live in a SIBLING dir under the same target parent (e.g.
    commandmarketinginnovations/intensive-scan-2026-05-23/phase02-versions/).
    We rglob from the target_folder first; if nothing found, walk up one
    level to the target parent and rglob across all sibling scan-runs.

    If multiple intensive scans exist under the same target, the most
    recent file (by mtime) wins per plugin slug.
    """
    by_slug: dict[str, tuple[float, PluginRecord]] = {}

    # Search under the passed folder first; if nothing turns up, expand to
    # the target parent so we pick up sibling intensive-scan-* dirs.
    search_roots = [target_folder]
    parent = target_folder.parent
    if parent != target_folder and parent.exists():
        search_roots.append(parent)

    for root in search_roots:
        for fp in root.rglob("wpvuln-*.json"):
            if not fp.is_file():
                continue
            try:
                data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            if data.get("type") != "plugin":
                continue
            slug = data.get("slug")
            if not slug:
                continue
            installed = data.get("installed_version")
            if not installed:
                continue
            mtime = fp.stat().st_mtime
            slug_key = normalize_slug(slug)
            cur = by_slug.get(slug_key)
            if cur is None or mtime > cur[0]:
                by_slug[slug_key] = (
                    mtime,
                    PluginRecord(
                        slug=slug,
                        version=str(installed),
                        matched_url=None,
                        source="wpvulnerability.net",
                    ),
                )
        # If we found wpvuln files at this level, don't bother with the
        # broader parent search — first hit wins.
        if by_slug:
            break
    return [rec for _, rec in by_slug.values()]


def merge_plugins(*lists: list[PluginRecord]) -> list[PluginRecord]:
    """Merge plugin records from multiple sources.

    Version-authoritativeness ordering (highest first):
      1. wpvulnerability.net (`installed_version` from the API response —
         scanner actually fetched the plugin file and matched the hash)
      2. plugin_versions.txt (homepage-fallback explicit pinning)
      3. nuclei / homepage cachebuster `?ver=` (least reliable)

    nuclei still wins on matched_url since wpvuln doesn't carry URLs.
    """
    by_slug: dict[str, PluginRecord] = {}
    for lst in lists:
        for p in lst:
            slug_key = normalize_slug(p.slug)
            if slug_key not in by_slug:
                by_slug[slug_key] = PluginRecord(
                    slug=p.slug, version=p.version, matched_url=p.matched_url, source=p.source,
                )
                continue
            cur = by_slug[slug_key]
            # wpvulnerability.net is the MOST authoritative version source.
            # It overrides anything previously set.
            if p.version and p.source == "wpvulnerability.net":
                cur.version = p.version
                cur.source = p.source
            # plugin_versions.txt is next — only overrides if current source
            # isn't already wpvulnerability.net.
            elif p.version and p.source == "plugin_versions.txt" and cur.source != "wpvulnerability.net":
                cur.version = p.version
                cur.source = p.source
            elif p.version and not cur.version:
                cur.version = p.version
            if p.matched_url and not cur.matched_url:
                cur.matched_url = p.matched_url
    return list(by_slug.values())


def build_index(folder: Path, asset_id: str) -> ArtifactIndex:
    """Build a single target's artifact index from all parseable scan files."""
    idx = ArtifactIndex(target_folder=folder, asset_id=asset_id)

    # plugin_versions.txt — explicit pinning (legacy flat layout)
    pv_records = parse_plugin_versions(folder / "plugin_versions.txt")

    # nuclei_results.txt — plugin slugs, matched URLs, WP version, WAF, tech tags
    nuc_records, wp_version, waf, tags = parse_nuclei(folder / "nuclei_results.txt")

    # wpvuln JSONs (phase02 of intensive scans) — authoritative installed_version
    wpv_records = parse_wpvuln_jsons(folder)

    idx.wp_version = wp_version
    idx.waf = waf
    idx.extra_tags.update(tags)
    # Merge order matters when both sources have versions; merge_plugins'
    # priority logic uses the `source` field, so the list order here is
    # informational only.
    idx.plugins = merge_plugins(pv_records, nuc_records, wpv_records)

    return idx


# ─── Finding → artifact matcher ─────────────────────────────────────────────

# Common words to strip when extracting component name from a finding title.
TITLE_STRIP = re.compile(
    r"\b(plugin|theme|version|outdated|abandoned|vulnerable|cve-\d{4}-\d+|"
    r"cvss\s*\d+\.\d+|high|medium|moderate|low|critical|info)\b",
    re.I,
)
# Match leading IDs like "F-01:", "M-04 -", etc.
TITLE_LEADER = re.compile(r"^\s*[A-Z]+-\d+\s*[:\-—]\s*")


def extract_keywords_from_title(title: str) -> list[str]:
    """Turn a finding title into candidate keywords to match against plugin slugs.

    The title can have a lot of shapes:
      "F-01: Abandoned Plugin — Mega Main Menu 2.2.1 (CVE-2023-1575)"
      "F-02: Email Encoder Bundle — Outdated with 7 Known CVEs"
      "Slider Revolution Outdated"
      "WPBakery Page Builder Outdated"

    Strategy: drop the leader, then look at EVERY dash-separated segment AND
    every sliding 2/3/4-word window of the cleaned title. The product is
    many candidate keyword strings; find_plugin() handles dedupe and
    short-string rejection.
    """
    t = title or ""
    t = TITLE_LEADER.sub("", t)                                 # drop "F-01: "
    t = re.sub(r"\(CVE-\d{4}-\d+\)", "", t)                     # drop trailing CVE tag
    t = re.sub(r"\d+(?:\.\d+)+", "", t)                         # drop version numbers
    t = TITLE_STRIP.sub("", t)
    # Each dash/colon-separated segment is a candidate
    segments = re.split(r"\s*[—\-:\(]+\s*", t)
    candidates: list[str] = []
    for seg in segments:
        seg = seg.strip()
        if len(seg) >= 4:
            candidates.append(seg)
        # Sliding 2/3/4-word windows inside the segment
        words = seg.split()
        for window in (4, 3, 2):
            for i in range(len(words) - window + 1):
                phrase = " ".join(words[i : i + window])
                if len(phrase) >= 4:
                    candidates.append(phrase)
    # De-dupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for c in candidates:
        k = c.lower()
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out


def parse_nuclei_oneliner(raw: str) -> dict:
    """
    Parse the short text-format nuclei output we see in many raw_excerpt
    fields:

      [CVE-2024-2473] [http] [medium] https://host/path
      [tech-detect:nginx] [http] [info] https://host

    The most useful field here is the URL — when it's a CVE-tagged template,
    that URL is the actual matched-at endpoint where the scanner triggered
    the finding (e.g. /wp-admin/?action=postpass for the WPS Hide Login bug).
    Far more useful than the generic '/wp-content/plugins/.../' fallback.

    Returns dict with:
      matched_url:  str   — captured URL
      cve:          list  — when the [template-id] is CVE-shaped
    """
    raw = (raw or "").strip()
    if not raw.startswith("["):
        return {}
    # Pattern: [template-id] [type] [severity] URL [...extra...]
    m = re.match(
        r"\[([^\]]+)\]\s+\[(\w+)\]\s+\[(\w+)\]\s+(https?://\S+)",
        raw,
    )
    if not m:
        return {}
    template_id = m.group(1)
    url = m.group(4)
    out: dict = {"matched_url": url}
    # If the template ID is CVE-shaped, expose it
    cve_match = re.match(r"^(CVE-\d{4}-\d+)$", template_id, re.I)
    if cve_match:
        out["cve"] = [cve_match.group(1).upper()]
    return out


def parse_testssl_json_excerpt(raw: str) -> dict:
    """
    Parse a testssl.sh JSON record. Shape:

      {"id": "DROWN_hint", "ip": "host/1.2.3.4", "port": "443",
       "severity": "INFO", "cve": "CVE-2016-0800 CVE-2016-0703",
       "cwe": "CWE-310", "finding": "..."}

    `cve` is a SPACE-SEPARATED string, not an array. `cwe` is a single string
    in "CWE-N" form. Both fields are optional.

    Returns dict of fields to merge (cve list, cwe list, port int) — only
    the ones that were present and non-empty.
    """
    import json as _json
    raw = (raw or "").strip()
    if not raw or not raw.startswith("{"):
        return {}
    try:
        obj = _json.loads(raw)
    except (_json.JSONDecodeError, ValueError):
        return {}
    if not isinstance(obj, dict):
        return {}
    # Shape check — testssl records always have these
    if not ({"id", "severity", "finding"} <= set(obj.keys())):
        return {}

    out: dict = {}

    # CVE — split space-separated string, normalize
    if obj.get("cve"):
        cves: list[str] = []
        for c in str(obj["cve"]).split():
            s = c.strip().upper()
            if re.match(r"CVE-\d{4}-\d+", s):
                cves.append(s)
        if cves:
            out["cve"] = sorted(set(cves))

    # CWE — single "CWE-NNN" or sometimes "CWE-NNN CWE-MMM"
    if obj.get("cwe"):
        cwes: list[int] = []
        for m in re.finditer(r"CWE-?(\d+)", str(obj["cwe"]), re.I):
            cwes.append(int(m.group(1)))
        if cwes:
            out["cwe"] = sorted(set(cwes))

    # Port — populate if numeric
    if obj.get("port"):
        try:
            out["port"] = int(obj["port"])
        except (TypeError, ValueError):
            pass

    return out


def parse_nuclei_json_excerpt(raw: str) -> dict:
    """
    Some findings have their full nuclei JSON record stored in
    finding_history.raw_excerpt. Parse it and return a dict of
    structured fields the walker can use. Returns {} if not parseable
    nuclei JSON.

    Returns keys (only the ones present in the input):
      cvss_score:    float — info.classification.cvss-score
      cvss_vector:   str   — info.classification.cvss-metrics
      cwe:           list[int] — info.classification.cwe-id (e.g. "cwe-200" → 200)
      cve:           list[str] — info.classification.cve-id (uppercase)
      matched_url:   str   — top-level "matched-at" field
      tags:          list[str] — info.tags
      severity:      str   — info.severity (lower-case)
      affected_component:         str — info.name parsed (e.g. "WPS Hide Login" from "WPS Hide Login <= 1.9.15.2 - ...")
      affected_component_version: str — version from info.name if present after "<= "
    """
    import json as _json
    raw = (raw or "").strip()
    if not raw or not raw.startswith("{"):
        return {}
    # Try strict parse first
    obj = None
    try:
        obj = _json.loads(raw)
    except (_json.JSONDecodeError, ValueError):
        # Truncated JSON — the original ingest cut off raw_excerpt mid-string.
        # Fall back to regex extraction of just the high-value nested fields.
        # This is targeted at the nuclei shape — we know exactly what keys to
        # look for.
        info_match = re.search(r'"info"\s*:\s*\{(.*?)\}\s*,\s*"', raw, re.DOTALL)
        cls_match = re.search(
            r'"classification"\s*:\s*\{([^}]*)\}', raw, re.DOTALL,
        )
        if not cls_match and not info_match:
            return {}
        # Reconstruct a partial dict that the rest of this function can read
        obj = {"info": {"classification": {}}}
        if cls_match:
            cls_text = "{" + cls_match.group(1) + "}"
            try:
                obj["info"]["classification"] = _json.loads(cls_text)
            except _json.JSONDecodeError:
                pass
        # Also extract top-level "matched-at" since it lives outside info
        ma = re.search(r'"matched-at"\s*:\s*"([^"]+)"', raw)
        if ma:
            obj["matched-at"] = ma.group(1)
        # Try to extract info.name from anywhere
        nm = re.search(r'"name"\s*:\s*"([^"]+)"', raw)
        if nm:
            obj["info"]["name"] = nm.group(1)
        # info.tags
        tg = re.search(r'"tags"\s*:\s*\[([^\]]+)\]', raw)
        if tg:
            tags = re.findall(r'"([^"]+)"', tg.group(1))
            if tags:
                obj["info"]["tags"] = tags
    if not isinstance(obj, dict):
        return {}
    info = obj.get("info") or {}
    cls = info.get("classification") or {}
    out: dict = {}

    # CVSS metrics
    if cls.get("cvss-metrics"):
        out["cvss_vector"] = str(cls["cvss-metrics"]).strip()
    if cls.get("cvss-score") is not None:
        try:
            out["cvss_score"] = float(cls["cvss-score"])
        except (TypeError, ValueError):
            pass

    # CWEs — "cwe-200" or ["cwe-200","cwe-79"]
    cwe_field = cls.get("cwe-id") or []
    if isinstance(cwe_field, str):
        cwe_field = [cwe_field]
    cwes: list[int] = []
    for c in cwe_field:
        m = re.search(r"cwe-?(\d+)", str(c), re.I)
        if m:
            cwes.append(int(m.group(1)))
    if cwes:
        out["cwe"] = sorted(set(cwes))

    # CVEs — "cve-2024-2473" or list
    cve_field = cls.get("cve-id") or []
    if isinstance(cve_field, str):
        cve_field = [cve_field]
    cves: list[str] = []
    for c in cve_field:
        s = str(c).strip().upper()
        if re.match(r"CVE-\d{4}-\d+", s):
            cves.append(s)
    if cves:
        out["cve"] = sorted(set(cves))

    # Matched URL — the actual exploit endpoint
    if obj.get("matched-at"):
        out["matched_url"] = str(obj["matched-at"]).strip()

    # Tags
    info_tags = info.get("tags") or []
    if isinstance(info_tags, list) and info_tags:
        out["tags"] = [str(t).strip() for t in info_tags if str(t).strip()]

    # Component name + version from info.name like "WPS Hide Login <= 1.9.15.2 - Login Page Disclosure"
    if info.get("name"):
        name = str(info["name"]).strip()
        # Try to split out version with patterns:
        #   "Component <= X.Y.Z - Description"
        #   "Component < X.Y.Z - Description"
        #   "Component X.Y.Z - Description"
        m = re.match(r"^([A-Za-z0-9 _\-]+?)\s*(?:<=?\s*|=\s*)?(\d+(?:\.\d+)+)\s*[-–—]", name)
        if m:
            out["affected_component"] = m.group(1).strip()
            out["affected_component_version"] = m.group(2).strip()
        else:
            # Fallback — take the part before the first " - "
            head = name.split(" - ", 1)[0].strip()
            if head and not re.search(r"\d", head):
                out["affected_component"] = head

    return out


def enrichment_for_finding(finding: dict, idx: ArtifactIndex) -> dict:
    """Given a finding row + the artifact index for its asset, return a dict
    of fields to merge into the row (only non-empty values)."""
    out: dict = {}

    # ──────────────────────────────────────────────────────────────────────
    # PRIORITY 1: nuclei JSON excerpt in the DB (richest source).
    # When the original ingest stored a full nuclei JSON in
    # finding_history.raw_excerpt, that JSON has every structured field
    # we want — CVSS metrics, EPSS, CWE, CVE, matched-at, info tags. No
    # title-matching needed; the JSON tells us exactly what was found.
    # ──────────────────────────────────────────────────────────────────────
    excerpt = (finding.get("_latest_excerpt") or "").strip()
    if excerpt:
        # ── nuclei one-liner: extract matched URL + CVE from text format
        # like "[CVE-2024-2473] [http] [medium] https://host/path"
        ol = parse_nuclei_oneliner(excerpt)
        if ol.get("matched_url") and not finding.get("matched_url"):
            out["matched_url"] = ol["matched_url"]
        if ol.get("cve"):
            prior_cve = finding.get("cve") or []
            merged = sorted({*prior_cve, *ol["cve"]})
            if merged != prior_cve:
                out["cve"] = merged

        # ── testssl.sh shape: lightweight CVE + CWE + port extraction
        # This is the dominant JSON shape on TLS-heavy findings.
        ts = parse_testssl_json_excerpt(excerpt)
        if ts.get("cve"):
            prior_cve = finding.get("cve") or []
            merged = sorted({*prior_cve, *ts["cve"]})
            if merged != prior_cve:
                out["cve"] = merged
        if ts.get("cwe"):
            prior_cwe = finding.get("cwe") or []
            merged = sorted({*prior_cwe, *ts["cwe"]})
            if merged != prior_cwe:
                out["cwe"] = merged

        # ── nuclei shape: rich extraction (CVSS vector, EPSS, matched URL, etc.)
        nuc = parse_nuclei_json_excerpt(excerpt)
        if nuc.get("cvss_score") is not None and finding.get("cvss_score") is None:
            out["cvss_score"] = nuc["cvss_score"]
        if nuc.get("cvss_vector") and not finding.get("cvss_vector"):
            out["cvss_vector"] = nuc["cvss_vector"]
        if nuc.get("affected_component") and not finding.get("affected_component"):
            out["affected_component"] = nuc["affected_component"]
        if nuc.get("affected_component_version") and not finding.get("affected_component_version"):
            out["affected_component_version"] = nuc["affected_component_version"]
        if nuc.get("matched_url") and not finding.get("matched_url"):
            out["matched_url"] = nuc["matched_url"]
        # Arrays — union with existing
        if nuc.get("cwe"):
            prior_cwe = finding.get("cwe") or []
            merged = sorted({*prior_cwe, *nuc["cwe"]})
            if merged != prior_cwe:
                out["cwe"] = merged
        if nuc.get("cve"):
            prior_cve = finding.get("cve") or []
            merged = sorted({*prior_cve, *nuc["cve"]})
            if merged != prior_cve:
                out["cve"] = merged
        if nuc.get("tags"):
            prior_tags = finding.get("tags") or []
            seen = {t.lower() for t in prior_tags}
            new_tags = list(prior_tags)
            for t in nuc["tags"]:
                if t.lower() not in seen and len(t) > 1:
                    new_tags.append(t)
                    seen.add(t.lower())
            if new_tags != prior_tags:
                out["tags"] = new_tags
        # If we got high-confidence component data from the JSON, we're
        # done — title-based matching can only confirm, not improve.
        if out.get("affected_component"):
            return out

    # ──────────────────────────────────────────────────────────────────────
    # PRIORITY 2: title-keyword match against the artifact-index plugins.
    # Used when there's no nuclei JSON excerpt, or the JSON didn't include
    # an info.name we could parse.
    # ──────────────────────────────────────────────────────────────────────
    keywords = extract_keywords_from_title(finding.get("title", ""))
    if not keywords:
        return out

    plugin = idx.find_plugin(*keywords)
    if plugin:
        # wpvulnerability.net is authoritative — overwrite stale values
        # rather than the default "only fill if NULL" merge. Without this,
        # affected_component_version gets frozen at the version observed
        # when the finding was first created (e.g. revslider 6.7.41) and
        # never updates when the plugin is upgraded (to 6.7.54), so the
        # finding detail page renders three different versions for the
        # same plugin. Caught by Howie 2026-05-24 on CVE-2026-6692.
        wpvuln_authoritative = plugin.source == "wpvulnerability.net"

        if wpvuln_authoritative or not finding.get("affected_component"):
            out["affected_component"] = display_name_for(plugin.slug)
        if plugin.version and (
            wpvuln_authoritative or not finding.get("affected_component_version")
        ):
            out["affected_component_version"] = plugin.version
        if not finding.get("matched_url") and plugin.matched_url:
            out["matched_url"] = plugin.matched_url

    # Tag union — ONLY when we matched a plugin. Adding asset-level tags
    # (wordpress, nginx, waf-x) to every finding on the asset would be
    # noisy on findings that have nothing to do with the asset's stack
    # (e.g. a DNS finding doesn't need 'wordpress' as a tag). When we have
    # a plugin match, the finding is clearly about that stack, so the
    # asset-level tags are signal not noise.
    if plugin:
        prior_tags = finding.get("tags") or []
        seen = {t.lower() for t in prior_tags}
        new_tags = list(prior_tags)
        plugin_tag = normalize_slug(plugin.slug).replace(" ", "-")
        candidate_tags = [
            "wordpress",
            "plugin",
            plugin_tag,
        ] + sorted(idx.extra_tags)
        for t in candidate_tags:
            if t and t.lower() not in seen and len(t) > 1:
                new_tags.append(t)
                seen.add(t.lower())
        if new_tags != prior_tags:
            out["tags"] = new_tags

    return out


# ─── DB / main ──────────────────────────────────────────────────────────────

def load_env(repo_root: Path) -> None:
    env_path = repo_root / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def discover_target_folders(scan_root: Path) -> list[tuple[Path, str]]:
    """Scan SCAN_ROOT for known target folders. Each entry returns the most
    detailed scan subfolder (prefer www-deep over www) + its asset_id."""
    out: list[tuple[Path, str]] = []
    for folder_name, asset_id in FOLDER_TO_ASSET.items():
        target = scan_root / folder_name
        if not target.is_dir():
            continue
        # Pick the most detailed scan dir available
        candidates = [target / "www-deep", target / "www", target]
        chosen = next((c for c in candidates if (c / "nuclei_results.txt").exists()), None)
        if chosen is None:
            # Fall back to base dir if nuclei output is at the root
            if (target / "nuclei_results.txt").exists():
                chosen = target
        if chosen is not None:
            out.append((chosen, asset_id))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Print proposed updates without writing.")
    parser.add_argument("--folder", help="Override: process this single scan folder. Requires --asset-id.")
    parser.add_argument("--asset-id", help="Asset ID to associate with --folder.")
    parser.add_argument("--scan-root", default=str(DEFAULT_SCAN_ROOT), help="Base path containing per-target scan folders.")
    parser.add_argument("--limit", type=int, default=500, help="Max findings per target to process.")
    args = parser.parse_args()

    try:
        from supabase import create_client
    except ImportError:
        sys.exit("Install deps: pip install supabase  (or activate the .venv used by the synth script)")

    repo_root = Path(__file__).resolve().parents[2]
    load_env(repo_root)
    sb_url = os.environ.get("SUPABASE_URL", DEFAULT_SUPABASE_URL)
    sb_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not sb_key:
        sys.exit("SUPABASE_SERVICE_ROLE_KEY not set (check .env)")
    sb = create_client(sb_url, sb_key)

    # Build target list
    if args.folder:
        if not args.asset_id:
            sys.exit("--folder requires --asset-id")
        targets = [(Path(args.folder).expanduser(), args.asset_id)]
    else:
        targets = discover_target_folders(Path(args.scan_root).expanduser())

    if not targets:
        sys.exit(f"No target folders found under {args.scan_root!r}. Check FOLDER_TO_ASSET mapping.")

    print(f"Walker ({'DRY RUN' if args.dry_run else 'WRITING TO DB'}) — {len(targets)} target folder(s)")
    print("=" * 76)

    total_findings = 0
    total_updates = 0

    for folder, asset_id in targets:
        print(f"\n▸ {asset_id}")
        print(f"  Scan folder: {folder}")
        idx = build_index(folder, asset_id)
        plugin_summary = ", ".join(
            f"{p.slug}={p.version or '?'}" for p in idx.plugins[:6]
        )
        print(f"  Indexed: {len(idx.plugins)} plugins ({plugin_summary}{', ...' if len(idx.plugins) > 6 else ''})")
        print(f"  WordPress: {idx.wp_version or '—'} · WAF: {idx.waf or '—'} · Tags: {len(idx.extra_tags)}")

        rows = (
            sb.table("findings")
            .select(
                "finding_id, title, tags, cve, cwe, cvss_score, cvss_vector, "
                "affected_component, affected_component_version, matched_url"
            )
            .eq("asset_id", asset_id)
            .limit(args.limit)
            .execute()
            .data
            or []
        )
        print(f"  Findings on this asset: {len(rows)}")

        # Pull the most-recent raw_excerpt for each finding in one batched
        # query so we don't fire 500 individual selects against the DB. This
        # is what unlocks parsing the nuclei JSON dumps that some findings
        # carry but the on-disk artifact files don't.
        finding_ids = [r["finding_id"] for r in rows]
        excerpts_by_id: dict[str, str] = {}
        if finding_ids:
            CHUNK = 100  # Supabase .in_ has a query-string-length limit
            for i in range(0, len(finding_ids), CHUNK):
                batch = finding_ids[i : i + CHUNK]
                hist = (
                    sb.table("finding_history")
                    .select("finding_id, raw_excerpt, observed_at")
                    .in_("finding_id", batch)
                    .order("observed_at", desc=True, nullsfirst=False)
                    .execute()
                    .data
                    or []
                )
                for h in hist:
                    fid = h["finding_id"]
                    ex = (h.get("raw_excerpt") or "").strip()
                    # Only keep the first (= most recent due to ORDER BY) record per finding
                    if fid not in excerpts_by_id and ex:
                        excerpts_by_id[fid] = ex

        for r in rows:
            total_findings += 1
            r["_latest_excerpt"] = excerpts_by_id.get(r["finding_id"], "")
            updates = enrichment_for_finding(r, idx)
            if not updates:
                continue
            total_updates += 1
            fid = r["finding_id"]
            print(f"  ↳ {fid}")
            for k, v in updates.items():
                preview = v if not isinstance(v, list) else f"[{len(v)} items]"
                print(f"      {k}: {preview}")
            if not args.dry_run:
                sb.table("findings").update(updates).eq("finding_id", fid).execute()

    print()
    print("=" * 76)
    print(f"Walked {total_findings} findings, {total_updates} updated"
          f"{' (DRY RUN — nothing written)' if args.dry_run else ''}.")


if __name__ == "__main__":
    main()
