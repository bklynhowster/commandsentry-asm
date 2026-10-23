#!/usr/bin/env python3
"""advisory_watch.py — new advisories against what our hosts run (KB 12 job 3d).

Once a day, before the 12:00 UTC digest: for every product the scans have seen
on an owned host (httpx's tech list, kept 90 days in scan_run_artifacts; plus a
CONFIRMED appliance vendor/product from assets.vendor_product, note 146's gate),
ask the US National Vulnerability Database for

  * critical advisories (CVSS >= 9.0) published in the last 30 days, and
  * advisories CISA added to its known-exploited list in the last 90 days,

that name that product. A match becomes one finding per (asset, product).

Rules (Howie, 2026-10-21, handoff 004 and the core "proved by a harmless
reaction" line):
  * Version shown and outside every affected range -> no finding (plan 302
    step 4). Version shown and inside a range -> the finding says so.
    Version NOT shown -> the finding says "version not shown — confirm it's
    patched". It never says "vulnerable" without a version to prove it.
  * MODERATE; HIGH when any of its CVEs is on CISA's known-exploited list.
  * A reviewed name map (PRODUCTS); an unknown name is never guessed.

It talks only to services.nvd.nist.gov and cisa.gov — never to a scanned host
(D-056). It reads the inventory the scans already banked; it scans nothing.

Lifecycle (no scan run owns these rows; last_seen_scan_run stays NULL, which
every other close path treats as "not mine" — plan review, refutation 3):
  * a match is re-written each run; its CVE list only grows (an advisory
    leaving the 30-day window does not make a host safe);
  * a version now shown and outside every range of a listed CVE drops that
    CVE; none left -> closed `remediated`;
  * the product no longer in the host's latest in-window tech list -> closed
    `remediated`; no in-window scan of the host -> nothing changes (so a
    confirmed-appliance row, which has no tech list, never closes by itself —
    the conservative direction; a person closes it);
  * findings.kev_listed is left to cve-scoring.yml, which owns that column;
  * a row the watcher closed comes back `regressed` if it matches again;
    a row a person closed (false positive, won't fix, accepted risk, ...) is
    never touched;
  * a lookup that fails closes nothing and drops nothing.

Sources are a list (SOURCES) so another feed can be added without a redesign
(Howie, 2026-10-21 19:41; VulnCheck's free feed is the planned first add-on).

Security devices (KB 12 job 3c, Howie 2026-10-22 07:28 and 09:01 "Yes to all four."):
a CONFIRMED Cisco ASA, FortiGate or FortiWeb (SECURITY_DEVICES) is matched against
EVERY advisory on CISA's exploited list for its product, not just the last 90 days
("an unpatched two-year-old exploited flaw on a firewall is the whole point"), and
  * a version read from the device (vendor_product.version, the light tier's
    stack_fingerprint) is range-matched as above;
  * a firmware build date only (vendor_product.release_date, FortiGate) keeps the
    advisories published AFTER the build: "built <month>; N advisories since —
    confirm it's patched";
  * severity: any CVE on CISA's exploited list -> CRITICAL; a shown version inside
    an affected range -> HIGH; otherwise MODERATE.
A CVE scored only by its reporting vendor (no NVD "Primary" score) now reads that
"Secondary" score instead of none (folded into 3c from the 330 read-back).

PROVEN / OUT OF DATE / GUESS (KB 12 job 3r, Howie 2026-10-22 15:58–16:05 and 20:34:
"There are risks and there are things that are known, that's all."), superseding the
severities above and 3c's D4:
  * version NOT shown and no firmware build date -> a guess: NO finding. Logged each
    run as background ("not written: …"); NVD is not even asked about a product no
    host shows a version or build date for. The guess rows earlier runs wrote (the
    'advisory:<key>' identity) are no longer this watcher's: it neither updates nor
    closes them — the one-time cleanup Howie runs retires them (migration 20260902b's
    contract: retirement is a human-run, audited batch).
  * version shown, or a firmware build date -> OUT OF DATE, under its own identity
    'out-of-date:<key>' (so a retired guess row can never block it — 3r plan review,
    must-fix 2): "Runs X 8.1.2: out of date — N published flaws fixed in later
    versions; update it". Severity evidence.version_based_severity(kev): MODERATE, or
    MODERATE-HIGH with a flaw on CISA's exploited list — security devices included
    (D4's CRITICAL / HIGH are gone). Never "vulnerable".
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import evidence

SOURCE = "advisory_watch"                       # findings.source (migration 20261021a)
USER_AGENT = "Sentry-ASM advisory-watch/1.0 (public advisory lookups)"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_DELAY_S = 6.5          # NVD: at most 5 requests per 30 s without a key (as cve_scoring.py)
RETRY_SLEEP_S = 10
NVD_PAGE = 2000
MAX_PAGES = 5
RECENT_DAYS = 30           # Decision 4
KEV_DAYS = 90              # Decision 4
MIN_CVSS = 9.0             # Decision 3: critical
INVENTORY_DAYS = 30        # only a host's latest tech list from the last 30 days counts
NET_ERRORS = (OSError, ValueError, http.client.HTTPException)

# httpx (Wappalyzer) product name, lower-cased -> (display name, NVD CPE prefixes
# "part:vendor:product"). Reviewed by hand; server-side products seen in either
# fleet only. JavaScript libraries stay with library_flaws.py (OSV).
# Not mapped, on purpose: "Windows Server" (httpx names no edition, and NVD has a
# separate product per edition — windows_server_2016, _2019, _2022, ...; guessing
# one would be the guess 302 step 4 forbids).
PRODUCTS = {
    "php": ("PHP", ("a:php:php",)),
    "wordpress": ("WordPress", ("a:wordpress:wordpress",)),
    "iis": ("Microsoft IIS", ("a:microsoft:internet_information_services",)),
    "microsoft asp.net": ("Microsoft ASP.NET", ("a:microsoft:asp.net",)),
    "apache tomcat": ("Apache Tomcat", ("a:apache:tomcat",)),
    "mysql": ("MySQL", ("a:oracle:mysql",)),
    "nginx": ("nginx", ("a:f5:nginx", "a:nginx:nginx")),
    "node.js": ("Node.js", ("a:nodejs:node.js",)),
    "next.js": ("Next.js", ("a:vercel:next.js",)),
}
# assets.vendor_product (vendor, product) lower-cased -> (map key, display, CPEs).
# Used only when vendor_product_confidence = 'confirmed' (note 146).
# Cisco ASA under BOTH NVD names: NVD re-keyed it from a: to o: in 2023-08 and older
# records still carry the deprecated a: form (checker, 3c plan review, NVD live
# 2026-10-22: o: 1089 records, a: 680, deprecatedBy o:). FortiGate's OS is FortiOS.
VENDOR_PRODUCTS = {
    ("fortinet", "fortiweb"): ("fortiweb", "Fortinet FortiWeb", ("a:fortinet:fortiweb",)),
    ("cisco", "asa"): ("cisco_asa", "Cisco ASA",
                       ("o:cisco:adaptive_security_appliance_software",
                        "a:cisco:adaptive_security_appliance_software")),
    ("fortinet", "fortigate"): ("fortigate", "Fortinet FortiGate (FortiOS)", ("o:fortinet:fortios",)),
}
# Edge security appliances (job 3c, D4 and its widening to FortiWeb): every CISA-KEV
# advisory counts regardless of age, and a KEV match is CRITICAL.
SECURITY_DEVICES = frozenset({"fortiweb", "cisco_asa", "fortigate"})
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

EARLIER = "listed by an earlier run; outside today's look-back window, still unconfirmed as patched"
ACTIVE = ("detected", "confirmed", "open", "regressed")   # the watcher may update or close these
WATCHER_CLOSED = ("remediated",)                           # the watcher may reopen these
VERSION_RE = re.compile(r"^\d{1,4}(?:\.\d{1,6}){0,5}[a-z]?$")


class SourceError(Exception):
    """A public source could not be read. Closes nothing."""


# ── identity ─────────────────────────────────────────────────────────────────

def finding_id(asset_id: str, key: str) -> str:
    """The identity runs before job 3r wrote: one row per (asset, product). Every such
    row is a guess (no version shown); this watcher no longer writes or touches them.
    Same formula as cs_parsers.common.stable_finding_id(asset, SOURCE, 'advisory:<key>',
    asset) (pinned by a test), kept here so the workflow needs no PYTHONPATH."""
    h = hashlib.sha256(asset_id.encode("utf-8")).hexdigest()[:7]
    return f"{asset_id}:{SOURCE}:advisory:{key}:{h}"


def ood_finding_id(asset_id: str, key: str) -> str:
    """Job 3r: one OUT-OF-DATE row per (asset, product), its own identity, so a retired
    guess row on the old identity can never block it. stable_finding_id(asset, SOURCE,
    'out-of-date:<key>', asset)."""
    h = hashlib.sha256(asset_id.encode("utf-8")).hexdigest()[:7]
    return f"{asset_id}:{SOURCE}:out-of-date:{key}:{h}"


# ── versions ─────────────────────────────────────────────────────────────────

def vtuple(v):
    """'8.3.10' -> (8, 3, 10); None when it is not a plain dotted number."""
    if not isinstance(v, str):
        return None
    parts = v.strip().split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def _cmp(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_in_range(version, m) -> bool | None:
    """Is `version` inside one NVD cpeMatch? None = cannot tell (treat as a match
    to keep, never as proof of safety). PURE."""
    v = vtuple(version)
    if v is None:
        return None
    parts = str(m.get("criteria", "")).split(":")
    exact = parts[5] if len(parts) > 5 else "*"
    bounds = {k: m.get(k) for k in ("versionStartIncluding", "versionStartExcluding",
                                    "versionEndIncluding", "versionEndExcluding")}
    if not any(bounds.values()):
        if exact in ("*", "-", ""):
            return True                         # every version of the product
        e = vtuple(exact)
        return None if e is None else _cmp(v, e) == 0
    for k, b in bounds.items():
        if not b:
            continue
        t = vtuple(b)
        if t is None:
            return None
        c = _cmp(v, t)
        if (k == "versionStartIncluding" and c < 0) or (k == "versionStartExcluding" and c <= 0) \
                or (k == "versionEndIncluding" and c > 0) or (k == "versionEndExcluding" and c >= 0):
            return False
    return True


def cpe_matches(cve: dict, cpes) -> list:
    """The vulnerable cpeMatch entries of one NVD CVE record that name one of
    `cpes` ("part:vendor:product"). PURE."""
    out = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                p = str(m.get("criteria", "")).split(":")
                if len(p) > 4 and ":".join(p[2:5]).lower() in cpes:
                    out.append(m)
    return out


def affects(cve: dict, cpes, version) -> bool:
    """Keep this CVE for a host showing `version` (None = not shown)? PURE.
    No version -> keep. A version -> keep unless EVERY matching range says no."""
    if version is None:
        return True
    ms = cpe_matches(cve, cpes)
    if not ms:
        return True                             # NVD matched it by product; can't rule it out
    return any(version_in_range(version, m) is not False for m in ms)


def cvss(cve: dict) -> float | None:
    """Highest NVD ("Primary") base score across CVSS v4.0 / v3.1 / v3.0; when NVD
    has not scored it, the highest "Secondary" (reporting vendor) score — as
    cve_scoring.py does — so a critical CVE NVD has not scored yet is not missed.
    PURE."""
    for wanted in ((None, "Primary"), ("Secondary",)):
        best = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            for m in (cve.get("metrics") or {}).get(key) or []:
                if m.get("type") not in wanted:
                    continue
                s = (m.get("cvssData") or {}).get("baseScore")
                if isinstance(s, (int, float)):
                    best = s if best is None else max(best, s)
        if best is not None:
            return best
    return None


# ── reading the public sources ───────────────────────────────────────────────

def http_get_json(url, timeout=30, opener=None, sleep=time.sleep):
    """GET JSON. One retry on rate limits, 5xx and network errors; anything
    else raises SourceError (a 404 included: these queries never 404 when they
    work)."""
    opener = opener or urllib.request.urlopen
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
    last = None
    for attempt in (1, 2):
        try:
            with opener(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last = e
            if e.code not in (429, 500, 502, 503, 504):
                break
        except NET_ERRORS as e:
            last = e
        if attempt == 1:
            sleep(RETRY_SLEEP_S)
    raise SourceError(f"{type(last).__name__}: {str(last)[:200]}")


def _iso(dt: datetime) -> str:
    return urllib.parse.quote(dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00"), safe="")


def nvd_url(cpe: str, kind: str, now: datetime, start_index: int = 0) -> str:
    """kind 'recent': published in the last RECENT_DAYS; kind 'kev': added to
    CISA KEV in the last KEV_DAYS; kind 'kev_all': every CVE on CISA KEV for the
    product, any age (security devices, job 3c). PURE."""
    match = urllib.parse.quote(f"cpe:2.3:{cpe}", safe="")
    if kind == "kev_all":
        return (f"{NVD_API}?virtualMatchString={match}&noRejected&hasKev"
                f"&resultsPerPage={NVD_PAGE}&startIndex={start_index}")
    days, a, b = ((RECENT_DAYS, "pubStartDate", "pubEndDate") if kind == "recent"
                  else (KEV_DAYS, "kevStartDate", "kevEndDate"))
    return (f"{NVD_API}?virtualMatchString={match}&noRejected"
            f"&{a}={_iso(now - timedelta(days=days))}&{b}={_iso(now)}"
            f"&resultsPerPage={NVD_PAGE}&startIndex={start_index}")


def nvd_cve_url(cve_id: str) -> str:
    return f"{NVD_API}?cveId={urllib.parse.quote(cve_id, safe='')}"


@dataclass
class Advisory:
    cve_id: str
    score: float | None
    published: str | None
    kev: bool
    summary: str
    record: dict = field(repr=False, default_factory=dict)


def _advisory(cve: dict, kev_ids) -> Advisory:
    desc = next((d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    cid = cve.get("id", "")
    return Advisory(cve_id=cid, score=cvss(cve), published=cve.get("published"),
                    kev=bool(cve.get("cisaExploitAdd")) or cid in kev_ids,
                    summary=(desc or "").strip()[:300], record=cve)


class Sources:
    """The feeds. Each fetch_* raises SourceError; callers decide what a
    failure means (it never closes anything)."""

    def __init__(self, get=http_get_json, sleep=time.sleep, now=None):
        self.get, self.sleep = get, sleep
        self.now = now or datetime.now(timezone.utc)
        self._calls = 0
        self._cve_cache: dict[str, dict | None] = {}

    def _nvd(self, url):
        if self._calls:
            self.sleep(NVD_DELAY_S)
        self._calls += 1
        return self.get(url)

    def kev_ids(self) -> set:
        d = self.get(KEV_FEED)
        vulns = (d or {}).get("vulnerabilities")
        if not isinstance(vulns, list):
            raise SourceError("KEV feed: no vulnerabilities list")
        return {v.get("cveID") for v in vulns if isinstance(v, dict) and v.get("cveID")}

    def nvd_query(self, cpe: str, kind: str) -> list:
        out, start = [], 0
        for _ in range(MAX_PAGES):
            d = self._nvd(nvd_url(cpe, kind, self.now, start))
            if not isinstance(d, dict) or not isinstance(d.get("vulnerabilities"), list):
                raise SourceError(f"NVD {kind} {cpe}: unexpected answer")
            out += [v.get("cve") for v in d["vulnerabilities"] if isinstance(v, dict) and v.get("cve")]
            total = d.get("totalResults") or 0
            start += len(d["vulnerabilities"])
            if start >= total or not d["vulnerabilities"]:
                return out
        raise SourceError(f"NVD {kind} {cpe}: more than {MAX_PAGES} pages")

    def nvd_cve(self, cve_id: str) -> dict | None:
        if cve_id not in self._cve_cache:
            d = self._nvd(nvd_cve_url(cve_id))
            vs = (d or {}).get("vulnerabilities") or []
            self._cve_cache[cve_id] = vs[0].get("cve") if vs else None
        return self._cve_cache[cve_id]


def advisories_for(src: Sources, cpes, kev_ids, all_kev: bool = False) -> dict:
    """{cve_id: Advisory} for one product: recent critical + KEV (last KEV_DAYS, or
    every KEV entry when all_kev — security devices). Raises SourceError if any
    query fails (the product is then skipped this run)."""
    found = {}
    for cpe in cpes:
        for cve in src.nvd_query(cpe, "recent"):
            a = _advisory(cve, kev_ids)
            if a.score is not None and a.score >= MIN_CVSS:
                found[a.cve_id] = a
        for cve in src.nvd_query(cpe, "kev_all" if all_kev else "kev"):
            a = _advisory(cve, kev_ids)
            a.kev = True                         # NVD returned it for a KEV query
            found[a.cve_id] = a
    return found


SOURCES = [("nvd_recent_critical", "NVD, published in the last 30 days, CVSS >= 9.0"),
           ("nvd_kev", "NVD's copy of CISA's known-exploited list, added in the last 90 days "
                       "(every entry, any age, for an edge security device)"),
           ("cisa_kev", "CISA's known-exploited catalog (severity flag)")]


# ── the parts list (read, not built) ─────────────────────────────────────────

INVENTORY_SQL = """
SELECT DISTINCT ON (sr.asset_id)
       sr.asset_id, sra.content_jsonb AS tech, sra.created_at AS seen_at,
       a.vendor_product, a.vendor_product_confidence
  FROM public.scan_run_artifacts sra
  JOIN public.scan_run sr ON sr.scan_run_id = sra.scan_run_id
  JOIN public.assets a    ON a.asset_id = sr.asset_id
 WHERE sra.tool_name = 'httpx_tech'
   AND sra.created_at > now() - make_interval(days => %(days)s)
   AND a.ownership = 'owned'
 ORDER BY sr.asset_id, sra.created_at DESC
"""
# Job 3o (2026-10-22): the WordPress core version run_light read from WordPress's own
# files (artifact wpvulnerability_detection, run_light.check_wpvulnerability). Same
# window and ownership as INVENTORY_SQL; the latest artifact per host decides.
WP_CORE_SQL = """
SELECT DISTINCT ON (sr.asset_id)
       sr.asset_id, sra.content_jsonb ->> 'core_version' AS core_version, sra.created_at AS seen_at
  FROM public.scan_run_artifacts sra
  JOIN public.scan_run sr ON sr.scan_run_id = sra.scan_run_id
  JOIN public.assets a    ON a.asset_id = sr.asset_id
 WHERE sra.tool_name = 'wpvulnerability_detection'
   AND sra.created_at > now() - make_interval(days => %(days)s)
   AND a.ownership = 'owned'
 ORDER BY sr.asset_id, sra.created_at DESC
"""
CONFIRMED_APPLIANCE_SQL = """
SELECT asset_id, vendor_product
  FROM public.assets
 WHERE ownership = 'owned' AND vendor_product_confidence = 'confirmed'
"""


def _tech_entries(payload) -> list:
    rows = payload if isinstance(payload, list) else [payload]
    out = []
    for r in rows:
        if isinstance(r, dict) and isinstance(r.get("tech"), list):
            out += [t for t in r["tech"] if isinstance(t, str)]
    return out


def products_from_tech(payload) -> dict:
    """{map key: version or None} from one httpx_tech artifact. PURE.
    'PHP' -> {'php': None}; 'Nginx:1.31.6' -> {'nginx': '1.31.6'}. Unknown names dropped."""
    found = {}
    for entry in _tech_entries(payload):
        name, sep, ver = entry.rpartition(":")
        if not sep or not VERSION_RE.match(ver.strip()):
            name, ver = entry, None
        key = name.strip().lower()
        if key in PRODUCTS:
            v = ver.strip() if ver else None
            if key not in found or (found[key] is None and v):
                found[key] = v
    return found


def appliance_product(vendor_product) -> tuple | None:
    if not isinstance(vendor_product, dict):
        return None
    k = (str(vendor_product.get("vendor", "")).lower(), str(vendor_product.get("product", "")).lower())
    return VENDOR_PRODUCTS.get(k)


@dataclass
class Host:
    asset_id: str
    products: dict            # key -> version or None
    scanned: bool             # a tech list from the last INVENTORY_DAYS exists
    release_dates: dict = field(default_factory=dict)   # key -> 'YYYY-MM-DD' (firmware build)


def appliance_version(vendor_product) -> str | None:
    """The version the device showed (job 3c, vendor_product.version), only if it
    is a plain dotted number. PURE."""
    v = vendor_product.get("version") if isinstance(vendor_product, dict) else None
    return v.strip() if isinstance(v, str) and vtuple(v.strip()) else None


def appliance_release_date(vendor_product) -> str | None:
    d = vendor_product.get("release_date") if isinstance(vendor_product, dict) else None
    return d if isinstance(d, str) and DATE_RE.match(d) else None


def build_inventory(tech_rows, appliance_rows, wp_core_rows=()) -> dict:
    """{asset_id: Host}. PURE.
    wp_core_rows (job 3o): {asset_id, core_version} from WP_CORE_SQL. A version fills
    WordPress ONLY where httpx already named WordPress without a number: it never adds
    WordPress to a host (the www. redirect twins), never overrides a version httpx
    showed, and a None takes nothing away."""
    inv = {}
    for r in tech_rows:
        inv[r["asset_id"]] = Host(r["asset_id"], products_from_tech(r["tech"]), True)
    for r in wp_core_rows:
        h = inv.get(r.get("asset_id"))
        v = r.get("core_version")
        v = v.strip() if isinstance(v, str) else None
        if (h and "wordpress" in h.products and h.products["wordpress"] is None
                and v and VERSION_RE.match(v) and vtuple(v)):
            h.products["wordpress"] = v
    for r in appliance_rows:
        ap = appliance_product(r["vendor_product"])
        if ap:
            h = inv.setdefault(r["asset_id"], Host(r["asset_id"], {}, False))
            ver = appliance_version(r["vendor_product"])
            h.products[ap[0]] = ver
            rd = None if ver else appliance_release_date(r["vendor_product"])
            if rd:
                h.release_dates[ap[0]] = rd
    return inv


def published_after(adv, day: str) -> bool:
    """Was this advisory published after the firmware build day? Unknown -> True
    (keep: never proof of safety). PURE."""
    p = (adv.published or "")[:10]
    return True if not DATE_RE.match(p) else p > day


def cpes_for(key: str):
    if key in PRODUCTS:
        return PRODUCTS[key]
    for k, disp, cpes in VENDOR_PRODUCTS.values():
        if k == key:
            return disp, cpes
    return None


# ── deciding (pure) ──────────────────────────────────────────────────────────

@dataclass
class Action:
    kind: str                 # 'upsert' | 'close'
    finding_id: str
    asset_id: str
    key: str
    fields: dict = field(default_factory=dict)
    reason: str = ""
    reopen: bool = False


MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def severity_for(key, version, kev) -> str:
    """Job 3r: an out-of-date finding is MODERATE, MODERATE-HIGH with a flaw on CISA's
    exploited list — every product, security devices included (3c's D4 superseded).
    Only a proven finding rates HIGH or CRITICAL, and a version match proves nothing.
    PURE."""
    return evidence.version_based_severity(kev)


def finding_fields(asset_id, key, version, advs, release_date=None) -> dict:
    """Finding columns for one (asset, product) and its kept advisories. PURE."""
    disp, _ = cpes_for(key)
    advs = sorted(advs, key=lambda a: (not a.kev, -(a.score or 0), a.cve_id))
    kev = any(a.kev for a in advs)
    n_kev = sum(1 for a in advs if a.kev)
    device = key in SECURITY_DEVICES
    n = len(advs)
    how = ("Nothing was sent to the site to check: this comes from public advisories only."
           if not device else
           "No attack was sent to check: the device was named from what it shows anyone "
           "before login, and the match comes from public advisories.")
    flaws = f"{n} published flaw{'' if n == 1 else 's'}"
    on_kev = f", {n_kev} on CISA’s exploited list" if kev else ""
    if version:
        title = f"Runs {disp} {version}: out of date — {flaws} fixed in later versions{on_kev}; update it"
        head = (f"{asset_id} shows {disp} {version}. Later versions fix the published flaws below. "
                f"Out of date: matched from the version the site shows, not confirmed by testing "
                f"— a vendor can patch without changing the number.")
    elif release_date:
        y, m = release_date[:4], MONTHS[int(release_date[5:7]) - 1]
        title = f"Runs {disp}, firmware built {m} {y}: out of date — {flaws} published since{on_kev}; update it"
        head = (f"{asset_id} shows {disp} but not its version. Its login page gives away the "
                f"firmware's build date, {release_date}. The flaws below were published after "
                f"that build, so it may not have their fixes. Out of date: not confirmed by testing. {how}")
    else:
        # Job 3r: a version we did not see is a guess, not a finding. plan() never asks.
        raise ValueError(f"{asset_id} {key}: no version and no build date is a guess, not a finding")
    lines = [head, ""]
    for a in advs[:20]:
        tag = " — on CISA’s known-exploited list" if a.kev else ""
        sc = f"CVSS {a.score}" if a.score is not None else "score not re-read"
        lines.append(f"- {a.cve_id} ({sc}{tag}): {a.summary}")
    if n > 20:
        lines.append(f"- … and {n - 20} more")
    lines += ["", "Sources: " + "; ".join(d for _, d in SOURCES) + "."]
    return dict(
        title=title[:200],
        severity=severity_for(key, version, kev),
        category="supply_chain",
        description="\n".join(lines),
        cve=[a.cve_id for a in advs],
        references=[f"https://nvd.nist.gov/vuln/detail/{a.cve_id}" for a in advs[:20]],
        tags=["advisory-watch", "out-of-date", "version-shown" if version else "firmware-build-date", key]
             + (["security-device"] if device else [])
             + (["cisa-kev"] if kev else []),
        affected_component=disp,
        affected_component_version=version,
    )


def guesses(inventory: dict) -> list:
    """Job 3r: what the watcher does NOT write — products a host runs whose version (and
    firmware build date) we did not see. Background for the run log only. PURE."""
    return [f"not written: Runs {cpes_for(key)[0]} on {asset_id}, version not shown"
            for asset_id, host in sorted(inventory.items())
            for key, version in sorted(host.products.items())
            if version is None and not host.release_dates.get(key)]


def needs_lookup(inventory: dict) -> list:
    """Products some host shows a version or a firmware build date for — the only ones
    worth asking NVD about (job 3r: a guess is never matched). PURE."""
    return sorted({key for host in inventory.values() for key, version in host.products.items()
                   if version is not None or host.release_dates.get(key)})


def plan(inventory: dict, found: dict, failed: set, existing: dict, recheck: dict,
         kev_ids=frozenset()) -> list:
    """What to write. PURE.
    inventory: {asset_id: Host}; found: {key: {cve: Advisory}} for products whose
    lookups all succeeded; failed: keys whose lookup failed; existing: {finding_id:
    {asset_id, key, status, cve[]}} for this source; recheck: {cve_id: Advisory|None}
    for listed CVEs of rows whose host now shows a version (None = lookup failed)."""
    acts, seen_ids = [], set()
    for asset_id, host in sorted(inventory.items()):
        for key, version in sorted(host.products.items()):
            built = None if version else host.release_dates.get(key)
            if version is None and built is None:
                continue                                   # job 3r: a guess is not a finding
            fid = ood_finding_id(asset_id, key)
            seen_ids.add(fid)
            cur = existing.get(fid)
            if cur and cur["status"] not in ACTIVE + WATCHER_CLOSED:
                continue                                   # a person closed it: hands off
            if key in failed:
                continue                                   # a failed lookup changes nothing
            _, cpes = cpes_for(key)
            new = {c: a for c, a in found.get(key, {}).items()
                   if affects(a.record, cpes, version) and (built is None or published_after(a, built))}
            keep = dict(new)
            if cur:
                for c in cur.get("cve") or []:
                    if c in keep:
                        continue
                    if c in found.get(key, {}):
                        continue          # this run's own record ruled it out (version range or build date)
                    earlier = Advisory(c, None, None, c in kev_ids, EARLIER)
                    if version is None:
                        keep[c] = earlier
                        continue
                    a = recheck.get(c, "missing")
                    if a is None or a == "missing":
                        keep[c] = earlier                                    # can't tell: keep
                    elif affects(a.record, cpes, version):
                        keep[c] = a
            if keep:
                if cur and cur["status"] in WATCHER_CLOSED and not new:
                    continue      # closed by the watcher; nothing NEW matches -> stay closed
                acts.append(Action("upsert", fid, asset_id, key,
                                   finding_fields(asset_id, key, version, keep.values(), built),
                                   reopen=bool(cur and cur["status"] in WATCHER_CLOSED)))
            elif cur and cur["status"] in ACTIVE:
                acts.append(Action("close", fid, asset_id, key,
                                   reason=(f"{cpes_for(key)[0]} firmware built {built} is newer than every listed advisory"
                                           if built else
                                           f"{cpes_for(key)[0]} {version} is outside every listed advisory's affected range")))
    for fid, cur in sorted(existing.items()):
        if fid in seen_ids or cur["status"] not in ACTIVE:
            continue
        host = inventory.get(cur["asset_id"])
        if host and host.scanned and cur["key"] not in host.products:
            acts.append(Action("close", fid, cur["asset_id"], cur["key"],
                               reason="the product is no longer seen in the host's latest scan"))
    return acts


# ── writing ──────────────────────────────────────────────────────────────────

EXISTING_SQL = """
SELECT finding_id, asset_id, current_status::text AS status, cve, tags
  FROM public.findings WHERE source::text = %(source)s
"""
UPSERT_SQL = """
INSERT INTO public.findings
  (finding_id, asset_id, title, severity, category, description, cve, "references",
   tags, current_status, source, first_detected_at, last_observed_at,
   affected_component, affected_component_version, description_source)
VALUES (%(finding_id)s, %(asset_id)s, %(title)s, %(severity)s::severity_t,
        %(category)s::finding_category_t, %(description)s, %(cve)s, %(references)s,
        %(tags)s, 'open'::finding_status_t, %(source)s::finding_source_t, now(), now(),
        %(affected_component)s, %(affected_component_version)s, 'scanner')
ON CONFLICT (finding_id) DO UPDATE SET
  title = EXCLUDED.title, severity = EXCLUDED.severity, description = EXCLUDED.description,
  cve = EXCLUDED.cve, "references" = EXCLUDED."references", tags = EXCLUDED.tags,
  last_observed_at = now(),
  affected_component = EXCLUDED.affected_component,
  affected_component_version = EXCLUDED.affected_component_version,
  current_status = CASE WHEN public.findings.current_status = 'remediated'
                        THEN 'regressed'::finding_status_t
                        ELSE public.findings.current_status END,
  last_regressed_at = CASE WHEN public.findings.current_status = 'remediated'
                           THEN now() ELSE public.findings.last_regressed_at END,
  remediated_at = CASE WHEN public.findings.current_status = 'remediated'
                       THEN NULL ELSE public.findings.remediated_at END
WHERE public.findings.current_status::text IN ('detected','confirmed','open','regressed','remediated')
"""
CLOSE_SQL = """
UPDATE public.findings
   SET current_status = 'remediated', remediated_at = now()
 WHERE finding_id = %(finding_id)s AND source::text = %(source)s
   AND current_status::text IN ('detected','confirmed','open','regressed')
RETURNING finding_id, severity::text AS severity
"""
AUDIT_SQL = """
INSERT INTO public.admin_audit_log
  (actor_user_id, action, target_user_id, target_email, before_state, after_state, details)
VALUES (NULL, %(action)s, NULL, NULL, %(before)s::jsonb, %(after)s::jsonb, %(details)s::jsonb)
"""


def apply(conn, acts, Json, log=print) -> dict:
    n = {"upsert": 0, "close": 0, "reopen": 0}
    for a in acts:
        with conn.cursor() as cur:
            if a.kind == "upsert":
                cur.execute(UPSERT_SQL, dict(a.fields, finding_id=a.finding_id, asset_id=a.asset_id,
                                             source=SOURCE))
                n["upsert"] += 1
                if a.reopen:
                    n["reopen"] += 1
                    cur.execute(AUDIT_SQL, {"action": "advisory_watch_reopen",
                                            "before": Json({"finding_id": a.finding_id, "current_status": "remediated"}),
                                            "after": Json({"finding_id": a.finding_id, "current_status": "regressed"}),
                                            "details": Json({"rule": "job_3r_advisory_watch", "cve": a.fields.get("cve")})})
            else:
                cur.execute(CLOSE_SQL, {"finding_id": a.finding_id, "source": SOURCE})
                row = cur.fetchone()
                if row:
                    n["close"] += 1
                    cur.execute(AUDIT_SQL, {"action": "advisory_watch_close",
                                            "before": Json({"finding_id": a.finding_id, "current_status": "open_family"}),
                                            "after": Json({"finding_id": a.finding_id, "current_status": "remediated"}),
                                            "details": Json({"rule": "job_3r_advisory_watch", "reason": a.reason})})
        log(f"  {a.kind}{' (reopen)' if a.reopen else ''}: {a.finding_id} {a.reason or a.fields.get('title', '')}")
    return n


def _key_of(row) -> str | None:
    """The product key of an OUT-OF-DATE row (job 3r identity). The pre-3r
    'advisory:<key>' rows (all guesses) give None: not this watcher's any more."""
    m = re.search(rf":{SOURCE}:out-of-date:([^:]+):[0-9a-f]{{7}}$", row["finding_id"])
    return m.group(1) if m else None


def run(conn, src: Sources, dry_run=False, log=print, Json=None) -> dict:
    """One watch. Returns counts."""
    with conn.cursor() as cur:
        cur.execute(INVENTORY_SQL, {"days": INVENTORY_DAYS})
        tech = cur.fetchall()
        cur.execute(CONFIRMED_APPLIANCE_SQL)
        appl = cur.fetchall()
        cur.execute(WP_CORE_SQL, {"days": INVENTORY_DAYS})
        wp_core = cur.fetchall()
        cur.execute(EXISTING_SQL, {"source": SOURCE})
        rows = cur.fetchall()
    inv = build_inventory(tech, appl, wp_core)
    existing = {r["finding_id"]: dict(asset_id=r["asset_id"], key=_key_of(r), status=r["status"],
                                      cve=list(r["cve"] or [])) for r in rows if _key_of(r)}
    log(f"inventory: {len(inv)} hosts, products {sorted({k for h in inv.values() for k in h.products})}; "
        f"existing out-of-date rows: {len(existing)}")
    for line in guesses(inv):
        log(f"  {line}")
    try:
        kev = src.kev_ids()
    except SourceError as e:
        # job 3s: the KEV list already held in cve_enrichments, so a CISA outage cannot
        # compute MODERATE here and lower a MODERATE-HIGH row (this upsert sets severity
        # outright)
        kev = evidence.kev_fallback()
        log(f"::warning::CISA KEV unreadable ({e}); using the {len(kev)} KEV CVEs already held "
            f"in cve_enrichments this run")
    found, failed = {}, set()
    for key in needs_lookup(inv):
        try:
            found[key] = advisories_for(src, cpes_for(key)[1], kev, all_kev=key in SECURITY_DEVICES)
            log(f"  {key}: {len(found[key])} advisories")
        except SourceError as e:
            failed.add(key)
            log(f"::warning::{key}: lookup failed ({e}); this product changes nothing this run")
    # A host that now shows a version: re-read each CVE its row already lists
    # (not in this run's results) so a patched version can drop it. A failed
    # read keeps the CVE.
    recheck = {}
    for cur in existing.values():
        host = inv.get(cur["asset_id"])
        if not host or cur["key"] in failed or host.products.get(cur["key"]) is None:
            continue
        for c in cur["cve"]:
            if c in recheck or c in found.get(cur["key"], {}):
                continue
            try:
                rec = src.nvd_cve(c)
                recheck[c] = _advisory(rec, kev) if rec else None
            except SourceError:
                recheck[c] = None
    acts = plan(inv, found, failed, existing, recheck, kev_ids=kev)
    if dry_run:
        for a in acts:
            log(f"  [dry-run] {a.kind}: {a.finding_id} {a.reason or a.fields.get('title', '')}")
        return {"planned": len(acts), "failed": sorted(failed)}
    n = apply(conn, acts, Json, log=log)
    n["failed"] = sorted(failed)
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="New advisories against what our hosts run (job 3d).")
    ap.add_argument("--dry-run", action="store_true", help="read everything, write nothing")
    args = ap.parse_args(argv)
    dsn = os.environ.get("SUPABASE_DSN", "").strip()
    if not dsn:
        print("::error::advisory-watch: SUPABASE_DSN is not set", file=sys.stderr)
        return 2
    evidence.set_kev_fallback(evidence.db_kev_reader(dsn))   # job 3s
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.types.json import Json
    dry = args.dry_run or os.environ.get("DRY_RUN", "").strip().lower() == "true"
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row, connect_timeout=15) as conn:
        conn.execute("SET statement_timeout = '60s'")
        n = run(conn, Sources(), dry_run=dry, Json=Json)
    print(f"advisory-watch: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
