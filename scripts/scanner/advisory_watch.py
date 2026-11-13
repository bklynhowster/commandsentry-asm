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

A SIGN-IN A DEEP SCAN NAMED (D-077, step 2 of plan-name-the-sign-in; Howie 2026-11-12
15:48 "Do it.", 16:21 "That text is absolutely fine. I approve."): its own track, beside
the product-name track above and never mixed with it.
  * Read: the deep scan's `signin_door` artifacts (push-434). Only a page that SAYS its
    product and prints a plain release number gives a version (rule 3r). A cookie name,
    a hidden footer or a development build writes nothing new.
  * Asked, none of them a scanned site: the maker's public release list on GitHub (the
    CVE numbers the notes of every FULL release newer than the version shown name), the
    open advisory database (OSV) for the product's own code, NVD for each flaw's
    published description (read to count the crash-or-overload ones, never kept),
    CISA's list. NVD by product name finds nothing here: the flaws are mostly in the
    language and libraries the product is built with.
  * Written: one OUT-OF-DATE row per site under the same identity and title as above,
    MODERATE (MODERATE-HIGH with a flaw on CISA's list), with its three page sections
    written in code by signin_flaws.py, so the AI enrichment job has nothing to fill.
    All of it short: two sentences, three lines about the flaws, one line to fix it
    (Howie, 2026-11-12 18:25: "No one will ever read anything like this", of a longer one).
  * A lookup that fails changes nothing for that site this run.
  * Closed only by a later deep scan that got a real answer: the page shows a release
    no listed flaw applies to, or the home page answered 2xx with no redirect to the
    sign-in. Silence, an error, a missing artifact or a hidden footer closes nothing; a
    hidden footer turns the text to "last showed X on <date>; confirm it was updated".
  * A person's text stands: once someone edits or approves the sections in the portal
    they are kept until the facts under them change, then rewritten and the change
    audited. "The facts" are the scanner description, which this job writes every run
    and which holds every fact the three sections render (the version, the releases and
    their dates, the counts, which flaws are described as crash or overload flaws, CISA's
    list, the fix). A rejected row's sections are never written.
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
import signin_flaws

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
DOOR_HISTORY_DAYS = 90     # how far back a sign-in's last SHOWN version is looked for
MAX_DOOR_NVD_READS = 100   # per run; a flaw past it is listed "not read today" (about 11 minutes)
GITHUB_API = "https://api.github.com"
RELEASES_PER_PAGE = 100
RELEASE_PAGES = 3          # newest first: 300 releases is every one newer than any version we will see
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_PAGES = 5
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

def http_get_json(url, timeout=30, opener=None, sleep=time.sleep, headers=None, body=None):
    """GET JSON (POST when `body` is given). One retry on rate limits, 5xx and network
    errors; anything else raises SourceError (a 404 included: these queries never 404
    when they work). `headers` go to `url` alone (never onto a redirect) and are never
    logged."""
    opener = opener or urllib.request.urlopen
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs,
                                 method="POST" if data is not None else "GET")
    for k, v in (headers or {}).items():
        # "Unredirected": sent to `url` only. urllib copies ordinary headers onto the request
        # it builds for a redirect, to whatever host that points at; a token must not go.
        req.add_unredirected_header(k, v)
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


def releases_url(repo: str, page: int = 1) -> str:
    """GitHub's public release list for one repository, newest first. PURE."""
    return f"{GITHUB_API}/repos/{repo}/releases?per_page={RELEASES_PER_PAGE}&page={page}"


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

    def __init__(self, get=http_get_json, sleep=time.sleep, now=None, github_token=None):
        self.get, self.sleep = get, sleep
        self.now = now or datetime.now(timezone.utc)
        self._calls = 0
        self._cve_cache: dict[str, dict | None] = {}
        self._github_token = github_token or None      # never logged, sent only to GITHUB_API
        self._releases: dict[str, list] = {}

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

    def releases(self, repo: str) -> list:
        """GitHub's public release list for `repo`, read once a run. Public data; the
        workflow's own token (when given) only lifts the shared-address rate limit."""
        if repo not in self._releases:
            out = []
            for page in range(1, RELEASE_PAGES + 1):
                url = releases_url(repo, page)
                d = (self.get(url, headers={"Authorization": f"Bearer {self._github_token}",
                                            "X-GitHub-Api-Version": "2022-11-28"})
                     if self._github_token else self.get(url))
                if not isinstance(d, list):
                    raise SourceError(f"release list {repo}: unexpected answer")
                out += [r for r in d if isinstance(r, dict)]
                if len(d) < RELEASES_PER_PAGE:
                    break
            self._releases[repo] = out
        return self._releases[repo]

    def osv(self, ecosystem: str, package: str, version: str) -> list:
        """Every record the open advisory database lists for this package version. The
        request carries a package name and a version number, nothing about any site."""
        body = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
        vulns = []
        for _ in range(OSV_PAGES):
            d = self.get(OSV_QUERY, body=body)
            page = d.get("vulns") if isinstance(d, dict) else None
            if page is None and isinstance(d, dict):
                page = []
            if not isinstance(page, list):
                raise SourceError(f"advisory database {package} {version}: unexpected answer")
            vulns += page
            token = d.get("next_page_token")
            if not token:
                return vulns
            body = dict(body, page_token=token)
        raise SourceError(f"advisory database {package} {version}: more than {OSV_PAGES} pages")


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
# The sign-in track's own sources (signin_flaws.SOURCES_LINE words them for the finding):
DOOR_SOURCES = [("maker_release_notes", "the maker's public release list on GitHub"),
                ("osv", "the open advisory database, for the product's own code at the version shown"),
                ("nvd_cve", "NVD, one read per flaw: its published description (read to count, not kept)"),
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


# D-077 step 2. Every `signin_door` artifact kept for an owned host (the deep scan writes
# one only for a site whose home page redirects to its own sign-in), newest decides.
DOOR_SQL = """
SELECT sr.asset_id, sra.content_jsonb AS door, sra.created_at AS seen_at
  FROM public.scan_run_artifacts sra
  JOIN public.scan_run sr ON sr.scan_run_id = sra.scan_run_id
  JOIN public.assets a    ON a.asset_id = sr.asset_id
 WHERE sra.tool_name = 'signin_door'
   AND sra.created_at > now() - make_interval(days => %(days)s)
   AND a.ownership = 'owned'
 ORDER BY sr.asset_id, sra.created_at DESC
"""
# The newest DEEP scan's own home-page record per owned host: the only thing, beside a
# newer version, that may close a sign-in's row (2xx, no redirect to the sign-in).
DOOR_HOME_SQL = """
SELECT DISTINCT ON (sr.asset_id)
       sr.asset_id, sra.content_jsonb AS home, sra.created_at AS seen_at
  FROM public.scan_run_artifacts sra
  JOIN public.scan_run sr ON sr.scan_run_id = sra.scan_run_id
  JOIN public.assets a    ON a.asset_id = sr.asset_id
 WHERE sra.tool_name = 'httpx_tech'
   AND sr.intensity::text = 'heavy'
   AND sra.created_at > now() - make_interval(days => %(days)s)
   AND a.ownership = 'owned'
 ORDER BY sr.asset_id, sra.created_at DESC
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


def door_lookup(src: Sources, key: str, version: str, kev_ids, budget: dict) -> "signin_flaws.Lookup":
    """What the public sources say about one sign-in product at the version a page
    showed. Raises SourceError if any read fails (that site then changes nothing this
    run). `budget["nvd"]` is the run's remaining NVD reads; a flaw past it stays unread
    and the finding then leaves the crash count off rather than understate it."""
    spec = signin_flaws.DOORS[key]
    newer = signin_flaws.newer(signin_flaws.full_releases(src.releases(spec["repo"])), version)
    ecosystem, package = spec["osv"]
    vulns = src.osv(ecosystem, package, version)
    flaws = signin_flaws.collect(newer, vulns, ecosystem, package, version)
    for fid in sorted(flaws):
        f = flaws[fid]
        f.kev = fid in kev_ids
        if not signin_flaws.CVE_ONE.match(fid):
            continue
        cached = fid in src._cve_cache
        if not cached and budget.get("nvd", 0) <= 0:
            continue
        rec = src.nvd_cve(fid)
        if rec is not None and not isinstance(rec, dict):
            raise SourceError(f"NVD {fid}: unexpected answer")
        if not cached:
            budget["nvd"] = budget.get("nvd", 0) - 1
        signin_flaws.describe(f, rec, kev_ids)
    named = {f.fixed_in for f in flaws.values() if f.in_notes}
    return signin_flaws.Lookup(flaws=flaws, releases=[r for r in newer if r.version in named],
                               osv_count=sum(1 for f in flaws.values() if f.in_osv),
                               osv_total=signin_flaws.osv_listed(vulns))


def plan_doors(doors: dict, existing: dict, lookup, today_year=None, log=print) -> list:
    """What to write for the sign-ins the deep scans named. PURE given `lookup`.
    doors: {asset_id: signin_flaws.Door}; existing: {finding_id: {asset_id, key, status,
    version}} for the sign-in keys only (version: the release the open row is about); lookup(key, version) -> signin_flaws.Lookup, or None when
    a public source could not be read (which changes nothing)."""
    acts = []
    for asset_id in sorted(set(doors) | {r["asset_id"] for r in existing.values()}):
        door = doors.get(asset_id) or signin_flaws.Door(asset_id)
        state, key, version = signin_flaws.reading(door.latest)
        keys = [key] if key else sorted({r["key"] for r in existing.values() if r["asset_id"] == asset_id})
        for k in keys:
            fid = ood_finding_id(asset_id, k)
            cur = existing.get(fid)
            if cur and cur["status"] not in ACTIVE + WATCHER_CLOSED:
                continue                                   # a person closed it: hands off
            active = bool(cur and cur["status"] in ACTIVE)
            disp = signin_flaws.DOORS[k]["display"]
            if door.home_ok:
                # A later deep scan's home page answered 2xx with no redirect to the sign-in.
                if active:
                    acts.append(Action("close", fid, asset_id, k,
                                       reason="a later deep scan's home page answered without this sign-in"))
                continue
            if state == signin_flaws.STATE_VERSION:
                look = lookup(k, version)
                if look is None:
                    continue                               # a failed lookup changes nothing
                if look.flaws:
                    acts.append(Action("upsert", fid, asset_id, k,
                                       signin_flaws.finding_fields(k, version, look, today_year),
                                       reopen=bool(cur and cur["status"] in WATCHER_CLOSED)))
                elif active:
                    # Closed only by a NEWER version shown. The same (or an older) version with
                    # no flaw listed today means the public sources changed, not the site: an
                    # emptied release list or edited notes must never close a finding.
                    was, now_v = signin_flaws.vt(cur.get("version")), signin_flaws.vt(version)
                    if was and now_v and now_v > was:
                        left = (f" (the open advisory database lists {look.osv_total} with no fixing release)"
                                if look.osv_total else "")
                        acts.append(Action("close", fid, asset_id, k,
                                           reason=f"the sign-in now shows {disp} {version}, and no later "
                                                  f"release fixes a published flaw in it{left}"))
                    else:
                        log(f"::warning::{asset_id}: the public sources list no flaw for {disp} {version} "
                            f"today, and the open finding is for {cur.get('version') or 'an unrecorded version'}; "
                            f"left open (only a newer version shown closes it)")
            elif state == signin_flaws.STATE_NO_VERSION:
                if not active:
                    log(f"  not written: a sign-in on {asset_id} looks like {disp}, version not shown")
                    continue                               # rule 3r: no version seen, nothing said
                if not door.shown_version or door.shown_key != k:
                    continue                               # nothing kept to word it from: leave the row as it is
                look = lookup(k, door.shown_version)
                if look is None or not look.flaws:
                    continue
                # The footer was hidden (or changed) after a version was shown: the row stays
                # open and says so. Hiding a version must never make a finding disappear.
                acts.append(Action("upsert", fid, asset_id, k,
                                   signin_flaws.finding_fields(k, door.shown_version, look, today_year,
                                                               last_shown_day=door.shown_day,
                                                               no_longer_shown=True)))
            # anything else (no artifact in the window, the phase switched off, no answer,
            # an unreadable record) decides nothing.
    return acts


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
SELECT finding_id, asset_id, current_status::text AS status, cve, tags,
       affected_component_version AS version
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
# The sign-in track's row (D-077 step 2): the same upsert, plus the three page sections
# written in code (signin_flaws.py) so the AI enrichment job has nothing to fill.
#   * "rejected": a person threw the text away in the portal (description_source
#     'scanner' with a review stamp, relay 154). Sticky: the sections are never written.
#   * the sections are the watcher's while description_source is 'scanner'. Once a person
#     edits or approves them they are kept, until the scanner DESCRIPTION this job is about
#     to write differs from the one stored. That column is the job's own (the portal's
#     edit, approve and reject never write it) and holds every fact the three sections
#     render, so "it differs" means a fact under the person's text moved: the sections are
#     rewritten, description_source goes back to 'scanner' and the review stamp is
#     cleared. apply() audits that from was_source. (A title-only test would miss a new
#     crash count, fixing release, release date or CISA listing: outside review, 17:41.)
#   * a blank section is stored as NULL, so the enrichment job's "is anything empty?"
#     test still sees it.
_DOOR_WRITE = ("""NOT (public.findings.description_source = 'scanner'
            AND public.findings.description_synth_reviewed_at IS NOT NULL)
       AND (public.findings.description_source = 'scanner'
            OR public.findings.description IS DISTINCT FROM EXCLUDED.description)""")
DOOR_UPSERT_SQL = f"""
WITH was AS (SELECT description_source FROM public.findings WHERE finding_id = %(finding_id)s)
INSERT INTO public.findings
  (finding_id, asset_id, title, severity, category, description, cve, "references",
   tags, current_status, source, first_detected_at, last_observed_at,
   affected_component, affected_component_version, description_source,
   description_synth, impact, remediation)
VALUES (%(finding_id)s, %(asset_id)s, %(title)s, %(severity)s::severity_t,
        %(category)s::finding_category_t, %(description)s, %(cve)s, %(references)s,
        %(tags)s, 'open'::finding_status_t, %(source)s::finding_source_t, now(), now(),
        %(affected_component)s, %(affected_component_version)s, 'scanner',
        NULLIF(btrim(%(description_synth)s), ''), NULLIF(btrim(%(impact)s), ''),
        NULLIF(btrim(%(remediation)s), ''))
ON CONFLICT (finding_id) DO UPDATE SET
  title = EXCLUDED.title, severity = EXCLUDED.severity, description = EXCLUDED.description,
  cve = EXCLUDED.cve, "references" = EXCLUDED."references", tags = EXCLUDED.tags,
  last_observed_at = now(),
  affected_component = EXCLUDED.affected_component,
  affected_component_version = EXCLUDED.affected_component_version,
  description_synth = CASE WHEN {_DOOR_WRITE}
                           THEN EXCLUDED.description_synth ELSE public.findings.description_synth END,
  impact = CASE WHEN {_DOOR_WRITE}
                THEN EXCLUDED.impact ELSE public.findings.impact END,
  remediation = CASE WHEN {_DOOR_WRITE}
                     THEN EXCLUDED.remediation ELSE public.findings.remediation END,
  description_synth_reviewed_at = CASE WHEN {_DOOR_WRITE}
                                       THEN NULL ELSE public.findings.description_synth_reviewed_at END,
  description_source = CASE WHEN {_DOOR_WRITE}
                            THEN 'scanner' ELSE public.findings.description_source END,
  current_status = CASE WHEN public.findings.current_status = 'remediated'
                        THEN 'regressed'::finding_status_t
                        ELSE public.findings.current_status END,
  last_regressed_at = CASE WHEN public.findings.current_status = 'remediated'
                           THEN now() ELSE public.findings.last_regressed_at END,
  remediated_at = CASE WHEN public.findings.current_status = 'remediated'
                       THEN NULL ELSE public.findings.remediated_at END
WHERE public.findings.current_status::text IN ('detected','confirmed','open','regressed','remediated')
RETURNING (SELECT description_source FROM was) AS was_source, description_source AS now_source
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
            if a.kind == "upsert" and "description_synth" in a.fields:
                # the sign-in track: its row carries the three page sections
                cur.execute(DOOR_UPSERT_SQL, dict(a.fields, finding_id=a.finding_id, asset_id=a.asset_id,
                                                  source=SOURCE))
                n["upsert"] += 1
                row = cur.fetchone() or {}
                was = row.get("was_source") if isinstance(row, dict) else None
                if was not in (None, "scanner") and row.get("now_source") == "scanner":
                    cur.execute(AUDIT_SQL, {"action": "advisory_watch_text_rewritten",
                                            "before": Json({"finding_id": a.finding_id, "description_source": was}),
                                            "after": Json({"finding_id": a.finding_id, "description_source": "scanner"}),
                                            "details": Json({"rule": "d077_signin_flaws",
                                                             "reason": "a fact the page sections render changed, "
                                                                       "so a person's text was replaced",
                                                             "title": a.fields.get("title")})})
                if a.reopen:
                    n["reopen"] += 1
                    cur.execute(AUDIT_SQL, {"action": "advisory_watch_reopen",
                                            "before": Json({"finding_id": a.finding_id, "current_status": "remediated"}),
                                            "after": Json({"finding_id": a.finding_id, "current_status": "regressed"}),
                                            "details": Json({"rule": "d077_signin_flaws", "cve": a.fields.get("cve")})})
            elif a.kind == "upsert":
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
                                      cve=list(r["cve"] or []), version=r.get("version"))
                for r in rows if _key_of(r)}
    # The sign-ins' rows are the sign-in track's alone: the product-name plan below would
    # close them as "no longer seen in the host's latest scan" (httpx never names them).
    existing_door = {fid: r for fid, r in existing.items() if r["key"] in signin_flaws.DOORS}
    existing = {fid: r for fid, r in existing.items() if fid not in existing_door}
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
    try:
        acts += door_track(conn, src, existing_door, kev, failed, log)
    except Exception as e:            # noqa: BLE001 — never let this track break the one above
        log(f"::warning::sign-in track failed ({type(e).__name__}: {str(e)[:200]}); "
            f"it changes nothing this run")
    if dry_run:
        for a in acts:
            log(f"  [dry-run] {a.kind}: {a.finding_id} {a.reason or a.fields.get('title', '')}")
        return {"planned": len(acts), "failed": sorted(failed)}
    n = apply(conn, acts, Json, log=log)
    n["failed"] = sorted(failed)
    return n


def door_track(conn, src: Sources, existing_door: dict, kev, failed: set, log=print) -> list:
    """The sign-in track's reads and plan (D-077 step 2). Returns its actions; a public
    source that cannot be read adds its key to `failed` and changes nothing."""
    with conn.cursor() as cur:
        cur.execute(DOOR_SQL, {"days": DOOR_HISTORY_DAYS})
        door_rows = [r for r in cur.fetchall() if isinstance(r, dict) and isinstance(r.get("door"), dict)]
        home_rows = []
        if door_rows:
            cur.execute(DOOR_HOME_SQL, {"days": INVENTORY_DAYS})
            home_rows = cur.fetchall()
    if not door_rows and not existing_door:
        return []
    doors = signin_flaws.doors_from(door_rows, home_rows, src.now, INVENTORY_DAYS)
    budget, memo = {"nvd": MAX_DOOR_NVD_READS}, {}

    def lookup(key, version):
        if (key, version) not in memo:
            try:
                memo[(key, version)] = door_lookup(src, key, version, kev, budget)
                look = memo[(key, version)]
                log(f"  {key} {version}: {len(look.flaws)} published flaws fixed in later releases "
                    f"({len(look.releases)} newer release(s) name one; the advisory database lists "
                    f"{look.osv_count})")
            except (SourceError, AttributeError, KeyError, TypeError, ValueError) as e:
                # a source that could not be read, or answered in a shape nobody expected
                memo[(key, version)] = None
                failed.add(key)
                log(f"::warning::{key} {version}: lookup failed ({type(e).__name__}: {str(e)[:200]}); "
                    f"this sign-in changes nothing this run")
        return memo[(key, version)]

    acts = plan_doors(doors, existing_door, lookup, today_year=src.now.year, log=log)
    log(f"sign-ins: {len(doors)} host(s) with a sign-in record; existing rows: {len(existing_door)}; "
        f"planned: {len(acts)}")
    return acts


def github_token(env=None) -> str | None:
    """The workflow's own short-lived token, for GitHub's PUBLIC release list only: it
    lifts the shared-address rate limit and nothing else. Handed to Sources, sent to
    api.github.com alone, never printed. None when the run has none (it still tries)."""
    return ((os.environ if env is None else env).get("GITHUB_TOKEN") or "").strip() or None


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
        n = run(conn, Sources(github_token=github_token()), dry_run=dry, Json=Json)
    print(f"advisory-watch: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
