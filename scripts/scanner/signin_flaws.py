#!/usr/bin/env python3
"""signin_flaws.py — the published flaws that later releases fix, for a sign-in a deep
scan named (D-077; step 2 of plan-name-the-sign-in). PURE: no network, no database.

The deep scan's `signin_door` artifact (signin_door.py, push-434) says what a sign-in
SHOWS: its product and, when its own footer prints one, a release number. This module
turns that, plus three public sources advisory_watch.py reads, into one rule-3r
OUT-OF-DATE finding per site:

    "Runs OAuth2 Proxy 7.15.5: out of date — 18 published flaws fixed in later
     versions; update it"

The sources (none is a scanned site):
  * the maker's own release notes (GitHub's public release list): every CVE number the
    notes of a FULL release newer than the version shown name. Pre-releases and drafts
    are ignored. A number is counted once however many releases name it;
  * the open advisory database (OSV) for the product's own code at the version shown;
  * NVD for each flaw's published description (read to count, never kept), and CISA's
    exploited list.

WORDING (Howie, 2026-11-12 16:13 "way too long", 16:17 no disclaimer about what Sentry
tested, 16:21 "That text is absolutely fine. I approve."). The lead is written HERE, in
code, never by an AI, and says only what was seen or read, each with its source:

    "This sign-in shows OAuth2 Proxy 7.15.5. Its maker says release 7.15.6 (Nov 5)
     fixes 18 published flaws; 6 are described as crash or overload flaws."

  * "shows": the page printed that number. Never "is vulnerable" (rule 3r).
  * "its maker says": the release notes list them. Most are in the language and
    libraries the product is built with; nothing here says any reaches this site.
  * "are described as": CRASH_WORDS run over each flaw's own published description.
    Never a score (a score can contradict its own description), never who could cause
    it or from where, never a claim about this site. Sentry does not test denial of
    service and this sentence does not say it did. When any flaw's description was not
    read, the count is left off that day instead of understated.

It writes the three page sections itself (description_synth / impact / remediation) so
the AI enrichment job has nothing to fill in and leaves the row alone; advisory_watch's
upsert stops writing them once a person has edited, approved or rejected the text.

SHORT, ALL OF IT (Howie, 2026-11-12 18:25, on a page that carried every flaw's write-up:
"It is an enormous amount of text. No one will ever read anything like this."). The
whole finding is the lead, three lines about the flaws, and one line saying what to do.
A flaw's published description is read to count the crash-or-overload ones and is never
stored or shown; nor is any score.

Nothing here closes a finding on silence. advisory_watch.plan_doors holds that rule.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from urllib.parse import urlsplit

import evidence
import signin_door

KEY = signin_door.PRODUCT_KEY                      # "oauth2_proxy"
# One row per sign-in product a deep scan can name. Reviewed by hand; a new row needs
# its own positive evidence in signin_door.py and its own look at what request is fair.
DOORS = {
    KEY: {
        "display": signin_door.PRODUCT,            # "OAuth2 Proxy"
        "repo": "oauth2-proxy/oauth2-proxy",       # GitHub's public release list
        "osv": ("Go", "github.com/oauth2-proxy/oauth2-proxy/v7"),
        "built_with": "the Go language and libraries it is built with",
    },
}

SOURCES_LINE = ("Sources: the maker's release notes on GitHub; the open advisory database "
                "(osv.dev); the US vulnerability database (NVD); CISA's known-exploited catalog.")
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

VERSION_RE = re.compile(r"\A(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z")
TAG_RE = re.compile(r"\Av?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z")
FIXED_RE = re.compile(r"\Av?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z")
DAY_RE = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})\Z")
CVE_FIND = re.compile(r"(?<![A-Za-z0-9-])CVE-\d{4}-\d{4,7}(?!\d)", re.I)
# \A ... \Z, never ^ ... $: in Python "$" also matches just before a final line break.
CVE_ONE = re.compile(r"\ACVE-\d{4}-\d{4,7}\Z")
# The advisory database's own id shapes. Anything else (spaces, line breaks, extra text) is
# not an id and is dropped: an id is printed as a label, outside the publisher's description.
GHSA_ONE = re.compile(r"\AGHSA(?:-[0-9a-z]{4}){3}\Z")
GO_ONE = re.compile(r"\AGO-\d{4}-\d{1,7}\Z")
# The publishers' own words for "it can be crashed or overloaded" (plan v5, step 2).
# Run over a flaw's published DESCRIPTION only. "excessive ... CPU / memory" allows a few
# words between ("an excessive amount of CPU"), never across a sentence.
CRASH_WORDS = re.compile(
    r"denial[ -]of[ -]service|\bcrash(?:es|ed|ing)?\b|\bpanic(?:s|ked|king)?\b"
    r"|\bexhaust(?:s|ed|ing|ion)?\b|\bexcessive\b[^.;]{0,40}\b(?:cpu|memory)\b", re.I)

STATE_VERSION = "version"          # the page showed a plain release number
STATE_NO_VERSION = "no_version"    # still looks like the product; no release number shown
STATE_UNCLEAR = "unclear"          # anything else: decides nothing


# ── reading the scan's artifact ──────────────────────────────────────────────

def vt(version) -> tuple | None:
    m = VERSION_RE.match(version) if isinstance(version, str) else None
    return tuple(int(x) for x in m.groups()) if m else None


def reading(record) -> tuple:
    """(state, product key or None, version or None) from one `signin_door` artifact.
    Only a page that SAYS the product and prints a plain release number is a version
    (rule 3r); a cookie name alone never is. PURE."""
    if not isinstance(record, dict) or record.get("schema") != signin_door.SCHEMA:
        return STATE_UNCLEAR, None, None
    if record.get("live_flag") is not True or record.get("qualifying_redirect") is not True:
        return STATE_UNCLEAR, None, None
    grade = record.get("grade")
    if grade == signin_door.GRADE_SAYS and record.get("product_key") in DOORS:
        key, v = record["product_key"], record.get("version")
        if vt(v):
            return STATE_VERSION, key, v
        return STATE_NO_VERSION, key, None
    if grade == signin_door.GRADE_LOOKS_LIKE:
        return STATE_NO_VERSION, None, None
    return STATE_UNCLEAR, None, None


def home_answers_without_door(payload, hostname) -> bool:
    """Did a deep scan's own home-page record (httpx) get an ordinary successful answer
    with no redirect to this site's sign-in? Anything unclear is False: an error, a
    redirect, a failed request or another host's page closes nothing. PURE."""
    rows = payload if isinstance(payload, list) else [payload]
    seen = False
    for r in rows:
        if not isinstance(r, dict) or str(r.get("path") or "/") != "/":
            continue
        try:
            status = int(r.get("status_code") or 0)
        except (TypeError, ValueError):
            return False
        want = str(hostname or "").lower().rstrip(".")
        host = str(r.get("host") or want).lower().rstrip(".")
        if (r.get("failed") or not 200 <= status <= 299 or r.get("location")
                or not want or host != want or _was_redirected(r, want)):
            return False
        seen = True
    return seen


def _was_redirected(rec: dict, want: str) -> bool:
    """Did the scan's client follow a redirect to get this answer? A followed redirect can
    end on the sign-in's own page with a 200 (same host, no Location left), which is the
    opposite of "the sign-in is gone". So: any redirect chain, or a final address that is
    not this host's own home page, counts as redirected. PURE."""
    if rec.get("chain") or rec.get("chain_status_codes"):
        return True
    for k in ("final_url", "url"):
        v = rec.get(k)
        if v is None or v == "":
            continue
        if not isinstance(v, str):
            return True
        try:
            u = urlsplit(v)
            port = u.port
        except ValueError:
            return True                       # an address that cannot be read is not "the home page"
        if ((u.hostname or "").lower().rstrip(".") != want or u.scheme.lower() != "https"
                or port not in (None, 443) or u.path not in ("", "/") or u.query):
            return True
    return False


@dataclass
class Door:
    """What the scans hold about one owned host's sign-in."""
    asset_id: str
    latest: dict | None = None        # the newest signin_door record inside the window
    shown_version: str | None = None  # the newest kept record that showed a release number
    shown_key: str | None = None
    shown_day: str | None = None      # the day it showed it, 'YYYY-MM-DD'
    home_ok: bool = False             # a LATER deep scan's home page answered without the sign-in


def _day(value) -> str | None:
    s = value.isoformat() if hasattr(value, "isoformat") else str(value or "")
    return s[:10] if DAY_RE.match(s[:10]) else None


def doors_from(door_rows, home_rows, now, window_days) -> dict:
    """{asset_id: Door}. door_rows: {asset_id, door, seen_at} (any order, the kept
    history); home_rows: {asset_id, home, seen_at}, the newest deep-scan home-page record
    per host. Rows of any other shape are ignored. PURE."""
    by = {}
    for r in door_rows or []:
        if (isinstance(r, dict) and isinstance(r.get("asset_id"), str)
                and isinstance(r.get("door"), dict) and hasattr(r.get("seen_at"), "timestamp")):
            by.setdefault(r["asset_id"], []).append(r)
    homes = {r["asset_id"]: r for r in home_rows or []
             if isinstance(r, dict) and isinstance(r.get("asset_id"), str)
             and hasattr(r.get("seen_at"), "timestamp")}
    out = {}
    for asset_id, rows in by.items():
        rows.sort(key=lambda r: r["seen_at"], reverse=True)
        d = Door(asset_id)
        newest = rows[0]
        if (now - newest["seen_at"]).total_seconds() <= window_days * 86400:
            d.latest = newest["door"]
        for r in rows:
            state, key, version = reading(r["door"])
            if state == STATE_VERSION:
                d.shown_version, d.shown_key = version, key
                d.shown_day = _day(r["door"].get("checked_at")) or _day(r["seen_at"])
                break
        h = homes.get(asset_id)
        d.home_ok = bool(h and h["seen_at"] > newest["seen_at"]
                         and home_answers_without_door(h.get("home"), asset_id))
        out[asset_id] = d
    return out


# ── reading the maker's release list and the advisory database ───────────────

def cves_in(text) -> tuple:
    """Every CVE number in a release's notes, once each, upper-cased. PURE."""
    return tuple(sorted({m.upper() for m in CVE_FIND.findall(text if isinstance(text, str) else "")}))


@dataclass(frozen=True)
class Release:
    version: str
    vt: tuple
    day: str | None
    cves: tuple


def full_releases(raw) -> list:
    """GitHub's release list -> full releases with a plain 'vX.Y.Z' tag, oldest first.
    Drafts, pre-releases and any other tag shape are dropped. PURE."""
    out = {}
    for r in raw if isinstance(raw, list) else []:
        if not isinstance(r, dict) or r.get("draft") is not False or r.get("prerelease") is not False:
            continue
        m = TAG_RE.match(str(r.get("tag_name") or "").strip())
        if not m:
            continue
        t = tuple(int(x) for x in m.groups())
        out[t] = Release(".".join(str(x) for x in t), t, _day(r.get("published_at")), cves_in(r.get("body")))
    return [out[t] for t in sorted(out)]


def newer(releases, version) -> list:
    seen = vt(version)
    return [r for r in releases if seen is not None and r.vt > seen]


@dataclass
class Flaw:
    id: str                          # a CVE number, or the advisory database's id when it has none
    fixed_in: str = ""               # the lowest later release that fixes it (always set by collect)
    in_notes: bool = False           # named by the maker's release notes
    in_osv: bool = False             # listed by the open advisory database for this version
    read: bool = False               # its published description was read this run
    crash: bool = False              # CRASH_WORDS matched that description
    kev: bool = False                # on CISA's exploited list


def _dicts(v):
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _lowest_fix(vuln, ecosystem, package, version):
    seen, best = vt(version), None
    for aff in _dicts(vuln.get("affected")):
        pkg = aff.get("package") if isinstance(aff.get("package"), dict) else {}
        if pkg.get("name") != package or pkg.get("ecosystem") != ecosystem:
            continue
        for rng in _dicts(aff.get("ranges")):
            for ev in _dicts(rng.get("events")):
                m = FIXED_RE.match(str(ev.get("fixed") or ""))
                t = tuple(int(x) for x in m.groups()) if m else None
                if t and seen and t > seen and (best is None or t < best):
                    best = t
    return ".".join(str(x) for x in best) if best else None


def _osv_key(vuln):
    aliases = vuln.get("aliases") if isinstance(vuln.get("aliases"), list) else []
    names = [str(vuln.get("id") or "")] + [a for a in aliases if isinstance(a, str)]
    cves = sorted(n.upper() for n in names if CVE_ONE.match(n.upper()))
    if cves:
        return cves[0]
    ghsa = sorted(n for n in names if GHSA_ONE.match(n))
    if ghsa:
        return ghsa[0]
    first = names[0] if names else ""
    return first if GO_ONE.match(first) else None      # e.g. MAL- records, or a malformed id: not a flaw advisory


def osv_listed(osv_vulns) -> int:
    """How many distinct flaws the advisory database lists for the version asked about,
    fixed later or not (withdrawn records and non-advisories dropped). PURE."""
    return len({k for k in (_osv_key(v) for v in _dicts(osv_vulns) if not v.get("withdrawn")) if k})


def collect(newer_releases, osv_vulns, ecosystem, package, version) -> dict:
    """{flaw id: Flaw}: every CVE the newer full releases' notes name, plus every record
    the advisory database lists for this version WITH a later release that fixes it, each
    flaw once. Every flaw kept has a fixing release, so "update to <the newest of them>"
    covers every flaw counted. PURE."""
    flaws = {}
    for r in sorted(newer_releases, key=lambda r: r.vt):
        for c in r.cves:
            flaws.setdefault(c, Flaw(c, fixed_in=r.version, in_notes=True))
    for v in _dicts(osv_vulns):
        if v.get("withdrawn"):
            continue
        key = _osv_key(v)
        if not key:
            continue
        fx = _lowest_fix(v, ecosystem, package, version)
        f = flaws.get(key)
        if f is None:
            if not fx:
                continue          # no later release fixes it: not an OUT-OF-DATE fact, so not counted here
            f = flaws[key] = Flaw(key, fixed_in=fx)
        elif fx and not f.in_notes and vt(fx) < vt(f.fixed_in):
            f.fixed_in = fx
        f.in_osv = True
        text = " ".join(str(v.get("summary") or v.get("details") or "").split())
        if text and not f.read and not CVE_ONE.match(key):
            f.read, f.crash = True, bool(CRASH_WORDS.search(text))
    return flaws


def describe(flaw: Flaw, record, kev_ids) -> Flaw:
    """Read one flaw's NVD record (None: NVD does not hold it): was its published
    description read, and does it use the crash-or-overload words. The description itself is
    never kept or shown: a page of eighteen write-ups is a page nobody reads (Howie,
    2026-11-12 18:25). A record in a shape nobody expects fills nothing. PURE."""
    flaw.kev = flaw.id in (kev_ids or ())
    if not isinstance(record, dict):
        return flaw
    flaw.kev = flaw.kev or (isinstance(record.get("cisaExploitAdd"), str) and bool(record["cisaExploitAdd"]))
    desc = next((d.get("value") for d in _dicts(record.get("descriptions"))
                 if d.get("lang") == "en" and isinstance(d.get("value"), str)), "")
    text = " ".join(desc.split())
    if text:
        flaw.read, flaw.crash = True, bool(CRASH_WORDS.search(text))
    return flaw


@dataclass
class Lookup:
    """What the public sources said for one (product, version shown)."""
    flaws: dict = field(default_factory=dict)       # id -> Flaw
    releases: list = field(default_factory=list)    # the newer full releases whose notes name a flaw
    osv_count: int = 0                              # of these flaws, how many the advisory database lists
    osv_total: int = 0                              # every flaw it lists for this version, fixed later or not


# ── wording ──────────────────────────────────────────────────────────────────

def _count(n: int) -> str:
    return f"{n} published flaw{'' if n == 1 else 's'}"


def month_day(day, today_year=None) -> str:
    """'2026-11-05' -> 'Nov 5'; the year is added when it is not this year. PURE."""
    m = DAY_RE.match(day or "")
    if not m or not 1 <= int(m.group(2)) <= 12:
        return ""
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    return f"{MONTHS[mo - 1]} {d}" + ("" if today_year is None or y == today_year else f", {y}")


def top_fix(flaws) -> str | None:
    """The newest of the listed flaws' fixing releases: updating to it covers every flaw
    counted (each flaw carries the lowest release that fixes it)."""
    vs = [vt(f.fixed_in) for f in flaws.values() if vt(f.fixed_in)]
    return ".".join(str(x) for x in max(vs)) if vs else None


def crash_count(flaws) -> int | None:
    """How many flaws their publishers describe as crash or overload flaws; None when any
    description was not read (the count is then left off, never understated). PURE."""
    if not flaws or not all(f.read for f in flaws.values()):
        return None
    return sum(1 for f in flaws.values() if f.crash)


# flaw_text's first line, when it has one. crash_ids_listed reads back exactly what flaw_text
# writes; a test pins the two together.
_CRASH_LINE = re.compile(r"\AThe (?:\d+ described as crash or overload flaws|one described as a crash or "
                         r"overload flaw): (.+)\.\Z")


def crash_ids_listed(description) -> set:
    """The flaw numbers a finding's own text lists as crash or overload flaws (the line
    flaw_text writes), or none. PURE."""
    for line in (description.split("\n") if isinstance(description, str) else ()):
        m = _CRASH_LINE.match(line)
        if m:
            return set(m.group(1).split(", "))
    return set()


def carried_over(look: Lookup, description) -> Lookup:
    """Today's reading with the finding's own earlier answer for each CVE whose published
    description was NOT read today: read, and a crash or overload flaw exactly when the
    finding's text lists it. A flaw read today keeps today's answer, and a flaw NVD is
    never asked about stays unread. Only for comparing with what the finding already says
    (advisory_watch.plan_doors): on a day NVD answers slowly, a finding that had its
    count keeps its words instead of losing the count until NVD is quick again. PURE."""
    listed = crash_ids_listed(description)
    flaws = {i: (f if f.read or not CVE_ONE.match(i) else replace(f, read=True, crash=i in listed))
             for i, f in look.flaws.items()}
    return replace(look, flaws=flaws)


def title(display, version, flaws) -> str:
    """Rule 3r's own title (Howie, 2026-10-22), the same words advisory_watch.finding_fields
    writes; a test pins the two equal."""
    n, n_kev = len(flaws), sum(1 for f in flaws.values() if f.kev)
    on_kev = f", {n_kev} on CISA’s exploited list" if n_kev else ""
    return f"Runs {display} {version}: out of date — {_count(n)} fixed in later versions{on_kev}; update it"


def lead(display, version, look: Lookup, today_year=None, last_shown_day=None, no_longer_shown=False) -> str:
    """The approved lead: what was seen, what its maker says, what the publishers'
    descriptions say. PURE."""
    flaws, n = look.flaws, len(look.flaws)
    if no_longer_shown:
        when = f" on {month_day(last_shown_day, today_year)}" if month_day(last_shown_day, today_year) else " in an earlier scan"
        first = (f"This sign-in last showed {display} {version}{when}; the version is no longer shown. "
                 f"Confirm it was updated. ")
    else:
        first = f"This sign-in shows {display} {version}. "
    notes = [f for f in flaws.values() if f.in_notes]
    only_osv = [f for f in flaws.values() if not f.in_notes]
    top = top_fix(flaws)
    rels = look.releases
    if notes and not only_osv and rels:
        last = rels[-1]
        date = f" ({month_day(last.day, today_year)})" if month_day(last.day, today_year) else ""
        if len(rels) == 1:
            said = f"Its maker says release {last.version}{date} fixes {_count(n)}"
        else:
            said = f"Its maker says the releases after it, up to {last.version}{date}, fix {_count(n)}"
    elif notes and not only_osv:
        said = f"Its maker’s release notes list {_count(n)} fixed in later releases"
    elif not notes:
        said = f"The open advisory database lists {_count(n)} in it, fixed by {top}"
    else:
        said = f"Its maker’s release notes and the open advisory database list {_count(n)} fixed by {top}"
    k = crash_count(flaws)
    if k:
        said += ("; 1 is described as a crash or overload flaw" if k == 1
                 else f"; {k} are described as crash or overload flaws")
    return first + said + "."


def fix_line(display, look: Lookup, no_longer_shown=False) -> str:
    to = f"to {top_fix(look.flaws)} or later"
    if no_longer_shown:
        return f"Confirm {display} was updated {to}. If it was not, update it."
    return f"Update {display} {to}."


def flaw_text(display, version, look: Lookup, built_with) -> str:
    """The "published flaws" section, a few lines and never one per flaw (Howie, 2026-11-12
    18:25, on a page that listed every write-up: "No one will ever read anything like this";
    18:30, on this short form: "yes"). Which flaws their publishers describe as crash or
    overload flaws, by number; where they sit, by the source that says so; CISA's list.
    Every flaw's number is already on the page. No sentence about this site. PURE."""
    flaws = sorted(look.flaws.values(), key=lambda f: f.id)
    n = len(flaws)
    lines = []
    k = crash_count(look.flaws)
    if k:
        ids = ", ".join(f.id for f in flaws if f.crash)
        lines.append(f"The {k} described as crash or overload flaws: {ids}." if k != 1 else
                     f"The one described as a crash or overload flaw: {ids}.")
    noted = sum(1 for f in flaws if f.in_notes)
    if noted == n:
        lines.append(f"Its maker’s notes place {'all ' + str(n) if n != 1 else 'it'} in {display} or in {built_with}.")
    elif noted:
        lines.append(f"Its maker’s notes place {noted} of them in {display} or in {built_with}; the open "
                     f"advisory database lists the other {n - noted} against {display}’s own code.")
    else:
        lines.append(f"The open advisory database lists {'them' if n != 1 else 'it'} against {display}’s own code.")
    listed = [f.id for f in flaws if f.kev]
    lines.append("None is on CISA’s exploited list." if not listed else
                 f"On CISA’s exploited list: {', '.join(listed)}.")
    return "\n".join(lines)


def finding_fields(key, version, look: Lookup, today_year=None, last_shown_day=None,
                   no_longer_shown=False) -> dict:
    """Every column advisory_watch writes for one sign-in's out-of-date finding. PURE.
    Raises ValueError without a version or without a flaw: neither is a finding."""
    spec = DOORS[key]
    disp = spec["display"]
    if not vt(version) or not look.flaws:
        raise ValueError(f"{key} {version!r}: no release number or no listed flaw is not a finding")
    kev = any(f.kev for f in look.flaws.values())
    what = lead(disp, version, look, today_year, last_shown_day, no_longer_shown)
    fix = fix_line(disp, look, no_longer_shown)
    could = flaw_text(disp, version, look, spec["built_with"])
    cves = sorted(f.id for f in look.flaws.values() if CVE_ONE.match(f.id))
    refs = [f"https://github.com/{spec['repo']}/releases/tag/v{r.version}" for r in look.releases[-5:]]
    refs += [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:20]]
    return dict(
        title=title(disp, version, look.flaws)[:200],
        severity=evidence.version_based_severity(kev),
        category="supply_chain",
        description="\n\n".join([what, could, SOURCES_LINE, "Fix: " + fix]),
        description_synth=what,
        impact=could,
        remediation=fix,
        cve=cves,
        references=refs,
        tags=["advisory-watch", "out-of-date", "version-shown", "sign-in", key]
             + (["version-no-longer-shown"] if no_longer_shown else [])
             + (["cisa-kev"] if kev else []),
        affected_component=disp,
        affected_component_version=version,
    )
