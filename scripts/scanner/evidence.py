"""evidence.py — what a version-based finding may claim, and how much it weighs (KB 12 job 3r).

Howie, 2026-10-22 15:58: "we don't know. We have no inside information on anything."
16:00: "the only thing that we show on the site is a proven vulnerability. Versions are
irrelevant until … we have found some type of a potential exploit." 20:34: "There are
risks and there are things that are known, that's all." The ladder (ruled 16:02–16:05):

  PROVEN       seen directly: a harmless reaction, or a fact the host shows anyone.
               Only proven can rate a site HIGH or CRITICAL. (Not decided here: every
               writer that is not version-based keeps its own severity.)
  OUT OF DATE  a version we SAW, inside a published flaw's affected range.
               MODERATE; MODERATE-HIGH when one of its flaws is on CISA's exploited
               list. Says "out of date … update it", never "vulnerable".
  GUESS        a version we did NOT see. Not a finding at all.

Also here: reading an advisory's own words for the range it affects. wpvulnerability.net's
operator often carries only the upper bound ("< 7.0.11") while the advisory text names a
narrower one ("in versions 7.0.0 to 7.0.10"); on 2026-10-22 four of five Slider Revolution
advisories matched 6.7.58 only that way. `range_excludes` is True only when the text states
at least one range and the version is outside every one of them; anything it cannot read
keeps the advisory. The writer trusts a two-ended operator over the sentence
(`operator_has_both_bounds`). The alerter's digest_words reads the same phrases with a copy
of `stated_ranges` (a test checks the two agree, sentence by sentence).

PURE except `kev_ids()`, which reads CISA's catalog once per process and never raises.
"""
from __future__ import annotations

import json
import re
import urllib.request

OUT_OF_DATE = "MODERATE"
OUT_OF_DATE_KEV = "MODERATE-HIGH"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIN_ENTRIES = 1000          # the real catalog has 1,400+; fewer means a bad download
USER_AGENT = "Sentry-ASM evidence/1.0 (public CISA catalog)"


def version_based_severity(kev: bool) -> str:
    """The out-of-date rung. PURE."""
    return OUT_OF_DATE_KEV if kev else OUT_OF_DATE


def _vt(v: str | None) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


_N = r"\d+(?:\.\d+)*"
# where an advisory states what it affects: "… in versions 7.0.0 to 7.0.10 via …",
# "… in all versions up to, and including, 2.5.10 due to …", "This issue affects SVG
# Support: from n/a through 2.5.14.", "… versions 6.0.0-6.7.55 and 7.0.0-7.0.14 …"
_ANCHOR = re.compile(r"\bversions?\b|\baffects [^.:]{0,80}:", re.I)
_CLAUSE_END = re.compile(r"\.\s+[A-Z]|\.\s*$|\s(?:via|due to|because|allows|which|This)\b")
_PAIR = re.compile(rf"(?:from\s+)?(n/?a|{_N})\s*(?:-|–|to|through)\s*({_N})", re.I)
_UPTO_INCL = re.compile(rf"\bup to,?(?: and including,?)?\s+(?:version\s+)?({_N})", re.I)
_BEFORE = re.compile(rf"\b(?:prior to|before|below|less than)\s+(?:version\s+)?({_N})", re.I)


def stated_ranges(text: str | None) -> list:
    """Every affected range the advisory's own words state: [(lo or None, hi, hi_inclusive)].
    Reads every clause that follows a "version(s)" or "affects …:" anchor, and every range
    in it (3r second check, Grok: CVE-2026-9050 says "versions 6.0.0-6.7.55 and
    7.0.0-7.0.14" — two ranges, both count). PURE."""
    t = text or ""
    out = []
    for a in _ANCHOR.finditer(t):
        window = t[a.end():a.end() + 200]
        e = _CLAUSE_END.search(window)
        clause = window[:e.start()] if e else window
        for m in _PAIR.finditer(clause):
            lo = None if m.group(1).lower().replace("/", "") == "na" else m.group(1)
            out.append((lo, m.group(2), True))
        for m in _UPTO_INCL.finditer(clause):
            out.append((None, m.group(1), True))
        for m in _BEFORE.finditer(clause):
            out.append((None, m.group(1), False))
    return list(dict.fromkeys(out))


def _inside(v: tuple, rng) -> bool:
    lo, hi, incl = rng
    if lo and _vt(lo) and v < _vt(lo):
        return False
    h = _vt(hi)
    return not h or v < h or (incl and v == h)


def range_excludes(version: str | None, text: str | None) -> bool:
    """True only when the advisory states at least one range and the version is outside
    EVERY one of them. Nothing readable, or no version: False (keep). PURE."""
    v = _vt(version)
    rs = stated_ranges(text)
    if not v or not rs:
        return False
    return not any(_inside(v, r) for r in rs)


def operator_has_both_bounds(operator_summary: str | None) -> bool:
    """wpvulnerability.net's structured operator, e.g. '>= 7.0.0 and < 7.0.11'. When it
    states both ends it is trusted over the sentence (3r second check, Grok): a sentence
    that disagrees with a two-ended operator keeps the advisory."""
    o = operator_summary or ""
    return ">" in o and "<" in o


_KEV_CACHE: set | None = None


def kev_ids(get=None) -> set:
    """CVE ids on CISA's known-exploited catalog, read once per process. A failed or
    short download gives an empty set: the rung stays MODERATE (never guessed up)."""
    global _KEV_CACHE
    if _KEV_CACHE is not None:
        return _KEV_CACHE
    try:
        if get is None:
            req = urllib.request.Request(KEV_FEED, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=30) as r:
                d = json.loads(r.read().decode("utf-8"))
        else:
            d = get(KEV_FEED)
        vulns = (d or {}).get("vulnerabilities")
        ids = {x.get("cveID") for x in vulns if isinstance(x, dict) and x.get("cveID")} \
            if isinstance(vulns, list) else set()
        _KEV_CACHE = ids if len(ids) >= KEV_MIN_ENTRIES else set()
    except Exception:            # network, JSON, anything: never sink a scan over a flag
        _KEV_CACHE = set()
    return _KEV_CACHE
