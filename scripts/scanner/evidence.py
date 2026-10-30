"""evidence.py — what a version-based finding may claim, and how much it weighs (KB 12 job 3r).

Howie, 2026-10-22 15:58: "we don't know. We have no inside information on anything."
16:00: "the only thing that we show on the site is a proven vulnerability. Versions are
irrelevant until … we have found some type of a potential exploit." 20:34: "There are
risks and there are things that are known, that's all." The ladder (ruled 16:02–16:05):

  PROVEN       seen directly: a harmless reaction, or a fact the host shows anyone.
               Only proven can rate a site HIGH or CRITICAL, and since D-074 (2026-10-29,
               `harm_rating` below) only when it could actually be exploited.
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

PURE except `kev_ids()`, which reads CISA's catalog once per process and never raises, and
falls back to the KEV list in cve_enrichments through the reader an entry point installs
(`set_kev_fallback`, `db_kev_reader`; job 3s); and `cna_record()` (S1, 2026-10-29), which reads
one CVE record from the CVE Program's own API, once per CVE per process, only after an entry
point has called `enable_cna_reads()`, and never raises.

S1 (2026-10-29, Howie 17:55 "Go with number one"): the flaw's own record. wpvulnerability.net
files CVE-2026-6728 as one range, "Slider Revolution < 7.0.10"; the record its CNA published
(Wordfence) has two, 6.0–6.7.54 and 7.0–7.0.9, everything else "unaffected". Five Command
sites run 6.7.58 or 6.8.1 and were told to "fix soon". `cna_leaves_out` reads the record's
structured `affected` list and says so only when the record is plain about it; anything it
cannot read keeps the advisory, the same direction as `range_excludes`.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
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
_KEV_FALLBACK = None


def set_kev_fallback(reader) -> None:
    """KB 12 job 3s (plan re-check MF1, 2026-10-23). Installed ONCE per process by each entry
    point that holds the real DSN (run_light, run_medium, run_heavy and advisory_watch mains):
    a callable returning the KEV CVE ids already held in public.cve_enrichments. Phases run
    through legacy_adapter see ctx.dsn = None (phase_contract._LegacyRecorder), so the reader
    must not depend on a phase's context. Without it, a scan run while CISA's download fails
    computes MODERATE and the upsert LOWERS a MODERATE-HIGH row cve_scoring raised."""
    global _KEV_FALLBACK
    _KEV_FALLBACK = reader


def kev_fallback() -> set:
    """The installed reader's answer, or an empty set (no reader, or the reader failed)."""
    if _KEV_FALLBACK is None:
        return set()
    try:
        return {c for c in (_KEV_FALLBACK() or ()) if c}
    except Exception:            # the database being away must never sink a scan either
        return set()


def db_kev_reader(dsn: str):
    """A reader for set_kev_fallback: the KEV-listed CVE ids in public.cve_enrichments
    (kept every two hours by cve-scoring.yml). One short read-only connection."""
    def read() -> set:
        import psycopg      # lazy: this module stays importable without a driver
        with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as c, c.cursor() as cur:
            cur.execute("SELECT cve_id FROM public.cve_enrichments WHERE kev_listed")
            return {r[0] for r in cur.fetchall() if r and r[0]}
    return read


def kev_ids(get=None, fallback=None) -> set:
    """CVE ids on CISA's known-exploited catalog, read once per process. A failed or
    short download falls back to the list already held in cve_enrichments (job 3s; the
    reader passed here, else the one set_kev_fallback installed), so a CISA outage can never
    make a writer compute MODERATE and lower a raised row; with no reader, an empty set (the
    rung stays MODERATE, never guessed up)."""
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
        if len(ids) >= KEV_MIN_ENTRIES:
            _KEV_CACHE = ids
            return _KEV_CACHE
    except Exception:            # network, JSON, anything: never sink a scan over a flag
        pass
    if fallback is not None:
        try:
            _KEV_CACHE = {c for c in (fallback() or ()) if c}
        except Exception:
            _KEV_CACHE = set()
    else:
        _KEV_CACHE = kev_fallback()
    return _KEV_CACHE


# ── S1 (2026-10-29): the flaw's own published record ─────────────────────────────────
CNA_RECORD_URL = "https://cveawg.mitre.org/api/cve/{}"
CNA_USER_AGENT = "Sentry-ASM evidence/1.0 (public CVE record)"
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
_CNA_CACHE: dict = {}
_CNA_READS_ON = False
# The S1 review's follow-up (2026-10-29, minor 1: "no aggregate cap on reads"): when the CVE
# Program's API does not answer (no network, a timeout, a 5xx or 429), every later read in this
# run would wait its own 15 seconds for the same outcome. So the first such failure stops reads
# for the rest of the process; every finding after it is kept as filed. A 404 or a bad answer
# for one CVE says nothing about the service and stops nothing.
_CNA_DOWN = ""


def cna_reads_down() -> str:
    """Why reads stopped for this run ("" while they have not)."""
    return _CNA_DOWN


def _service_failure(e: BaseException) -> str:
    """A short reason when `e` means the service itself did not answer, else ""."""
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code}" if (e.code >= 500 or e.code == 429) else ""
    if isinstance(e, (TimeoutError, OSError)):        # URLError, socket timeout, refused, reset
        return type(e).__name__
    return ""


def enable_cna_reads() -> None:
    """Called ONCE per process by each entry point that runs the WordPress check
    (run_light, run_medium, run_heavy mains). Off by default, so nothing that merely
    imports this module (tests, the alerter) ever reaches the network."""
    global _CNA_READS_ON
    _CNA_READS_ON = True


def cna_record(cve_id: str | None, get=None) -> dict | None:
    """The CVE record (CVE JSON 5) for `cve_id`, as the CVE Program serves it, read once per
    CVE per process (a failure is remembered too, so one bad id never costs a timeout per
    plugin). None when reads are off, the id is malformed, the answer is not that CVE's
    record, or anything fails. Never raises: a missing record only ever KEEPS a finding.
    The first time the service itself does not answer, reads stop for the run (`_CNA_DOWN`)."""
    global _CNA_DOWN
    cid = (cve_id or "").strip().upper()
    if not _CVE_ID.fullmatch(cid):
        return None
    if cid in _CNA_CACHE:
        return _CNA_CACHE[cid]
    if get is None and not _CNA_READS_ON:
        return None
    if _CNA_DOWN:
        return None
    rec = None
    try:
        url = CNA_RECORD_URL.format(cid)
        if get is None:
            req = urllib.request.Request(url, headers={"User-Agent": CNA_USER_AGENT})
            with urllib.request.urlopen(req, timeout=15) as r:
                d = json.loads(r.read().decode("utf-8"))
        else:
            d = get(url)
        meta = (d or {}).get("cveMetadata") if isinstance(d, dict) else None
        if isinstance(meta, dict) and str(meta.get("cveId", "")).upper() == cid:
            rec = d
    except Exception as e:       # network, JSON, anything: keep the finding
        rec = None
        why = _service_failure(e)
        if why:
            _CNA_DOWN = why
            print(f"[evidence] CVE records: the CVE Program's API did not answer ({why}); no more "
                  f"reads this run, every later WordPress advisory is kept as filed", file=sys.stderr)
    _CNA_CACHE[cid] = rec
    return rec


def _norm_name(s: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


_NUMERIC_TYPES = {"", "semver", "custom", "python", "maven", "rpm"}   # read as dotted numbers


def _vcmp(a: tuple, b: tuple) -> int:
    """Compare two dotted-number tuples, padding the shorter with zeros ("6.0" == "6.0.0")."""
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _plain(v) -> tuple | None:
    """A version we can compare: digits and dots only ("6.7.54", "7.0"). Anything else
    ("7.0.9-beta", "6.x", "") is None, which keeps the finding."""
    v = str(v or "").strip()
    return tuple(int(x) for x in v.split(".")) if re.fullmatch(r"\d+(?:\.\d+)*", v) else None


def cna_leaves_out(version: str | None, record: dict | None, names) -> str | None:
    """S1. A short reason ("Wordfence's record: affected 6.0 to 6.7.54, 7.0 to 7.0.9") when the
    flaw's published record leaves `version` out, and None (keep the finding) otherwise.
    Says so only when ALL of these hold:
      * the version is plain digits and dots;
      * the record's CNA `affected` list has at least one entry for this product: its
        product name, letters and digits only, equals one of `names` (the plugin's name from
        the title, its slug) — exactly, so "Slider" never stands in for "Slider Revolution";
      * EVERY such entry says defaultStatus "unaffected", lists at least one affected
        version, and every affected version is a range this reads plainly: a numeric lower
        bound ("0", "n/a" or "*" = from the start) with lessThan / lessThanOrEqual, or one
        exact version; no `changes`, no version types it cannot compare;
      * the version is inside none of them.
    A product entry that does not match the names is not read at all. PURE."""
    v = _plain(version)
    if v is None or not isinstance(record, dict):
        return None
    cna = ((record.get("containers") or {}).get("cna") or {})
    affected = cna.get("affected")
    if not isinstance(affected, list):
        return None
    wanted = {n for n in (_norm_name(x) for x in (names or ())) if len(n) >= 3}
    mine = [a for a in affected if isinstance(a, dict) and _norm_name(a.get("product")) in wanted]
    if not mine:
        return None
    spans = []
    for a in mine:
        if a.get("defaultStatus") != "unaffected":
            return None
        items = [x for x in (a.get("versions") or []) if isinstance(x, dict)]
        hits = [x for x in items if x.get("status") == "affected"]
        if not hits:
            return None
        for x in hits:
            if x.get("changes") or str(x.get("versionType") or "").lower() not in _NUMERIC_TYPES:
                return None
            lo_raw = str(x.get("version") or "").strip()
            lo = None if lo_raw.lower() in ("0", "n/a", "*") else _plain(lo_raw)
            if lo is None and lo_raw.lower() not in ("0", "n/a", "*"):
                return None
            if "lessThan" in x or "lessThanOrEqual" in x:
                incl = "lessThanOrEqual" in x
                hi_raw = str(x.get("lessThanOrEqual") if incl else x.get("lessThan")).strip()
                if hi_raw == "*":
                    if lo is None or _vcmp(v, lo) >= 0:
                        return None                         # open-ended above: inside
                    spans.append(f"{lo_raw} and later")
                    continue
                hi = _plain(hi_raw)
                if hi is None:
                    return None
                below = lo is not None and _vcmp(v, lo) < 0
                above = _vcmp(v, hi) > 0 if incl else _vcmp(v, hi) >= 0
                if not below and not above:
                    return None                             # inside this range: keep
                spans.append(f"{'from the start' if lo is None else lo_raw} "
                             f"{'to' if incl else 'up to, not including,'} {hi_raw}")
            else:
                if lo is None:
                    return None
                if _vcmp(v, lo) == 0:
                    return None                             # this exact version: keep
                spans.append(f"exactly {lo_raw}")
    who = ((record.get("cveMetadata") or {}).get("assignerShortName") or "the CNA")
    return f"{who}'s record: affected {', '.join(spans)}"


# ── D-074 (2026-10-29): High and Critical mean it could actually be exploited ─────────────
# Howie, 2026-10-29 19:30: "It has to be something that could actually be exploited." (his
# Horizon3 NodeZero paradigm). A rating answers "how worried should you be": HIGH or CRITICAL
# needs (1) seen directly, not a version number (job 3r, above) AND (2) a way in, or a way to
# read or change data or take over a session, that someone on the internet could use. Seen
# directly but not exploitable (a firewall's self-made certificate, no revocation, a long
# certificate life, a method merely advertised, a port that is open) is MODERATE at most.
# Applied by every writer (run_light, run_medium, run_heavy, the offline import_jsonl) to the
# severity it is about to write, so no tool's own rating reaches the database unchecked.
# An ALLOW-list, not a block list: a kind not named here is capped, so a tool that invents a
# new HIGH can never slip past (the #037 ceiling's lesson, note 243).
HARM_CAP = "MODERATE"
_HARM_RATED = {"HIGH", "CRITICAL"}
# testssl ids whose own test shows a flaw someone on the internet can use against the server
# directly (no need to sit between a visitor and the site): memory read (heartbleed,
# ticketbleed) and the RSA oracle (ROBOT). LOGJAM, BEAST, SWEET32, POODLE, CCS, old protocol
# versions and every certificate fact need a network position or open nothing: capped.
EXPLOITABLE_TESTSSL_IDS = frozenset({"heartbleed", "ticketbleed", "robot"})
# Template tags (nuclei) that name a way in or a way to data, shown by the template's own
# harmless match (D-056: detection only). A template with none of these keeps at most MODERATE.
EXPLOITABLE_TAGS = frozenset({
    "exposure", "takeover", "unauth", "auth-bypass", "bypass", "middleware-bypass",
    "lfi", "file-read", "traversal", "rce", "sqli", "injection", "ssrf", "xxe", "xss", "idor",
    "backup", "leak", "secret", "token", "keys",
})


def _check_of(finding_id: str) -> tuple[str, str]:
    """('<tier or tool>', '<check>') from '<asset>:<tier>:<check>[:<hash>]'. The asset part may
    itself hold colons (ip:1.2.3.4), so the tier is found by name, not by position."""
    parts = (finding_id or "").split(":")
    for i, p in enumerate(parts):
        if p in ("light", "medium", "heavy", "exposure", "testssl", "sslyze", "commandsentry_heavy"):
            return p, ":".join(parts[i + 1:])
    return "", ""


def harm_exploitable(finding_id: str, source: str = "", tags=()) -> bool:
    """True when this kind of finding, at HIGH or CRITICAL, shows something that could
    actually be exploited. PURE."""
    tier, check = _check_of(finding_id)
    low = check.lower()
    tagset = {str(t).lower() for t in (tags or ())}
    if tier == "light" and low.startswith("exposed-path-"):
        # light writes HIGH here only after reading the file's content (a secret or source
        # code anyone can download); otherwise the path is INFO or suppressed.
        return True
    if tier in ("testssl", "sslyze") or source in ("testssl", "sslyze"):
        return low.split(":", 1)[0] in EXPLOITABLE_TESTSSL_IDS
    if "waf-absent-exposed" in low:
        # HIGH only when an open HIGH or CRITICAL sits behind the missing firewall, and after
        # this rule that can only be an exploitable one (run_heavy._maybe_emit_exposed_finding).
        return True
    if tier == "medium" and low.startswith("nuclei-"):
        return bool(tagset & EXPLOITABLE_TAGS)
    return False


def harm_rating(severity: str | None, *, finding_id: str = "", source: str = "",
                tags=()) -> tuple[str | None, str | None]:
    """(severity to write, reason or None). HIGH or CRITICAL that `harm_exploitable` doesn't
    back becomes MODERATE, with a plain reason for the log. A hand-test entry
    (source manual_named) keeps the rating the person gave it: Sentry never rewrites a
    person's judgement (the same line as never auto-closing them). Everything else passes
    unchanged. Never raises. PURE."""
    sev = (severity or "").upper()
    if sev not in _HARM_RATED or (source or "") == "manual_named":
        return severity, None
    try:
        if harm_exploitable(finding_id, source, tags):
            return severity, None
    except Exception:
        pass
    return HARM_CAP, (f"{sev} capped to {HARM_CAP}: seen, but nothing here shows a way in "
                      f"(D-074)")
