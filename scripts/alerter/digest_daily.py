"""digest_daily.py — the daily digest as a to-do list (KB 12 job 3l, slice 1, design D).

Howie, 2026-10-22 08:50: "This entire email needs to be simplified and redesigned."
14:45: "Let's have it be colorful. Let's have it have HTML. It can even have a little bit
of effects. There has to be a way that we can convey the information in a clever and
well-designed way, instead of throwing together a bunch of data that is almost impossible
to understand." 15:12, on design D ("your list"): "Happy, I'm thrilled."

Reworked after Howie read the first test sends (2026-10-22 19:08–19:57): "We don't have any
tickets"; "Too many of the items are complete repeats"; "What do I have to do with this risk
level?"; "What was fixed? … I have no idea what actually happened here"; and the standard for
every item: "identify it to the best of our knowledge, provide what the risk is, and provide
what the remediation is" — for business owners and the Command / Unimac IT team, who "just
need a quick glance".

WHAT THIS IS. Pure functions, no database and no network. run_alerter.py reads the same
rows it always read (plus each live site's rating now and at the window's start,
certificates about to expire with their real end date, each host's previous deep scan, and
each listed finding's remediation, description and CVEs) and hands them here. The daily:

    headline        the day's job ("Today: renew the certificate on pm.unimacgraphics.com.")
    Needs you today coverage gaps, CRITICAL / HIGH / MODERATE-HIGH new or regressed
                    findings, a firewall that stopped blocking, certificates <= 14 days
    This week       MODERATE new or regressed findings, findings confirmed again, sites
                    that got riskier unexplained, unrecognized block pages, new or dark hosts
    Fixed since     each real fix, saying what and where
    yesterday
    one plain line  minor (LOW) items by name; INFO is never mentioned

Every finding item says what we found, what it means, and the fix and who does it, in
digest_words' plain words; one problem across sites is one item (www. folded into its
site). Only what is known: "version not shown" rows are never listed, counted or
mentioned, and do not set a site's level (SQL_SITE_RATINGS). No risk tally: where every site
stands is the Monday weekly's.

EMAIL-SAFE BY CONSTRUCTION. Tables, inline styles, bgcolor; no flex, no grid, no script; a
fluid 640 px column that never runs off a phone; site names that never break mid-word. The
logo is an inline image (cid:brandlogo) that mailer.py attaches; the brand (name, colors,
logo) is a data file per repo, scripts/alerter/brand/brand.json, so this code is identical
in both repos.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from html import escape, unescape

import digest_words as dw_words
import told as told_rule

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9
    ZoneInfo = None  # type: ignore

BRAND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "brand")
LOGO_CID = "brandlogo"

SEV_ORDER = {"CRITICAL": 1, "HIGH": 2, "MODERATE-HIGH": 3, "MODERATE": 4, "LOW": 5, "INFO": 6}
DO_TODAY_SEVERITIES = ("CRITICAL", "HIGH", "MODERATE-HIGH")
TICKET_SEVERITIES = ("MODERATE",)
CERT_DAYS = 14          # a certificate this close to expiring is a "do today"
DEEP_SCAN_GAP_DAYS = 30  # "first deep scan since <date>" when the previous one is this old

# The bar's bands, worst first: (key, words, fill, text on fill). Colors that must be
# told apart also differ in lightness (berry, burnt orange, amber, yellow, mint, pale
# green, grey). CRITICAL and MODERATE-HIGH have their own bands (checker minor 7);
# "not rated" splits honestly into never-scanned and everything-resolved (minor 8).
BANDS = (
    ("critical", "critical", "#8B1A4A", "#FFFFFF"),
    ("high", "high", "#C2410C", "#FFFFFF"),
    ("modhigh", "moderate-high", "#F08C00", "#2E1A00"),
    ("moderate", "moderate", "#FFD43B", "#3A2E00"),
    ("low", "low", "#63E6BE", "#083B2C"),
    ("clear", "all clear", "#D3F0DF", "#0B4A31"),
    ("unscanned", "not scanned yet", "#D9DEE5", "#2B3747"),
)
BAND_RANK = {k: i for i, (k, *_r) in enumerate(BANDS)}
BAND_FILL_TEXT = {k: (fill, text) for k, _w, fill, text in BANDS}
BAND_TITLE = {"critical": "Critical", "high": "High", "modhigh": "Moderate-high", "moderate": "Moderate",
              "low": "Low", "clear": "All clear", "unscanned": "Not scanned yet"}
SEV_STYLE = {  # (pill fill, pill text, card tint)
    "CRITICAL": ("#8B1A4A", "#FFFFFF", "#F9E8EF"),
    "HIGH": ("#C2410C", "#FFFFFF", "#FFF1E8"),
    "MODERATE-HIGH": ("#F08C00", "#2E1A00", "#FFF4E0"),
    "MODERATE": ("#FFD43B", "#3A2E00", "#FFF8D6"),
    "LOW": ("#63E6BE", "#083B2C", "#EAFBF4"),
}
SEV_WORD = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE-HIGH": "Moderate-high",
            "MODERATE": "Moderate", "LOW": "Low", "INFO": "Info"}
INK, MUTED, RULE, PAGE = "#0F1B2D", "#4A5668", "#E4E9F0", "#E9EEF5"
GOOD = "#0B7A55"
FONT = "-apple-system, BlinkMacSystemFont, 'Helvetica Neue', Helvetica, Arial, sans-serif"
DISPLAY = "'Bricolage Grotesque', 'Helvetica Neue', Helvetica, Arial, sans-serif"

DEFAULT_BRAND = {
    "short_name": "Sentry", "band_bg": "#0A4595", "band_text": "#FFFFFF",
    "band_muted": "#D5E2F5", "band_border": "", "button": "#0A4595",
    "logo_file": "", "logo_alt": "", "logo_width": 160, "tz": "America/New_York",
}


# ── brand ─────────────────────────────────────────────────────────────────────
def load_brand(directory: str = BRAND_DIR) -> dict:
    """brand.json beside its logo. A missing or broken file falls back to a plain brand
    with no logo: the digest still goes out (decoration never costs the send)."""
    brand = dict(DEFAULT_BRAND)
    try:
        with open(os.path.join(directory, "brand.json"), encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            brand.update({k: v for k, v in data.items() if v is not None})
    except (OSError, ValueError):
        pass
    brand["logo_bytes"] = b""
    if brand.get("logo_file"):
        try:
            with open(os.path.join(directory, brand["logo_file"]), "rb") as f:
                brand["logo_bytes"] = f.read()
        except OSError:
            brand["logo_bytes"] = b""
    return brand


def inline_images(brand: dict) -> list[tuple[str, bytes, str]]:
    """What mailer.send_email(inline_images=...) needs for this brand."""
    data = brand.get("logo_bytes") or b""
    if not data:
        return []
    mime = "image/png" if str(brand.get("logo_file", "")).lower().endswith(".png") else "image/jpeg"
    return [(LOGO_CID, data, mime)]


def local_time(dt: datetime, brand: dict) -> datetime:
    if ZoneInfo is None:  # pragma: no cover
        return dt
    try:
        return dt.astimezone(ZoneInfo(brand.get("tz") or "America/New_York"))
    except Exception:  # pragma: no cover - unknown zone name
        return dt


def _clock(dt: datetime) -> str:
    """'8:09 AM'"""
    h = dt.hour % 12 or 12
    return f"{h}:{dt.minute:02d} {'AM' if dt.hour < 12 else 'PM'}"


def _day(dt: datetime) -> str:
    """'Oct 9'"""
    return f"{dt:%b} {dt.day}"


# ── sites: from the evidence (KB 12 job 4, push B) ────────────────────────────
# Howie, 2026-10-24 21:44: "it's the same damn box it's the same site." Ruled 2026-10-25
# 08:46 (D1): a www name and its plain name are one site only on evidence seen on both
# names (public.site_members, read through the v_site_of view, migration 20261025b) —
# never because of what the names look like. run_alerter loads the map once per run with
# set_site_map(); every site_of() call below reads it.
_SITE_MAP: dict | None = None


def set_site_map(rows) -> None:
    """Rows of SQL_SITE_MAP: (asset_id, site_asset_id) for each name the evidence puts on
    another name's site. None — the read failed, or migration B isn't applied yet — keeps
    the old name rule, so a failed read never un-merges a site."""
    global _SITE_MAP
    _SITE_MAP = None if rows is None else {str(a).strip(): str(s).strip() for a, s in rows}


def site_of(asset_id: str, names) -> str:
    """The site a host belongs to, when that site is also a live asset in `names`.
    With the evidence loaded: www.example.com -> example.com only if site_members says
    they are one site; the three Unimac www.<sub> names (wildcard DNS, job 4 D5) stay
    themselves. Without it (set_site_map(None), tests, a failed read): the old name rule,
    'www.example.com' -> 'example.com' when the plain name is also a live asset."""
    a = (asset_id or "").strip()
    if _SITE_MAP is not None:
        s = _SITE_MAP.get(a)
        return s if s and s in names else a
    if a.lower().startswith("www.") and a[4:] in names:
        return a[4:]
    return a


def band_of(rating: str | None, ever_found: bool) -> str:
    r = (rating or "").upper()
    if r == "CRITICAL":
        return "critical"
    if r == "HIGH":
        return "high"
    if r == "MODERATE-HIGH":
        return "modhigh"
    if r == "MODERATE":
        return "moderate"
    if r in ("LOW", "INFO"):
        return "low"
    return "clear" if ever_found else "unscanned"


def site_bands(rows) -> tuple[dict, dict]:
    """Rows of SQL_SITE_RATINGS: (asset_id, rating_now, ever_found, rating_then).
    Returns ({site: band now}, {site: band then}); a site takes the worst of its hosts.
    'then' is rebuilt from findings at the window's start (rating = worst open finding,
    job 3m), with the same band words."""
    rows = list(rows or [])
    names = {r[0] for r in rows}
    now: dict = {}
    then: dict = {}
    for aid, rating, ever, before in rows:
        s = site_of(aid, names)
        b_now = band_of(rating, bool(ever))
        b_then = band_of(before, bool(ever))
        if s not in now or BAND_RANK[b_now] < BAND_RANK[now[s]]:
            now[s] = b_now
        if s not in then or BAND_RANK[b_then] < BAND_RANK[then[s]]:
            then[s] = b_then
    return now, then


def band_counts(bands: dict) -> dict:
    out = {k: 0 for k, *_r in BANDS}
    for b in bands.values():
        out[b] = out.get(b, 0) + 1
    return out


RATED = ("critical", "high", "modhigh", "moderate", "low")


def site_moves(now_b: dict, then_b: dict) -> list[tuple[str, str, list]]:
    """[(band then, band now, [sites])] for every rated site whose band changed, riskier
    moves first. A site that had no rating before is new, not a move."""
    moves: dict = {}
    for s_, b in now_b.items():
        a = then_b.get(s_)
        if a is None or a == b or a not in RATED or b not in RATED + ("clear",):
            continue
        moves.setdefault((a, b), []).append(s_)
    out = [(a, b, sorted(v)) for (a, b), v in moves.items()]
    out.sort(key=lambda t: (BAND_RANK[t[1]] > BAND_RANK[t[0]], -len(t[2]), BAND_RANK[t[1]]))
    return out


def change_words(now_counts: dict, then_counts: dict, now_b=None, then_b=None,
                 since: str = "yesterday") -> str:
    """'Since yesterday, 2 sites got riskier (Moderate to Moderate-high).' or 'No site's
    risk level changed since yesterday.' Said by site, not by tally: "moderate 18 to 16"
    left Howie asking whether sites got worse, better, or went dark (10-22)."""
    if now_b is None or then_b is None:
        diffs = [k for k in RATED if then_counts.get(k, 0) != now_counts.get(k, 0)]
        return f"No site's risk level changed since {since}." if not diffs else ""
    mv = site_moves(now_b, then_b)
    if not mv:
        return f"No site's risk level changed since {since}."
    parts = []
    for a, b, sites in mv:
        n = len(sites)
        verb = "got riskier" if BAND_RANK[b] < BAND_RANK[a] else "got safer"
        who = sites[0] if n == 1 else f"{_n(n)} sites"
        parts.append(f"{who} {verb} ({BAND_TITLE[a]} to {BAND_TITLE[b]})")
    return f"Since {since}, " + "; ".join(parts) + "."


def counts_words(counts: dict) -> str:
    """'4 critical, 13 high, 28 moderate, 2 low, 4 not scanned yet' (zeros left out)."""
    parts = [f"{counts[k]} {w}" for k, w, *_r in BANDS if counts.get(k)]
    return ", ".join(parts) if parts else "none"


# ── findings, grouped by problem ──────────────────────────────────────────────
_TAIL = re.compile(r"\s*\((?:\d+ reports?|\d+ rows merged)\)\s*$", re.I)


def problem_key(title: str | None) -> str:
    t = unescape(title or "").strip()
    return _TAIL.sub("", t).lower()


SOURCE_WORDS = {
    "advisory_watch": "daily advisory check",
    "commandsentry_heavy": "deep scan", "commandsentry_medium": "medium scan",
    "commandsentry_light": "quick scan",
}


def source_words(source: str | None) -> str:
    s = (source or "").strip().lower()
    if s in SOURCE_WORDS:
        return SOURCE_WORDS[s]
    for tail, words in (("heavy", "deep scan"), ("medium", "medium scan"), ("light", "quick scan")):
        if s.endswith(tail):
            return words
    return s.replace("_", " ") or "a scan"


def first_step(remediation: str | None, limit: int = 200) -> str:
    """The first concrete step of a finding's remediation text, as one sentence."""
    t = unescape(remediation or "").strip()
    if not t:
        return ""
    t = t.split("\n", 1)[0].strip()
    t = re.sub(r"^\s*(?:\d+[.)]|[-*•])\s*", "", t)
    # a sentence ends at . ! ? followed by a capital (or the end): "vs. prevention" goes on
    # (or the next numbered step: "… the console. 2. Switch it")
    m = re.match(r"(.+?[.!?])(?=\s+(?:[A-Z(\"']|\d+[.)]\s)|$)", t)
    if m and len(m.group(1)) >= 20:
        t = m.group(1)
    if len(t) > limit:
        t = t[: limit - 1].rsplit(" ", 1)[0] + "…"
    return t


WHO_WORDS = {"it": "your IT team", "wordpress": "the company that runs your WordPress sites"}


def group_problems(rows, names, prev_deep=None, hints=None, window_start=None, tag="",
                   details=None):
    """Finding rows (finding_id, asset_id, title, severity, status, source, ts) ->
    [item], one per problem, worst first, each in digest_words' plain words: what we found
    (title), what it means (body), the fix (do) and who does it (who). Grouped by family, so
    every advisory about one WordPress plugin is one item. `details` {finding_id:
    (description, [cve])} lets a plugin advisory be judged: one whose affected range excludes
    the version we saw is dropped (10-22: four of five Slider Revolution advisories did not
    cover 6.7.58), and the ones that apply say what an attacker could do. "Version not
    shown" rows are not passed here at all."""
    prev_deep = prev_deep or {}
    hints = hints or {}
    details = details or {}
    groups: dict = {}
    for r in rows or []:
        fid, aid, title, sev = r[0], r[1], r[2], (r[3] or "").upper()
        src = r[5] if len(r) > 5 else None
        adv = None
        if dw_words.plugin_of(title):
            desc, cves = details.get(fid, ("", []))
            adv = dw_words.advisory(title, desc)
            if adv["applies"] is False:
                continue          # its own range excludes the version we saw
            adv["cves"] = sorted(set(adv["cves"]) | set(cves or []))
        g = groups.setdefault(dw_words.family_key(title), {
            "severity": sev, "raw": unescape(title or "").strip(), "sites": set(),
            "assets": set(), "finding_ids": [], "sources": set(), "tag": tag, "advs": [],
        })
        if SEV_ORDER.get(sev, 9) < SEV_ORDER.get(g["severity"], 9):
            g["severity"] = sev
        g["sites"].add(site_of(aid, names))
        g["assets"].add(aid)
        g["finding_ids"].append(fid)
        g["sources"].add(src)
        if adv is not None:
            adv["site"] = site_of(aid, names)
            g["advs"].append(adv)
    items = []
    for g in groups.values():
        w = dw_words.words(g["raw"], len(g["sites"]))
        note = ""
        if any(source_words(s) == "deep scan" for s in g["sources"]) and window_start is not None:
            gaps = []
            for a in g["assets"]:
                if a not in prev_deep:
                    continue  # unknown: say nothing rather than guess
                p = prev_deep[a]
                if p is None:
                    gaps.append(None)
                elif window_start - p >= timedelta(days=DEEP_SCAN_GAP_DAYS):
                    gaps.append(p)
            if gaps:
                note = ("New because this was its first deep scan ever." if None in gaps else
                        f"New because this was its first deep scan since {_day(min(gaps))}; "
                        f"it may have been there a while.")
        body, do, forward = w["why"], w["do"], ""
        if g["advs"]:
            body, do, forward = _plugin_words(g["advs"], sorted(g["sites"]), dw_words.plugin_of(g["raw"]))
        if not do:
            steps = {first_step(hints.get(f, "")) for f in g["finding_ids"]}
            if len(steps) == 1:
                do = steps.pop()
        items.append({
            "kind": "finding", "severity": g["severity"], "title": w["title"], "family": w["key"],
            "body": body, "sites": sorted(g["sites"]), "finding_ids": g["finding_ids"],
            "why": note, "do": do, "who": w.get("who", "it"), "forward": forward,
            "tag": g["tag"], "fixed_words": w["fixed"],
            "headline": w.get("headline", "").replace("{where}", where_words(sorted(g["sites"]))),
        })
    items.sort(key=lambda i: (SEV_ORDER.get(i["severity"], 9), -len(i["sites"]), i["title"]))
    return items


def where_words(sites: list) -> str:
    """'pm.unimacgraphics.com' / 'bitec and highcom (prodexlabs.com)' / 'five sites' — short
    enough for a headline."""
    if len(sites) == 1:
        return sites[0]
    if len(sites) > 3:
        return f"{_n(len(sites))} sites"
    doms = {".".join(x.split(".")[-2:]) for x in sites}
    if len(doms) == 1 and all(x.count(".") >= 2 for x in sites):
        d = doms.pop()
        short = [x[: -(len(d) + 1)] for x in sites]
        return (" and ".join(short) if len(short) == 2 else f"{short[0]}, {short[1]} and {short[2]}") + f" ({d})"
    return " and ".join(sites) if len(sites) == 2 else f"{sites[0]}, {sites[1]} and {sites[2]}"


def _vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def _plugin_words(advs: list, sites: list, plugin: dict) -> tuple[str, str, str]:
    """(what it means, the fix, a paragraph to forward) for one WordPress plugin's advisories
    that apply. The fix is the newest fixed version any of them names, or removal when one
    has no fix at all."""
    name = plugin["name"]
    risks = []
    for a in advs:
        if a["risk"] and a["risk"] not in risks:
            risks.append(a["risk"])
    fixes = sorted({a["fixed_in"] for a in advs if a["fixed_in"]}, key=_vkey)
    unfixed = any(a["fixed_in"] is None for a in advs)
    cves = sorted({c for a in advs for c in a["cves"]})
    seen = sorted({a["seen"] for a in advs if a["seen"]}, key=_vkey)
    body = (" ".join(risks[:2]) if risks else
            "It has a published security flaw, and nobody is fixing it: there is no patched version." if unfixed else
            "It has a published security flaw, and a fixed version exists.")
    if unfixed:
        do = f"Replace {name} with a maintained plugin, or remove it. No update is coming."
    else:
        do = f"Update {name} to version {fixes[-1]} or later."
    where = ", ".join(sites)
    ver = f" (version {' / '.join(seen)})" if seen else ""
    forward = (f"Our security scanning found {name}{ver} on {where}. It has a published security flaw"
               + (f" ({', '.join(cves)})" if cves else "") + ". "
               + (risks[0] + " " if risks else "")
               + ("There is no fixed version: please remove the plugin or replace it with a maintained one."
                  if unfixed else f"Please update {name} to {fixes[-1]} or later and let us know when it's done."))
    return body, do, forward


def cert_expiry(row) -> datetime | None:
    """SQL_CERTS_EXPIRING row (asset_id, title, last_observed_at[, not_after]) -> when it
    expires. The certificate's own end date when the deep scan recorded it ('2026-10-26
    17:53', UTC); otherwise the '(N)' whole days the TLS check wrote, counted from when it
    looked — which can land a day early (pm.unimacgraphics.com: "(9)" on Oct 16 read as
    Sunday; the certificate ends Monday 1:53 PM)."""
    if len(row) > 3 and row[3]:
        try:
            return datetime.strptime(str(row[3]).strip()[:16], "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    m = re.search(r"\((\d+)\)\s*$", (row[1] or "") if len(row) > 1 else "")
    if not m or len(row) < 3 or row[2] is None:
        return None
    return row[2] + timedelta(days=int(m.group(1)))


def cert_days_left(row, now: datetime) -> int | None:
    """Whole days left at `now` (negative: already expired)."""
    exp = cert_expiry(row)
    return None if exp is None else (exp - now).days


def deny_words(denies) -> str:
    """'HTTP 403 x3' — the shape of the deny pages nobody recognized."""
    by: dict = {}
    for d in denies or []:
        if isinstance(d, dict):
            by[d.get("status")] = by.get(d.get("status"), 0) + 1
    return "; ".join(f"HTTP {k}" + (f" x{n}" if n > 1 else "") for k, n in sorted(by.items(), key=lambda kv: str(kv[0]))) or "no page captured"


# ── the model ─────────────────────────────────────────────────────────────────
def _dedupe(rows, seen: set) -> list:
    out = []
    for r in rows or []:
        if r[0] in seen:
            continue
        seen.add(r[0])
        out.append(r)
    return out


def build_model(*, window_start, window_end, new_findings, confirmed, regressed,
                high_risk, new_assets, dark_assets, stale_assets, canary_violations,
                baseline, came_back=None, fixed=None, enforcement_flips=None,
                unrecognized_pages=None, sites=None, certs=None, prev_deep=None,
                hints=None, brand=None, stale_words=None, stale_intro="",
                stale_note="", details=None, told=None) -> dict:
    """Everything the two renderers need, decided once. PURE.

    Job 3s ("say it once"): `told` is the record of what was told ({finding_id: row});
    None = no record (table missing or unreadable) = today's email, unfiltered. With a
    record, a problem is listed only when it is NEW, got WORSE or CAME BACK; anything told
    before and unchanged waits for the weekly ("Still open, no change", or its reminder).
    `told_full` lists the findings behind every problem card shown, for run_alerter to
    record after the send."""
    brand = brand or dict(DEFAULT_BRAND)
    came_back = came_back or []
    fixed = fixed or []
    enforcement_flips = enforcement_flips or []
    unrecognized_pages = unrecognized_pages or []
    site_rows = list(sites or [])
    names = {r[0] for r in site_rows} | {r[1] for r in (new_findings or [])} | \
            {r[1] for r in (regressed or [])} | {r[1] for r in (confirmed or [])} | \
            {r[1] for r in fixed}
    # names drives www. folding only; a host missing from site_rows folds the same way.

    seen: set = set()
    changed = _dedupe(list(regressed or []), seen)          # came back first: their tag wins
    created = _dedupe(list(new_findings or []), seen)
    reconfirmed = _dedupe(list(confirmed or []), seen)

    # Only what is known (Howie, 10-22: "There are risks and there are things that are
    # known, that's all"): "Runs X, version not shown" is not listed, counted or mentioned.
    changed = [r for r in changed if not dw_words.is_guess(r[2])]
    created = [r for r in created if not dw_words.is_guess(r[2])]
    reconfirmed = [r for r in reconfirmed if not dw_words.is_guess(r[2])]

    def pick(rows, sevs):
        return [r for r in rows if (r[3] or "").upper() in sevs]

    member_sev = {r[0]: (r[3] or "").upper() for r in changed + created + reconfirmed}
    shown: list = []

    def rule(items, came_back_event=False):
        """Job 3s: keep NEW / WORSE / CAME BACK; drop what was told and has not changed (a
        reminder that is due belongs to the weekly). A REGRESSED event is a came-back by
        definition, even if no run saw the finding closed in between."""
        if told is None:
            shown.extend(items)
            return items
        keep = []
        for g in items:
            if came_back_event:
                verdict, reason = "full", "back"
            else:
                verdict, reason = told_rule.decide(g, told, window_end, member_sev, "serious")
            if verdict != "full" or reason == "due":
                continue
            if reason == "worse" or (reason == "back" and not g.get("tag")):
                g["tag"] = told_rule.tag_for(reason, g, told, "serious", _day)
            keep.append(g)
        shown.extend(keep)
        return keep

    do, ticket, done = [], [], []

    # 1. our own coverage, first: a gap in our checking hides everything below it
    if stale_assets or canary_violations:
        lines = []
        for r in stale_assets or []:
            if stale_words:
                aid, seen_w, scan_w = stale_words(r)
                # notes 320/321: say which of the two checks is overdue, in words
                seen_w += " (overdue)" if (len(r) > 5 and r[5]) else ""
                scan_w += " (overdue)" if (len(r) > 7 and (r[6] or r[7])) else ""
                lines.append(f"{aid}: {seen_w}; {scan_w}")
            else:
                lines.append(str(r[0]))
        for r in canary_violations or []:
            lines.append(f"{r[0]}: expected live and ours, filed as {r[1]} / {r[2]}")
        n = len(stale_assets or []) + len(canary_violations or [])
        body = stale_intro or "A gap in our own checking, not a problem found on these hosts."
        do.append({
            "kind": "coverage", "severity": "",
            "title": f"Sentry lost sight of {n} host{'s' if n != 1 else ''}",
            "body": body + " Until it closes, they get no new findings.",
            "lines": lines, "note": (f"Overdue means: {stale_note}." if stale_note else ""),
            "sites": [], "why": "", "do": "", "tag": "",
        })

    # 2. findings that need you today
    do += rule(group_problems(pick(changed, DO_TODAY_SEVERITIES), names, prev_deep, hints,
                              window_start, tag="Came back after being fixed", details=details), True)
    do += rule(group_problems(pick(created, DO_TODAY_SEVERITIES), names, prev_deep, hints,
                              window_start, details=details))

    # 3. a web firewall that stopped blocking — said once, for all its sites, and not at
    # all for a site whose firewall finding is already on the list (the 10-22 Prodex test
    # send said "not blocking" three times about two sites).
    on_list = {x for i in do if str(i.get("family", "")).startswith("waf") for x in i.get("sites", [])}
    stopped_rows = {}
    for r in enforcement_flips:
        if not r[4] and site_of(r[0], names) not in on_list:
            stopped_rows.setdefault(site_of(r[0], names), r)
    stopped = sorted(stopped_rows)
    if stopped:
        it = dw_words._it(len(stopped))

        def went(r):
            return (f"our harmless test attacks got through on {_day(r[3])}"
                    + (f"; the test before, {_day(r[6])}, was turned away" if r[6] is not None else ""))
        one = stopped_rows[stopped[0]]
        do.append({"kind": "enforcement", "severity": "HIGH",
                   "title": (f"The web firewall on {stopped[0]} stopped blocking" if len(stopped) == 1 else
                             f"Web firewalls stopped blocking on {_n(len(stopped))} sites"),
                   "body": ((went(one)[0].upper() + went(one)[1:] + ". ") if len(stopped) == 1 else "")
                           + "Either it was switched off or someone told it to just watch. (We measure "
                             "whether something turns our test attacks away; we don't name a product.)",
                   "lines": [] if len(stopped) == 1 else [f"{x}: {went(stopped_rows[x])}" for x in stopped],
                   "sites": stopped, "who": "it",
                   "do": f"Check that the firewall in front of {it['it']} is on and set to block.",
                   "why": "", "tag": "", "family": "waf-stopped",
                   "headline": f"check the web firewall in front of {where_words(stopped)} is on and blocking"})

    # 4. certificates about to expire — one item, however many (two near-identical cards
    # for ftp. and pm. on 10-22 read as the same thing twice)
    soon = []
    for r in certs or []:
        left = cert_days_left(r, window_end)
        if left is None or left > CERT_DAYS:
            continue
        soon.append((left, r[0], local_time(cert_expiry(r), brand)))
    if soon:
        soon.sort()
        def when(left, exp):
            on = f"{exp:%A}, {_day(exp)}"
            return (f"expired {on}" if left < 0 else "expires today" if left == 0 else
                    f"expires {on} ({left} day{'s' if left != 1 else ''})")
        first = soon[0]
        if len(soon) == 1:
            title = f"Renew the certificate on {first[1]}"
            body = (f"It {when(first[0], first[2])}. After that, every browser that visits gets a "
                    f"full-page security warning, which is a great way to lose a customer.")
            lines = []
        else:
            title = f"Renew {_n(len(soon))} certificates, the first by {first[2]:%A}"
            body = ("After each one lapses, every browser that visits gets a full-page security "
                    "warning. They don't renew themselves out of guilt.")
            lines = [f"{h}: {when(l, e)}" for l, h, e in soon]
        do.append({"kind": "cert", "severity": "HIGH" if first[0] <= 3 else "MODERATE-HIGH",
                   "title": title, "body": body, "lines": lines, "who": "it",
                   "do": ("Install a renewed certificate before it lapses. If the same certificate covers other "
                          "servers (a *.yourdomain certificate usually does), install the new one on all of them."),
                   "sites": [h for _l, h, _e in soon], "why": "", "tag": ""})

    # This week (was "Worth a ticket" — Howie, 10-22: "We don't have any tickets")
    ticket += rule(group_problems(pick(changed, TICKET_SEVERITIES), names, prev_deep, hints,
                                  window_start, tag="Came back after being fixed", details=details), True)
    ticket += rule(group_problems(pick(created, TICKET_SEVERITIES), names, prev_deep, hints,
                                  window_start, details=details))
    ticket += rule(group_problems(pick(reconfirmed, DO_TODAY_SEVERITIES + TICKET_SEVERITIES),
                                  names, prev_deep, hints, window_start,
                                  tag="Confirmed by a second scan", details=details))
    # Ratings that went up: only the sites today's list does not already explain (the
    # header bar says "critical 0 to 4"; repeating each site's reason under the item that
    # caused it is the noise this redesign removes).
    explained = {s for i in do for s in i.get("sites", [])}
    def _top(r):
        t = unescape(r[4] or "").split("top: ", 1)
        return t[1] if len(t) == 2 else ""
    rose = [r for r in high_risk or [] if site_of(r[0], names) not in explained
            and not dw_words.is_guess(_top(r))]
    if rose:
        lines = []
        for r in rose:
            top = unescape(r[4] or "").split("top: ", 1)
            lines.append(f"{site_of(r[0], names)} is now {SEV_WORD.get((r[3] or '').upper(), r[3])}"
                         + (f", because of: {dw_words.words(top[1])['title']}" if len(top) == 2 else ""))
        ticket.append({"kind": "rating", "severity": "",
                       "title": ("A site got riskier" if len(rose) == 1 else f"{_n(len(rose)).capitalize()} sites got riskier"),
                       "body": "Its risk level is its worst open problem, and that got worse." if len(rose) == 1 else
                               "A site's risk level is its worst open problem; on these, that got worse.",
                       "lines": lines, "sites": [], "why": "", "do": "", "tag": ""})
    for r in unrecognized_pages:
        ticket.append({"kind": "blockpage", "severity": "",
                       "title": f"Something unrecognized is blocking in front of {r[0]}",
                       "body": f"On {_day(r[3])} it turned away the attack-style test strings with a "
                               f"page no vendor the block-page library knows ({deny_words(r[4])}). "
                               f"The page is saved with the scan, to add to the library.",
                       "sites": [r[0]], "why": "", "do": "", "tag": ""})
    if new_assets:
        ticket.append({"kind": "assets", "severity": "",
                       "title": f"{len(new_assets)} new host{'s' if len(new_assets) != 1 else ''} found",
                       "lines": [f"{r[0]}: first seen {_day(r[3])}"
                                 + (f", rated {SEV_WORD.get(str(r[4]).upper(), r[4]).lower()}"
                                    if r[4] and str(r[4]).upper() not in ("NONE", "UNKNOWN") else ", not rated yet")
                                 for r in new_assets], "sites": [], "why": "", "do": "", "tag": ""})
    if dark_assets:
        def _last(r):
            v = r[4] if isinstance(r[4], dict) else {}
            return f"last answered {v['last_seen']}" if v.get("last_seen") else "last answer unknown"
        ticket.append({"kind": "dark", "severity": "",
                       "title": f"{len(dark_assets)} host{'s' if len(dark_assets) != 1 else ''} stopped answering",
                       "lines": [f"{r[0]}: {_last(r)}" for r in dark_assets], "sites": [], "why": "",
                       "do": "", "tag": ""})

    # Off your plate
    # a guess that went away was never listed, so its going is not news either
    fixed_problems = [r for r in fixed if (r[3] or "").upper() not in ("INFO", "LOW")
                      and not dw_words.is_guess(r[2])]
    for g in group_problems(fixed_problems, names)[:8]:
        what = g["fixed_words"]
        line = (f"{what[0].upper() + what[1:]} on {', '.join(g['sites'])}." if what != "fixed" else
                f"Fixed on {', '.join(g['sites'])}: {g['title']}.")
        done.append({"kind": "fixed", "title": line, "lines": []})
    if came_back:
        done.append({"kind": "back", "title": f"{len(came_back)} host{'s' if len(came_back) != 1 else ''} answering again",
                     "lines": [f"{r[0]}: stopped answering {_day(r[4])}, answering again {_day(r[3])}"
                               for r in came_back]})
    started_rows = {}
    for r in enforcement_flips:
        if r[4]:
            started_rows.setdefault(site_of(r[0], names), r)
    if started_rows:
        def how(r):
            if r[5] is None:
                return f"turned our test attacks away on {_day(r[3])}, the first time we tested"
            return (f"turned our test attacks away on {_day(r[3])}"
                    + (f"; the test before, {_day(r[6])}, got through" if r[6] is not None else ""))
        started = sorted(started_rows)
        done.append({"kind": "blocking",
                     "title": (f"A web firewall started blocking on {started[0]}" if len(started) == 1 else
                               f"Web firewalls started blocking on {_n(len(started))} sites"),
                     "lines": [f"{x}: {how(started_rows[x])}." for x in started]})

    # The quiet line
    low_rows = pick(created + changed, ("LOW",))
    low = len(low_rows)
    info = len(pick(created + changed, ("INFO",)))
    minor = [(site_of(r[1], names), dw_words.words(r[2])["title"]) for r in low_rows]

    # The bar
    now_b, then_b = site_bands(site_rows)
    now_c, then_c = band_counts(now_b), band_counts(then_b)

    n_do, n_ticket = len(do), len(ticket)
    return {
        "brand": brand, "window_start": window_start, "window_end": window_end,
        "local_end": local_time(window_end, brand),
        "do": do, "ticket": ticket, "done": done, "low": low, "info": info,
        "sites_total": len(now_b), "counts": now_c, "counts_then": then_c,
        "bands_now": now_b, "bands_then": then_b,
        "change": change_words(now_c, then_c, now_b, then_b, "yesterday") if now_b else "",
        "degraded": bool(stale_assets or canary_violations),
        "headline": headline(n_do, n_ticket, do, ticket),
        "minor": minor,
        "baseline": baseline or {},
        "told_full": told_rule.records(shown, member_sev, "daily"),
    }


_WORDS = ("no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten")


def _n(n: int) -> str:
    return _WORDS[n] if 0 <= n < len(_WORDS) else str(n)


def open_words(bl: dict) -> str:
    """'4 critical, 16 high, 187 moderate, 406 low' — moderate-high only when there is one."""
    parts = [f"{bl.get('critical_open', 0)} critical", f"{bl.get('high_open', 0)} high"]
    if bl.get("mod_high_open"):
        parts.append(f"{bl['mod_high_open']} moderate-high")
    parts += [f"{bl.get('moderate_open', 0)} moderate", f"{bl.get('low_open', 0)} low"]
    return ", ".join(parts)


def minor_words(minor: list) -> str:
    """'Also found today, no action needed: OCSP stapling not enabled (myorders.unimacgraphics.com).'"""
    if not minor:
        return ""
    if len(minor) <= 3:
        def one(s_, t):
            if t.startswith("its "):
                return f"{s_}'s {t[4:]}"
            if t.startswith("it "):
                return f"{s_} {t[3:]}"
            return f"{s_}: {t}"
        return "Also found today, minor, no action needed: " + "; ".join(one(s_, t) for s_, t in minor) + "."
    return f"Also found today: {len(minor)} minor issues, no action needed. They're listed in the portal."


def headline(n_do: int, n_ticket: int, do=None, ticket=None) -> str:
    """The first thing read says what to do. One item: name it (Howie, 10-22, on "One thing
    for today. That's it." above a block of numbers: "What do I have to do with this?")."""
    def first(items):
        t = (items[0].get("headline") or items[0]["title"]) if items else ""
        return t[0].lower() + t[1:] if t and not t[1:2].isupper() else t
    if n_do == 1 and do:
        h = f"Today: {first(do)}."
        return h + (f" Plus {_n(n_ticket)} for this week." if n_ticket else "")
    if n_do:
        return (f"{_n(n_do).capitalize()} thing{'s' if n_do != 1 else ''} for today"
                + (f", {_n(n_ticket)} for this week." if n_ticket else "."))
    if n_ticket == 1 and ticket:
        return f"Nothing urgent today. This week: {first(ticket)}."
    if n_ticket:
        return (f"Nothing urgent today. {_n(n_ticket).capitalize()} thing{'s' if n_ticket != 1 else ''} "
                f"for this week.")
    return "Nothing needs you today."


def subject(model: dict, product_name: str) -> str:
    """'[PRODEXsentry] Prodex, Thursday: 1 for today, 2 this week'. The [name] prefix is
    kept so mail filters on it keep working; '(!) Coverage gap.' leads when Sentry has
    lost sight of hosts."""
    b = model["brand"]
    day = f"{model['local_end']:%A}"
    n_do, n_ticket = len(model["do"]), len(model["ticket"])
    if n_do and n_ticket:
        what = f"{n_do} for today, {n_ticket} this week"
    elif n_do:
        what = f"{n_do} for today"
    elif n_ticket:
        what = f"nothing urgent, {n_ticket} this week"
    else:
        what = "nothing needs you"
    prefix = f"[{product_name}] " if product_name else ""
    gap = "(!) Coverage gap. " if model["degraded"] else ""
    return f"{prefix}{gap}{b.get('short_name', 'Sentry')}, {day}: {what}"


# ── HTML ──────────────────────────────────────────────────────────────────────
# Job 3r (Howie 2026-10-23 07:21–07:25): an out-of-date finding with a known fix, open more
# than 30 days, is MODERATE but "shouldn't be the same as another moderate … some kind of
# indication that there is still some action required". Its own calm color: not an alarm.
OVERDUE_DAYS = 30
OVERDUE_FILL, OVERDUE_TINT = "#6E56A6", "#F3F0FA"


def overdue_pill() -> str:
    return (f'<span style="display:inline-block;background:{OVERDUE_FILL};color:#FFFFFF;font-size:12px;'
            f'font-weight:700;line-height:18px;padding:2px 9px;border-radius:999px;">Overdue</span>')


# Howie, 2026-10-23 07:58: "inject a little bit of my cynicism and sarcasm into this … something
# funny like that that will get the IT team's attention." One line per Overdue item, never the
# same line twice in one email (the 10-22 rule: no copy-paste sameness). Never in the paragraph
# that gets forwarded to the WordPress company: that one stays polite.
# Howie, 08:01: "give the reader a little bit more in terms of what they should do or who they
# should contact … is there nobody maintaining the WordPress site, or who maintains this?" So
# each line asks the question AND says the next step, addressed by who does the fix.
OVERDUE_NUDGES = {
    "wordpress": (
        "Is anyone actually maintaining this WordPress site? Whoever it is, send them the paragraph "
        "below. If nobody here knows who that is, that's the bigger problem.",
        "Could somebody please get in touch with whoever maintains this damn site? Forward them the "
        "paragraph below. They're clearly not doing their jobs.",
        "What are we spending our money on? Send the paragraph below to the company that runs the "
        "site and ask them for a date.",
        "Sitting here since {since}. It's an afternoon's work for whoever runs the site. Forward the "
        "paragraph below and ask when it'll be done.",
        "We'd say this is a gentle reminder, but it stopped being gentle around {since}. The "
        "paragraph below is ready to send.",
    ),
    "it": (
        "Who on the IT team owns this? Whoever it is: the fix is below, and it's been waiting since {since}.",
        "Is anyone responsible for this server? The fix is below. It's been {age}.",
        "Still here. Still waiting. If this belongs to someone outside IT, tell them; the fix is below.",
        "Sitting here since {since}. The fix below is routine. Who's picking it up?",
    ),
}


def overdue_nudge(item: dict, i: int) -> str:
    """The i-th Overdue line for whoever does the fix (Howie's voice): the question, then the
    next step. PURE."""
    since = item["overdue_since"]
    end = item.get("as_of") or since
    days = max(0, (end - since).days)
    age = f"{days // 30} months" if days >= 60 else f"{days} days"
    lines = OVERDUE_NUDGES.get(item.get("who") or "it", OVERDUE_NUDGES["it"])
    return lines[i % len(lines)].format(since=_day(since), age=age)


def overdue_words(item: dict) -> str:
    """'Moderate. Known since Jun 2; still needs someone to act.'"""
    sev = SEV_WORD.get(item.get("severity") or "", "")
    return (f"{sev + '. ' if sev else ''}Known since {_day(item['overdue_since'])}; "
            f"still needs someone to act.")


def _pill(sev: str) -> str:
    fill, text, _tint = SEV_STYLE.get(sev, ("#D9DEE5", INK, "#F4F7FB"))
    return (f'<span style="display:inline-block;background:{fill};color:{text};font-size:12px;'
            f'font-weight:700;line-height:18px;padding:2px 9px;border-radius:999px;">'
            f'{escape(SEV_WORD.get(sev, sev.title()))}</span>')


def _p(text: str, color: str = INK, size: int = 15, extra: str = "") -> str:
    return (f'<p style="margin:6px 0 0;font-family:{FONT};font-size:{size}px;line-height:1.55;'
            f'color:{color};{extra}">{text}</p>')


def _h2(text: str) -> str:
    return (f'<tr><td class="px" style="padding:26px 32px 10px;"><h2 style="margin:0;font-family:{DISPLAY};'
            f'font-size:22px;line-height:1.2;font-weight:700;color:{INK};">{escape(text)}</h2></td></tr>')


def _ring(color: str, filled: bool = False) -> str:
    if filled:
        return (f'<td width="30" valign="top" style="padding:2px 0 0;"><div style="width:24px;height:24px;'
                f'border-radius:12px;background:{color};color:#FFFFFF;font-size:15px;line-height:24px;'
                f'text-align:center;font-family:{FONT};font-weight:700;">&#10003;</div></td>')
    return (f'<td width="30" valign="top" style="padding:2px 0 0;"><div style="width:20px;height:20px;'
            f'border-radius:12px;border:2px solid {color};"></div></td>')


def chips(sites, limit: int = 12) -> str:
    """Site names as pills that wrap between names, never inside one (Howie, 10-22: it
    'wraps around in the middle of words')."""
    out = "".join(
        f'<span style="display:inline-block;white-space:nowrap;margin:6px 6px 0 0;font-family:{FONT};font-size:13px;'
        f'font-weight:600;color:{INK};background:#FFFFFF;border:1px solid #D6DEE8;border-radius:999px;'
        f'padding:3px 10px;">{escape(s)}</span>' for s in list(sites)[:limit])
    if len(sites) > limit:
        out += f'<span style="font-family:{FONT};font-size:13px;color:{MUTED};"> and {len(sites) - limit} more</span>'
    return f'<div style="margin-top:2px;">{out}</div>'


def band_chip(band: str, size: int = 12) -> str:
    fill, text = BAND_FILL_TEXT[band]
    return (f'<span style="display:inline-block;white-space:nowrap;background:{fill};color:{text};font-family:{FONT};'
            f'font-size:{size}px;font-weight:700;line-height:18px;padding:1px 8px;border-radius:4px;">'
            f'{escape(BAND_TITLE[band])}</span>')


def tally(counts: dict, then: dict | None = None, since: str = "", on_dark: bool = True,
          brand: dict | None = None) -> str:
    """Every live site, counted by risk level, each box labeled (Howie, 10-22, on the bar:
    "there's no legend. I have no idea what it means"). With `then`, each box also says
    what it was. Boxes are table cells: they shrink on a phone, never spill off it."""
    cells = []
    for k, _w, fill, text in BANDS:
        n, was = counts.get(k, 0), (then or {}).get(k, 0)
        if not n and not was:
            continue
        sub = ""
        if then is not None:
            sub = (f'<div style="font-size:11px;line-height:14px;opacity:.85;white-space:nowrap;">'
                   f'{"no change" if n == was else f"was {was}"}</div>')
        cells.append(
            f'<td valign="top" style="padding:0 3px 0 0;"><div style="background:{fill};color:{text};border-radius:8px;'
            f'padding:8px 6px 7px;text-align:center;font-family:{FONT};">'
            f'<div style="font-family:{DISPLAY};font-size:24px;line-height:26px;font-weight:800;">{n}</div>'
            f'<div style="font-size:12px;line-height:15px;font-weight:700;">{escape(BAND_TITLE[k])}</div>{sub}</div></td>')
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
            f'style="table-layout:fixed;"><tr>{"".join(cells)}</tr></table>')


RISK_LEVEL_WORDS = ("Each site's risk level is the worst problem we can see on it right now. "
                    "Riskier means that worst problem got worse; safer means it got better or went away.")


def _card(item: dict, portal: str) -> str:
    sev = item.get("severity") or ""
    fill, _t, tint = SEV_STYLE.get(sev, ("#0A4595", "#FFFFFF", "#EEF3FA"))
    ring = fill if sev else "#0A4595"
    if item.get("kind") == "coverage":      # our own blind spot: berry, no severity pill
        ring, tint = "#8B1A4A", "#F9E8EF"
    if item.get("overdue_since"):           # job 3r: known, has a fix, sitting — calm violet
        ring, tint = OVERDUE_FILL, OVERDUE_TINT
    head = escape(item["title"])
    if item.get("kind") == "finding" and item.get("finding_ids") and portal:
        head = (f'<a href="{escape(portal)}/findings/{escape(item["finding_ids"][0])}" '
                f'style="color:{INK};text-decoration:none;">{head}</a>')
    pill = (overdue_pill() if item.get("overdue_since") else _pill(sev) if sev in SEV_STYLE else "")
    parts = [f'<div style="font-family:{FONT};font-size:17px;line-height:1.35;font-weight:700;color:{INK};">'
             + (f'{pill}&nbsp; ' if pill else "") + head + "</div>"]
    if item.get("overdue_since"):
        parts.append(_p(escape(overdue_words(item)), OVERDUE_FILL, 13, "font-weight:700;"))
        if item.get("nudge"):
            parts.append(_p(escape(item["nudge"]), OVERDUE_FILL, 14, "font-style:italic;margin-top:4px;"))
    if item.get("tag"):
        parts.append(_p(escape(item["tag"]) + ".", MUTED, 13, "font-weight:600;"))
    if item.get("body"):
        lead = '<span style="font-weight:700;">What it means:</span> ' if item.get("kind") == "finding" else ""
        parts.append(_p(lead + escape(item["body"]), "#2B3747"))
    if item.get("sites") and item.get("kind") in ("finding", "enforcement"):
        parts.append(chips(item["sites"]))
    for label, sites in item.get("groups", []):
        parts.append(_p(f'<span style="font-weight:700;">{escape(label)}</span>', INK, 14, "margin-top:10px;")
                     + chips(sites))
    if item.get("lines"):
        def _line(l):
            head, sep, rest = l.partition(": ")
            return (f'<span style="font-weight:700;">{escape(head)}</span>: {escape(rest)}' if sep and " " not in head
                    else escape(l))
        parts.append("".join(_p(_line(l), "#2B3747", 14, "margin-top:4px;") for l in item["lines"][:12]))
        if len(item["lines"]) > 12:
            parts.append(_p(f"and {len(item['lines']) - 12} more", MUTED, 13))
    if item.get("note"):
        parts.append(_p(escape(item["note"]), MUTED, 13))
    if item.get("do"):
        who = WHO_WORDS.get(item.get("who") or "", "")
        label = f"The fix, for {who}:" if who and item.get("kind") in ("finding", "cert", "enforcement") else "The fix:"
        parts.append(_p(f'<span style="font-weight:700;">{escape(label)}</span> {escape(item["do"])}', INK, 15,
                        "margin-top:10px;"))
    if item.get("forward"):
        parts.append(f'<div style="margin-top:10px;padding:10px 12px;background:#FFFFFF;border:1px dashed #C9D3E0;'
                     f'border-radius:8px;font-family:{FONT};font-size:13px;line-height:1.5;color:#2B3747;">'
                     f'<div style="font-weight:700;color:{INK};margin-bottom:2px;">Ready to forward to them:</div>'
                     f'{escape(item["forward"])}</div>')
    if item.get("why"):
        parts.append(_p(escape(item["why"]), MUTED, 13))
    return (f'<tr><td class="px" style="padding:0 32px 12px;"><table role="presentation" width="100%" cellpadding="0" '
            f'cellspacing="0" border="0" bgcolor="{tint}" style="background:{tint};border-radius:12px;">'
            f'<tr><td class="card" style="padding:18px 20px;"><table role="presentation" width="100%" cellpadding="0" '
            f'cellspacing="0" border="0"><tr>{_ring(ring)}<td valign="top" style="padding-left:12px;">'
            f'{"".join(parts)}</td></tr></table></td></tr></table></td></tr>')


def _done_row(item: dict) -> str:
    lines = "".join(_p(escape(l), "#2B3747", 14, "margin-top:3px;") for l in item.get("lines", [])[:10])
    return (f'<tr><td class="px" style="padding:0 32px 12px;"><table role="presentation" width="100%" cellpadding="0" '
            f'cellspacing="0" border="0"><tr>{_ring(GOOD, filled=True)}<td valign="top" style="padding-left:12px;">'
            f'<div style="font-family:{FONT};font-size:15px;line-height:1.5;font-weight:700;color:{INK};">'
            f'{escape(item["title"])}</div>{lines}</td></tr></table></td></tr>')


def render_html(model: dict, *, portal_url: str = "", product_name: str = "") -> str:
    b = model["brand"]
    end = model["local_end"]
    portal = (portal_url or "").rstrip("/")
    logo = (f'<img src="cid:{LOGO_CID}" width="{int(b.get("logo_width") or 160)}" alt="{escape(b.get("logo_alt") or b["short_name"])}" '
            f'style="display:block;border:0;height:auto;max-width:{int(b.get("logo_width") or 160)}px;">'
            if b.get("logo_bytes") else
            f'<span style="font-family:{DISPLAY};font-size:22px;font-weight:800;color:{b["band_text"]};">'
            f'{escape(b["short_name"])}</span>')
    border = f'border-bottom:1px solid {b["band_border"]};' if b.get("band_border") else ""
    rows = []
    rows.append(
        f'<tr><td bgcolor="{b["band_bg"]}" style="background:{b["band_bg"]};{border}border-radius:14px 14px 0 0;">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
        f'<tr><td class="px" style="padding:22px 32px 0;" valign="middle">{logo}</td>'
        f'<td class="px" style="padding:22px 32px 0;font-family:{FONT};font-size:13px;line-height:1.4;color:{b["band_muted"]};white-space:nowrap;" '
        f'align="right" valign="middle">{end:%a}, {end:%b} {end.day}, {_clock(end)}</td></tr>'
        f'<tr><td colspan="2" class="px" style="padding:20px 32px 22px;"><h1 style="margin:0;font-family:{DISPLAY};'
        f'font-size:36px;line-height:1.06;font-weight:800;letter-spacing:-0.02em;color:{b["band_text"]};">'
        f'{escape(model["headline"])}</h1></td></tr>'
        f'</table></td></tr>')
    if model["do"]:
        rows.append(_h2("Needs you today"))
        rows += [_card(i, portal) for i in model["do"]]
    if model["ticket"]:
        rows.append(_h2("This week"))
        rows += [_card(i, portal) for i in model["ticket"]]
    if model["done"]:
        rows.append(_h2("Fixed since yesterday"))
        rows += [_done_row(i) for i in model["done"]]
    quiet = []
    if model.get("minor"):
        quiet.append(minor_words(model["minor"]))
    if not (model["do"] or model["ticket"] or model["done"]):
        quiet.append("Every scan since yesterday came back with nothing that needs anyone.")
    if quiet:
        rows.append(f'<tr><td class="px" style="padding:18px 32px 0;">{"".join(_p(escape(q), MUTED, 14) for q in quiet)}</td></tr>')
    if portal:
        rows.append(
            f'<tr><td class="px" style="padding:22px 32px 28px;"><table role="presentation" cellpadding="0" cellspacing="0" '
            f'border="0"><tr><td bgcolor="{b["button"]}" style="background:{b["button"]};border-radius:8px;">'
            f'<a href="{escape(portal)}" style="display:inline-block;padding:12px 18px;font-family:{FONT};'
            f'font-size:15px;font-weight:600;color:#FFFFFF;text-decoration:none;">Open the portal</a>'
            f'</td></tr></table></td></tr>')
    footer = (f"Sent by {escape(product_name or b['short_name'])} at {_clock(end)}. "
              f"Where every site stands, and why, comes in the weekly review on Monday.")
    rows.append(f'<tr><td bgcolor="#F4F7FB" class="px" style="background:#F4F7FB;border-radius:0 0 14px 14px;padding:14px 32px;'
                f'font-family:{FONT};font-size:12px;line-height:1.5;color:{MUTED};">{footer}</td></tr>')

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light"><title>{escape(model["headline"])}</title>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,700;12..96,800&amp;display=swap" rel="stylesheet">
<style>
@keyframes grow{{from{{transform:scaleX(0)}}to{{transform:scaleX(1)}}}}
.seg{{transform-origin:left center;animation:grow .9s cubic-bezier(.3,.7,.2,1) both}}
@media (prefers-reduced-motion:reduce){{.seg{{animation:none}}}}
@media (max-width:620px){{h1{{font-size:30px !important}} .px{{padding-left:18px !important;padding-right:18px !important}} .card{{padding:16px 14px !important}}}}
</style></head>
<body style="margin:0;padding:0;background:{PAGE};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="{PAGE}" style="background:{PAGE};">
<tr><td align="center" style="padding:20px 8px 28px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#FFFFFF" style="width:100%;max-width:640px;background:#FFFFFF;border-radius:14px;">
{"".join(rows)}
</table>
</td></tr></table>
</body></html>"""


# ── plain text ────────────────────────────────────────────────────────────────
def render_text(model: dict, *, portal_url: str = "", product_name: str = "") -> str:
    b, end = model["brand"], model["local_end"]
    out = [f"{product_name or b['short_name']} — {b['short_name']}, {end:%A} {end:%B} {end.day}, {_clock(end)}", "",
           model["headline"], ""]

    def block(title, items):
        if not items:
            return
        out.append(title.upper())
        for i in items:
            sev = SEV_WORD.get(i.get("severity") or "", "")
            out.append(f"  [ ] {('[' + sev + '] ') if sev else ''}{i['title']}")
            if i.get("tag"):
                out.append(f"      {i['tag']}.")
            if i.get("body"):
                out.append(f"      {'What it means: ' if i.get('kind') == 'finding' else ''}{i['body']}")
            if i.get("sites") and i.get("kind") in ("finding", "enforcement"):
                out.append(f"      Sites: {', '.join(i['sites'])}")
            for label, sites in i.get("groups", []):
                out.append(f"      - {label}: {', '.join(sites)}")
            for l in i.get("lines", [])[:20]:
                out.append(f"      - {l}")
            if i.get("note"):
                out.append(f"      {i['note']}")
            if i.get("do"):
                who = WHO_WORDS.get(i.get("who") or "", "")
                out.append(f"      The fix{', for ' + who if who and i.get('kind') in ('finding', 'cert', 'enforcement') else ''}: {i['do']}")
            if i.get("forward"):
                out.append(f"      Ready to forward: {i['forward']}")
            if i.get("why"):
                out.append(f"      {i['why']}")
            if i.get("finding_ids"):     # plaintext keeps the ids: it is what gets grepped (152 P2)
                out.append(f"      ({', '.join(i['finding_ids'][:6])}"
                           f"{', …' if len(i['finding_ids']) > 6 else ''})")
        out.append("")

    block("Needs you today", model["do"])
    block("This week", model["ticket"])
    if model["done"]:
        out.append("FIXED SINCE YESTERDAY")
        for i in model["done"]:
            out.append(f"  [x] {i['title']}")
            for l in i.get("lines", [])[:10]:
                out.append(f"      - {l}")
        out.append("")
    if model.get("minor"):
        out.append(minor_words(model["minor"]))
    if not (model["do"] or model["ticket"] or model["done"]):
        out.append("Every scan since yesterday came back with nothing that needs anyone.")
    if portal_url:
        out.append(f"Open the portal: {portal_url.rstrip('/')}")
    out.append(f"Sent at {_clock(end)}. Where every site stands, and why, comes in the weekly review on Monday.")
    return "\n".join(out)
