"""digest_daily.py — the daily digest as a to-do list (KB 12 job 3l, slice 1, design D).

Howie, 2026-10-22 08:50: "This entire email needs to be simplified and redesigned."
14:45: "Let's have it be colorful. Let's have it have HTML. It can even have a little bit
of effects. There has to be a way that we can convey the information in a clever and
well-designed way, instead of throwing together a bunch of data that is almost impossible
to understand." 15:12, on design D ("your list"): "Happy, I'm thrilled."

WHAT THIS IS. Pure functions, no database and no network. run_alerter.py reads the same
rows it always read (plus four small reads: each live site's rating now and at the start
of the window, certificates about to expire, each host's previous deep scan, and the
first remediation step of the findings it lists) and hands them here. This module sorts
every part of the old email into three buckets a reader acts on:

    Do today        coverage gaps, CRITICAL / HIGH / MODERATE-HIGH new or regressed
                    findings, a firewall that stopped blocking, certificates <= 14 days
    Worth a ticket  MODERATE new or regressed findings, findings confirmed again,
                    ratings that went up, unrecognized block pages, new assets,
                    assets that went dark
    Off your plate  fixed findings, assets back online, a firewall that started blocking

LOW and INFO are counted on one quiet line, never listed. Findings are grouped BY
PROBLEM across sites (same title -> one item naming its sites), the www. twin of a site
counts as that site, and the header carries one bar: every live site by its rating.

EMAIL-SAFE BY CONSTRUCTION. Tables, inline styles, bgcolor; no flex, no grid, no script.
One <style> block for the bar's grow-in (Apple Mail plays it; Gmail and Outlook show the
same design still) and it respects prefers-reduced-motion. The logo is an inline image
(cid:brandlogo) that mailer.py attaches; the brand (name, colors, logo) is a data file per
repo, scripts/alerter/brand/brand.json, so this code is identical in both repos.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from html import escape, unescape

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


# ── sites: one per name, www. folded in ───────────────────────────────────────
def site_of(asset_id: str, names) -> str:
    """'www.example.com' -> 'example.com' when the plain name is also a live asset.
    The two are one website to a reader (Howie, 10-22: the apex/www split 'is
    confusing and needs to be rethought'); a www. host with no plain twin stays itself."""
    a = (asset_id or "").strip()
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


def change_words(now_counts: dict, then_counts: dict) -> str:
    """'Same as yesterday.' or 'Since yesterday: high 12 to 13, moderate 29 to 28.'
    Only the rated bands are compared; never-scanned vs all-clear is bookkeeping."""
    diffs = [(k, then_counts.get(k, 0), now_counts.get(k, 0)) for k in RATED
             if then_counts.get(k, 0) != now_counts.get(k, 0)]
    if not diffs:
        return "Same as yesterday."
    words = dict((k, w) for k, w, *_r in BANDS)
    return "Since yesterday: " + ", ".join(f"{words[k]} {a} to {b}" for k, a, b in diffs) + "."


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


def group_problems(rows, names, prev_deep=None, hints=None, window_start=None, tag=""):
    """Finding rows (finding_id, asset_id, title, severity, status, source, ts) ->
    [item], one per problem, worst first. Each item: severity, title, sites (folded,
    sorted), finding_ids, why (which check found it, and 'first deep scan since …' when
    the host had not had one in DEEP_SCAN_GAP_DAYS), do (the first remediation step,
    only when the problem is on ONE site: a step written for one host is not advice for
    three), tag ('came back after being fixed' / 'confirmed by a second scan')."""
    prev_deep = prev_deep or {}
    hints = hints or {}
    groups: dict = {}
    for r in rows or []:
        fid, aid, title, sev = r[0], r[1], r[2], (r[3] or "").upper()
        src = r[5] if len(r) > 5 else None
        g = groups.setdefault(problem_key(title), {
            "severity": sev, "title": unescape(title or "").strip(), "sites": set(),
            "assets": set(), "finding_ids": [], "sources": set(), "tag": tag,
        })
        if SEV_ORDER.get(sev, 9) < SEV_ORDER.get(g["severity"], 9):
            g["severity"] = sev
        g["sites"].add(site_of(aid, names))
        g["assets"].add(aid)
        g["finding_ids"].append(fid)
        g["sources"].add(src)
    items = []
    for g in groups.values():
        srcs = sorted({source_words(s) for s in g["sources"]})
        why = "Found by the " + " and the ".join(srcs) if srcs else ""
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
                why += (", its first deep scan ever" if None in gaps
                        else f", its first deep scan since {_day(min(gaps))}")
        do = ""
        if len(g["sites"]) == 1:
            do = first_step(hints.get(g["finding_ids"][0], ""))
        items.append({
            "kind": "finding", "severity": g["severity"], "title": g["title"],
            "sites": sorted(g["sites"]), "finding_ids": g["finding_ids"],
            "why": why + ("." if why else ""), "do": do, "tag": g["tag"],
        })
    items.sort(key=lambda i: (SEV_ORDER.get(i["severity"], 9), -len(i["sites"]), i["title"]))
    return items


def cert_expiry(row) -> datetime | None:
    """SQL_CERTS_EXPIRING row (asset_id, title, last_observed_at) -> when it expires:
    the '(N)' days the TLS check wrote, counted from when it last looked."""
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
                stale_note="") -> dict:
    """Everything the two renderers need, decided once. PURE."""
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

    def pick(rows, sevs):
        return [r for r in rows if (r[3] or "").upper() in sevs]

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
    do += group_problems(pick(changed, DO_TODAY_SEVERITIES), names, prev_deep, hints,
                         window_start, tag="Came back after being fixed")
    do += group_problems(pick(created, DO_TODAY_SEVERITIES), names, prev_deep, hints,
                         window_start)

    # 3. a firewall that stopped blocking
    for r in enforcement_flips:
        if not r[4]:
            before = f" The test before, {_day(r[6])}, was blocked." if r[6] is not None else ""
            do.append({"kind": "enforcement", "severity": "HIGH",
                       "title": f"Something in front of {r[0]} stopped blocking",
                       "body": f"The deep scan's harmless attack-style test strings reached the site "
                               f"on {_day(r[3])}.{before} Sentry names no product here: it only "
                               f"measures whether something turned the strings away.",
                       "sites": [r[0]], "why": "", "do": "", "tag": ""})

    # 4. certificates about to expire
    for r in certs or []:
        left = cert_days_left(r, window_end)
        if left is None or left > CERT_DAYS:
            continue
        expires = local_time(cert_expiry(r), brand)
        on = f"{expires:%A}, {_day(expires)}"
        if left < 0:
            body = (f"It expired {on}, by the deep scan's count on {_day(r[2])}. Anyone "
                    f"connecting to it securely now gets a certificate error.")
        else:
            when = "today" if left == 0 else f"in {left} day{'s' if left != 1 else ''}, {on}"
            body = (f"It expires {when}, by the deep scan's count on {_day(r[2])}. After that, "
                    f"anyone connecting to it securely gets a certificate error.")
        do.append({"kind": "cert", "severity": "HIGH" if left <= 3 else "MODERATE-HIGH",
                   "title": f"Renew the certificate on {r[0]}", "body": body,
                   "sites": [r[0]], "why": "", "do": "", "tag": ""})

    # Worth a ticket
    ticket += group_problems(pick(changed, TICKET_SEVERITIES), names, prev_deep, hints,
                             window_start, tag="Came back after being fixed")
    ticket += group_problems(pick(created, TICKET_SEVERITIES), names, prev_deep, hints,
                             window_start)
    ticket += group_problems(pick(reconfirmed, DO_TODAY_SEVERITIES + TICKET_SEVERITIES),
                             names, prev_deep, hints, window_start,
                             tag="Confirmed by a second scan")
    # Ratings that went up: only the sites today's list does not already explain (the
    # header bar says "critical 0 to 4"; repeating each site's reason under the item that
    # caused it is the noise this redesign removes).
    explained = {s for i in do for s in i.get("sites", [])}
    rose = [r for r in high_risk or [] if site_of(r[0], names) not in explained]
    if rose:
        lines = []
        for r in rose:
            top = unescape(r[4] or "").split("top: ", 1)
            lines.append(f"{site_of(r[0], names)} is now {SEV_WORD.get((r[3] or '').upper(), r[3]).lower()}"
                         + (f": {top[1]}" if len(top) == 2 else ""))
        ticket.append({"kind": "rating", "severity": "", "title": "Ratings that went up",
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
    fixed_problems = [r for r in fixed if (r[3] or "").upper() != "INFO"]
    if fixed_problems:
        groups = group_problems(fixed_problems, names)
        done.append({"kind": "fixed", "title": f"{len(fixed_problems)} finding"
                     f"{'s' if len(fixed_problems) != 1 else ''} closed",
                     "lines": [f"{g['title']} ({', '.join(g['sites'])})" for g in groups[:8]]
                     + ([f"and {len(groups) - 8} more"] if len(groups) > 8 else [])})
    if came_back:
        done.append({"kind": "back", "title": f"{len(came_back)} host{'s' if len(came_back) != 1 else ''} answering again",
                     "lines": [f"{r[0]}: stopped answering {_day(r[4])}, answering again {_day(r[3])}"
                               for r in came_back]})
    for r in enforcement_flips:
        if r[4]:
            how = (f"first test, {_day(r[3])}" if r[5] is None else
                   f"{_day(r[3])}; the test before, {_day(r[6])}, got through" if r[6] is not None else _day(r[3]))
            done.append({"kind": "blocking", "title": f"Something in front of {r[0]} is blocking",
                         "lines": [f"It turned away the attack-style test strings ({how}). "
                                   f"Sentry names no product here."]})

    # The quiet line
    low = len(pick(created + changed, ("LOW",)))
    info = len(pick(created + changed, ("INFO",)))

    # The bar
    now_b, then_b = site_bands(site_rows)
    now_c, then_c = band_counts(now_b), band_counts(then_b)

    n_do, n_ticket = len(do), len(ticket)
    return {
        "brand": brand, "window_start": window_start, "window_end": window_end,
        "local_end": local_time(window_end, brand),
        "do": do, "ticket": ticket, "done": done, "low": low, "info": info,
        "sites_total": len(now_b), "counts": now_c, "counts_then": then_c,
        "change": change_words(now_c, then_c) if now_b else "",
        "degraded": bool(stale_assets or canary_violations),
        "headline": headline(n_do, n_ticket),
        "baseline": baseline or {},
    }


_WORDS = ("no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten")


def _n(n: int) -> str:
    return _WORDS[n] if 0 <= n < len(_WORDS) else str(n)


def headline(n_do: int, n_ticket: int) -> str:
    if n_do:
        h = f"Your list for today: {_n(n_do)} check{'s' if n_do != 1 else ''}"
        if n_ticket:
            h += f", {_n(n_ticket)} for a ticket"
        return h + "."
    if n_ticket:
        return (f"Nothing urgent today. {_n(n_ticket).capitalize()} "
                f"thing{'s' if n_ticket != 1 else ''} for a ticket.")
    return "Nothing needs you today."


def subject(model: dict, product_name: str) -> str:
    """'[COMMANDsentry] Command, Thursday: 2 checks and 1 ticket'. The [name] prefix is
    kept so mail filters on it keep working; '(!)' and the coverage gap lead when Sentry
    has lost sight of hosts."""
    b = model["brand"]
    day = f"{model['local_end']:%A}"
    n_do, n_ticket = len(model["do"]), len(model["ticket"])
    if n_do and n_ticket:
        what = f"{n_do} check{'s' if n_do != 1 else ''} and {n_ticket} ticket{'s' if n_ticket != 1 else ''}"
    elif n_do:
        what = f"{n_do} check{'s' if n_do != 1 else ''}"
    elif n_ticket:
        what = f"nothing urgent, {n_ticket} ticket{'s' if n_ticket != 1 else ''}"
    else:
        what = "nothing needs you"
    prefix = f"[{product_name}] " if product_name else ""
    gap = "(!) Coverage gap. " if model["degraded"] else ""
    return f"{prefix}{gap}{b.get('short_name', 'Sentry')}, {day}: {what}"


# ── HTML ──────────────────────────────────────────────────────────────────────
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


def _card(item: dict, portal: str) -> str:
    sev = item.get("severity") or ""
    fill, _t, tint = SEV_STYLE.get(sev, ("#0A4595", "#FFFFFF", "#EEF3FA"))
    ring = fill if sev else "#0A4595"
    if item.get("kind") == "coverage":      # our own blind spot: berry, no severity pill
        ring, tint = "#8B1A4A", "#F9E8EF"
    head = escape(item["title"])
    if item.get("kind") == "finding" and item.get("finding_ids") and portal:
        head = (f'<a href="{escape(portal)}/findings/{escape(item["finding_ids"][0])}" '
                f'style="color:{INK};text-decoration:none;">{head}</a>')
    parts = [f'<div style="font-family:{FONT};font-size:17px;line-height:1.35;font-weight:700;color:{INK};">'
             + (f'{_pill(sev)}&nbsp; ' if sev in SEV_STYLE else "") + head + "</div>"]
    if item.get("tag"):
        parts.append(_p(escape(item["tag"]) + ".", MUTED, 13, "font-weight:600;"))
    if item.get("body"):
        parts.append(_p(escape(item["body"]), "#2B3747"))
    if item.get("sites") and item.get("kind") == "finding":
        chips = "".join(
            f'<span style="display:inline-block;margin:6px 6px 0 0;font-family:{FONT};font-size:13px;'
            f'font-weight:600;color:{INK};background:#FFFFFF;border:1px solid #D6DEE8;border-radius:999px;'
            f'padding:4px 11px;">{escape(s)}</span>' for s in item["sites"][:12])
        more = (f'<span style="font-family:{FONT};font-size:13px;color:{MUTED};"> and '
                f'{len(item["sites"]) - 12} more</span>' if len(item["sites"]) > 12 else "")
        parts.append(f'<div style="margin-top:4px;">{chips}{more}</div>')
    if item.get("lines"):
        parts.append("".join(_p(escape(l), "#2B3747", 14, "margin-top:4px;") for l in item["lines"][:12]))
        if len(item["lines"]) > 12:
            parts.append(_p(f"and {len(item['lines']) - 12} more", MUTED, 13))
    if item.get("note"):
        parts.append(_p(escape(item["note"]), MUTED, 13))
    if item.get("do"):
        parts.append(_p(f'<span style="font-weight:700;">Do:</span> {escape(item["do"])}'))
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


def _bar(model: dict) -> str:
    c, total, b = model["counts"], model["sites_total"], model["brand"]
    if not total:
        return ""
    cells, delay = [], 0.1
    for k, _w, fill, _t in BANDS:
        n = c.get(k, 0)
        if not n:
            continue
        pct = max(1, round(100 * n / total))
        cells.append(f'<td width="{pct}%" style="padding:0 1px 0 0;"><div class="seg" style="height:22px;'
                     f'background:{fill};border-radius:4px;animation-delay:{delay:.2f}s;"></div></td>')
        delay += 0.12
    legend = (f'<span style="color:{b["band_text"]};font-weight:700;">{total} live '
              f'site{"s" if total != 1 else ""}:</span> {escape(counts_words(c))}. '
              f'{escape(model["change"])}')
    return (f'<tr><td colspan="2" class="px" style="padding:0 32px 26px;"><table role="presentation" width="100%" cellpadding="0" '
            f'cellspacing="0" border="0"><tr>{"".join(cells)}</tr></table>'
            f'<div style="margin-top:8px;font-family:{FONT};font-size:13px;line-height:1.5;color:{b["band_muted"]};">'
            f'{legend}</div></td></tr>')


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
        f'{_bar(model)}</table></td></tr>')
    if model["do"]:
        rows.append(_h2("Do today"))
        rows += [_card(i, portal) for i in model["do"]]
    if model["ticket"]:
        rows.append(_h2("Worth a ticket"))
        rows += [_card(i, portal) for i in model["ticket"]]
    if model["done"]:
        rows.append(_h2("Off your plate"))
        rows += [_done_row(i) for i in model["done"]]
    quiet = []
    if model["low"] or model["info"]:
        quiet.append(f'Also new: {model["low"]} low and {model["info"]} informational '
                     f'item{"s" if model["info"] != 1 else ""}, listed in the portal.')
    if not (model["do"] or model["ticket"] or model["done"]):
        quiet.append("Every scan since yesterday came back with nothing new.")
    if quiet:
        rows.append(f'<tr><td class="px" style="padding:18px 32px 0;">{"".join(_p(escape(q), MUTED, 14) for q in quiet)}</td></tr>')
    if portal:
        rows.append(
            f'<tr><td class="px" style="padding:22px 32px 28px;"><table role="presentation" cellpadding="0" cellspacing="0" '
            f'border="0"><tr><td bgcolor="{b["button"]}" style="background:{b["button"]};border-radius:8px;">'
            f'<a href="{escape(portal)}" style="display:inline-block;padding:12px 18px;font-family:{FONT};'
            f'font-size:15px;font-weight:600;color:#FFFFFF;text-decoration:none;">Open today\'s report</a>'
            f'</td></tr></table></td></tr>')
    bl = model["baseline"]
    footer = f"Sent by {escape(product_name or b['short_name'])} at {_clock(end)}."
    if bl:
        stale = bl.get("problems_stale_30d") or 0
        footer = (f"Open across {escape(b['short_name'])} right now: {bl.get('critical_open', 0)} critical, "
                  f"{bl.get('high_open', 0)} high, {bl.get('moderate_open', 0)} moderate, "
                  f"{bl.get('low_open', 0)} low"
                  + (f"; {stale} not re-checked in 30+ days" if stale else "")
                  + ". " + footer)
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
<tr><td align="center" style="padding:24px 12px 32px;">
<table role="presentation" width="680" cellpadding="0" cellspacing="0" border="0" bgcolor="#FFFFFF" style="width:100%;max-width:680px;background:#FFFFFF;border-radius:14px;">
{"".join(rows)}
</table>
</td></tr></table>
</body></html>"""


# ── plain text ────────────────────────────────────────────────────────────────
def render_text(model: dict, *, portal_url: str = "", product_name: str = "") -> str:
    b, end = model["brand"], model["local_end"]
    out = [f"{product_name or b['short_name']} — {b['short_name']}, {end:%A} {end:%B} {end.day}, {_clock(end)}", "",
           model["headline"]]
    if model["sites_total"]:
        out.append(f"{model['sites_total']} live sites: {counts_words(model['counts'])}. {model['change']}")
    out.append("")

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
                out.append(f"      {i['body']}")
            if i.get("sites") and i.get("kind") == "finding":
                out.append(f"      Sites: {', '.join(i['sites'])}")
            for l in i.get("lines", [])[:20]:
                out.append(f"      - {l}")
            if i.get("note"):
                out.append(f"      {i['note']}")
            if i.get("do"):
                out.append(f"      Do: {i['do']}")
            if i.get("why"):
                out.append(f"      {i['why']}")
            if i.get("finding_ids"):
                out.append(f"      ({', '.join(i['finding_ids'][:6])}"
                           f"{', …' if len(i['finding_ids']) > 6 else ''})")
        out.append("")

    block("Do today", model["do"])
    block("Worth a ticket", model["ticket"])
    if model["done"]:
        out.append("OFF YOUR PLATE")
        for i in model["done"]:
            out.append(f"  [x] {i['title']}")
            for l in i.get("lines", [])[:10]:
                out.append(f"      - {l}")
        out.append("")
    if model["low"] or model["info"]:
        out.append(f"Also new: {model['low']} low and {model['info']} informational items, listed in the portal.")
    bl = model["baseline"]
    if bl:
        out.append(f"Open across {b['short_name']} right now: {bl.get('critical_open', 0)} critical, "
                   f"{bl.get('high_open', 0)} high, {bl.get('moderate_open', 0)} moderate, {bl.get('low_open', 0)} low"
                   + (f"; {bl['problems_stale_30d']} not re-checked in 30+ days" if bl.get("problems_stale_30d") else "")
                   + ".")
    if portal_url:
        out.append(f"Open today's report: {portal_url.rstrip('/')}")
    return "\n".join(out)
