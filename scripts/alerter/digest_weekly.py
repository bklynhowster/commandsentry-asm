"""digest_weekly.py — the Monday weekly review (KB 12 job 3l, slice 2, design B + C).

Howie, 2026-10-22 14:51, on the redesign boards: "maybe there's a way that we change this
somewhat. There's a weekly, in other words, that has more detail." 14:59: "the weekly
should definitely be Monday. If it's not Monday, it's Friday, and frankly, on Friday,
nobody pays attention." 15:12: "Happy, I'm thrilled." Canvas board "Weekly, Monday 8 AM
(B + C)" (claude.ai artifact PKowwaTmCM9rWHAdkiFmzb).

Reworked the same evening after Howie read the first test sends (19:08–19:57): "What the
hell does up or down actually mean?"; "there's no legend"; "This week, do — what?"; "Why isn't
it 8 sites got safer?"

WHAT THIS IS. Pure functions, no database and no network, beside digest_daily.py and
built from its pieces (the brand, the bands, www. folding, digest_words' plain words). The
week is the seven whole local days before today (Monday's send covers Monday to Sunday).
In order, the email carries:

    the headline       the week's biggest change: "got riskier" / "got safer", never up/down
    the boxes          every live site counted by risk level, each box labeled, with last
                       week's count (a past level is rebuilt from findings, job 3m), and one
                       sentence saying what a risk level is
    what changed       every site whose level changed, grouped by the REASON (one card for
                       eight sites that got safer for one reason; a site that landed
                       elsewhere is said inside it)
    worth your time    certificates within 14 days, then problems told in full: what we
                       found, what it means, the fix and who does it (six at most) — job 3s:
                       only what is NEW, WORSE, CAME BACK or DUE a reminder (told.py)
    overdue            out-of-date problems with a known fix, 30+ days, in full when due
    still open         every other open problem told before: one line each (job 3s)
    how hard we looked seven day-columns of deep and quick scans
    every site         one tile per site by registered domain, alphabetical, colored by
                       level, outlined when it changed this week, with a legend

Only what is known (Howie, 10-22: "There are risks and there are things that are known,
that's all"): a "Runs X, version not shown" row is not listed, not counted, and does not set
a site's level here — SQL_SITE_RATINGS rates such a site by its other findings.

EMAIL-SAFE BY CONSTRUCTION, as the daily: tables, inline styles, bgcolor; the day columns
are table cells with pixel heights; one <style> block for the rise-in and the outline
pulse (Apple Mail plays them; Gmail and Outlook show the same design still), respecting
prefers-reduced-motion.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from html import escape, unescape

import digest_daily as dd
import digest_words as words
import told as told_rule
from digest_daily import (BANDS, BAND_RANK, DISPLAY, FONT, INK, MUTED, PAGE, RULE,
                          SEV_ORDER, SEV_WORD, LOGO_CID)

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9
    ZoneInfo = None  # type: ignore

DO_MAX = 6            # open serious problems listed under "This week, do"; the rest: portal
COLUMN_PX = 110       # the tallest day column, in pixels
NO_NAME = "Addresses with no name"
BAND_FILL = {k: (fill, text, words) for k, words, fill, text in BANDS}

# Suffixes under which anyone can register a name: the registered domain is one label
# deeper (commandsentry-portal.netlify.app is its own site, not "netlify.app").
SHARED_SUFFIXES = {
    "netlify.app", "github.io", "vercel.app", "herokuapp.com", "azurewebsites.net",
    "cloudfront.net", "pages.dev", "web.app", "firebaseapp.com",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz", "co.jp", "com.br",
}


# ── the week ──────────────────────────────────────────────────────────────────
def _zone(brand: dict):
    if ZoneInfo is None:  # pragma: no cover
        return timezone.utc
    try:
        return ZoneInfo(brand.get("tz") or "America/New_York")
    except Exception:  # pragma: no cover - unknown zone name
        return timezone.utc


def week_window(now: datetime, brand: dict) -> tuple[datetime, datetime, list]:
    """The seven whole local days before today: (start, end) as UTC instants at local
    midnight, and the seven local dates. A send on Monday 8 AM covers Monday to Sunday;
    a test send on any other day covers the seven days before it. Midnights are built
    per date, so a week across a clock change is still seven calendar days."""
    tz = _zone(brand)
    today = now.astimezone(tz).date()
    days = [today - timedelta(days=i) for i in range(7, 0, -1)]
    start = datetime(days[0].year, days[0].month, days[0].day, tzinfo=tz)
    end = datetime(today.year, today.month, today.day, tzinfo=tz)
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc), days


# ── sites, grouped by registered domain ───────────────────────────────────────
def _is_address(host: str) -> bool:
    h = (host or "").strip().lower()
    if h.startswith("ip-range:") or "/" in h:
        return True
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str | None:
    """'portal-test.unimacgraphics.com' -> 'unimacgraphics.com'; an address (IP, range)
    -> None. Not assets.apex_domain: seven live Command assets have none (plan claim 6)."""
    h = (host or "").strip().lower().rstrip(".")
    if not h or _is_address(h):
        return None
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    if ".".join(labels[-2:]) in SHARED_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def tile_label(site: str, domain: str | None) -> str:
    """What a tile says inside its domain's row: the part before the domain, 'site' for
    the domain itself (its www. twin is folded in), the address itself for an address."""
    if domain is None:
        return site
    if site == domain:
        return "site"
    return site[: -(len(domain) + 1)] if site.endswith("." + domain) else site


def _addr_key(s: str):
    h = s.split(":", 1)[1] if s.lower().startswith("ip-range:") else s
    try:
        return (0, ipaddress.ip_network(h, strict=False).network_address.packed, s)
    except ValueError:
        return (1, b"", s)


def site_groups(now_bands: dict, then_bands: dict) -> list[dict]:
    """[{name, tiles: [{site, label, band, changed}]}], named domains alphabetical, then
    the addresses with no name; tiles alphabetical inside a row (the bare domain first)."""
    rows: dict = {}
    for site, band in now_bands.items():
        d = registered_domain(site)
        rows.setdefault(d, []).append({
            "site": site, "label": tile_label(site, d), "band": band,
            "changed": then_bands.get(site, band) != band,
        })
    out = []
    for d in sorted(k for k in rows if k is not None):
        tiles = sorted(rows[d], key=lambda t: (t["label"] != "site", t["label"]))
        out.append({"name": d, "tiles": tiles})
    if None in rows:
        out.append({"name": NO_NAME, "tiles": sorted(rows[None], key=lambda t: _addr_key(t["site"]))})
    return out


# ── why ratings moved ─────────────────────────────────────────────────────────
def _worst(rows):
    return min(rows, key=lambda r: (SEV_ORDER.get((r[3] or "").upper(), 9), r[0])) if rows else None


def moves(now_bands: dict, then_bands: dict, opened, closed, names) -> dict:
    """{'up': [{title, severity, sites}], 'down': [...]} — each site that went up is
    explained by the worst finding opened on it this week, each that came down by the
    worst finding closed on it; sites with the same reason share one line. A move with no
    finding this week to explain it says so rather than guess."""
    by_site_open: dict = {}
    for r in opened or []:
        if (r[3] or "").upper() != "INFO":
            by_site_open.setdefault(dd.site_of(r[1], names), []).append(r)
    by_site_closed: dict = {}
    for r in closed or []:
        if (r[3] or "").upper() != "INFO":
            by_site_closed.setdefault(dd.site_of(r[1], names), []).append(r)

    def explain(sites, pool, fallback):
        lines: dict = {}
        for s in sites:
            w = _worst(pool.get(s, []))
            key = dd.problem_key(w[2]) if w else ""
            ln = lines.setdefault(key, {
                "title": unescape(w[2]).strip() if w else fallback,
                "severity": (w[3] or "").upper() if w else "", "sites": []})
            if w and SEV_ORDER.get((w[3] or "").upper(), 9) < SEV_ORDER.get(ln["severity"], 9):
                ln["severity"] = (w[3] or "").upper()
            ln["sites"].append(s)
        out = list(lines.values())
        for ln in out:
            ln["sites"].sort()
        out.sort(key=lambda ln: (ln["title"] == fallback, -len(ln["sites"]), ln["title"]))
        return out

    # A site rated for the first time (not scanned a week ago) did not "go up": it has
    # its first rating, and its tile is outlined as changed.
    up = sorted(s for s in now_bands if s in then_bands and BAND_RANK[now_bands[s]] < BAND_RANK[then_bands[s]]
                and now_bands[s] in dd.RATED and then_bands[s] != "unscanned")
    down = sorted(s for s in now_bands if s in then_bands and BAND_RANK[now_bands[s]] > BAND_RANK[then_bands[s]]
                  and then_bands[s] in dd.RATED)
    return {
        "up": explain(up, by_site_open, "no finding opened this week explains it"),
        "down": explain(down, by_site_closed, "no finding closed this week explains it"),
        "n_up": len(up), "n_down": len(down),
    }


# ── the week, day by day ──────────────────────────────────────────────────────
def scans_by_day(rows, days) -> list[tuple[int, int]]:
    """Rows (local date, intensity, count) -> [(deep, quick)] per day, in `days` order.
    Deep = heavy; quick = light and medium."""
    idx = {d: i for i, d in enumerate(days)}
    out = [[0, 0] for _ in days]
    for d, intensity, n in rows or []:
        if hasattr(d, "date") and not isinstance(d, type(days[0])):
            d = d.date()
        if d not in idx:
            continue
        out[idx[d]][0 if (intensity or "").lower() == "heavy" else 1] += int(n or 0)
    return [tuple(x) for x in out]


# ── the model ─────────────────────────────────────────────────────────────────
def changes(now_bands: dict, then_bands: dict, opened, closed, names) -> list[dict]:
    """Every site whose risk level changed this week, grouped by (was, is, reason):
    [{was, now, riskier, reason, sites}], riskier first. The reason is in plain words: for a
    site that got riskier, the worst problem that appeared on it; for one that got safer,
    what went away ("a web firewall now blocks our test attacks"). Nothing this week to
    explain it says so (Howie, 10-22: "What the hell does up or down actually mean?")."""
    by_open: dict = {}
    for r in opened or []:
        if (r[3] or "").upper() != "INFO":
            by_open.setdefault(dd.site_of(r[1], names), []).append(r)
    by_closed: dict = {}
    for r in closed or []:
        if (r[3] or "").upper() != "INFO":
            by_closed.setdefault(dd.site_of(r[1], names), []).append(r)
    def lower1(t):
        return t if len(t) > 1 and t[1].isupper() else t[0].lower() + t[1:]

    # Grouped by the REASON, not by the exact levels: eight Prodex sites got safer for one
    # reason on 10-22, and splitting them 7 + 1 by where they landed read as two stories
    # (Howie: "Why isn't it 8 sites got safer?"). A site that landed somewhere else, or still
    # has something open, is said inside its group.
    groups: dict = {}
    for was, now, sites in dd.site_moves(now_bands, then_bands):
        riskier = BAND_RANK[now] < BAND_RANK[was]
        for s_ in sites:
            w = _worst((by_open if riskier else by_closed).get(s_, []))
            still = ""
            if w is None:
                key = (riskier, "none", "")
            elif riskier:
                key = (riskier, "new", words.words(w[2])["title"].replace("this site", "it"))
            else:
                fw = words.words(w[2])["fixed"]
                key = (riskier, "fixed", fw) if fw != "fixed" else (riskier, "fixed-raw", unescape(w[2]).strip())
                if BAND_RANK[now] <= BAND_RANK["modhigh"]:
                    top = [r for r in by_open.get(s_, []) if dd.band_of(r[3], True) == now]
                    if top:
                        still = words.words(top[0][2])["key"] or words.words(top[0][2])["title"]
            groups.setdefault(key, []).append((s_, was, now, still))

    def reason(kind, text, n):
        if kind == "none":
            return "Nothing we saw this week explains it; the portal shows the history."
        if kind == "new":
            return ("New problem: " if n == 1 else "New problem on each: ") + lower1(text) + "."
        return (text[0].upper() + text[1:] + ".") if kind == "fixed" else f"Fixed: {text}."

    def aside(s_, was, now, still, common_now):
        if still == "waf-not-blocking":
            return (f"On {s_}, though, the firewall only watches so far: our test attacks still get "
                    f"through, so it's {dd.BAND_TITLE[now]}, not {dd.BAND_TITLE[common_now]}.")
        if still:
            t = words.FAMILY_BY_KEY[still]["title"] if still in words.FAMILY_BY_KEY else still
            return f"On {s_} one problem is still open ({lower1(t)}), so it's {dd.BAND_TITLE[now]}."
        return f"{s_} went from {dd.BAND_TITLE[was]} to {dd.BAND_TITLE[now]}."

    out = []
    for (riskier, kind, text), rows in groups.items():
        pairs: dict = {}
        for _s, was, now, still in rows:
            if not still:
                pairs[(was, now)] = pairs.get((was, now), 0) + 1
        common = max(pairs, key=pairs.get) if pairs else (rows[0][1], rows[0][2])
        asides = [aside(s_, was, now, still, common[1]) for s_, was, now, still in sorted(rows)
                  if still or (was, now) != common]
        out.append({"was": common[0], "now": common[1], "riskier": riskier,
                    "reason": reason(kind, text, len(rows)), "asides": asides,
                    "sites": sorted(r[0] for r in rows)})
    # single sites moving the same way for different reasons are one card, not "1 site got
    # riskier" twice in a row
    for riskier in (True, False):
        singles = [g for g in out if g["riskier"] == riskier and len(g["sites"]) == 1 and not g["asides"]
                   ]
        if len(singles) < 2:
            continue
        for g in singles:
            out.remove(g)
        out.append({"was": None, "now": None, "riskier": riskier, "reason": "",
                    "asides": [f"{g['sites'][0]} ({dd.BAND_TITLE[g['was']]} to {dd.BAND_TITLE[g['now']]}): "
                               f"{g['reason'][0].lower() + g['reason'][1:] if not g['reason'][1:2].isupper() else g['reason']}"
                               for g in sorted(singles, key=lambda g: g["sites"][0])],
                    "sites": sorted(g["sites"][0] for g in singles)})
    out.sort(key=lambda g: (not g["riskier"], -len(g["sites"]), BAND_RANK[g["now"]] if g["now"] else 0))
    return out


def build_weekly(*, now, window_start, window_end, days, sites, opened, closed, scans,
                 certs=None, open_serious=None, hints=None, stale_assets=None,
                 canary_violations=None, stale_words=None, stale_intro="", stale_note="",
                 baseline=None, brand=None, details=None, overdue=None, gaps=None,
                 told=None, fleet_has_waf=True) -> dict:
    """Everything the two weekly renderers need, decided once. PURE. `sites` are
    SQL_SITE_RATINGS rows with the rebuild taken at window_start. `overdue` are
    SQL_OPEN_OUT_OF_DATE rows (job 3r): out-of-date findings with a known fix, open
    more than OVERDUE_DAYS — their own section, never also in "Worth your time".

    Job 3s: `gaps` are SQL_OPEN_FIREWALL_GAPS rows (the MODERATE firewall gaps the serious
    list leaves out); `told` is the record of what was told ({finding_id: row}, empty or None =
    nothing told yet: everything is new). Serious, overdue and gap rows go through ONE
    group_problems call, so a problem is one item; told.decide splits the items into full
    cards (new / worse / came back / reminder due) and quiet lines ("Still open, no change").
    `told_full` lists the findings behind every card actually rendered in full, for
    run_alerter to record after the send."""
    brand = brand or dict(dd.DEFAULT_BRAND)
    site_rows = list(sites or [])
    # only what is known: a version we could not see is not a finding, opened or closed
    opened = [r for r in opened or [] if not words.is_guess(r[2])]
    closed = [r for r in closed or [] if not words.is_guess(r[2])]
    overdue = [r for r in overdue or [] if words.is_out_of_date(r[0], r[2]) and not words.is_guess(r[2])]
    od_ids = {r[0] for r in overdue}
    open_serious = [r for r in open_serious or [] if not words.is_guess(r[2]) and r[0] not in od_ids]
    _taken = od_ids | {r[0] for r in open_serious}
    gaps = [r for r in gaps or [] if not words.is_guess(r[2]) and r[0] not in _taken]
    names = {r[0] for r in site_rows} | {r[1] for r in (opened or [])} | \
            {r[1] for r in (closed or [])} | {r[1] for r in (open_serious or [])} | \
            {r[1] for r in overdue} | {r[1] for r in gaps}
    now_b, then_b = dd.site_bands(site_rows)
    now_c, then_c = dd.band_counts(now_b), dd.band_counts(then_b)
    mv = moves(now_b, then_b, opened, closed, names)

    # the daily's own cards for the two things the week shares with it: a gap in our own
    # checking (it leads) and certificates within 14 days (one card, however many)
    daily = dd.build_model(
        window_start=window_start, window_end=now, new_findings=[], confirmed=[],
        regressed=[], high_risk=[], new_assets=[], dark_assets=[],
        stale_assets=stale_assets or [], canary_violations=canary_violations or [],
        baseline={}, brand=brand, certs=certs, stale_words=stale_words,
        stale_intro=stale_intro, stale_note=stale_note)
    do = [i for i in daily["do"] if i["kind"] in ("coverage", "cert")]
    n_certs = sum(len(i.get("sites", [])) for i in do if i["kind"] == "cert")
    # Job 3s (plan re-check MF2): ONE grouping over every open problem the week considers,
    # so a family with a young serious member and old overdue ones is one item, printed once.
    rows_all = list(open_serious) + list(overdue) + list(gaps)
    member_sev = {r[0]: (r[3] or "").upper() for r in rows_all}
    first_seen = {r[0]: r[6] for r in overdue if len(r) > 6 and r[6] is not None}
    for r in list(open_serious) + list(gaps):
        if len(r) > 9 and r[9] is not None:
            first_seen.setdefault(r[0], r[9])
    merged = dict(details or {})
    for r in list(overdue) + list(gaps):
        merged.setdefault(r[0], (r[7] if len(r) > 7 else "", list(r[8] or []) if len(r) > 8 else []))
    told = told or {}
    full, late, quiet = [], [], []
    for g in dd.group_problems(rows_all, names, hints=hints, details=merged):
        g["why"] = ""
        kind = told_rule.kind_of(g, od_ids, fleet_has_waf)
        verdict, reason = told_rule.decide(g, told, now, member_sev, kind)
        seen = [first_seen[f] for f in g["finding_ids"] if f in first_seen]
        g["since"] = min(seen) if seen else told_rule.first_told(g, told)
        g["told_kind"] = kind
        if verdict == "quiet":
            quiet.append(g)
            continue
        tag = told_rule.tag_for(reason, g, told, kind, dd._day)
        if tag:
            g["tag"] = tag
        if kind == "overdue":
            # Job 3r (Howie 2026-10-23 07:21–07:25): MODERATE, "but … some kind of indication
            # that there is still some action required": known since <first sighting>, violet.
            g["overdue_since"] = min(seen) if seen else None
            if g["overdue_since"] is not None:
                late.append(g)
        else:
            full.append(g)
    do += full[:DO_MAX]
    also = full[DO_MAX:]          # listed one line each, NOT recorded: told in full next time
    more = len(also)
    late.sort(key=lambda g: (g["overdue_since"], g["title"]))
    quiet.sort(key=lambda g: (SEV_ORDER.get(g["severity"], 9),
                              g["since"] or datetime.max.replace(tzinfo=timezone.utc), g["title"]))
    seen_who: dict = {}
    for g in late:
        g["as_of"] = now
        k = seen_who.get(g.get("who") or "it", 0)
        seen_who[g.get("who") or "it"] = k + 1
        g["nudge"] = dd.overdue_nudge(g, k)        # a different line for each item, per audience

    scan_cols = scans_by_day(scans, days)
    # The counts are the seven days; `opened` / `closed` may run on to now (Monday's early
    # hours) so a rating that moved before the send is still explained.
    def _in_week(r):
        ts = r[6] if len(r) > 6 else None
        return ts is not None and window_start <= ts < window_end
    n_closed = sum(1 for r in closed or [] if (r[3] or "").upper() != "INFO" and _in_week(r))
    n_opened = sum(1 for r in opened or [] if (r[3] or "").upper() != "INFO" and _in_week(r))
    ws = dd.local_time(window_start, brand)
    model = {
        "brand": brand, "now": now, "local_now": dd.local_time(now, brand),
        "window_start": window_start, "window_end": window_end, "days": days,
        "since": f"last {ws:%a}", "since_long": f"last {ws:%A}, {dd._day(ws)}",
        "sites_total": len(now_b), "counts": now_c, "counts_then": then_c,
        "moves": mv, "changes": changes(now_b, then_b, opened, closed, names),
        "scans": scan_cols, "n_scans": sum(a + b for a, b in scan_cols),
        "groups": site_groups(now_b, then_b), "do": do, "more": more, "overdue": late,
        "also": also, "quiet": quiet,
        "told_full": told_rule.records(full[:DO_MAX] + late, member_sev, "weekly"),
        "n_closed": n_closed, "n_opened": n_opened, "n_certs": n_certs,
        "degraded": bool(stale_assets or canary_violations), "baseline": baseline or {},
    }
    model["headline"] = weekly_headline(model)
    return model


def weekly_headline(m: dict) -> str:
    """The week's biggest change in one sentence, in words that say which way is good:
    riskier / safer, never up / down (Howie, 10-22)."""
    mv = m["moves"]
    up, down = mv["n_up"], mv["n_down"]

    def sites(n, verb):
        return f"{dd._n(n).capitalize()} site{'s' if n != 1 else ''} {verb}"

    if up and down:
        if down > up:
            return f"{sites(down, 'got safer')} this week. {dd._n(up).capitalize()} got riskier."
        return f"{sites(up, 'got riskier')} this week. {dd._n(down).capitalize()} got safer."
    if up:
        return f"{sites(up, 'got riskier')} this week." if up > 1 else \
               f"{mv['up'][0]['sites'][0]} got riskier this week."
    if down:
        return f"{sites(down, 'got safer')} this week. Nothing got riskier." if down > 1 else \
               f"{mv['down'][0]['sites'][0]} got safer this week. Nothing got riskier."
    if m["n_closed"]:
        return f"A steady week: no site changed risk level, and {m['n_closed']} problem{'s' if m['n_closed'] != 1 else ''} got fixed."
    return "A quiet week. No site changed risk level. We checked."


def weekly_subject(m: dict, product_name: str) -> str:
    """'[PRODEXsentry] Prodex, your week: 8 sites safer, 2 riskier, 8 problems fixed'."""
    b, mv = m["brand"], m["moves"]
    up, down = mv["n_up"], mv["n_down"]
    moves_ = [(up, "riskier"), (down, "safer")]
    if down > up:
        moves_.reverse()
    parts = []
    for i, (n, word) in enumerate(x for x in moves_ if x[0]):
        parts.append(f"{n} site{'s' if n != 1 else ''} {word}" if i == 0 else f"{n} {word}")
    if m["n_closed"]:
        parts.append(f"{m['n_closed']} problem{'s' if m['n_closed'] != 1 else ''} fixed")
    if m["n_certs"]:
        parts.append(f"{m['n_certs']} certificate{'s' if m['n_certs'] != 1 else ''} to renew")
    what = ", ".join(parts) if parts else "a quiet week"
    prefix = f"[{product_name}] " if product_name else ""
    gap = "(!) Coverage gap. " if m["degraded"] else ""
    return f"{prefix}{gap}{b.get('short_name', 'Sentry')}, your week: {what}"


open_words = dd.open_words


# ── HTML ──────────────────────────────────────────────────────────────────────
def _section(title: str, aside: str = "", intro: str = "") -> str:
    head = (f'<tr><td class="px" style="padding:28px 32px 6px;"><table role="presentation" width="100%" cellpadding="0" '
            f'cellspacing="0" border="0"><tr><td><h2 style="margin:0;font-family:{DISPLAY};font-size:22px;line-height:1.2;'
            f'font-weight:700;color:{INK};">{escape(title)}</h2></td>'
            + (f'<td align="right" style="font-family:{FONT};font-size:13px;color:{MUTED};white-space:nowrap;">{escape(aside)}</td>'
               if aside else "") + '</tr></table>'
            + (dd._p(escape(intro), MUTED, 14, "margin-top:4px;") if intro else "") + '</td></tr>')
    return head


def _header(m: dict) -> str:
    b = m["brand"]
    now = m["local_now"]
    logo = (f'<img src="cid:{LOGO_CID}" width="{int(b.get("logo_width") or 160)}" alt="{escape(b.get("logo_alt") or b["short_name"])}" '
            f'style="display:block;border:0;height:auto;max-width:{int(b.get("logo_width") or 160)}px;">'
            if b.get("logo_bytes") else
            f'<span style="font-family:{DISPLAY};font-size:22px;font-weight:800;color:{b["band_text"]};">'
            f'{escape(b["short_name"])}</span>')
    border = f'border-bottom:1px solid {b["band_border"]};' if b.get("band_border") else ""
    tally = ""
    if m["sites_total"]:
        tally = (f'<tr><td colspan="2" class="px" style="padding:0 32px 24px;">'
                 f'<div style="font-family:{FONT};font-size:13px;line-height:1.5;margin-bottom:8px;color:{b["band_text"]};font-weight:700;">'
                 f'Your {m["sites_total"]} live sites, by risk level, compared with {escape(m["since_long"])}</div>'
                 f'{dd.tally(m["counts"], m["counts_then"], m["since"])}'
                 f'<div style="margin-top:10px;font-family:{FONT};font-size:12px;line-height:1.5;color:{b["band_muted"]};">'
                 f'{escape(dd.RISK_LEVEL_WORDS)}</div></td></tr>')
    return (f'<tr><td bgcolor="{b["band_bg"]}" style="background:{b["band_bg"]};{border}border-radius:14px 14px 0 0;">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
            f'<tr><td class="px" style="padding:22px 32px 0;" valign="middle">{logo}</td>'
            f'<td class="px" style="padding:22px 32px 0;font-family:{FONT};font-size:13px;line-height:1.4;color:{b["band_muted"]};white-space:nowrap;" '
            f'align="right" valign="middle">Your week<br>{now:%a}, {now:%b} {now.day}</td></tr>'
            f'<tr><td colspan="2" class="px" style="padding:20px 32px 20px;"><h1 style="margin:0;font-family:{DISPLAY};'
            f'font-size:32px;line-height:1.1;font-weight:800;letter-spacing:-0.015em;color:{b["band_text"]};">'
            f'{escape(m["headline"])}</h1></td></tr>{tally}</table></td></tr>')


def change_title(g: dict) -> str:
    """ "Two sites got riskier" / "1 site got safer"."""
    n = len(g["sites"])
    verb = "got riskier" if g["riskier"] else "got safer"
    return f"{dd._n(n).capitalize()} sites {verb}" if n > 1 else f"1 site {verb}"


def _changed(m: dict) -> list[str]:
    ch = m["changes"]
    if not ch:
        return [_section("What changed"),
                '<tr><td class="px" style="padding:0 32px;">'
                + dd._p("No site changed risk level this week.", MUTED, 14) + '</td></tr>']
    rows = [_section("What changed", intro=f"Every site whose risk level is different from {m['since_long']}.")]
    for g in ch:
        who = change_title(g)
        tint = "#FDF1EA" if g["riskier"] else "#EAF6EF"
        rows.append(
            f'<tr><td class="px" style="padding:0 32px 10px;"><table role="presentation" width="100%" cellpadding="0" '
            f'cellspacing="0" border="0" bgcolor="{tint}" style="background:{tint};border-radius:12px;"><tr>'
            f'<td class="card" style="padding:14px 18px;">'
            f'<div style="font-family:{FONT};font-size:16px;line-height:1.4;font-weight:700;color:{INK};">'
            f'{escape(who)}'
            + (f'&nbsp; {dd.band_chip(g["was"])} <span style="color:{MUTED};">&rarr;</span> {dd.band_chip(g["now"])}'
               if g["was"] else "") + '</div>'
            + (dd._p(escape(g["reason"]), "#2B3747", 14, "margin-top:6px;") if g["reason"] else "")
            + "".join(dd._p(escape(x), "#2B3747", 14, "margin-top:4px;") for x in g.get("asides", []))
            + dd.chips(g["sites"]) + '</td></tr></table></td></tr>')
    return rows


def _week(m: dict) -> list[str]:
    cols, days = m["scans"], m["days"]
    deep_c = m["brand"].get("button") or "#0A4595"
    top = max([a + b for a, b in cols] + [1])
    cells = []
    for i, (deep, quick) in enumerate(cols):
        hd = round(COLUMN_PX * deep / top)
        hq = round(COLUMN_PX * quick / top)
        pad = COLUMN_PX - hd - hq
        delay = 0.1 + i * 0.07
        parts = []
        if pad > 0:
            parts.append(f'<tr><td height="{pad}" style="height:{pad}px;font-size:0;line-height:0;">&nbsp;</td></tr>')
        if hq:
            parts.append(f'<tr><td height="{hq}" bgcolor="#A9BCD8" class="col" style="height:{hq}px;background:#A9BCD8;'
                         f'border-radius:4px 4px 0 0;font-size:0;line-height:0;animation-delay:{delay:.2f}s;">&nbsp;</td></tr>')
        if hd:
            parts.append(f'<tr><td height="{hd}" bgcolor="{deep_c}" class="col" style="height:{hd}px;background:{deep_c};'
                         f'{"" if hq else "border-radius:4px 4px 0 0;"}font-size:0;line-height:0;animation-delay:{delay:.2f}s;">&nbsp;</td></tr>')
        cells.append(f'<td valign="bottom" style="padding:0 3px;">'
                     f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{"".join(parts)}</table></td>')
    labels = "".join(f'<td align="center" style="padding:6px 0 0;font-family:{FONT};font-size:12px;'
                     f'color:{MUTED};">{d:%a}</td>' for d in days)
    key = (f'<span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:{deep_c};margin-right:6px;"></span>Deep scans (the full workout)'
           f'<span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#A9BCD8;margin:0 6px 0 16px;"></span>Quick scans')
    return [
        _section("How hard we looked", aside=f"{m['n_scans']} scans"),
        f'<tr><td class="px" style="padding:6px 32px 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'border="0" style="table-layout:fixed;border-bottom:2px solid #D6DEE8;"><tr>{"".join(cells)}</tr></table>'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="table-layout:fixed;"><tr>{labels}</tr></table>'
        f'<div style="margin-top:10px;font-family:{FONT};font-size:12px;color:{MUTED};">{key}</div></td></tr>',
    ]


def _tiles(m: dict) -> list[str]:
    if not m["groups"]:
        return []
    legend = "".join(
        f'<span style="display:inline-block;white-space:nowrap;margin:0 12px 6px 0;font-family:{FONT};font-size:12px;color:{INK};">'
        f'<span style="display:inline-block;width:11px;height:11px;border-radius:3px;background:{fill};margin-right:5px;vertical-align:-1px;"></span>'
        f'{escape(dd.BAND_TITLE[k])}</span>' for k, _w, fill, _t in BANDS if m["counts"].get(k))
    rows = [_section("Every site, by risk level", intro="A box with a dark outline changed this week."),
            f'<tr><td class="px" style="padding:4px 32px 4px;">{legend}</td></tr>']
    one = len(m["groups"]) == 1
    body = []
    for g in m["groups"]:
        tiles = []
        for t in g["tiles"]:
            fill, text, words_ = BAND_FILL[t["band"]]
            edge = INK if t["changed"] else fill
            tiles.append(
                f'<span class="{"isnew" if t["changed"] else ""}" title="{escape(t["site"])}: {escape(words_)}'
                f'{", changed this week" if t["changed"] else ""}" style="display:inline-block;white-space:nowrap;margin:0 6px 6px 0;'
                f'padding:6px 9px;border-radius:6px;border:2px solid {edge};'
                f'background:{fill};color:{text};font-family:{FONT};font-size:12px;font-weight:600;line-height:16px;">'
                f'{escape("main site" if t["label"] == "site" and not one else g["name"] if t["label"] == "site" else t["label"])}</span>')
        name = (f'<div style="font-family:{FONT};font-size:13px;font-weight:700;line-height:20px;color:{INK};'
                f'padding:0 0 6px;white-space:nowrap;">{escape(g["name"])}</div>')
        body.append(f'<tr><td style="padding:10px 0 4px;border-top:1px solid {RULE};">{name}{"".join(tiles)}</td></tr>')
    rows.append(f'<tr><td class="px" style="padding:0 32px;"><table role="presentation" width="100%" cellpadding="0" '
                f'cellspacing="0" border="0">{"".join(body)}</table></td></tr>')
    return rows


def quiet_line(i: dict) -> str:
    """One line for a problem told before: "Overdue: Slider Revolution … on 3 sites (since May
    23)". Job 3s, Howie 2026-10-22: 'Still open, no change: … (since Oct 15)'."""
    sites = i.get("sites") or []
    where = (f" on {sites[0]}" if len(sites) == 1 else f" on {len(sites)} sites" if sites else "")
    title = i["title"]
    if any(s in title for s in sites):
        where = ""
    pre = "Overdue: " if i.get("told_kind") == "overdue" else ""
    since = f" (since {dd._day(i['since'])})" if i.get("since") is not None else ""
    return f"{pre}{title}{where}{since}"


def _quiet_row(i: dict) -> str:
    fill = (dd.OVERDUE_FILL if i.get("told_kind") == "overdue"
            else dd.SEV_STYLE.get(i.get("severity") or "", ("#D9DEE5", INK, ""))[0])
    dot = (f'<span style="display:inline-block;width:9px;height:9px;border-radius:5px;background:{fill};'
           f'margin-right:8px;"></span>')
    return (f'<tr><td class="px" style="padding:0 32px;"><div style="font-family:{FONT};font-size:14px;'
            f'line-height:1.5;color:#2B3747;padding:7px 0;border-bottom:1px solid #EDF1F6;">{dot}'
            f'{escape(quiet_line(i))}</div></td></tr>')


def render_weekly_html(m: dict, *, portal_url: str = "", product_name: str = "") -> str:
    b = m["brand"]
    portal = (portal_url or "").rstrip("/")
    rows = [_header(m)]
    rows += _changed(m)
    if m["do"]:
        rows.append(_section("Worth your time this week",
                             intro="Worth working on this week, worst first. Each says what we found, what it means, and the fix."))
        rows += [dd._card(i, portal) for i in m["do"]]
        if m.get("also"):
            rows.append('<tr><td class="px" style="padding:0 32px;">'
                        + dd._p('<span style="font-weight:700;">Also this week:</span>', INK, 14)
                        + "".join(dd._p(escape(quiet_line(i)), "#2B3747", 14, "margin-top:3px;") for i in m["also"])
                        + dd._p("Each gets its full card next week.", MUTED, 13) + '</td></tr>')
    if m.get("overdue"):
        rows.append(_section("Overdue",
                             intro=f"Known problems with a known fix, open more than {dd.OVERDUE_DAYS} days. "
                                   f"Not urgent; still waiting on someone."))
        rows += [dd._card(i, portal) for i in m["overdue"]]
    if m.get("quiet"):
        rows.append(_section("Still open, no change",
                             intro="Told before and still open. Each comes back as a full reminder when it is due."))
        rows += [_quiet_row(i) for i in m["quiet"]]
    rows += _week(m)
    rows += _tiles(m)
    if portal:
        rows.append(
            f'<tr><td class="px" style="padding:24px 32px 28px;"><table role="presentation" cellpadding="0" cellspacing="0" '
            f'border="0"><tr><td bgcolor="{b["button"]}" style="background:{b["button"]};border-radius:8px;">'
            f'<a href="{escape(portal)}" style="display:inline-block;padding:12px 18px;font-family:{FONT};'
            f'font-size:15px;font-weight:600;color:#FFFFFF;text-decoration:none;">Open the portal</a>'
            f'</td></tr></table></td></tr>')
    bl = m["baseline"]
    footer = (f"Sent by {escape(product_name or b['short_name'])} every Monday morning. "
              f"The daily list keeps coming every morning.")
    if bl:
        footer = f"Open across {escape(b['short_name'])} right now: {open_words(bl)}. " + footer
    rows.append(f'<tr><td bgcolor="#F4F7FB" class="px" style="background:#F4F7FB;border-radius:0 0 14px 14px;padding:14px 32px;'
                f'font-family:{FONT};font-size:12px;line-height:1.5;color:{MUTED};">{footer}</td></tr>')
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light"><title>{escape(m["headline"])}</title>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,700;12..96,800&amp;display=swap" rel="stylesheet">
<style>
@keyframes rise{{from{{transform:scaleY(0)}}to{{transform:scaleY(1)}}}}
@keyframes ping{{0%{{box-shadow:0 0 0 0 rgba(15,27,45,.45)}}70%{{box-shadow:0 0 0 8px rgba(15,27,45,0)}}100%{{box-shadow:0 0 0 8px rgba(15,27,45,0)}}}}
.col{{transform-origin:bottom center;animation:rise .8s cubic-bezier(.3,.7,.2,1) both}}
.isnew{{animation:ping 2.2s ease-out 3}}
@media (prefers-reduced-motion:reduce){{.col,.isnew{{animation:none}}}}
@media (max-width:620px){{h1{{font-size:27px !important}} .px{{padding-left:16px !important;padding-right:16px !important}} .card{{padding:14px 14px !important}}}}
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
def render_weekly_text(m: dict, *, portal_url: str = "", product_name: str = "") -> str:
    b, now, days = m["brand"], m["local_now"], m["days"]
    out = [f"{product_name or b['short_name']} — {b['short_name']}, your week, {now:%A} {now:%B} {now.day}", "",
           m["headline"]]
    if m["sites_total"]:
        out.append(f"Your {m['sites_total']} live sites, by risk level: {dd.counts_words(m['counts'])} "
                   f"({m['since']}: {dd.counts_words(m['counts_then'])}).")
        out.append(dd.RISK_LEVEL_WORDS)
    out.append("")
    out.append("WHAT CHANGED")
    if not m["changes"]:
        out.append("  No site changed risk level this week.")
    for g in m["changes"]:
        span = f" ({dd.BAND_TITLE[g['was']]} to {dd.BAND_TITLE[g['now']]})" if g["was"] else ""
        out.append(f"  {change_title(g)}{span}{': ' + g['reason'] if g['reason'] else ''}")
        for x in g.get("asides", []):
            out.append(f"      {x}")
        out.append(f"      {', '.join(g['sites'])}")
    out.append("")
    def item_lines(i):
        sev = SEV_WORD.get(i.get("severity") or "", "")
        tag = "[Overdue] " if i.get("overdue_since") else (f"[{sev}] " if sev else "")
        out.append(f"  [ ] {tag}{i['title']}")
        if i.get("overdue_since"):
            out.append(f"      {dd.overdue_words(i)}")
            if i.get("nudge"):
                out.append(f"      {i['nudge']}")
        if i.get("body"):
            out.append(f"      {i['body']}")
        if i.get("sites") and i.get("kind") == "finding":
            out.append(f"      Sites: {', '.join(i['sites'])}")
        for label, sites in i.get("groups", []):
            out.append(f"      - {label}: {', '.join(sites)}")
        for l in i.get("lines", [])[:20]:
            out.append(f"      - {l}")
        if i.get("do"):
            who = dd.WHO_WORDS.get(i.get("who") or "", "")
            out.append(f"      The fix{', for ' + who if who and i.get('kind') == 'finding' else ''}: {i['do']}")
        if i.get("forward"):
            out.append(f"      Ready to forward: {i['forward']}")

    if m["do"]:
        out.append("WORTH YOUR TIME THIS WEEK (worst first)")
        for i in m["do"]:
            item_lines(i)
        for i in m.get("also", []):
            out.append(f"  Also this week: {quiet_line(i)}")
        out.append("")
    if m.get("overdue"):
        out.append(f"OVERDUE (known, with a fix, open more than {dd.OVERDUE_DAYS} days)")
        for i in m["overdue"]:
            item_lines(i)
        out.append("")
    if m.get("quiet"):
        out.append("STILL OPEN, NO CHANGE (told before; a full reminder comes when it is due)")
        for i in m["quiet"]:
            out.append(f"  - {quiet_line(i)}")
        out.append("")
    out.append(f"HOW HARD WE LOOKED: {m['n_scans']} scans, {days[0]:%a %b} {days[0].day} to {days[-1]:%a %b} {days[-1].day}")
    out.append("  " + "  ".join(f"{d:%a} {deep} deep/{quick} quick" for d, (deep, quick) in zip(days, m["scans"])))
    out.append("")
    out.append("EVERY SITE, BY RISK LEVEL (* changed this week)")
    for g in m["groups"]:
        out.append(f"  {g['name']}: " + ", ".join(
            f"{t['label']} {dd.BAND_TITLE[t['band']].lower()}{' *' if t['changed'] else ''}" for t in g["tiles"]))
    out.append("")
    bl = m["baseline"]
    if bl:
        out.append(f"Open across {b['short_name']} right now: {open_words(bl)}.")
    if portal_url:
        out.append(f"Open the portal: {portal_url.rstrip('/')}")
    return "\n".join(out)
