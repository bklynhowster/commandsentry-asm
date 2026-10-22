"""digest_weekly.py — the Monday weekly review (KB 12 job 3l, slice 2, design B + C).

Howie, 2026-10-22 14:51, on the redesign boards: "maybe there's a way that we change this
somewhat. There's a weekly, in other words, that has more detail." 14:59: "the weekly
should definitely be Monday. If it's not Monday, it's Friday, and frankly, on Friday,
nobody pays attention." 15:12: "Happy, I'm thrilled." Canvas board "Weekly, Monday 8 AM
(B + C)" (claude.ai artifact PKowwaTmCM9rWHAdkiFmzb).

WHAT THIS IS. Pure functions, no database and no network, beside digest_daily.py and
built from its pieces (the brand, the bands, www. folding, grouping by problem). The week
is the seven whole local days before today (Monday's send covers Monday to Sunday). In
order, the email carries:

    the headline       the week's biggest change, in one sentence
    two bars           every live site by rating a week ago and today (a past rating is
                       rebuilt from findings: rating = worst open finding, job 3m)
    why it moved       the finding behind each site that went up or came down
    the week           seven day-columns of deep and quick scans, then the days' events
                       (serious findings opened, findings closed)
    every live site    one tile per site, grouped by its registered domain, alphabetical,
                       colored by rating, outlined when its rating changed this week
    this week, do      certificates expiring within 14 days, then the open serious
                       problems grouped (six at most; the rest are in the portal)

EMAIL-SAFE BY CONSTRUCTION, as the daily: tables, inline styles, bgcolor; the day columns
are table cells with pixel heights; one <style> block for the grow-in and the outline
pulse (Apple Mail plays them; Gmail and Outlook show the same design still), respecting
prefers-reduced-motion.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from html import escape, unescape

import digest_daily as dd
from digest_daily import (BANDS, BAND_RANK, DISPLAY, FONT, GOOD, INK, MUTED, PAGE, RULE,
                          SEV_ORDER, SEV_STYLE, SEV_WORD, LOGO_CID)

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9
    ZoneInfo = None  # type: ignore

SERIOUS = ("CRITICAL", "HIGH", "MODERATE-HIGH")
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


def _local_date(ts: datetime, brand: dict):
    return ts.astimezone(_zone(brand)).date()


def day_events(opened, closed, names, days, brand) -> list[dict]:
    """Pinned events, in day order: serious findings opened (grouped by problem per day)
    and findings closed (one line per day, naming the biggest problem closed)."""
    events = []
    for d in days:
        o = [r for r in opened or [] if (r[3] or "").upper() in SERIOUS and _local_date(r[6], brand) == d]
        for g in dd.group_problems(o, names):
            events.append({"day": d, "kind": "opened", "severity": g["severity"],
                           "text": f"{g['title']}: {', '.join(g['sites'][:6])}"
                                   + (f" and {len(g['sites']) - 6} more" if len(g["sites"]) > 6 else "")})
        c = [r for r in closed or [] if (r[3] or "").upper() != "INFO" and _local_date(r[6], brand) == d]
        if c:
            gs = dd.group_problems(c, names)
            top = gs[0]
            text = f"{len(c)} finding{'s' if len(c) != 1 else ''} closed"
            text += (f": {top['title']}" if len(gs) == 1 else f", the biggest: {top['title']}")
            text += f" ({', '.join(top['sites'][:4])}{', …' if len(top['sites']) > 4 else ''})"
            events.append({"day": d, "kind": "closed", "severity": "", "text": text})
    return events


# ── the model ─────────────────────────────────────────────────────────────────
def build_weekly(*, now, window_start, window_end, days, sites, opened, closed, scans,
                 certs=None, open_serious=None, hints=None, stale_assets=None,
                 canary_violations=None, stale_words=None, stale_intro="", stale_note="",
                 baseline=None, brand=None) -> dict:
    """Everything the two weekly renderers need, decided once. PURE. `sites` are
    SQL_SITE_RATINGS rows with the rebuild taken at window_start."""
    brand = brand or dict(dd.DEFAULT_BRAND)
    site_rows = list(sites or [])
    names = {r[0] for r in site_rows} | {r[1] for r in (opened or [])} | \
            {r[1] for r in (closed or [])} | {r[1] for r in (open_serious or [])}
    now_b, then_b = dd.site_bands(site_rows)
    now_c, then_c = dd.band_counts(now_b), dd.band_counts(then_b)
    mv = moves(now_b, then_b, opened, closed, names)

    do = []
    if stale_assets or canary_violations:
        # the daily's coverage card, the same words: a gap in our own checking leads
        daily = dd.build_model(
            window_start=window_start, window_end=window_end, new_findings=[], confirmed=[],
            regressed=[], high_risk=[], new_assets=[], dark_assets=[],
            stale_assets=stale_assets or [], canary_violations=canary_violations or [],
            baseline={}, brand=brand, stale_words=stale_words, stale_intro=stale_intro,
            stale_note=stale_note)
        do += [i for i in daily["do"] if i["kind"] == "coverage"]
    n_certs = 0
    for r in certs or []:
        left = dd.cert_days_left(r, now)
        if left is None or left > dd.CERT_DAYS:
            continue
        n_certs += 1
        exp = dd.local_time(dd.cert_expiry(r), brand)
        on = f"{exp:%A}, {dd._day(exp)}"
        if left < 0:
            body = f"It expired {on}. Anyone connecting to it securely now gets a certificate error."
        else:
            when = "today" if left == 0 else f"in {left} day{'s' if left != 1 else ''}, {on}"
            body = f"It expires {when}. After that, anyone connecting to it securely gets a certificate error."
        do.append({"kind": "cert", "severity": "HIGH" if left <= 3 else "MODERATE-HIGH",
                   "title": f"Renew the certificate on {r[0]}", "body": body,
                   "sites": [r[0]], "why": "", "do": "", "tag": ""})
    serious = dd.group_problems(open_serious or [], names, hints=hints)
    for g in serious:
        g["why"] = ""          # "found by" is the daily's question; the week asks what's open
    do += serious[:DO_MAX]
    more = max(0, len(serious) - DO_MAX)

    scan_cols = scans_by_day(scans, days)
    # The counts are the seven days; `opened` / `closed` may run on to now (Monday's early
    # hours) so a rating that moved before the send is still explained.
    def _in_week(r):
        ts = r[6] if len(r) > 6 else None
        return ts is not None and window_start <= ts < window_end
    n_closed = sum(1 for r in closed or [] if (r[3] or "").upper() != "INFO" and _in_week(r))
    n_opened = sum(1 for r in opened or [] if (r[3] or "").upper() != "INFO" and _in_week(r))
    model = {
        "brand": brand, "now": now, "local_now": dd.local_time(now, brand),
        "window_start": window_start, "window_end": window_end, "days": days,
        "sites_total": len(now_b), "counts": now_c, "counts_then": then_c,
        "moves": mv, "scans": scan_cols, "n_scans": sum(a + b for a, b in scan_cols),
        "events": day_events(opened, closed, names, days, brand),
        "groups": site_groups(now_b, then_b), "do": do, "more": more,
        "n_closed": n_closed, "n_opened": n_opened, "n_certs": n_certs,
        "degraded": bool(stale_assets or canary_violations), "baseline": baseline or {},
    }
    model["headline"] = weekly_headline(model)
    return model


def weekly_headline(m: dict) -> str:
    """The week's biggest change in one sentence: the larger of the two moves leads."""
    mv = m["moves"]
    up, down = mv["n_up"], mv["n_down"]

    def sites(n, verb):
        return f"{dd._n(n).capitalize()} site{'s' if n != 1 else ''} {verb}"

    if up and down:
        if down > up:
            return f"{sites(down, 'came down')} this week, and {dd._n(up)} went up."
        return f"{sites(up, 'went up')} this week, and {dd._n(down)} came down."
    if up == 1:
        return f"{mv['up'][0]['sites'][0]} went up this week."
    if up:
        same = len(mv["up"]) == 1 and mv["up"][0]["severity"]
        return f"{sites(up, 'went up')} this week" + (", all for the same reason." if same else ".")
    if down == 1:
        return f"{mv['down'][0]['sites'][0]} came down this week."
    if down:
        same = len(mv["down"]) == 1 and mv["down"][0]["severity"]
        return f"{sites(down, 'came down')} this week" + (", all for the same reason." if same else ".")
    if m["n_closed"]:
        return f"A steady week: no rating changed, and {m['n_closed']} finding{'s' if m['n_closed'] != 1 else ''} closed."
    return "A quiet week: no rating changed."


def weekly_subject(m: dict, product_name: str) -> str:
    """'[COMMANDsentry] Command, your week: 6 sites went up, 28 findings closed, 1
    certificate to renew'."""
    b, mv = m["brand"], m["moves"]
    parts = []
    up, down = mv["n_up"], mv["n_down"]
    moves_ = [(up, "went up"), (down, "came down")]
    if down > up:
        moves_.reverse()
    for i, (n, verb) in enumerate(x for x in moves_ if x[0]):
        parts.append(f"{n} site{'s' if n != 1 else ''} {verb}" if i == 0 else f"{n} {verb}")
    if m["n_closed"]:
        parts.append(f"{m['n_closed']} finding{'s' if m['n_closed'] != 1 else ''} closed")
    if m["n_certs"]:
        parts.append(f"{m['n_certs']} certificate{'s' if m['n_certs'] != 1 else ''} to renew")
    what = ", ".join(parts) if parts else "a quiet week"
    prefix = f"[{product_name}] " if product_name else ""
    gap = "(!) Coverage gap. " if m["degraded"] else ""
    return f"{prefix}{gap}{b.get('short_name', 'Sentry')}, your week: {what}"


def change_line(m: dict) -> str:
    """'High 6 to 12, moderate 39 to 33, out of 47 live sites.' / 'No rating changed …'"""
    words = {k: w for k, w, *_r in BANDS}
    diffs = [(k, m["counts_then"].get(k, 0), m["counts"].get(k, 0)) for k in dd.RATED
             if m["counts_then"].get(k, 0) != m["counts"].get(k, 0)]
    total = m["sites_total"]
    if not diffs:
        return f"No rating changed. {total} live site{'s' if total != 1 else ''}: {dd.counts_words(m['counts'])}."
    s = ", ".join(f"{words[k]} {a} to {b}" for k, a, b in diffs)
    return s[0].upper() + s[1:] + f", out of {total} live site{'s' if total != 1 else ''}."


def open_words(bl: dict) -> str:
    """'4 critical, 16 high, 187 moderate, 406 low' — moderate-high only when there is one."""
    parts = [f"{bl.get('critical_open', 0)} critical", f"{bl.get('high_open', 0)} high"]
    if bl.get("mod_high_open"):
        parts.append(f"{bl['mod_high_open']} moderate-high")
    parts += [f"{bl.get('moderate_open', 0)} moderate", f"{bl.get('low_open', 0)} low"]
    return ", ".join(parts)


# ── HTML ──────────────────────────────────────────────────────────────────────
def _seg_bar(counts: dict, total: int, delay0: float) -> str:
    cells, delay = [], delay0
    for k, _w, fill, _t in BANDS:
        n = counts.get(k, 0)
        if not n:
            continue
        pct = max(1, round(100 * n / total))
        cells.append(f'<td width="{pct}%" style="padding:0 1px 0 0;"><div class="seg" style="height:20px;'
                     f'background:{fill};border-radius:4px;animation-delay:{delay:.2f}s;"></div></td>')
        delay += 0.1
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
            f'<tr>{"".join(cells)}</tr></table>')


def _bars(m: dict) -> str:
    b, total = m["brand"], m["sites_total"]
    if not total:
        return ""
    ws = dd.local_time(m["window_start"], b)
    lab = f'font-family:{FONT};font-size:13px;line-height:20px;white-space:nowrap;'
    return (f'<tr><td colspan="2" class="px" style="padding:0 32px 26px;">'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
            f'<tr><td width="96" style="{lab}color:{b["band_muted"]};padding:0 12px 8px 0;">{ws:%a}, {ws:%b} {ws.day}</td>'
            f'<td style="padding:0 0 8px;">{_seg_bar(m["counts_then"], total, 0.1)}</td></tr>'
            f'<tr><td width="96" style="{lab}color:{b["band_text"]};font-weight:700;padding:0 12px 0 0;">Today</td>'
            f'<td>{_seg_bar(m["counts"], total, 0.5)}</td></tr>'
            f'<tr><td></td><td style="padding-top:8px;font-family:{FONT};font-size:13px;line-height:1.5;'
            f'color:{b["band_muted"]};">{escape(change_line(m))}</td></tr></table></td></tr>')


def _dot(color: str) -> str:
    return (f'<span style="display:inline-block;width:10px;height:10px;border-radius:5px;background:{color};'
            f'margin-right:8px;vertical-align:middle;"></span>')


def _moved(m: dict) -> list[str]:
    mv = m["moves"]
    if not (mv["up"] or mv["down"]):
        return []
    rows = []
    for title, lines, color in (("Why ratings went up", mv["up"], "#C2410C"),
                                ("Why ratings came down", mv["down"], GOOD)):
        if not lines:
            continue
        rows.append(dd._h2(title))
        for ln in lines:
            sev = ln["severity"]
            dot = SEV_STYLE.get(sev, (color,))[0] if color != GOOD else GOOD
            rows.append(
                f'<tr><td class="px" style="padding:0 32px 10px;">'
                f'<div style="font-family:{FONT};font-size:15px;line-height:1.55;color:{INK};">{_dot(dot)}'
                f'<span style="font-weight:700;">{escape(ln["title"])}</span></div>'
                f'<div style="font-family:{FONT};font-size:14px;line-height:1.55;color:#2B3747;padding-left:18px;">'
                f'{escape(", ".join(ln["sites"]))}</div></td></tr>')
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
        cells.append(f'<td width="14%" valign="bottom" style="padding:0 4px;" title="{deep} deep, {quick} quick">'
                     f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">{"".join(parts)}</table></td>')
    labels = "".join(f'<td width="14%" align="center" style="padding:6px 2px 0;font-family:{FONT};font-size:12px;'
                     f'color:{MUTED};white-space:nowrap;">{d:%a} {d.day}</td>' for d in days)
    key = (f'<span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:{deep_c};margin-right:6px;"></span>Deep scans'
           f'<span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#A9BCD8;margin:0 6px 0 16px;"></span>Quick scans')
    rows = [
        f'<tr><td class="px" style="padding:26px 32px 12px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
        f'<td><h2 style="margin:0;font-family:{DISPLAY};font-size:22px;line-height:1.2;font-weight:700;color:{INK};">The week</h2></td>'
        f'<td align="right" style="font-family:{FONT};font-size:13px;color:{MUTED};white-space:nowrap;">'
        f'{m["n_scans"]} scan{"s" if m["n_scans"] != 1 else ""}, {days[0]:%a} to {days[-1]:%a}</td></tr></table></td></tr>',
        f'<tr><td class="px" style="padding:0 32px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'border="0" style="border-bottom:2px solid #D6DEE8;"><tr>{"".join(cells)}</tr></table>'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>{labels}</tr></table>'
        f'<div style="margin-top:10px;font-family:{FONT};font-size:12px;color:{MUTED};">{key}</div></td></tr>',
    ]
    if m["events"]:
        ev = []
        for e in m["events"]:
            color = GOOD if e["kind"] == "closed" else SEV_STYLE.get(e["severity"], ("#C2410C",))[0]
            ev.append(f'<tr><td width="64" valign="top" style="padding:0 10px 10px 0;font-family:{FONT};font-size:14px;'
                      f'line-height:1.5;font-weight:700;color:{MUTED};white-space:nowrap;">{e["day"]:%a} {e["day"].day}</td>'
                      f'<td valign="top" style="padding:0 0 10px;font-family:{FONT};font-size:14px;line-height:1.5;color:{INK};">'
                      f'{_dot(color)}{escape(e["text"])}</td></tr>')
        rows.append(f'<tr><td class="px" style="padding:14px 32px 0;"><table role="presentation" width="100%" cellpadding="0" '
                    f'cellspacing="0" border="0">{"".join(ev)}</table></td></tr>')
    else:
        rows.append('<tr><td class="px" style="padding:14px 32px 0;">'
                    + dd._p("No serious finding opened and none closed this week.", MUTED, 14) + '</td></tr>')
    return rows


def _tiles(m: dict) -> list[str]:
    if not m["groups"]:
        return []
    rows = [
        f'<tr><td class="px" style="padding:26px 32px 12px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
        f'<td><h2 style="margin:0;font-family:{DISPLAY};font-size:22px;line-height:1.2;font-weight:700;color:{INK};">Every live site today</h2></td>'
        f'<td align="right" style="font-family:{FONT};font-size:13px;color:{MUTED};white-space:nowrap;">Outlined: changed this week</td>'
        f'</tr></table></td></tr>']
    body = []
    for g in m["groups"]:
        tiles = []
        for t in g["tiles"]:
            fill, text, words = BAND_FILL[t["band"]]
            edge = INK if t["changed"] else fill
            tiles.append(
                f'<span class="{"isnew" if t["changed"] else ""}" title="{escape(t["site"])}: {escape(words)}'
                f'{", changed this week" if t["changed"] else ""}" style="display:inline-block;margin:0 6px 6px 0;'
                f'padding:7px 10px;min-width:26px;text-align:center;border-radius:6px;border:2px solid {edge};'
                f'background:{fill};color:{text};font-family:{FONT};font-size:12px;font-weight:600;line-height:16px;'
                f'white-space:nowrap;">{escape(t["label"])}</span>')
        body.append(f'<tr><td class="dom" width="225" valign="top" style="padding:12px 12px 6px 0;font-family:{FONT};font-size:13px;'
                    f'font-weight:600;line-height:20px;color:{INK};border-bottom:1px solid {RULE};overflow-wrap:anywhere;">{escape(g["name"])}</td>'
                    f'<td class="tl" valign="top" style="padding:10px 0 4px;border-bottom:1px solid {RULE};">{"".join(tiles)}</td></tr>')
    rows.append(f'<tr><td class="px" style="padding:0 32px;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
                f'border="0" style="border-top:1px solid {RULE};">{"".join(body)}</table>'
                f'<div style="margin-top:10px;font-family:{FONT};font-size:12px;color:{MUTED};">'
                + "".join(f'<span style="display:inline-block;margin:0 14px 4px 0;"><span style="display:inline-block;width:10px;'
                          f'height:10px;border-radius:2px;background:{fill};margin-right:6px;"></span>{escape(w.capitalize())}</span>'
                          for k, w, fill, _t in BANDS if m["counts"].get(k))
                + '</div></td></tr>')
    return rows


def render_weekly_html(m: dict, *, portal_url: str = "", product_name: str = "") -> str:
    b = m["brand"]
    now = m["local_now"]
    portal = (portal_url or "").rstrip("/")
    logo = (f'<img src="cid:{LOGO_CID}" width="{int(b.get("logo_width") or 160)}" alt="{escape(b.get("logo_alt") or b["short_name"])}" '
            f'style="display:block;border:0;height:auto;max-width:{int(b.get("logo_width") or 160)}px;">'
            if b.get("logo_bytes") else
            f'<span style="font-family:{DISPLAY};font-size:22px;font-weight:800;color:{b["band_text"]};">'
            f'{escape(b["short_name"])}</span>')
    border = f'border-bottom:1px solid {b["band_border"]};' if b.get("band_border") else ""
    rows = [
        f'<tr><td bgcolor="{b["band_bg"]}" style="background:{b["band_bg"]};{border}border-radius:14px 14px 0 0;">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
        f'<tr><td class="px" style="padding:22px 32px 0;" valign="middle">{logo}</td>'
        f'<td class="px" style="padding:22px 32px 0;font-family:{FONT};font-size:13px;line-height:1.4;color:{b["band_muted"]};white-space:nowrap;" '
        f'align="right" valign="middle">Weekly review<br>{now:%A}, {now:%b} {now.day}</td></tr>'
        f'<tr><td colspan="2" class="px" style="padding:20px 32px 22px;"><h1 style="margin:0;font-family:{DISPLAY};'
        f'font-size:34px;line-height:1.08;font-weight:800;letter-spacing:-0.015em;color:{b["band_text"]};">'
        f'{escape(m["headline"])}</h1></td></tr>{_bars(m)}</table></td></tr>']
    rows += _moved(m)
    rows += _week(m)
    rows += _tiles(m)
    if m["do"]:
        rows.append(dd._h2("This week, do"))
        rows += [dd._card(i, portal) for i in m["do"]]
        if m["more"]:
            rows.append('<tr><td class="px" style="padding:0 32px;">'
                        + dd._p(f"And {m['more']} more serious problem{'s' if m['more'] != 1 else ''}, listed in the portal.", MUTED, 14)
                        + '</td></tr>')
    if portal:
        rows.append(
            f'<tr><td class="px" style="padding:22px 32px 28px;"><table role="presentation" cellpadding="0" cellspacing="0" '
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
@keyframes grow{{from{{transform:scaleX(0)}}to{{transform:scaleX(1)}}}}
@keyframes rise{{from{{transform:scaleY(0)}}to{{transform:scaleY(1)}}}}
@keyframes ping{{0%{{box-shadow:0 0 0 0 rgba(15,27,45,.45)}}70%{{box-shadow:0 0 0 8px rgba(15,27,45,0)}}100%{{box-shadow:0 0 0 8px rgba(15,27,45,0)}}}}
.seg{{transform-origin:left center;animation:grow .9s cubic-bezier(.3,.7,.2,1) both}}
.col{{transform-origin:bottom center;animation:rise .8s cubic-bezier(.3,.7,.2,1) both}}
.isnew{{animation:ping 2.2s ease-out 3}}
@media (prefers-reduced-motion:reduce){{.seg,.col,.isnew{{animation:none}}}}
@media (max-width:620px){{h1{{font-size:28px !important}} .px{{padding-left:18px !important;padding-right:18px !important}} .card{{padding:16px 14px !important}} .dom{{display:block !important;width:auto !important;border-bottom:0 !important;padding:12px 0 2px !important}} .tl{{display:block !important}}}}
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
def render_weekly_text(m: dict, *, portal_url: str = "", product_name: str = "") -> str:
    b, now, days = m["brand"], m["local_now"], m["days"]
    out = [f"{product_name or b['short_name']} — {b['short_name']}, weekly review, {now:%A} {now:%B} {now.day}", "",
           m["headline"]]
    if m["sites_total"]:
        out.append(change_line(m))
    out.append("")
    mv = m["moves"]
    for title, lines in (("WHY RATINGS WENT UP", mv["up"]), ("WHY RATINGS CAME DOWN", mv["down"])):
        if lines:
            out.append(title)
            for ln in lines:
                out.append(f"  - {ln['title']}: {', '.join(ln['sites'])}")
            out.append("")
    out.append(f"THE WEEK ({m['n_scans']} scans, {days[0]:%a %b} {days[0].day} to {days[-1]:%a %b} {days[-1].day})")
    out.append("  " + "  ".join(f"{d:%a} {deep}d/{quick}q" for d, (deep, quick) in zip(days, m["scans"])))
    for e in m["events"]:
        out.append(f"  {e['day']:%a} {e['day'].day}: {e['text']}")
    out.append("")
    out.append("EVERY LIVE SITE TODAY (* changed this week)")
    words = {k: w for k, w, *_r in BANDS}
    for g in m["groups"]:
        out.append(f"  {g['name']}: " + ", ".join(
            f"{t['label']} {words[t['band']]}{' *' if t['changed'] else ''}" for t in g["tiles"]))
    out.append("")
    if m["do"]:
        out.append("THIS WEEK, DO")
        for i in m["do"]:
            sev = SEV_WORD.get(i.get("severity") or "", "")
            out.append(f"  [ ] {('[' + sev + '] ') if sev else ''}{i['title']}")
            if i.get("body"):
                out.append(f"      {i['body']}")
            if i.get("sites") and i.get("kind") == "finding":
                out.append(f"      Sites: {', '.join(i['sites'])}")
            for l in i.get("lines", [])[:20]:
                out.append(f"      - {l}")
            if i.get("do"):
                out.append(f"      Do: {i['do']}")
        if m["more"]:
            out.append(f"  And {m['more']} more serious problems, listed in the portal.")
        out.append("")
    bl = m["baseline"]
    if bl:
        out.append(f"Open across {b['short_name']} right now: {open_words(bl)}.")
    if portal_url:
        out.append(f"Open the portal: {portal_url.rstrip('/')}")
    return "\n".join(out)
