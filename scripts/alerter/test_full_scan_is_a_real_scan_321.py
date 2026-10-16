"""321 (2026-10-16) — the digest's own health check tells the truth about full scans.

Howie, on the 10-16 Command digest line
  "ns02.sciimage.com  last seen Oct 16 (11 hours ago)  last full scan Oct 16 (11 hours ago)"
listed under "We may have lost sight of these": "To me, it looks like an impossibility."

It was. ns02's last real full scan was 2026-08-27; since 2026-09-03 (4.7 ruling 74) the weekly
sweep skips the four nameservers on purpose (assets.not_web_scannable). The "full scan" date
was asset_surface.last_seen, which the discovery importer also stamps every 6 hours. And
"lost sight" fired at 9 hours for a host an outside source lists about 2 passes in 3.

Three changes, pinned here:
  1. The full-scan date comes from public.scan_run (newest complete or degraded run).
  2. A host skipped on purpose says so and is never counted as behind on full scans; a host
     known for less than the full-scan window is not overdue for its first one yet.
  3. "Lost sight" after a day (24h) unseen, not 9 hours.
And one found while building it: the weekly sweep rescans a host just past 7 days (median
168.2h, 97% within 170h over 45 days), so a 168h full-scan line would call on-schedule hosts
behind every week. The line is 8 days (192h).
"""
from __future__ import annotations

import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
import run_alerter as ra  # noqa: E402

UTC = timezone.utc
T = lambda *a: datetime(*a, tzinfo=UTC)  # noqa: E731


def _sql_code() -> str:
    """The query with its comments removed, flattened — what Postgres actually runs."""
    code = "\n".join(line.split("--", 1)[0] for line in ra.SQL_STALE_LIVE_ASSETS.splitlines())
    return " ".join(code.split())


def _row(aid, lo, ls, hd, hs, disc_stale, never, scan_stale, via="discovery", skipped=False):
    return (aid, lo, ls, hd, hs, disc_stale, never, scan_stale, via, skipped)


def test_321_full_scan_date_comes_from_real_scans_not_the_discovery_stamp():
    sql = _sql_code()
    assert "FROM public.scan_run r" in sql
    assert "r.status IN ('complete', 'degraded')" in sql
    assert "max(r.completed_at)" in sql
    # asset_surface is stamped by discovery every pass; it must not be the full-scan clock
    assert "asset_surface" not in sql
    assert "last_seen" not in sql.replace("deep_scan_last_seen", "")


def test_321_no_bare_percent_anywhere_in_the_query_comments_included():
    # psycopg reads every % in the string, comments too: a "97%" in a comment made this
    # query raise "incomplete placeholder" (caught on a scratch Postgres before it shipped;
    # it would have killed the digest). Only placeholders (%s, %(name)s) and %% may carry
    # one, in every query the digest runs.
    sqls = {k: v for k, v in vars(ra).items() if k.startswith("SQL_") and isinstance(v, str)}
    assert "SQL_STALE_LIVE_ASSETS" in sqls and len(sqls) > 10
    bad = [k for k, v in sqls.items() if "%" in re.sub(r"%\(\w+\)s|%s|%%", "", v)]
    assert not bad, bad


def test_321_skipped_hosts_are_never_behind_on_full_scans_but_still_watched():
    sql = _sql_code()
    assert "COALESCE(a.not_web_scannable, false) AS skipped" in sql
    assert "NOT c.skipped AND c.scanned_at IS NULL" in sql
    assert "NOT c.skipped AND c.scanned_at IS NOT NULL" in sql
    # the "seen" leg does not care about skipping: we still want to know if one vanishes
    seen_leg = sql[sql.index("SELECT c.*,"):sql.index("AS discovery_stale")]
    assert "c.seen_at IS NULL OR c.seen_at <" in seen_leg and "skipped" not in seen_leg


def test_321_a_new_host_is_not_overdue_for_its_first_full_scan_yet():
    sql = _sql_code()
    assert "COALESCE(a.first_observed, a.created_at) AS known_since" in sql
    assert "c.known_since IS NULL OR c.known_since < (now() - (%(deep_h)s::int * interval '1 hour'))" in sql


def test_321_the_row_still_has_the_columns_the_renderers_index():
    sql = _sql_code()
    tail = sql[sql.rindex("SELECT f.asset_id"):]
    cols = ["f.asset_id", "AS last_observed", "AS deep_scan_last_seen", "AS hours_since_discovery",
            "AS hours_since_deep_scan", "f.discovery_stale", "AS never_deep_scanned", "AS deep_scan_stale",
            "f.seen_via", "f.skipped"]
    pos = [tail.index(c) for c in cols]
    assert pos == sorted(pos), "column order changed; the renderers read r[5], r[6], r[7], r[9]"


def test_321_lost_sight_after_a_day_and_behind_after_eight_days():
    src = open(ra.__file__, encoding="utf-8").read()
    assert '_env("ALERTER_DISCOVERY_STALE_HOURS", default="24") or "24"' in src
    assert '_env("ALERTER_DEEPSCAN_STALE_HOURS",  default="192") or "192"' in src
    assert 'default="9"' not in src and 'default="168"' not in src
    assert ra.stale_overdue_note(24, 192) == "not seen in a day, no full scan in 8 days, or never"
    assert ra.stale_overdue_note(24, 168) == "not seen in a day, no full scan in 7 days, or never"
    assert ra.stale_overdue_note(9, 168) == "not seen in 9 hours, no full scan in 7 days, or never"
    assert ra.stale_overdue_note(48, 168) == "not seen in 2 days, no full scan in 7 days, or never"


def test_321_words_for_a_host_skipped_on_purpose():
    # ns02.sciimage.com as it would read if we ever stop seeing it for a day
    aid, d, s = ra.stale_row_words(_row("ns02.sciimage.com", T(2026, 10, 15, 1, 11), T(2026, 8, 27, 22, 40),
                                        35.0, 1181.0, True, False, False, skipped=True))
    assert d == "last seen Oct 15 (35 hours ago)"
    assert s == "not full-scanned on purpose (not a website)"
    assert "Aug" not in s and "never" not in s


def test_321_words_for_a_new_host_with_no_full_scan_yet():
    aid, d, s = ra.stale_row_words(_row("new.example.com", T(2026, 10, 14, 0, 0), None, 60.0, None, True, False, False))
    assert s == "first full scan not due yet"


def test_321_the_older_tuples_still_render():
    nine = ("x.example.com", T(2026, 10, 1), T(2026, 10, 2), 300.0, 280.0, True, False, True, "discovery")
    eight = nine[:8]
    for r in (nine, eight):
        assert ra.stale_row_words(r)[2] == "last full scan Oct 2 (12 days ago)"


def _render(stale):
    base = {"critical_open": 0, "high_open": 0, "mod_high_open": 0, "moderate_open": 0, "low_open": 0}
    kw = dict(window_start=T(2026, 10, 15, 12), window_end=T(2026, 10, 16, 12), new_findings=[], confirmed=[],
              regressed=[], high_risk=[], new_assets=[], dark_assets=[], stale_assets=stale, canary_violations=[],
              discovery_stale_hours=24, deepscan_stale_hours=192, baseline=base, product_name="X")
    return ra.render_html(dashboard_url="https://x.invalid", **kw), ra.render_text(**kw)


def test_321_both_renderers_mark_a_skipped_host_as_not_overdue_on_scans():
    stale = [_row("ns02.sciimage.com", T(2026, 10, 15, 1, 11), T(2026, 8, 27, 22, 40),
                  35.0, 1181.0, True, False, False, skipped=True)]
    html, text = _render(stale)
    flat = " ".join(text.split())
    for out in (html, flat):
        assert "not full-scanned on purpose (not a website)" in out
        assert "not seen in a day, no full scan in 8 days, or never" in out
        assert "gives each website a full scan about once a week" in out
    # text mail: the seen line is marked overdue, the scan line is not
    lines = text.splitlines()
    i = next(n for n, ln in enumerate(lines) if "ns02.sciimage.com" in ln)
    assert lines[i + 1].lstrip().startswith("! last seen Oct 15")
    assert not lines[i + 2].lstrip().startswith("!") and "not full-scanned on purpose" in lines[i + 2]
    # html mail: the scan cell is grey, not red
    cell = re.search(r'<td[^>]*style="([^"]*)"[^>]*>[^<]*not full-scanned on purpose', html)
    assert cell and "#a51c30" not in cell.group(1)
