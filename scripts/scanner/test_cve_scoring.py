#!/usr/bin/env python3
"""302 step 3 — automatic CVE scoring (2026-10-09).

cve_scoring reads NVD, FIRST EPSS and the CISA known-exploited list for every
CVE on a finding and rolls them onto the findings. These tests pin the rules
that make it safe to run unattended every two hours:

  * a public source that fails or answers nonsense changes NOTHING
  * a finding is rewritten only when a value actually changes
  * it never touches severity (a raise would be undone by the next scan)
  * it gives way to a scan holding the same rows (lock_timeout < deadlock check)
  * it only ever talks to the three public sources
"""
from __future__ import annotations

import http.client
import io
import json
import os
import sys
import urllib.error
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal as D

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cve_scoring as S  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WORKFLOW = os.path.join(HERE, "..", "..", ".github", "workflows", "cve-scoring.yml")


# ── CVE ids ───────────────────────────────────────────────────────────────────

def test_cve_ids_are_normalised_and_junk_dropped():
    assert S.normalize_cves(["cve-2021-41184 ", "CVE-2021-41184", "CVE-2022-31160", "N/A", None, 7,
                             "CVE-21-1", "CVE-2021-123", " cve-2020-12345"]) == \
        ["CVE-2020-12345", "CVE-2021-41184", "CVE-2022-31160"]


# ── HTTP ──────────────────────────────────────────────────────────────────────

class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(*outcomes):
    calls = []

    def op(req, timeout):
        calls.append((req.full_url, timeout, req.get_header("User-agent")))
        o = outcomes[len(calls) - 1]
        if isinstance(o, Exception):
            raise o
        return _Resp(o if isinstance(o, bytes) else json.dumps(o).encode())
    op.calls = calls
    return op


def _http(code):
    return urllib.error.HTTPError("u", code, "x", {}, None)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(S.time, "sleep", lambda s: None)


def test_get_json_ok_and_identifies_itself():
    op = _opener({"a": 1})
    assert S.http_get_json("https://x/y", opener=op) == {"a": 1}
    assert "cve-scoring" in op.calls[0][2]


def test_get_json_404_is_none():
    assert S.http_get_json("https://x", opener=_opener(_http(404))) is None


@pytest.mark.parametrize("first", [_http(429), _http(503), urllib.error.URLError("reset"), TimeoutError(), b"not json",
                                   http.client.IncompleteRead(b"{"), http.client.BadStatusLine("x")])
def test_get_json_retries_once_on_transient_problems(first):
    op = _opener(first, {"ok": True})
    assert S.http_get_json("https://x", opener=op) == {"ok": True}
    assert len(op.calls) == 2


def test_get_json_403_is_not_retried():
    op = _opener(_http(403), {"never": 1})
    with pytest.raises(S.SourceError):
        S.http_get_json("https://x", opener=op)
    assert len(op.calls) == 1


def test_get_json_gives_up_after_two():
    with pytest.raises(S.SourceError):
        S.http_get_json("https://x", opener=_opener(_http(503), _http(503), {"x": 1}))


# ── NVD ──────────────────────────────────────────────────────────────────────

def _nvd(metrics, **cve):
    return {"vulnerabilities": [{"cve": {"metrics": metrics, **cve}}]}


def _m(score, vec, typ="Primary", sev="MEDIUM"):
    return {"type": typ, "cvssData": {"baseScore": score, "vectorString": vec, "baseSeverity": sev}}


def test_nvd_prefers_nvd_own_score_over_the_vendor_s():
    out = S.parse_nvd(_nvd({"cvssMetricV31": [_m(5.4, "SEC", "Secondary"), _m(6.1, "PRI")]}))
    assert (out["nvd_cvss_v3_score"], out["nvd_cvss_v3_vector"], out["nvd_severity"]) == (6.1, "PRI", "MEDIUM")


def test_nvd_falls_back_to_v30_and_to_the_only_entry():
    out = S.parse_nvd(_nvd({"cvssMetricV30": [_m(7.5, "V30", "Secondary", "high")]}))
    assert (out["nvd_cvss_v3_score"], out["nvd_severity"]) == (7.5, "HIGH")


@pytest.mark.parametrize("score", [None, "7.5", True, -1, 10.5])
def test_nvd_ignores_a_score_that_is_not_a_cvss_number(score):
    out = S.parse_nvd(_nvd({"cvssMetricV31": [_m(score, "V")]}))
    assert out["nvd_cvss_v3_score"] is None and out["nvd_cvss_v3_vector"] is None


def test_nvd_text_loses_nul_characters_postgres_cannot_store():
    out = S.parse_nvd(_nvd({"cvssMetricV31": [_m(5.0, "CVSS:3.1/\x00X")]},
                           descriptions=[{"lang": "en", "value": "a\x00b"}], references=[{"url": "https://a\x00"}]))
    assert out["nvd_description"] == "ab" and out["nvd_cvss_v3_vector"] == "CVSS:3.1/X"
    assert out["nvd_references"] == ["https://a"]


def test_nvd_other_fields():
    out = S.parse_nvd(_nvd({}, published="2021-10-26T15:15:07.947", lastModified="2024-01-01T00:00:00Z",
                           descriptions=[{"lang": "es", "value": "no"}, {"lang": "en", "value": "yes"}],
                           weaknesses=[{"description": [{"value": "CWE-79"}, {"value": "NVD-CWE-noinfo"},
                                                        {"value": "CWE-79"}, {"value": "cwe-20"}]}],
                           references=[{"url": "https://a"}, {"x": 1}, "junk"]))
    assert out["nvd_published_at"] == "2021-10-26T15:15:07.947+00:00"
    assert out["nvd_last_modified"] == "2024-01-01T00:00:00Z"
    assert out["nvd_description"] == "yes" and out["nvd_cwe_ids"] == [20, 79]
    assert out["nvd_references"] == ["https://a"] and out["nvd_cvss_v3_score"] is None


@pytest.mark.parametrize("doc", [None, {}, {"vulnerabilities": []}, {"vulnerabilities": ["x"]}])
def test_nvd_not_found_is_none(doc):
    assert S.parse_nvd(doc) is None


# ── EPSS ─────────────────────────────────────────────────────────────────────

def test_epss_parses_strings_and_rounds_to_the_column():
    out = S.parse_epss({"data": [{"cve": "cve-2022-31160", "epss": "0.004260000", "percentile": "0.618560000"}]})
    assert out == {"CVE-2022-31160": {"epss_score": 0.0043, "epss_percentile": 0.6186}}


@pytest.mark.parametrize("item", [{"cve": "CVE-2022-31160", "epss": "1.5", "percentile": "0.5"},
                                  {"cve": "CVE-2022-31160", "epss": "0.5", "percentile": "-0.1"},
                                  {"cve": "CVE-2022-31160", "epss": "x", "percentile": "0.5"},
                                  {"cve": "CVE-2022-31160", "epss": "0.1"},
                                  {"cve": "NOPE", "epss": "0.1", "percentile": "0.5"}, "junk"])
def test_epss_drops_anything_malformed(item):
    assert S.parse_epss({"data": [item]}) == {}


# ── KEV ──────────────────────────────────────────────────────────────────────

def _kev(n=S.KEV_MIN_ENTRIES, extra=()):
    return {"vulnerabilities": [{"cveID": f"CVE-2000-{i:05d}"} for i in range(n)] + list(extra)}


def test_kev_catalog_indexed():
    idx = S.parse_kev(_kev(extra=[{"cveID": "cve-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
                                   "shortDescription": "d", "requiredAction": "a"},
                                  {"cveID": "CVE-2020-00001", "dateAdded": "soon", "dueDate": None}]))
    assert idx["CVE-2021-44228"] == {"kev_added_date": "2021-12-10", "kev_due_date": "2021-12-24",
                                     "kev_short_desc": "d", "kev_required_action": "a"}
    assert idx["CVE-2020-00001"]["kev_added_date"] is None
    assert S.parse_kev(_kev(extra=[{"cveID": "CVE-2021-44228", "shortDescription": "x\x00y"}]))[
        "CVE-2021-44228"]["kev_short_desc"] == "xy"


@pytest.mark.parametrize("doc", [None, [], {}, {"vulnerabilities": "x"}, _kev(n=S.KEV_MIN_ENTRIES - 1)])
def test_a_catalog_that_does_not_look_real_is_refused(doc):
    """A truncated or wrong download must never clear a KEV flag."""
    with pytest.raises(S.SourceError):
        S.parse_kev(doc)


def test_kev_falls_back_to_cisa_s_github_copy():
    seen = []

    def get(url, timeout=30):
        seen.append(url)
        if "cisa.gov" in url:
            raise S.SourceError("HTTPError: 403")
        return _kev()
    idx, authoritative = S.fetch_kev(get)
    assert len(idx) == S.KEV_MIN_ENTRIES and authoritative is False      # the copy may lag: adds only
    assert [u.split("/")[2] for u in seen] == ["www.cisa.gov", "raw.githubusercontent.com"]


def test_kev_from_cisa_gov_is_authoritative():
    idx, authoritative = S.fetch_kev(lambda url, timeout=30: _kev())
    assert authoritative is True


def test_kev_both_down_names_both():
    with pytest.raises(S.SourceError) as e:
        S.fetch_kev(lambda url, timeout=30: None)
    assert "www.cisa.gov" in str(e.value) and "raw.githubusercontent.com" in str(e.value)


# ── fetching EPSS and NVD ────────────────────────────────────────────────────

def test_epss_is_batched_and_a_failed_batch_is_skipped(monkeypatch):
    monkeypatch.setattr(S, "EPSS_BATCH", 2)
    cves = ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0004", "CVE-2020-0005"]
    asked = []

    def get(url, timeout=30):
        batch = url.split("cve=")[1].split(",")
        asked.append(batch)
        if "CVE-2020-0003" in batch:
            raise S.SourceError("HTTPError: 503")
        return {"status-code": 200, "data": [{"cve": c, "epss": "0.1", "percentile": "0.2"} for c in batch]
                + [{"cve": "CVE-1999-0001", "epss": "0.9", "percentile": "0.9"}]}
    out, errs = S.fetch_epss(cves, get)
    assert asked == [cves[0:2], cves[2:4], cves[4:5]]
    assert sorted(out) == ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0005"]   # never a CVE we did not ask
    assert len(errs) == 1


@pytest.mark.parametrize("answer", [None, {"status-code": 500, "data": []}, {"message": "x"}])
def test_epss_answer_without_data_is_an_error(answer):
    out, errs = S.fetch_epss(["CVE-2020-0001"], lambda url, timeout=30: answer)
    assert out == {} and len(errs) == 1


def test_nvd_is_paced_and_stops_at_the_first_refusal():
    sleeps, asked = [], []

    def get(url, timeout=30):
        cve = url.split("cveId=")[1]
        asked.append(cve)
        if cve == "CVE-2020-0003":
            raise S.SourceError("HTTPError: 403")
        return _nvd({"cvssMetricV31": [_m(5.0, "V")]})
    out, err = S.fetch_nvd(["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0004"], get,
                           sleep=sleeps.append)
    assert asked == ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"]
    assert sleeps == [S.NVD_DELAY_S, S.NVD_DELAY_S] and sorted(out) == ["CVE-2020-0001", "CVE-2020-0002"]
    assert "CVE-2020-0003" in err


def test_nvd_due_never_read_first_then_stale_capped(monkeypatch):
    now = datetime(2026, 10, 9, tzinfo=timezone.utc)
    cache = {"CVE-2020-0001": (now - timedelta(days=1), True),           # scored, fresh
             "CVE-2020-0002": (now - timedelta(days=45), True),          # scored, stale
             "CVE-2020-0003": (now - timedelta(days=31), True),          # scored, stale, newer
             "CVE-2020-0004": (now - timedelta(hours=2), False),         # unscored, asked today
             "CVE-2020-0005": (now - timedelta(days=2), False)}          # unscored, asked 2 days ago
    cves = ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0004", "CVE-2020-0005", "CVE-2020-0009"]
    assert S.nvd_due(cves, cache, now) == ["CVE-2020-0009", "CVE-2020-0002", "CVE-2020-0003", "CVE-2020-0005"]
    monkeypatch.setattr(S, "NVD_MAX_PER_RUN", 2)
    assert S.nvd_due(cves, cache, now) == ["CVE-2020-0009", "CVE-2020-0002"]


# ── what changes on a finding ────────────────────────────────────────────────

def _row(**kw):
    base = dict(finding_id="f", severity="MODERATE", current_status="detected",
                epss_score=None, epss_percentile=None, kev_listed=False, kev_due_date=None,
                cvss_score=None, cvss_vector=None,
                r_epss_score=None, r_epss_percentile=None, r_kev_known=True, r_kev_listed=False,
                r_kev_due_date=None, r_cvss_score=None, r_cvss_vector=None)
    base.update(kw)
    return base


def test_nothing_changed_writes_nothing():
    assert S.plan_finding_update(_row()) == {}
    assert S.plan_finding_update(_row(epss_score=D("0.1"), epss_percentile=D("0.5"),
                                      r_epss_score=D("0.1000"), r_epss_percentile=D("0.50"))) == {}


def test_epss_written_when_new_or_changed_never_blanked():
    assert S.plan_finding_update(_row(r_epss_score=D("0.2"), r_epss_percentile=D("0.6"))) == \
        {"epss_score": D("0.2"), "epss_percentile": D("0.6")}
    assert S.plan_finding_update(_row(epss_score=D("0.2"), epss_percentile=D("0.6"))) == {}


def test_kev_listing_sets_flag_and_date():
    out = S.plan_finding_update(_row(r_kev_listed=True, r_kev_due_date=date(2021, 12, 24)))
    assert out == {"kev_listed": True, "kev_due_date": date(2021, 12, 24)}


def test_kev_unknown_touches_no_kev_column():
    """Some CVE on the finding was never checked against the catalog."""
    out = S.plan_finding_update(_row(kev_listed=True, kev_due_date=date(2021, 12, 24), r_kev_known=False))
    assert "kev_listed" not in out and "kev_due_date" not in out


def test_leaving_the_list_clears_flag_and_date():
    out = S.plan_finding_update(_row(kev_listed=True, kev_due_date=date(2021, 12, 24), severity="HIGH"))
    assert out == {"kev_listed": False, "kev_due_date": None}


@pytest.mark.parametrize("sev", ["INFO", "LOW", "MODERATE", "MODERATE-HIGH"])
def test_severity_is_never_touched(sev):
    """The scan writers set severity again on every pass, so a raise here
    would be undone and flip back every two hours."""
    out = S.plan_finding_update(_row(severity=sev, current_status="open", r_kev_listed=True,
                                     r_epss_score=D("0.9"), r_epss_percentile=D("0.99"), r_cvss_score=D("9.8")))
    assert "severity" not in out and set(out) <= set(S.FINDING_COLUMNS)
    assert "severity" not in S.ROLLUP_SQL


def test_cvss_filled_only_when_the_finding_has_none():
    assert S.plan_finding_update(_row(r_cvss_score=D("6.1"), r_cvss_vector="V")) == \
        {"cvss_score": D("6.1"), "cvss_vector": "V"}
    assert S.plan_finding_update(_row(cvss_score=D("9.9"), r_cvss_score=D("6.1"), r_cvss_vector="V")) == {}
    assert S.plan_finding_update(_row(cvss_vector="OWN", r_cvss_score=D("6.1"), r_cvss_vector="V")) == \
        {"cvss_score": D("6.1")}


# ── the UPDATE ───────────────────────────────────────────────────────────────

def test_update_sql_sets_only_named_columns_and_stamps_time():
    sql = S.update_finding_sql(["epss_score", "kev_listed"])
    assert "epss_score = %(epss_score)s" in sql and "kev_listed = %(kev_listed)s" in sql
    assert "cvss_score" not in sql and "cve_enriched_at = now()" in sql
    assert sql.endswith("WHERE finding_id = %(finding_id)s")


@pytest.mark.parametrize("cols", [["severity"], ["title"], ["current_status"], ["epss_score", "severity"],
                                  ["finding_id; DROP TABLE findings"], []])
def test_update_sql_refuses_any_other_column(cols):
    with pytest.raises(ValueError):
        S.update_finding_sql(cols)


@pytest.mark.parametrize("server,ms", [("1s", 500), ("500ms", 250), ("200ms", 100), ("1min", 500),
                                       ("2", 1), ("junk", 250)])
def test_lock_timeout_is_always_below_the_deadlock_check(server, ms):
    assert S.lock_timeout_ms(server) == ms


# ── the whole run, on a fake connection ──────────────────────────────────────

class _Cur:
    def __init__(self, rows=(), rowcount=1):
        self._rows, self.rowcount = list(rows), rowcount

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def __iter__(self):
        return iter(self._rows)


class _Tx:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        self.conn.tx += 1
        return self

    def __exit__(self, *a):
        return False


class _Conn:
    def __init__(self, finding_cves, rollup=(), busy=(), bad_cve=None):
        self.sql, self.tx = [], 0
        self.finding_cves, self.rollup, self.busy, self.bad_cve = finding_cves, list(rollup), set(busy), bad_cve

    def transaction(self):
        return _Tx(self)

    def execute(self, sql, params=None):
        self.sql.append((sql, params))
        if sql is S.SELECT_FINDING_CVES_SQL:
            return _Cur([{"cve": c} for c in self.finding_cves])
        if sql is S.SELECT_CACHE_SQL:
            return _Cur([])
        if sql == "SHOW deadlock_timeout":
            return _Cur([{"deadlock_timeout": "1s"}])
        if sql is S.ROLLUP_SQL:
            return _Cur(self.rollup)
        if sql.startswith("UPDATE public.findings") and params["finding_id"] in self.busy:
            import psycopg
            raise psycopg.errors.LockNotAvailable("busy")
        if params and params.get("cve_id") == self.bad_cve and "epss_score" in sql:
            import psycopg
            raise psycopg.errors.CharacterNotInRepertoire("bad value")
        return _Cur()

    def wrote(self, prefix):
        return [p for s, p in self.sql if s.strip().startswith(prefix)]


def _source(kev_ok=True):
    def get(url, timeout=30):
        if "known_exploited" in url:
            return _kev(extra=[{"cveID": "CVE-2021-44228", "dueDate": "2021-12-24"}]) if kev_ok else None
        if "epss" in url:
            return {"status-code": 200, "data": [{"cve": "CVE-2021-44228", "epss": "0.9", "percentile": "0.99"}]}
        return _nvd({"cvssMetricV31": [_m(10.0, "V")]})
    return get


def test_run_with_no_cve_findings_contacts_nobody():
    def get(url, timeout=30):
        raise AssertionError("no source should be contacted")
    assert S.run(_Conn([]), get=get, log=lambda m: None)["cves"] == 0


def test_run_writes_cache_then_findings_and_counts():
    conn = _Conn(["CVE-2021-44228"], rollup=[_row(finding_id="f1", r_kev_listed=True),
                                             _row(finding_id="f2")])
    s = S.run(conn, get=_source(), sleep=lambda x: None, log=lambda m: None)
    assert s["kev_loaded"] and s["epss"] == 1 and s["nvd_read"] == 1
    assert conn.wrote("UPDATE public.cve_enrichments SET\n    kev_listed")[0]["kev_listed"] is True
    assert ("SET lock_timeout = '500ms'", None) in conn.sql
    upd = conn.wrote("UPDATE public.findings")
    assert [p["finding_id"] for p in upd] == ["f1"]                         # f2 had nothing to change
    assert s["findings_updated"] == 1 and "severity" not in upd[0]


def test_one_bad_cache_row_does_not_block_the_others():
    msgs = []
    conn = _Conn(["CVE-2021-44228", "CVE-2022-31160"], bad_cve="CVE-2021-44228")
    s = S.run(conn, get=_source(), sleep=lambda x: None, log=msgs.append)
    assert s["cache_rows_failed"] == 1 and conn.tx == 2                  # one transaction per CVE
    assert any("CVE-2021-44228: cache row not saved" in m for m in msgs)
    assert [p["cve_id"] for p in conn.wrote("UPDATE public.cve_enrichments SET\n    kev_listed")] == ["CVE-2022-31160"]


def test_kev_from_the_github_copy_adds_but_never_clears():
    def get(url, timeout=30):
        if "cisa.gov" in url:
            raise S.SourceError("HTTPError: 403")
        if "known_exploited" in url:
            return _kev(extra=[{"cveID": "CVE-2021-44228"}])
        return {"status-code": 200, "data": []}
    conn = _Conn(["CVE-2021-44228", "CVE-2022-31160"])
    s = S.run(conn, get=get, sleep=lambda x: None, log=lambda m: None)
    kev_writes = conn.wrote("UPDATE public.cve_enrichments SET\n    kev_listed")
    assert [(p["cve_id"], p["kev_listed"]) for p in kev_writes] == [("CVE-2021-44228", True)]
    assert "GitHub copy" in s["kev_source"]


def test_a_cve_not_in_nvd_is_stamped_so_it_waits_a_day():
    def get(url, timeout=30):
        if "known_exploited" in url:
            return _kev()
        if "epss" in url:
            return {"status-code": 200, "data": []}
        return {"vulnerabilities": [], "totalResults": 0}
    conn = _Conn(["CVE-2026-99999"])
    S.run(conn, get=get, sleep=lambda x: None, log=lambda m: None)
    assert [p["cve_id"] for s_, p in conn.sql if s_ is S.UPDATE_NVD_MISSING_SQL] == ["CVE-2026-99999"]
    assert not [1 for s_, _ in conn.sql if s_ is S.UPDATE_NVD_SQL]


def test_run_with_kev_down_writes_no_kev_and_warns():
    msgs = []
    conn = _Conn(["CVE-2021-44228"])
    s = S.run(conn, get=_source(kev_ok=False), sleep=lambda x: None, log=msgs.append)
    assert not s["kev_loaded"]
    assert conn.wrote("UPDATE public.cve_enrichments SET\n    kev_listed") == []
    assert conn.wrote("UPDATE public.cve_enrichments SET\n    epss_score")      # EPSS still written
    assert any(m.startswith("::warning::cve-scoring: KEV") for m in msgs)


def test_run_skips_a_row_a_scan_is_holding():
    conn = _Conn(["CVE-2021-44228"], rollup=[_row(finding_id="f1", r_kev_listed=True),
                                             _row(finding_id="f2", r_kev_listed=True)], busy={"f1"})
    s = S.run(conn, get=_source(), sleep=lambda x: None, log=lambda m: None)
    assert s["busy_skipped"] == 1 and s["findings_updated"] == 1


def test_dry_run_writes_nothing():
    conn = _Conn(["CVE-2021-44228"], rollup=[_row(finding_id="f1", r_kev_listed=True)])
    S.run(conn, get=_source(), sleep=lambda x: None, log=lambda m: None, dry_run=True)
    assert not [s for s, _ in conn.sql if s.lstrip().startswith(("INSERT", "UPDATE", "SET"))]


def test_main_without_a_dsn_fails_loudly(monkeypatch):
    monkeypatch.delenv("SUPABASE_DSN", raising=False)
    assert S.main([]) == 2


# ── it only ever talks to the three public sources ───────────────────────────

def test_only_public_cve_sources_are_contacted():
    hosts = {u.split("/")[2] for u in (S.NVD_API, S.EPSS_API, *S.KEV_FEEDS)}
    assert hosts == {"services.nvd.nist.gov", "api.first.org", "www.cisa.gov", "raw.githubusercontent.com"}


# ── the schedule ─────────────────────────────────────────────────────────────

def test_workflow_runs_the_job_every_two_hours_with_read_only_repo_access():
    import yaml
    with open(WORKFLOW) as fh:
        wf = yaml.safe_load(fh)
    on = wf.get("on", wf.get(True))
    assert on["schedule"] == [{"cron": "41 */2 * * *"}] and "workflow_dispatch" in on
    assert wf["permissions"] == {"contents": "read"}
    assert wf["concurrency"] == {"group": "cve-scoring", "cancel-in-progress": False}
    steps = wf["jobs"]["score"]["steps"]
    run = [s for s in steps if s.get("name") == "Score CVE findings"][0]
    assert run["run"] == "python scripts/scanner/cve_scoring.py"
    assert run["env"]["SUPABASE_DSN"] == "${{ secrets.SUPABASE_DSN }}"
    text = open(WORKFLOW).read()
    assert text.count("secrets.") == 1          # the database, nothing else
