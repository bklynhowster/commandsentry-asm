"""(KB 12 job 4, 2026-10-25) One site, not two: the evidence rule for a www name and its plain name.

Howie, 2026-10-24 21:44: "it's the same damn box it's the same site." Ruled 2026-10-25 08:46 (D1):
merge only on evidence seen on both names. Plan review M3/M4 (2026-10-25 08:38; the checker window
was running Claude Sonnet 5.5 although the note was signed GLM-5.3):
  * a failed check, a bot challenge or any reading that isn't the site itself -> 'unknown', which
    never changes a stored verdict;
  * two runs in a row must agree before a first verdict is set or a verdict flips (code review);
  * leg 2 needs the same page, and a wildcard zone's addresses prove nothing by themselves;
  * a case where the rule MUST say 'separate' (same address, same wildcard certificate,
    different page).

The eight real pairs are fixtures from readings taken 2026-10-25 08:50-09:10 ET (DNS from
getaddrinfo, the leaf from a TLS handshake, the HTTP answer from curl without -L).
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import site_members as sm  # noqa: E402

NOW = datetime(2026, 10, 25, 13, 0, tzinfo=timezone.utc)
NOT_WILDCARD = {"wildcard": False, "addrs": []}
UNIMAC_WILDCARD = {"wildcard": True, "addrs": ["199.16.172.68", "199.16.173.113"]}


def reading(name, addrs, leaf="aa", status=200, location=None, title="T", page="p1", words=None,
            dns="ok", tls="ok", http="ok"):
    return {"name": name, "dns": dns, "addrs": list(addrs), "tls": tls, "leaf": leaf, "http": http,
            "status": status, "location": location, "title": title, "page": page,
            "words": words if words is not None else ["a", "b", "c"]}


# ── the eight real pairs ─────────────────────────────────────────────────────────────────────
CCC = ["24.38.70.5"]
CCC_PAGE = dict(leaf="bcbc3bfe", title="CommandCommCentral", page="5899c599b934bba4")
REAL = {
    "commandcommcentral.com": (
        reading("commandcommcentral.com", CCC, **CCC_PAGE),
        reading("www.commandcommcentral.com", CCC, **CCC_PAGE), NOT_WILDCARD,
        ("same_site", "same_page")),
    "commandcompanies.com": (
        reading("commandcompanies.com", ["199.16.172.42", "199.16.173.153"], leaf="65d0eb47",
                title="Home - Command Companies", page="x1"),
        reading("www.commandcompanies.com", ["199.16.173.153", "199.16.172.42"], leaf="8a481185",
                status=301, location="https://commandcompanies.com/", title="301 Moved Permanently"),
        NOT_WILDCARD, ("same_site", "redirect")),
    "commandmarketinginnovations.com": (
        reading("commandmarketinginnovations.com", ["199.16.172.41", "199.16.173.231"], leaf="2dae4311"),
        reading("www.commandmarketinginnovations.com", ["199.16.172.41", "199.16.173.231"], leaf="2dae4311",
                status=301, location="https://commandmarketinginnovations.com/"),
        NOT_WILDCARD, ("same_site", "redirect")),
    "unimacgraphics.com": (
        reading("unimacgraphics.com", UNIMAC_WILDCARD["addrs"], leaf="d9fb5086",
                title="Home - Unimac, a Command Company"),
        reading("www.unimacgraphics.com", UNIMAC_WILDCARD["addrs"], leaf="4a2cd7b9", status=301,
                location="https://unimacgraphics.com/"),
        UNIMAC_WILDCARD, ("same_site", "redirect")),
    "prodexlabs.com": (
        reading("prodexlabs.com", ["8.232.147.166"], leaf="d43cd150", status=301,
                location="https://www.prodexlabs.com:443/", title=None),
        reading("www.prodexlabs.com", ["8.232.147.166"], leaf="d43cd150",
                title="Your AI Industrial Engineer — ProDex Labs"),
        NOT_WILDCARD, ("same_site", "redirect")),
    "portal.unimacgraphics.com": (
        reading("portal.unimacgraphics.com", ["40.71.11.138"], leaf="c17dd7b7",
                title="Home Page - Unimac Ordering Portal"),
        reading("www.portal.unimacgraphics.com", UNIMAC_WILDCARD["addrs"], leaf="bd5a6246", status=404,
                title=None),
        UNIMAC_WILDCARD, ("separate", "")),
    "firewall.unimacgraphics.com": (
        reading("firewall.unimacgraphics.com", ["208.199.0.130"], leaf=None, tls="error", http="error",
                status=None, title=None, page=None),
        reading("www.firewall.unimacgraphics.com", UNIMAC_WILDCARD["addrs"], leaf="bd5a6246", status=404,
                title=None),
        UNIMAC_WILDCARD, ("separate", "")),
    "zoetislabs.unimacgraphics.com": (
        reading("zoetislabs.unimacgraphics.com", ["40.71.11.138"], leaf="a2cd9173",
                title="Home Page - Zoetis Labs"),
        reading("www.zoetislabs.unimacgraphics.com", UNIMAC_WILDCARD["addrs"], leaf="bd5a6246", status=404,
                title=None),
        UNIMAC_WILDCARD, ("separate", "")),
}


def test_the_eight_real_pairs_five_one_site_three_not():
    got = {k: sm.decide(p, w, z)[:2] for k, (p, w, z, _want) in REAL.items()}
    assert got == {k: v[3] for k, v in REAL.items()}
    assert sum(1 for r, _ in got.values() if r == "same_site") == 5


def test_the_three_unimac_www_names_are_kept_apart_by_their_addresses():
    for k in ("portal.unimacgraphics.com", "firewall.unimacgraphics.com", "zoetislabs.unimacgraphics.com"):
        p, w, z, _ = REAL[k]
        assert sm.decide(p, w, z) == ("separate", "", "the two names resolve to different addresses")


# ── what must NOT merge, and what must not split ─────────────────────────────────────────────
def test_must_fail_same_address_same_wildcard_certificate_different_page():
    """M4's fixture: two virtual hosts on one shared box with one *.example certificate."""
    p = reading("app.example.com", ["10.0.0.5"], leaf="wild", title="Ordering portal", page="h1")
    w = reading("www.app.example.com", ["10.0.0.5"], leaf="wild", title="Lab results", page="h2")
    assert sm.decide(p, w, NOT_WILDCARD)[0] == "separate"


def test_same_title_but_a_different_page_is_separate_and_near_identical_is_one_site():
    words_a = [f"w{i}" for i in range(200)]
    p = reading("x.com", ["1.1.1.1"], page="h1", words=words_a)
    assert sm.decide(p, reading("www.x.com", ["1.1.1.1"], page="h2", words=[f"z{i}" for i in range(200)]),
                     NOT_WILDCARD)[0] == "separate"
    near = words_a[:-2] + ["changed", "date"]                    # 99% alike: a footer date moved
    r, leg, why = sm.decide(p, reading("www.x.com", ["1.1.1.1"], page="h3", words=near), NOT_WILDCARD)
    assert (r, leg) == ("same_site", "same_page") and "alike" in why


def test_a_bot_challenge_is_unknown_not_separate():
    """2026-10-25: Pressable answered one client with 403 'Checking your browser...' on all three
    WordPress sites. Read as 'separate', that would have split three real sites."""
    p = reading("commandcompanies.com", ["199.16.172.42"], status=403, title="Checking your browser...")
    w = reading("www.commandcompanies.com", ["199.16.172.42"], status=403, title="Checking your browser...")
    r, _leg, why = sm.decide(p, w, NOT_WILDCARD)
    assert r == "unknown" and "403" in why


def test_failed_lookups_connections_and_temporary_redirects_are_unknown():
    a = ["1.1.1.1"]
    assert sm.decide(reading("x.com", [], dns="error"), reading("www.x.com", a), NOT_WILDCARD)[0] == "unknown"
    assert sm.decide(reading("x.com", a, tls="error"), reading("www.x.com", a), NOT_WILDCARD)[0] == "unknown"
    assert sm.decide(reading("x.com", a, http="error", status=None), reading("www.x.com", a),
                     NOT_WILDCARD)[0] == "unknown"
    assert sm.decide(reading("x.com", a), reading("www.x.com", a, status=302, location="https://x.com/"),
                     NOT_WILDCARD)[0] == "unknown"
    assert sm.decide(reading("x.com", a, status=503), reading("www.x.com", a), NOT_WILDCARD)[0] == "unknown"


def test_both_redirecting_elsewhere_is_unknown_one_page_one_redirect_elsewhere_is_separate():
    a = ["1.1.1.1"]
    away = dict(status=301, location="https://elsewhere.com/")
    assert sm.decide(reading("x.com", a, **away), reading("www.x.com", a, **away), NOT_WILDCARD)[0] == "unknown"
    r, _, why = sm.decide(reading("x.com", a), reading("www.x.com", a, **away), NOT_WILDCARD)
    assert r == "separate" and "elsewhere.com" in why


def test_a_redirect_to_a_sign_in_page_never_merges():
    a = ["1.1.1.1"]
    w = reading("www.x.com", a, status=301, location="https://login.microsoftonline.com/x")
    assert sm.decide(reading("x.com", a), w, NOT_WILDCARD)[0] != "same_site"


def test_a_name_that_does_not_exist_is_separate():
    assert sm.decide(reading("x.com", ["1.1.1.1"]), reading("www.x.com", [], dns="nxdomain"),
                     NOT_WILDCARD)[0] == "separate"


def test_a_failed_request_is_unknown_even_in_a_zone_that_answers_every_name():
    """Code review M1 (Claude Sonnet 5.5 and Qwen3.8 Max, blind, both): the old wildcard branch
    could only fire when the request FAILED, and it said 'separate'. On unimacgraphics.com one
    curl timeout would have split a real site on its first run."""
    z = UNIMAC_WILDCARD
    p = reading("unimacgraphics.com", z["addrs"])
    for failed in (dict(http="error", status=None), dict(tls="error", leaf=None)):
        w = reading("www.unimacgraphics.com", z["addrs"], **failed)
        assert sm.decide(p, w, z)[0] == "unknown"
        assert sm.decide(p, w, NOT_WILDCARD)[0] == "unknown"
        assert sm.decide(p, w, None)[0] == "unknown"


def test_two_identical_pages_with_no_title_are_one_site_and_the_reason_is_true():
    """Code review M2 (Qwen3.8 Max; Claude Sonnet 5.5 as a minor): two absent titles were 'different
    titles' and the identical-page check was never reached."""
    a = ["1.1.1.1"]
    r, leg, why = sm.decide(reading("x.com", a, title=None, page="same"),
                            reading("www.x.com", a, title=None, page="same"), NOT_WILDCARD)
    assert (r, leg) == ("same_site", "same_page")
    r, _, why = sm.decide(reading("x.com", a, title=None, page="h1", words=["a"] * 50),
                          reading("www.x.com", a, title=None, page="h2", words=["b"] * 50), NOT_WILDCARD)
    assert r == "separate" and "title" not in why
    r, _, why = sm.decide(reading("x.com", a, title="T"), reading("www.x.com", a, title=None), NOT_WILDCARD)
    assert r == "separate" and "one has a title" in why


def test_a_name_with_only_ipv6_addresses_is_unknown_not_missing():
    a = ["1.1.1.1"]
    r, _, why = sm.decide(reading("x.com", a), reading("www.x.com", [], dns="v6only"), NOT_WILDCARD)
    assert r == "unknown" and "IPv6" in why


def test_resolve_tells_ipv6_only_from_missing(monkeypatch):
    import socket

    def fake(name, port, family=0, type=0):
        if family == socket.AF_INET:
            raise socket.gaierror(socket.EAI_NONAME, "no v4")
        if name == "v6.example.com":
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 443, 0, 0))]
        raise socket.gaierror(socket.EAI_NONAME, "nothing")
    monkeypatch.setattr(sm.socket, "getaddrinfo", fake)
    assert sm.resolve("v6.example.com") == ("v6only", [])
    assert sm.resolve("gone.example.com") == ("nxdomain", [])


def test_a_permanent_redirect_to_the_same_name_is_unknown():
    a = ["1.1.1.1"]
    for loc in ("/en/", "https://www.x.com/home", None):
        w = reading("www.x.com", a, status=301, location=loc)
        r, _, why = sm.decide(reading("x.com", a), w, NOT_WILDCARD)
        assert r == "unknown" and "itself" in why, loc


def test_a_wildcard_zone_still_merges_on_a_real_redirect():
    p, w, z, want = REAL["unimacgraphics.com"]
    assert z["wildcard"] is True and sm.decide(p, w, z)[:2] == want


# ── the stored state (M3) ────────────────────────────────────────────────────────────────────
def _run(prev, result, at=NOW):
    return sm.advance(prev, result, "redirect" if result == "same_site" else "", "why", {"r": 1}, at)


def _settled(result, at=NOW):
    """A pair whose first verdict is set: two agreeing runs, 6 h apart, ending at `at`."""
    return _run(_run(None, result, at - timedelta(hours=6)), result, at)


def test_a_first_verdict_needs_two_agreeing_runs_like_a_flip():
    """Code review (both reviewers): one bad first run used to store a verdict at once."""
    assert _run(None, "unknown")["verdict"] is None
    one = _run(None, "same_site")
    assert one["verdict"] is None and one["contrary_runs"] == 1 and one["last_result"] == "same_site"
    two = _run(one, "same_site", NOW + timedelta(hours=6))
    assert two["verdict"] == "same_site" and two["since"] and two["contrary_runs"] == 0 and not two["flipped"]
    first = two["evidence"]["first"]
    assert first["to"] == "same_site" and len(first["runs"]) == 2
    mixed = _run(_run(None, "separate"), "same_site", NOW + timedelta(hours=6))
    assert mixed["verdict"] is None and mixed["contrary_runs"] == 1
    gap = _run(_run(one, "unknown", NOW + timedelta(hours=6)), "same_site", NOW + timedelta(hours=12))
    assert gap["verdict"] == "same_site"


def test_unknown_never_changes_the_stored_state():
    row = _settled("same_site")
    after = _run(row, "unknown", NOW + timedelta(hours=6))
    assert (after["verdict"], after["contrary_runs"], after["since"]) == ("same_site", 0, row["since"])
    assert after["last_result"] == "unknown" and after["evidence"]["basis"] == row["evidence"]["basis"]


def test_one_contrary_run_does_not_flip_two_in_a_row_do_and_are_both_kept():
    row = _settled("same_site")
    one = _run(row, "separate", NOW + timedelta(hours=6))
    assert one["verdict"] == "same_site" and one["contrary_runs"] == 1 and not one["flipped"]
    two = _run(one, "separate", NOW + timedelta(hours=12))
    assert two["verdict"] == "separate" and two["flipped"] and two["contrary_runs"] == 0
    flip = two["evidence"]["flips"][-1]
    assert flip["from"] == "same_site" and flip["to"] == "separate" and len(flip["runs"]) == 2
    assert flip["runs"][0]["at"] == one["evidence"]["last"]["at"]


def test_an_unknown_between_two_contrary_runs_neither_resets_nor_counts():
    row = _settled("same_site")
    one = _run(row, "separate", NOW + timedelta(hours=6))
    gap = _run(one, "unknown", NOW + timedelta(hours=12))
    assert gap["contrary_runs"] == 1
    assert _run(gap, "separate", NOW + timedelta(hours=18))["verdict"] == "separate"


def test_a_contrary_run_then_an_agreeing_one_resets_the_count():
    row = _settled("same_site")
    one = _run(row, "separate", NOW + timedelta(hours=6))
    back = _run(one, "same_site", NOW + timedelta(hours=12))
    assert back["contrary_runs"] == 0 and back["verdict"] == "same_site" and back["evidence"]["pending"] is None


def test_flips_kept_are_capped():
    row = _settled("same_site")
    for i in range(30):
        row = _run(row, "separate" if row["verdict"] == "same_site" else "same_site",
                   NOW + timedelta(hours=6 * (i + 1)))
    assert len(row["evidence"]["flips"]) <= sm.FLIPS_KEPT


# ── the page and the probe's parsing ─────────────────────────────────────────────────────────
def test_strip_page_removes_what_changes_on_every_load():
    a = ('<html><head><title>Portal</title><style nonce="CSS_10005">.x{}</style></head><body>'
         '<input type="hidden" value="CfDJ8OGfBVpvAaNEoYx5oB4uQPFwm1tYHc3Jl9DvE"><script nonce="n1">var t=1;'
         '</script><p>Hello</p></body></html>')
    b = a.replace("CSS_10005", "CSS_10006").replace("CfDJ8OGfBVpvAaNEoYx5oB4uQPFwm1tYHc3Jl9DvE",
                                                    "CfDJ8ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ").replace("n1", "n2")
    assert sm.page_signature(a.encode()) ["page"] == sm.page_signature(b.encode())["page"]
    assert sm.page_signature(a.encode())["title"] == "Portal"
    assert sm.page_signature(a.replace("Hello", "Goodbye").encode())["page"] != sm.page_signature(a.encode())["page"]


def test_location_host_and_the_control_name():
    assert sm.location_host("https://www.prodexlabs.com:443/", "prodexlabs.com") == "www.prodexlabs.com"
    assert sm.location_host("/home", "www.x.com") == "www.x.com"
    assert sm.location_host(None, "x.com") is None
    c = sm.control_name("www.portal.unimacgraphics.com", "abc123")
    assert c == "sentry-site-check-abc123.portal.unimacgraphics.com"


def test_parse_head_reads_http2_and_location():
    head = "HTTP/2 301 \r\ndate: x\r\nlocation: https://commandcompanies.com/\r\n\r\n"
    assert sm.parse_head(head) == (301, "https://commandcompanies.com/")
    assert sm.parse_head("") == (None, None)


def test_the_probe_never_follows_a_redirect():
    import inspect
    src = inspect.getsource(sm.get_page)
    assert '"curl"' in src and '"-L"' not in src and "--location" not in src
    assert "--resolve" in src


def test_stored_readings_drop_the_word_list():
    assert "words" not in sm.stored_reading(reading("x.com", ["1.1.1.1"]))


# ── the run: reads pairs, writes rows, network only through the readers ───────────────────────
class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self._rows = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.conn.sql.append((sql, params))
        if sql is sm.Q_PAIRS:
            self._rows = self.conn.pairs
        elif sql is sm.Q_READ:
            self._rows = self.conn.stored
        else:
            self._rows = []

    def fetchall(self):
        return self._rows


class FakeConn:
    def __init__(self, pairs, stored=()):
        self.pairs, self.stored, self.sql = list(pairs), list(stored), []
        self.committed = self.rolled_back = False

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


def _readers():
    by = {}
    for p, w, z, _ in REAL.values():
        by[p["name"]], by[w["name"]] = p, w
    zones = {w["name"]: z for _p, w, z, _ in REAL.values()}
    return (lambda n: dict(by[n])), (lambda m: zones[m])


def test_run_writes_one_row_per_pair_and_dry_run_writes_nothing():
    pairs = [(w["name"], p["name"]) for p, w, _z, _ in REAL.values()]
    reader, zone_reader = _readers()
    conn = FakeConn(pairs)
    rows = sm.run(conn, dry_run=False, now=NOW, reader=reader, zone_reader=zone_reader)
    upserts = [p for s, p in conn.sql if s is sm.Q_UPSERT]
    assert len(upserts) == 8 and conn.committed
    # the first run records each reading and sets no verdict yet
    assert all(r["verdict"] is None for r in rows)
    assert sorted(r["site"] for r in rows if r["last_result"] == "same_site") == [
        "commandcommcentral.com", "commandcompanies.com", "commandmarketinginnovations.com",
        "prodexlabs.com", "unimacgraphics.com"]
    stored = [(r["member"], r["verdict"], r["contrary_runs"], r["evidence"], r["since"]) for r in rows]
    second = sm.run(FakeConn(pairs, stored), dry_run=False, now=NOW + timedelta(hours=6),
                    reader=reader, zone_reader=zone_reader)
    assert sorted(r["site"] for r in second if r["verdict"] == "same_site") == [
        "commandcommcentral.com", "commandcompanies.com", "commandmarketinginnovations.com",
        "prodexlabs.com", "unimacgraphics.com"]
    assert sum(1 for r in second if r["verdict"] == "separate") == 3
    dry = FakeConn(pairs)
    sm.run(dry, dry_run=True, now=NOW, reader=reader, zone_reader=zone_reader)
    assert not [s for s, _ in dry.sql if s is sm.Q_UPSERT] and dry.rolled_back and not dry.committed


def test_the_pairs_query_uses_the_portal_scope_and_names_only():
    q = " ".join(sm.Q_PAIRS.split())
    for must in ("coalesce(a.ownership, 'unknown') = 'owned'",
                 "<> ALL (ARRAY['ct_ghost', 'went_dark', 'retired'])",
                 "coalesce(a.discovery_status, 'unverified') <> 'unverified'",
                 "a.asset_id !~ '^[0-9.]+$'",
                 "JOIN scope p ON w.asset_id = 'www.' || p.asset_id"):
        assert must in q, must


_WRITE = r"(?<!DO )\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?|MERGE\s+INTO)\s+(?:public\.)?(\w+)"


def test_the_module_writes_only_site_members():
    """Code review (Qwen3.8 Max): the old pattern needed the 'public.' prefix, so an unprefixed
    write would have passed. This one catches both, and is itself checked below."""
    import re as _re
    src = Path(sm.__file__).read_text()
    assert set(_re.findall(_WRITE, src)) == {"site_members"}
    assert _re.findall(_WRITE, "UPDATE assets SET x=1; DELETE FROM public.findings") == ["assets", "findings"]
    assert _re.findall(_WRITE, "ON CONFLICT (k) DO UPDATE SET a = 1") == []
