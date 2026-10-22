"""(KB 12 job 3o, 2026-10-22) The WordPress core version from WordPress's own files.

Howie, 2026-10-22 13:33: "We'll build it into the light, and it will get inherited by
the heavy." Managed WordPress hosts (wp.cloud) strip the meta generator and the feed
generator, so Sentry never read a core version on our three WordPress sites. Their
homepages still carry it in the ?ver= of WordPress's own files (read live 13:40 ET:
7.1.3 on all three). Libraries under wp-includes carry their own numbers — an
allow-list, agreement or nothing. The advisory watch then range-matches the number.
"""
import sys
import types

import pytest

import advisory_watch as aw
import run_light
from run_light import wp_core_version_from_assets

# ── the three homepages' relevant lines, as read 2026-10-22 (claim 3) ───────────────
CC_HOME = """
<link rel='stylesheet' id='mediaelement-css' href='https://commandcompanies.com/wp-includes/js/mediaelement/mediaelementplayer-legacy.min.css?ver=4.2.17' media='all' />
<link rel='stylesheet' id='wp-mediaelement-css' href='https://commandcompanies.com/wp-includes/js/mediaelement/wp-mediaelement.min.css?ver=7.1.3' media='all' />
<script src="https://commandcompanies.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1" id="jquery-core-js"></script>
<script src="https://commandcompanies.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1" id="jquery-migrate-js"></script>
<script src="https://commandcompanies.com/wp-includes/js/comment-reply.min.js?ver=7.1.3" id="comment-reply-js" async></script>
<script src="https://commandcompanies.com/wp-includes/js/dist/hooks.min.js?ver=f0f188028580e8dc1255" id="wp-hooks-js"></script>
<script src="https://commandcompanies.com/wp-includes/js/dist/vendor/wp-polyfill.min.js?ver=3.15.0" id="wp-polyfill-js"></script>
<script>window._wpemojiSettings = {"source":{"concatemoji":"https:\\/\\/commandcompanies.com\\/wp-includes\\/js\\/wp-emoji-release.min.js?ver=7.1.3"}};</script>
<meta name="generator" content="Powered by WPBakery Page Builder - drag and drop page builder for WordPress."/>
<link rel='stylesheet' href='https://commandcompanies.com/wp-content/plugins/js_composer/assets/css/js_composer.min.css?ver=9.0.1' />
"""
CMI_HOME = """
<script src="https://commandmarketinginnovations.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
<script src="https://commandmarketinginnovations.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"></script>
<script src="https://commandmarketinginnovations.com/wp-includes/js/comment-reply.min.js?ver=7.1.3" async></script>
<link rel='stylesheet' href='https://commandmarketinginnovations.com/wp-content/plugins/wpforms/x.css?ver=28.0.4' />
"""
LIBS_ONLY = """
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
<link href="/wp-includes/js/mediaelement/mediaelementplayer-legacy.min.css?ver=4.2.17" />
<script src="/wp-includes/js/dist/i18n.min.js?ver=1dfe7db3940c23ea9216"></script>
<script src="/wp-includes/js/dist/vendor/wp-polyfill.min.js?ver=3.15.0"></script>
<script src="/wp-includes/js/wp-embed-template.min.js?ver=9.9.9"></script>
"""


# ── the pure reader ─────────────────────────────────────────────────────────────────
def test_commandcompanies_reads_7_1_3_from_three_core_files_and_ignores_libraries():
    v, ev = wp_core_version_from_assets(CC_HOME)
    assert v == "7.1.3"
    assert ev == ["js/comment-reply.min.js=7.1.3",
                  "js/mediaelement/wp-mediaelement.min.css=7.1.3",
                  "js/wp-emoji-release.min.js=7.1.3"]


def test_one_core_file_is_enough_cmi():
    assert wp_core_version_from_assets(CMI_HOME) == ("7.1.3", ["js/comment-reply.min.js=7.1.3"])


def test_the_emoji_url_in_escaped_json_is_read():
    html = '{"concatemoji":"https:\\/\\/x.com\\/wp-includes\\/js\\/wp-emoji-release.min.js?ver=6.9.4"}'
    assert wp_core_version_from_assets(html) == ("6.9.4", ["js/wp-emoji-release.min.js=6.9.4"])


def test_libraries_hashes_and_lookalike_files_are_never_wordpress():
    """jQuery 3.7.1 read as WordPress 3.7.1 would sit in the range of everything."""
    assert wp_core_version_from_assets(LIBS_ONLY) == (None, [])


@pytest.mark.parametrize("ver", ["1729999999", "f0f188028580e8dc1255", "7.1.3-beta1", "2.9.2", "7"])
def test_values_that_are_not_a_core_version_are_skipped(ver):
    assert wp_core_version_from_assets(f"/wp-includes/js/comment-reply.min.js?ver={ver}") == (None, [])


def test_disagreement_is_nothing_never_a_guess():
    html = ("/wp-includes/js/comment-reply.min.js?ver=7.1.3 "
            "/wp-includes/css/dashicons.min.css?ver=7.1.1")
    v, ev = wp_core_version_from_assets(html)
    assert v is None
    assert ev == ["css/dashicons.min.css=7.1.1", "js/comment-reply.min.js=7.1.3"]


@pytest.mark.parametrize("path", ["js/comment-reply.js", "js/wp-embed.min.js", "js/admin-bar.min.js",
                                  "css/admin-bar.min.css", "css/dashicons.css",
                                  "js/mediaelement/wp-mediaelement.min.js", "js/wp-emoji-release.min.js"])
def test_every_allow_listed_core_file_is_read(path):
    assert wp_core_version_from_assets(f"/wp-includes/{path}?ver=6.8.11")[0] == "6.8.11"


def test_empty_or_missing_html():
    assert wp_core_version_from_assets("") == (None, [])
    assert wp_core_version_from_assets(None) == (None, [])


# ── _detect_wp_core_version: the order of sources, and no second homepage fetch ────
class Cmds:
    def __init__(self, answers=None):
        self.calls, self.answers = [], list(answers or [])

    def __call__(self, cmd, timeout=30, input_str=None):
        self.calls.append(cmd)
        return self.answers.pop(0) if self.answers else (0, "", "")


def _ctx():
    return run_light.ScanContext(descriptor={}, hostname="commandcompanies.com",
                                 asset_id="commandcompanies.com", scan_run_id="r", queue_id="q",
                                 intensity="light")


def test_core_files_answer_first_and_nothing_is_fetched(monkeypatch):
    cmds = Cmds()
    monkeypatch.setattr(run_light, "run_cmd", cmds)
    v, src, ev = run_light._detect_wp_core_version(_ctx(), CC_HOME)
    assert (v, src) == ("7.1.3", "core_asset_ver") and len(ev) == 3
    assert cmds.calls == []


def test_meta_generator_still_answers_from_the_passed_html(monkeypatch):
    cmds = Cmds()
    monkeypatch.setattr(run_light, "run_cmd", cmds)
    html = '<meta name="generator" content="WordPress 6.5.4" />'
    assert run_light._detect_wp_core_version(_ctx(), html) == ("6.5.4", "meta_generator", [])
    assert cmds.calls == []


def test_the_feed_is_fetched_only_when_the_homepage_has_nothing(monkeypatch):
    cmds = Cmds([(0, "<generator>https://wordpress.org/?v=6.4.2</generator>", "")])
    monkeypatch.setattr(run_light, "run_cmd", cmds)
    assert run_light._detect_wp_core_version(_ctx(), LIBS_ONLY) == ("6.4.2", "feed_generator", [])
    assert len(cmds.calls) == 1 and cmds.calls[0][-1] == "https://commandcompanies.com/feed/"


def test_nothing_anywhere_is_none(monkeypatch):
    monkeypatch.setattr(run_light, "run_cmd", Cmds())
    assert run_light._detect_wp_core_version(_ctx(), LIBS_ONLY) == (None, None, [])


# ── check_wpvulnerability end to end: one homepage fetch, the artifact says where ───
def test_check_wpvulnerability_reads_the_core_version_with_one_request(monkeypatch):
    cmds = Cmds([(0, CC_HOME.replace("</script>", "</script> wp-content "), "")])
    monkeypatch.setattr(run_light, "run_cmd", cmds)
    looked = []
    fake = types.SimpleNamespace(lookup_core=lambda v: looked.append(v) or [],
                                 lookup_plugin=lambda s, v: [])
    monkeypatch.setitem(sys.modules, "wpvulnerability_client", fake)
    ctx = _ctx()
    run_light.check_wpvulnerability(ctx)
    assert len(cmds.calls) == 1 and cmds.calls[0][-1] == "https://commandcompanies.com/"
    assert looked == ["7.1.3"]
    (art,) = [a for a in ctx.artifacts if a[0] == "wpvulnerability_detection"]
    import json
    body = json.loads(art[2])
    assert body["core_version"] == "7.1.3" and body["core_version_source"] == "core_asset_ver"
    assert body["core_version_evidence"] == ["js/comment-reply.min.js=7.1.3",
                                             "js/mediaelement/wp-mediaelement.min.css=7.1.3",
                                             "js/wp-emoji-release.min.js=7.1.3"]
    assert body["plugins"] == {"js_composer": "9.0.1"}
    assert ctx.tool_status["wpvulnerability"] == {"ok": True}


# ── the advisory watch uses it (D3) ─────────────────────────────────────────────────
def _tech(asset, *tech):
    return {"asset_id": asset, "tech": {"tech": list(tech)}}


def test_a_read_version_fills_wordpress_where_httpx_named_it_without_a_number():
    inv = aw.build_inventory([_tech("cc.example.com", "WordPress", "PHP")], [],
                             [{"asset_id": "cc.example.com", "core_version": "7.1.3"}])
    assert inv["cc.example.com"].products == {"wordpress": "7.1.3", "php": None}


def test_never_adds_wordpress_to_a_host_httpx_did_not_name_it_on():
    """The www. redirect twins: httpx sees a 301 and ["HSTS","Nginx"]."""
    inv = aw.build_inventory([_tech("www.cc.example.com", "HSTS", "Nginx")], [],
                             [{"asset_id": "www.cc.example.com", "core_version": "7.1.3"},
                              {"asset_id": "unscanned.example.com", "core_version": "7.1.3"}])
    assert inv["www.cc.example.com"].products == {"nginx": None}
    assert "unscanned.example.com" not in inv


def test_never_overrides_a_version_httpx_showed():
    inv = aw.build_inventory([_tech("cc.example.com", "WordPress:6.9.4")], [],
                             [{"asset_id": "cc.example.com", "core_version": "7.1.3"}])
    assert inv["cc.example.com"].products == {"wordpress": "6.9.4"}


@pytest.mark.parametrize("cv", [None, "", "abc", "7.1.3-beta1"])
def test_no_usable_read_changes_nothing(cv):
    inv = aw.build_inventory([_tech("cc.example.com", "WordPress")], [],
                             [{"asset_id": "cc.example.com", "core_version": cv}])
    assert inv["cc.example.com"].products == {"wordpress": None}


def test_the_wp_query_reads_owned_hosts_latest_artifact_in_the_window():
    s = " ".join(aw.WP_CORE_SQL.split())
    assert "sra.tool_name = 'wpvulnerability_detection'" in s
    assert "content_jsonb ->> 'core_version'" in s
    assert "a.ownership = 'owned'" in s
    assert "make_interval(days => %(days)s)" in s
    assert s.startswith("SELECT DISTINCT ON (sr.asset_id)") and s.endswith("ORDER BY sr.asset_id, sra.created_at DESC")


def wp_cve(cve_id="CVE-2026-87902", kev=True):
    """Shaped like the checker's read of NVD (handoff 002): a:wordpress:wordpress, one
    range per maintained branch, the highest ending excluding 7.1.2."""
    rec = {
        "id": cve_id, "published": "2026-10-20T14:00:00.000",
        "descriptions": [{"lang": "en", "value": "WordPress core flaw."}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8}}]},
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "4.7.0", "versionEndExcluding": "7.0.6"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "7.1.0", "versionEndExcluding": "7.1.2"},
        ]}]}],
    }
    if kev:
        rec["cisaExploitAdd"] = "2026-10-20"
    return rec


def _existing_wp(asset="cc.example.com"):
    return {aw.finding_id(asset, "wordpress"): dict(asset_id=asset, key="wordpress", status="open",
                                                    cve=["CVE-2026-87902"])}


@pytest.mark.parametrize("version,closes", [("7.1.3", True), ("7.1.2", True), ("7.1.1", False),
                                            ("7.0.6", True), ("7.0.5", False)])
def test_the_read_version_decides_the_open_wordpress_row(version, closes):
    inv = aw.build_inventory([_tech("cc.example.com", "WordPress")], [],
                             [{"asset_id": "cc.example.com", "core_version": version}])
    a = aw._advisory(wp_cve(), {"CVE-2026-87902"})
    acts = aw.plan(inv, {"wordpress": {"CVE-2026-87902": a}}, set(), _existing_wp(), {},
                   kev_ids={"CVE-2026-87902"})
    (act,) = acts
    if closes:
        assert act.kind == "close" and f"WordPress {version} is outside every listed advisory" in act.reason
    else:
        assert act.kind == "upsert"
        assert act.fields["title"].startswith(f"WordPress {version} is in the affected range of 1 advisory")
        assert act.fields["affected_component_version"] == version


def test_run_reads_the_artifact_and_closes_the_row(monkeypatch):
    from test_advisory_watch import Conn, FakeGet, NOW
    get = FakeGet([("wordpress%3Awordpress&noRejected&pubStartDate", {"totalResults": 0, "vulnerabilities": []}),
                   ("wordpress%3Awordpress&noRejected&kevStartDate", {"totalResults": 1, "vulnerabilities": [{"cve": wp_cve()}]}),
                   ("known_exploited", {"vulnerabilities": [{"cveID": "CVE-2026-87902"}]})])
    src = aw.Sources(get=get, sleep=lambda s: None, now=NOW)
    existing = [{"finding_id": aw.finding_id("cc.example.com", "wordpress"), "asset_id": "cc.example.com",
                 "status": "open", "cve": ["CVE-2026-87902"], "tags": ["advisory-watch", "wordpress"]}]
    conn = Conn([_tech("cc.example.com", "WordPress")], existing,
                wp=[{"asset_id": "cc.example.com", "core_version": "7.1.3"}])
    n = aw.run(conn, src, log=lambda *a: None, Json=lambda x: x)
    assert n["close"] == 1 and n["upsert"] == 0
    # two latest-per-host reads: the httpx tech list and the WordPress core read
    assert sum(c.startswith("SELECT DISTINCT ON (sr.asset_id)") for c, _ in conn.s["calls"]) == 2
