#!/usr/bin/env python3
"""
Unit tests for derive_asset_kind.derive() and its pure helpers.

Pure-function coverage — no DB. Same testing bar as scripts/scanner/
test_run_heavy.py (4.7 code-review hole 3: prod data-write path must be tested
before backfill). Run:

    python -m pytest scripts/normalize/test_derive_asset_kind.py -q
"""
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
from derive_asset_kind import (                     # noqa: E402
    derive, compute_drift, schema_supported, is_staging_name,
    meaningful_title, web_server_fingerprint, platform_hints, pick_sub, _parse_ts,
)

UTC = timezone.utc


def mk_sub(name="h.example.com", live=True, status=200, title=None, tech=None,
           waf_vendor="None", waf_detected=True, services="http", is_root=False):
    if services == "http":
        services = [{"port": 80, "service": "http"},
                    {"port": 443, "service": "https", "tls": True}]
    return {
        "name": name, "is_root": is_root,
        "reachability": {"live": live, "http_status": status, "title": title},
        "fingerprint": {"tech": [{"name": t} for t in (tech or [])], "server": None},
        "waf": {"vendor": waf_vendor, "detected": waf_detected},
        "services": services,
    }


# ---- dead ------------------------------------------------------------------
def test_dead_via_live_false():
    k, c, u, ev = derive(mk_sub(live=False, status=None), None, False, None)
    assert k == "dead" and ev["rule"] == "dead"

def test_dead_via_504():
    k, c, u, ev = derive(mk_sub(status=504, title="Service unavailable"), None, False, None)
    assert k == "dead" and c == "low" and ev["consecutive_dead"] == 1

def test_dead_via_cloudflare_521():
    assert derive(mk_sub(status=521), None, False, None)[0] == "dead"

def test_dead_counter_idempotent_same_observation():
    sub = mk_sub(status=504)
    t1 = datetime(2026, 7, 5, 8, 0, tzinfo=UTC)
    _, c1, _, ev1 = derive(sub, None, False, t1)
    assert ev1["consecutive_dead"] == 1 and c1 == "low"
    # re-run --apply on the SAME observation must NOT advance the streak
    _, c2, _, ev2 = derive(sub, ev1, False, t1)
    assert ev2["consecutive_dead"] == 1 and c2 == "low"

def test_dead_counter_advances_on_new_observation():
    sub = mk_sub(status=504)
    t1 = datetime(2026, 7, 5, 8, 0, tzinfo=UTC)
    t2 = datetime(2026, 7, 5, 9, 0, tzinfo=UTC)
    t3 = datetime(2026, 7, 5, 10, 0, tzinfo=UTC)
    _, _, _, ev1 = derive(sub, None, False, t1)
    _, c2, _, ev2 = derive(sub, ev1, False, t2)
    assert ev2["consecutive_dead"] == 2 and c2 == "low"
    _, c3, _, ev3 = derive(sub, ev2, False, t3)
    assert ev3["consecutive_dead"] == 3 and c3 == "high"   # temporal gate reached


# ---- portal / api / web ----------------------------------------------------
def test_portal_401():
    assert derive(mk_sub(status=401), None, False, None)[0] == "portal"

def test_portal_login_title():
    assert derive(mk_sub(status=200, title="Sign in - Google Accounts"), None, False, None)[0] == "portal"

def test_portal_auth_gated_flag():
    assert derive(mk_sub(status=200, title="anything"), None, True, None)[0] == "portal"

def test_api_403_non_waf():
    # waf_vendor 'None' -> waf_det False -> 403 classifies api, not waf-web
    assert derive(mk_sub(status=403, waf_vendor="None"), None, False, None)[0] == "api"

def test_api_404_no_tech():
    assert derive(mk_sub(status=404, title=None, tech=[]), None, False, None)[0] == "api"

def test_waf_403_fallthrough_to_web():
    k, c, u, ev = derive(mk_sub(status=403, waf_vendor="Cloudflare", waf_detected=True), None, False, None)
    assert k == "web" and ev["rule"] == "waf-403-web"

def test_web_happy_path():
    k, c, u, ev = derive(mk_sub(status=200, title="PRODEX", tech=["Nginx"]), None, False, None)
    assert k == "web" and c == "high"

def test_web_server_fingerprint_votes_web_without_title():
    assert derive(mk_sub(status=200, title=None, tech=["Nginx"]), None, False, None)[0] == "web"

def test_loading_placeholder_rejected():
    # 200 + "Loading..." + platform-only tech -> NOT web-high (placeholder title,
    # no server fingerprint) -> falls to web-default(low)
    k, c, u, ev = derive(mk_sub(status=200, title="Loading...", tech=["Vercel"]), None, False, None)
    assert ev["rule"] == "web-default" and c == "low"

def test_hole2_vercel_api_stays_api():
    # 404 + no title + Vercel platform hint: Vercel must NOT cast a web vote
    k, c, u, ev = derive(mk_sub(status=404, title=None, tech=["Vercel", "HSTS"]), None, False, None)
    assert k == "api" and "vercel" in ev["platform_hints"]


# ---- non-HTTP --------------------------------------------------------------
def _svc_only(port, service):
    return {"name": "h", "reachability": {"live": None, "http_status": None, "title": None},
            "fingerprint": {}, "waf": {}, "services": [{"port": port, "service": service}]}

def test_mail_25_only():
    assert derive(_svc_only(25, "smtp"), None, False, None)[0] == "mail"

def test_ftp_21_only():
    assert derive(_svc_only(21, "ftp"), None, False, None)[0] == "ftp"

def test_unknown_no_reachability():
    sub = {"name": "x", "reachability": {}, "fingerprint": {}, "waf": {}, "services": []}
    k, c, u, ev = derive(sub, None, False, None)
    assert k == "unknown" and ev["rule"] == "no-reachability"


# ---- pure helpers ----------------------------------------------------------
def test_is_staging_name():
    assert is_staging_name("staging.x.com")
    assert is_staging_name("uat.x.com")
    assert is_staging_name("preview.x.com")
    assert not is_staging_name("prod.x.com")

def test_compute_drift():
    assert compute_drift(True, "web", "api", "high") is True
    assert compute_drift(True, "web", "web", "high") is False      # same kind
    assert compute_drift(True, "web", "api", "medium") is False    # not high conf
    assert compute_drift(False, "web", "api", "high") is False     # not manual

def test_schema_supported():
    assert schema_supported("3.0") is True
    assert schema_supported(None) is False
    assert schema_supported("2.0") is False

def test_web_server_fingerprint_split():
    assert web_server_fingerprint(["Nginx"])
    assert not web_server_fingerprint(["Vercel", "Google Cloud", "Google Cloud CDN"])

def test_platform_hints():
    assert "vercel" in platform_hints(["Vercel"])
    assert platform_hints(["Nginx"]) == []

def test_meaningful_title():
    assert meaningful_title("PRODEX")
    assert not meaningful_title("Loading...")
    assert not meaningful_title(None)
    assert not meaningful_title("   ")

def test_pick_sub_name_then_root_then_none():
    sd = {"subdomains": [{"name": "a.x.com"}, {"name": "b.x.com", "is_root": True}]}
    assert pick_sub(sd, "a.x.com")["name"] == "a.x.com"
    assert pick_sub(sd, "zzz.x.com")["is_root"] is True     # falls to is_root
    assert pick_sub({"subdomains": [{"name": "a"}]}, "zzz") is None   # no guess (hole 5)

def test_parse_ts():
    assert _parse_ts(None) is None
    assert _parse_ts("2026-07-05T08:00:00+00:00").year == 2026
    assert _parse_ts(datetime(2026, 7, 5, tzinfo=UTC)).month == 7


if __name__ == "__main__":
    raise SystemExit(os.system(f"python -m pytest {__file__} -q"))
