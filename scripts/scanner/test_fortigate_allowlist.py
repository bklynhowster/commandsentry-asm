"""Spec 221 ruling ③ — the append-free classifier (fortigate_allowlist).

Pins the fail-CLOSED construction: only templates that fire the URL as-given
(no path append, no attack payload, GET/HEAD, recognised safe shape) are
append-free. Everything uncertain is excluded.

The load-bearing case is test_injection_payload_on_root_is_not_safe: run #4 showed
`/?q=<script>alert(1)>` was blocked though its path was {{BaseURL}} — an append-free
PATH is necessary but NOT sufficient; an attack PAYLOAD on the root still trips the
content signature. A path-only classifier would wrongly allow it.

Run: python -m pytest scripts/scanner/test_fortigate_allowlist.py -q
"""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from fortigate_allowlist import is_append_free, _is_base_only_path   # noqa: E402


def _t(**kw) -> dict:
    """Minimal nuclei template dict with info.tags settable."""
    doc = {"id": kw.pop("id", "test-tmpl"),
           "info": {"tags": kw.pop("tags", "")}}
    doc.update(kw)
    return doc


# ── append-free: the safe shapes ─────────────────────────────────────────────

def test_ssl_template_is_safe():
    ok, reason = is_append_free(_t(ssl=[{"address": "{{Host}}:{{Port}}"}], tags="ssl,tls"))
    assert ok and reason.startswith("safe_protocol")


def test_dns_template_is_safe():
    ok, _ = is_append_free(_t(dns=[{"name": "{{FQDN}}", "type": "A"}], tags="dns"))
    assert ok


@pytest.mark.parametrize("path", ["{{BaseURL}}", "{{RootURL}}", "{{BaseURL}}/",
                                  "{{BaseURL}}?x=1", "{{RootURL}}/?a=b"])
def test_http_root_get_is_safe(path):
    ok, reason = is_append_free(_t(http=[{"method": "GET", "path": [path]}],
                                   tags="tech,headers"))
    assert ok, reason


def test_legacy_requests_block_root_get_is_safe():
    ok, _ = is_append_free(_t(requests=[{"method": "GET", "path": ["{{BaseURL}}"]}]))
    assert ok


def test_default_method_treated_as_get():
    ok, _ = is_append_free(_t(http=[{"path": ["{{BaseURL}}"]}]))
    assert ok


# ── NOT append-free: the fail-closed exclusions ──────────────────────────────

def test_appended_path_is_not_safe():
    ok, reason = is_append_free(_t(http=[{"method": "GET", "path": ["{{BaseURL}}/.env"]}]))
    assert not ok and reason.startswith("appends_path")


def test_template_variable_path_is_not_safe():
    ok, reason = is_append_free(_t(http=[{"method": "GET", "path": ["{{BaseURL}}/{{path}}"]}]))
    assert not ok and reason.startswith("appends_path")


def test_injection_payload_on_root_is_not_safe():
    # THE run #4 lesson: XSS payload on {{BaseURL}} — append-free PATH but the
    # PAYLOAD trips the signature. A path-only classifier would wrongly allow it.
    ok, reason = is_append_free(_t(http=[{"method": "GET", "path": ["{{BaseURL}}?q=<script>"]}],
                                   tags="xss"))
    assert not ok and reason.startswith("injection_tag")


def test_raw_request_is_not_safe():
    ok, reason = is_append_free(_t(http=[{"raw": ["GET / HTTP/1.1\nHost: {{Host}}"]}]))
    assert not ok and reason == "raw_request"


def test_non_get_method_is_not_safe():
    ok, reason = is_append_free(_t(http=[{"method": "POST", "path": ["{{BaseURL}}"]}]))
    assert not ok and reason.startswith("unsafe_method")


def test_any_appended_path_across_entries_excludes_whole_template():
    ok, _ = is_append_free(_t(http=[
        {"method": "GET", "path": ["{{BaseURL}}"]},
        {"method": "GET", "path": ["{{BaseURL}}/admin"]},
    ]))
    assert not ok


@pytest.mark.parametrize("proto", ["tcp", "network", "file", "headless",
                                   "javascript", "code", "flow"])
def test_unsafe_protocols_excluded(proto):
    ok, reason = is_append_free(_t(**{proto: [{}]}))
    assert not ok and reason.startswith("unsafe_protocol")


def test_no_protocol_block_excluded():
    ok, reason = is_append_free(_t())
    assert not ok and reason == "no_recognised_protocol_block"


def test_non_dict_excluded():
    ok, reason = is_append_free("not a dict")   # type: ignore[arg-type]
    assert not ok and reason == "not_a_template_dict"


@pytest.mark.parametrize("tag", ["sqli", "ssrf", "lfi", "rce", "fuzz", "intrusive",
                                 "path-traversal", "open-redirect"])
def test_injection_tags_excluded_regardless_of_path(tag):
    ok, reason = is_append_free(_t(http=[{"method": "GET", "path": ["{{BaseURL}}"]}], tags=tag))
    assert not ok and reason.startswith("injection_tag")


def test_tags_as_list_supported():
    ok, reason = is_append_free(_t(http=[{"method": "GET", "path": ["{{BaseURL}}"]}],
                                   tags=["xss", "wordpress"]))
    assert not ok and reason.startswith("injection_tag")


# ── the path predicate itself ────────────────────────────────────────────────

@pytest.mark.parametrize("p,expect", [
    ("{{BaseURL}}", True), ("{{RootURL}}", True), ("{{BaseURL}}/", True),
    ("{{BaseURL}}?a=1", True), ("  {{BaseURL}}  ", True),
    ("{{BaseURL}}/.env", False), ("{{BaseURL}}/a", False),
    ("{{BaseURL}}/{{x}}", False), ("/relative", False), ("", False),
])
def test_is_base_only_path(p, expect):
    assert _is_base_only_path(p) is expect
