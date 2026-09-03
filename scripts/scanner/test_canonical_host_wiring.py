"""Wiring tests for canonical-host resolution in run_medium (4.7 77-82).

test_canonical_host.py proves the DECISION is right. This file proves the
decision is actually CONNECTED — the ⑭′ post-mortem lesson: pure-function
tests passed while the wiring was broken, because they exercised a mirror of
the logic rather than the shipped path.

So these call the real `resolve_web_host()` against a real `ScanContext` and
assert on `ctx.web_host`, plus source-pins that the HTTP-layer call sites
actually read `web_host` and the identity/allowlist sites still read
`hostname`.

Run: python -m pytest scripts/scanner/test_canonical_host_wiring.py -q
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import run_medium
from run_medium import ScanContext

SRC = Path(__file__).with_name("run_medium.py").read_text()


def _strip_comments(src: str) -> str:
    """Assert on CODE, not prose. A pin that matches a comment is worse than
    no pin — it passes for the wrong reason (see the .limit(1000) episode)."""
    out = []
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        out.append(line.split("  #", 1)[0])
    return "\n".join(out)


CODE = _strip_comments(SRC)


def mkctx(hostname="prodexlabs.com", **kw):
    return ScanContext(
        descriptor={}, hostname=hostname, asset_id=hostname,
        scan_run_id="s", queue_id="q", intensity="medium", **kw
    )


# ─── web_host fallback ───────────────────────────────────────────────────


def test_web_host_defaults_to_hostname():
    """No resolution -> byte-for-byte the pre-change behaviour."""
    assert mkctx().web_host == "prodexlabs.com"


def test_web_host_uses_http_host_once_set():
    ctx = mkctx()
    ctx.http_host = "www.prodexlabs.com"
    assert ctx.web_host == "www.prodexlabs.com"
    assert ctx.hostname == "prodexlabs.com", "asset identity must not change"


# ─── resolve_web_host: the shipped function ──────────────────────────────


def _patch(monkeypatch, *, probe, ips, assets=()):
    monkeypatch.setattr(run_medium, "_canonical_probe", lambda h: probe)
    monkeypatch.setattr(run_medium, "_resolve_a_records", lambda h: ips.get(h))
    monkeypatch.setattr(run_medium, "_known_asset_hosts", lambda ctx: set(assets))


def test_authorised_canonical_rewrites_web_host(monkeypatch):
    ctx = mkctx()
    _patch(
        monkeypatch,
        probe=(301, "https://www.prodexlabs.com:443/"),
        ips={"prodexlabs.com": ["8.232.147.166"],
             "www.prodexlabs.com": ["8.232.147.166"]},
    )
    run_medium.resolve_web_host(ctx)
    assert ctx.web_host == "www.prodexlabs.com"
    assert ctx.http_host == "www.prodexlabs.com"
    assert ctx.hostname == "prodexlabs.com"
    assert ctx.canonical_diag["outcome"] == "canonical_redirect"


def test_off_domain_redirect_does_not_rewrite(monkeypatch):
    """The Microsoft case, through the SHIPPED wiring."""
    ctx = mkctx("myordersauth.unimacgraphics.com")
    _patch(
        monkeypatch,
        probe=(301, "https://login.microsoftonline.com/x/oauth2/v2.0/authorize"),
        ips={"myordersauth.unimacgraphics.com": ["203.0.113.10"],
             "login.microsoftonline.com": ["203.0.113.10"]},
    )
    run_medium.resolve_web_host(ctx)
    assert ctx.http_host == "", "must not set a canonical host off-domain"
    assert ctx.web_host == "myordersauth.unimacgraphics.com"
    assert "microsoftonline" not in ctx.web_host
    assert ctx.canonical_diag["outcome"] == "http_surface_is_third_party"


def test_probe_failure_leaves_asset_host(monkeypatch):
    ctx = mkctx()
    _patch(monkeypatch, probe=None, ips={})
    run_medium.resolve_web_host(ctx)
    assert ctx.web_host == "prodexlabs.com"
    assert ctx.canonical_diag["reason"] == "probe_failed"


def test_different_ips_leave_asset_host(monkeypatch):
    ctx = mkctx()
    _patch(
        monkeypatch,
        probe=(301, "https://www.prodexlabs.com/"),
        ips={"prodexlabs.com": ["8.232.147.166"],
             "www.prodexlabs.com": ["203.0.113.99"]},
    )
    run_medium.resolve_web_host(ctx)
    assert ctx.http_host == ""
    assert ctx.canonical_diag["reason"] == "same_domain_different_infrastructure"


def test_redundant_stub_does_not_rewrite_host(monkeypatch):
    """(C) is a later increment — for now the stub must simply not rewrite."""
    ctx = mkctx("www.unimacgraphics.com")
    _patch(
        monkeypatch,
        probe=(301, "https://unimacgraphics.com/"),
        ips={"www.unimacgraphics.com": ["199.16.172.68"],
             "unimacgraphics.com": ["199.16.172.68"]},
        assets=("unimacgraphics.com",),
    )
    run_medium.resolve_web_host(ctx)
    assert ctx.http_host == ""
    assert ctx.canonical_diag["outcome"] == "redundant_redirect_stub"


def test_asset_lookup_failure_only_makes_boundary_stricter(monkeypatch):
    """An unavailable DB must never AUTHORISE something it otherwise wouldn't."""
    ctx = mkctx("www.unimacgraphics.com")
    _patch(
        monkeypatch,
        probe=(301, "https://unimacgraphics.com/"),
        ips={"www.unimacgraphics.com": ["199.16.172.68"],
             "unimacgraphics.com": ["199.16.172.68"]},
        assets=(),  # lookup "failed" -> empty set
    )
    run_medium.resolve_web_host(ctx)
    # Same-domain + same-IP still authorises (condition 2), which is correct:
    # it is the same box. What must NOT happen is an off-domain authorisation.
    assert ctx.canonical_diag["outcome"] in (
        "canonical_redirect", "redundant_redirect_stub"
    )


# ─── Source pins: the wiring itself ──────────────────────────────────────


HTTP_LAYER_PINS = [
    (r'"-u",\s*f"https://\{ctx\.web_host\}/"\]', "generic HTTP probe"),
    (r'\["wafw00f",\s*f"https://\{ctx\.web_host\}/"', "wafw00f"),
    (r'"-u",\s*f"https://\{ctx\.web_host\}",', "httpx[-td] tech detect"),
    (r'base_url\s*=\s*f"https://\{ctx\.web_host\}"', "nuclei base url"),
    (r'"-host",\s*f"https://\{ctx\.web_host\}",', "nikto"),
    (r'"-u",\s*f"https://\{ctx\.web_host\}/FUZZ"', "ffuf"),
]


@pytest.mark.parametrize("pattern,label", HTTP_LAYER_PINS)
def test_http_layer_targets_use_web_host(pattern, label):
    assert re.search(pattern, CODE), (
        f"{label} no longer targets ctx.web_host — a canonical rewrite would "
        f"silently stop applying to it"
    )


def test_no_http_target_still_built_from_ctx_hostname():
    """Any `https://{ctx.hostname}` left in CODE is a missed call site."""
    leftovers = re.findall(r'https://\{ctx\.hostname\}', CODE)
    assert not leftovers, (
        f"{len(leftovers)} HTTP target(s) still built from ctx.hostname"
    )


def test_validate_mode_allowlist_still_uses_asset_hostname():
    """Safety allowlist must not be satisfiable by a derived host."""
    assert re.search(
        r"assert_validate_mode_target_allowed\(ctx\.hostname,", CODE
    ), "validate-mode allowlist must assert on the ASSET hostname"


def test_fortigate_match_still_uses_asset_hostname():
    assert "ctx.hostname in FORTIGATE_HOSTNAMES" in CODE


def test_resolution_runs_before_detect_waf():
    """Ordering: every HTTP-layer phase downstream reads ctx.web_host."""
    i_resolve = CODE.find("resolve_web_host(ctx)")
    i_waf = CODE.find("detect_waf(ctx)")
    assert i_resolve != -1 and i_waf != -1
    assert i_resolve < i_waf, "canonical resolution must precede detect_waf"


def test_probe_does_not_follow_redirects():
    """-L would chase the redirect instead of observing it."""
    m = re.search(r"def _canonical_probe.*?\n\n\n", SRC, re.S)
    assert m, "probe function not found"
    body = m.group(0)
    assert '"-L"' not in body and "'-L'" not in body, (
        "canonical probe must NOT follow redirects"
    )
