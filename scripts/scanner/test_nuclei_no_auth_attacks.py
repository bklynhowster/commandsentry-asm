#!/usr/bin/env python3
"""test_nuclei_no_auth_attacks.py — D-056 enforced where the traffic is made.

⛔ WHY THIS FILE EXISTS. D-056 (2026-09-29, Howie, ABSOLUTE): no authentication-
type attacks, ever — no default-credential logins, no password guessing, no
auth-bypass probes. The 09-29 audit that wrote "nothing built crosses it" read
safe_exploit.py and never read nuclei's template library. On 2026-10-07 Prodex's
own load-balancer and Cloud IDS logs for the 17:47 prod heavy showed nuclei
sending default-login POSTs (Jellyfin, JBoss jbpm, Lutron's literal
"login=lutron&password=lutron", MagnusBilling) and an auth-bypass check. Every
heavy scan on both instances had been doing it.

These tests drive the REAL command builder (run_nuclei_chunk) with run_cmd
captured, so they read the argv nuclei would actually receive — not a comment,
not a constant in isolation.

⚠ This file pins the tag/id DENYLIST, which on its own fails OPEN for a
mistagged login template. The FAIL-CLOSED content check that closes that hole
(2026-10-08) is pinned in test_nuclei_auth_guard.py. Since then nuclei always
lists its corpus first (`-tl`), so the helper below answers that listing with a
one-template corpus and captures the SCAN command that follows.
"""
from __future__ import annotations

import os
import re
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_medium as m  # noqa: E402

# Families D-056 forbids, as nuclei-templates tags them (measured 2026-10-07:
# the first two alone cover all 307 templates under http/default-logins/).
REQUIRED_TAGS = {
    "default-login", "default-logins",
    "auth-bypass", "authbypass", "login-bypass",
    "creds-stuffing", "token-spray", "authenticated",
}
REQUIRED_IDS = {"wordpress-xmlrpc-brute-force", "CVE-2025-26793", "CVE-2025-47646"}


class _Stop(Exception):
    pass


# A detection check: D-056 detection-only (2026-10-09) never hands nuclei anything else.
_ONE = "id: ok\ninfo:\n  name: Acme config - Exposure\n  severity: critical\n"


def _captured_argv(waf_detected: bool, tag_filter=None, severity="critical,high", tl_seen=None):
    """Run the real run_nuclei_chunk until it calls the nuclei SCAN, and return its argv.
    The `-tl` listing that now always comes first is answered with one benign template."""
    import tempfile
    seen = []
    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, "http", "exposures"))
    with open(os.path.join(root, "http", "exposures", "ok.yaml"), "w") as fh:
        fh.write(_ONE)

    def fake_run_cmd(cmd, timeout=None, **kw):
        seen.append(list(cmd))
        if cmd and cmd[0] == "nuclei" and "-tl" in cmd:
            return 0, "http/exposures/ok.yaml\n", ""
        raise _Stop()

    ctx = types.SimpleNamespace(
        waf_detected=waf_detected, dsn=None, asset_id="test-asset",
        corpus_prewarm_meta=None, artifacts=[])
    orig, orig_dir, dsn = m.run_cmd, m.nuclei_templates_dir, os.environ.pop("SUPABASE_DSN", None)
    m.run_cmd = fake_run_cmd
    m.nuclei_templates_dir = lambda: root
    try:
        with pytest.raises(_Stop):
            m.run_nuclei_chunk(ctx, "https://example.invalid/", severity, tag_filter)
    finally:
        m.run_cmd, m.nuclei_templates_dir = orig, orig_dir
        if dsn is not None:
            os.environ["SUPABASE_DSN"] = dsn
    if tl_seen is not None:
        tl_seen.extend(c for c in seen if c and c[0] == "nuclei" and "-tl" in c)
    nuc = [c for c in seen if c and c[0] == "nuclei" and "-tl" not in c]
    assert len(nuc) == 1, f"expected one nuclei scan command, saw {seen}"
    return nuc[0]


def _flag(argv, name):
    vals = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == name]
    assert len(vals) == 1, f"{name} must appear exactly once, got {vals}"
    return set(vals[0].split(","))


@pytest.mark.parametrize("waf", [False, True])
@pytest.mark.parametrize("tag_filter", [None, "cve", "exposure,config"])
def test_every_scan_command_excludes_the_login_attack_families(waf, tag_filter):
    argv = _captured_argv(waf, tag_filter)
    tags = _flag(argv, "-exclude-tags")
    missing = REQUIRED_TAGS - tags
    assert not missing, (
        f"D-056: the nuclei command (waf_detected={waf}, tags={tag_filter}) no "
        f"longer excludes {sorted(missing)} — default-login / auth-bypass "
        "templates would fire again")
    assert "dos" in tags, "the pre-existing 'dos' exclusion must survive"
    if waf:
        assert {"intrusive", "fuzz"} <= tags, "the WAF branch's exclusions must survive"


@pytest.mark.parametrize("waf", [False, True])
def test_every_scan_command_excludes_the_untagged_login_attacks(waf):
    ids = _flag(_captured_argv(waf), "-exclude-id")
    assert REQUIRED_IDS <= ids, f"missing {sorted(REQUIRED_IDS - ids)}"


@pytest.mark.parametrize("waf", [False, True])
def test_the_listing_uses_the_same_exclusions_as_the_run(waf):
    """The guard and the coverage cursor both work from the corpus `nuclei -tl`
    lists. If the listing and the run disagreed, they would check (or slice) a
    different set of templates from the one the run may fire."""
    tl = []
    argv = _captured_argv(waf, tl_seen=tl)
    assert len(tl) == 1, f"expected one -tl listing, saw {tl}"
    assert _flag(tl[0], "-exclude-tags") == _flag(argv, "-exclude-tags")
    assert _flag(tl[0], "-exclude-id") == _flag(argv, "-exclude-id")


def test_no_exclusion_is_built_anywhere_but_the_one_helper():
    """A second hand-built '-exclude-tags' is how a future call site would
    silently drop D-056. Comments are allowed to mention the flag."""
    code = [ln for ln in open(m.__file__, encoding="utf-8").read().splitlines()
            if not ln.lstrip().startswith("#")]
    hits = [ln for ln in code if re.search(r'["\']-exclude-tags["\']', ln)]
    assert len(hits) == 1 and "return [" in hits[0], (
        f"'-exclude-tags' must be built only inside nuclei_exclusion_args; found {hits}")
