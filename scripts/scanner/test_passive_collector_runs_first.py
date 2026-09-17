#!/usr/bin/env python3
"""The passive collector must run before anything that can earn a ban.
Relay 231/233, ruling 14. 2026-09-17.

⛔ ESTABLISHED FROM THE LOG, NOT INFERRED. Scanner #2697, Command,
`commandcommcentral.com` heavy (cumulative), 2026-09-03:

    20:11:34  wafw00f      OK — WAF detected
    20:12:06  httpx[-td]   OK — tech detected (hsts, jquery, asp.net …)
    20:13:27  pre-chunk  healthcheck 23.234.111.163   HTTP 200
    20:13:31  post-chunk healthcheck 23.234.111.163   HTTP 200   <- still reachable
    20:13:32  nikto starts on the same egress
    20:14:21  nikto rc=-13 · 0 reported                          <- THE BAN LANDS HERE
    20:14:33  ffuf calibration probes failed (fail-closed)       <- same egress, dead
    20:14:44  httpx DEGRADED reason=no_output rc=0               <- same egress
    20:14:56  stack_id_passive: collected nothing (cookies=0)    <- same egress
    20:15:22  close-out — findings 0, 250s

Reachable at 20:13:31, unreachable from 20:14:21, NO VPN rotation in between, and
the only phase that ran in the gap was nikto. That is what distinguishes "banned
partway through" from "the host was not serving HTTP" — the host served HTTP to
this same run's first two tools and to five healthchecks.

WHY IT ONLY STARTED IN SEPTEMBER: 93e8acea (2026-09-02) made heavy cumulative, so
medium's noisy phases run BEFORE heavy's own. That put nikto ahead of this
collector for the first time.

    pre-cutover    130/130 passive envelopes FULL
    post-cutover     5/11  FULL   — and every empty one is a run where the httpx
                                     family was also degraded (6/6, vs 0 of 134)

WHAT IT COSTS: the collector gathers the FortiWeb cookie and the TLS cert — two of
the three signals that make `waf/confirmed` reachable. Losing them costs the
classifier its corroboration on exactly the FortiGate hosts that earn the ban.

⚠ FIXTURE SCOPE. `commandcommcentral.com` only. `ftp.sciimage.com` and
`ftp.unimacgraphics.com` also show empty envelopes and are EXCLUDED: they are the
SFTP pair with no HTTPS surface, where an empty envelope may be correct. Folding
them in would have overstated the defect 3x.
"""

from __future__ import annotations

import ast
import json
import os
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_heavy as h  # noqa: E402

HERE = Path(__file__).resolve().parent

# The 08-28 heavy's real collection, for shape (cookies incl. the FortiWeb tell).
CERT_OUT = ("subject=CN = *.commandcommcentral.com\n"
            "issuer=C = US, O = GoDaddy.com\\, Inc., CN = Go Daddy Secure Certificate Authority - G2\n")
HEADERS_OUT = ("HTTP/1.1 200 OK\r\n"
               "Server: nginx\r\n"
               "Set-Cookie: cookiesession1=678B2867; path=/\r\n"
               "Set-Cookie: .SCI.Session=abc; path=/\r\n"
               "Strict-Transport-Security: max-age=31536000\r\n\r\n")


def _ctx():
    return types.SimpleNamespace(hostname="commandcommcentral.com", artifacts=[])


def _envelope(ctx):
    for name, fmt, blob in ctx.artifacts:
        if name == "stack_id_passive":
            return json.loads(blob)
    return None


class _Egress:
    """A fake egress that answers until it is banned, then returns nothing.

    Models what the log shows: rc=0-ish output before the ban, empty output after
    — NOT an exception. That is the whole difficulty, because an empty collection
    and a banned collection are indistinguishable at the call site."""

    def __init__(self, banned=False):
        self.banned = banned
        self.calls = 0

    def __call__(self, argv, *a, **k):
        self.calls += 1
        if self.banned:
            return (0, "", "")
        joined = " ".join(argv) if isinstance(argv, (list, tuple)) else str(argv)
        if "openssl" in joined:
            return (0, CERT_OUT, "")
        return (0, HEADERS_OUT, "")


# ---------------------------------------------------------------------------
# ⭐ the fires / doesn't-fire pair
# ---------------------------------------------------------------------------

def test_collector_on_an_unbanned_egress_collects_the_tells(monkeypatch):
    """Runs FIRST: the egress is fresh, and the two tells that carry
    `waf/confirmed` corroboration are collected."""
    monkeypatch.setattr(h, "run_cmd", _Egress(banned=False))
    ctx = _ctx()
    h.run_stack_id_passive_phase(ctx, HERE)
    env = _envelope(ctx)
    assert env is not None, "the phase must always append its artifact"
    assert env.get("set_cookie_names"), "cookies not collected on a healthy egress"
    assert "cookiesession1" in env["set_cookie_names"], (
        "the FortiWeb tell is the signal this whole reorder exists to protect")
    assert env.get("cert") or env.get("cert_raw"), "cert not collected"


def test_collector_on_a_banned_egress_produces_the_empty_envelope(monkeypatch):
    """Runs LAST, after nikto: the same code, the same host, an egress that has
    stopped answering — and the result is the empty envelope seen in production.

    This is the doesn't-fire half. It asserts the FAILURE MODE, so that the pair
    above is not merely 'the collector works'."""
    monkeypatch.setattr(h, "run_cmd", _Egress(banned=True))
    ctx = _ctx()
    h.run_stack_id_passive_phase(ctx, HERE)
    env = _envelope(ctx)
    assert env is not None, "even a banned run writes an envelope — that is the trap"
    assert not env.get("set_cookie_names"), "expected the empty-envelope failure mode"
    assert not env.get("headers")
    assert set(env) <= {"schema", "collected_at", "hostname"}, (
        f"a banned collection should carry only the envelope keys, got {sorted(env)} — "
        f"this is the shape that is indistinguishable from 'looked and found nothing'")


def test_the_two_envelopes_are_distinguishable_only_by_content(monkeypatch):
    """⛔ THE REASON RULING 12 EXISTS. Both runs produce an artifact with the same
    NAME. Only the contents differ. A capability test keyed on the artifact name
    would call the banned run 'capable' and treat absent cookies as evidence of
    absence."""
    monkeypatch.setattr(h, "run_cmd", _Egress(banned=False))
    good = _ctx(); h.run_stack_id_passive_phase(good, HERE)
    monkeypatch.setattr(h, "run_cmd", _Egress(banned=True))
    bad = _ctx(); h.run_stack_id_passive_phase(bad, HERE)
    assert [a[0] for a in good.artifacts] == [a[0] for a in bad.artifacts] == ["stack_id_passive"]
    assert _envelope(good) != _envelope(bad)


# ---------------------------------------------------------------------------
# the order pin — the actual fix
# ---------------------------------------------------------------------------

def _call_lines() -> dict:
    """Line number of the FIRST CALL to each phase function, from the AST.

    ⚠ AST, NOT TEXT SEARCH, AND THAT IS THE POINT. Three earlier versions of
    order-pins in this repo matched the wrong thing: one found "is behind" in an
    explanatory COMMENT, and the first draft of THIS test matched
    `def run_testssl_phase(` — the DEFINITION, which sits ~1000 lines above the
    call — and so failed on a correctly-ordered tree. A pin that cannot tell a
    definition from a call, or code from prose, is not a pin. The AST can.
    """
    tree = ast.parse((HERE / "run_heavy.py").read_text(encoding="utf-8"))
    first: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            first.setdefault(node.func.id, node.lineno)
            first[node.func.id] = min(first[node.func.id], node.lineno)
    return first


def test_the_collector_runs_before_the_registry_loop():
    """THE FIX. The registry loop executes medium's phases — nikto among them.
    The collector must be called before it."""
    calls = _call_lines()
    assert "run_stack_id_passive_phase" in calls, "the collector call is gone from run_heavy"
    assert "run_phases" in calls, "no run_phases call — re-anchor this pin"
    assert calls["run_stack_id_passive_phase"] < calls["run_phases"], (
        "the passive collector runs AFTER the registry loop again. That loop executes "
        "nikto, which earned a FortiGate ban in 49 seconds on commandcommcentral.com "
        "and took ffuf, httpx_tech and this collector down with it.")


def test_the_collector_is_called_exactly_once():
    """Moving a call is how you end up with two. A second execution would collect
    on a banned egress and append a SECOND, empty envelope — and the newest-wins
    read would then pick the empty one."""
    tree = ast.parse((HERE / "run_heavy.py").read_text(encoding="utf-8"))
    n = sum(1 for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "run_stack_id_passive_phase")
    assert n == 1, f"run_stack_id_passive_phase is called {n}x; exactly one is correct"


@pytest.mark.parametrize("noisy", ["run_phases", "run_testssl_phase",
                                   "run_fwbbot_check_probe_phase",
                                   "run_waf_differential_probe_phase"])
def test_the_collector_runs_before_every_noisy_heavy_phase(noisy):
    """Not just before the registry loop — before heavy's own attack-shaped phases
    too, so a phase inserted between them later is caught."""
    calls = _call_lines()
    if noisy not in calls:
        pytest.skip(f"{noisy} is not called in this tree")
    assert calls["run_stack_id_passive_phase"] < calls[noisy], (
        f"the passive collector must run before {noisy}")


def test_the_phase_still_depends_on_nothing_that_runs_before_it():
    """The move is only safe because the collector reads ctx.hostname and appends
    to ctx.artifacts — nothing else. If it grows a dependency on a field an
    earlier phase populates, it can no longer be first, and this fails loudly."""
    src = (HERE / "run_heavy.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "run_stack_id_passive_phase")
    used = {n.attr for n in ast.walk(fn)
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
            and n.value.id == "ctx"}
    assert used <= {"hostname", "artifacts"}, (
        f"run_stack_id_passive_phase now reads {sorted(used - {'hostname', 'artifacts'})} "
        f"off ctx. If any of those is populated by a later phase, running first is "
        f"no longer safe — re-check the order before relaxing this pin.")
