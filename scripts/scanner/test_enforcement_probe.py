#!/usr/bin/env python3
"""(354a) The differential enforcement probe — the MEASUREMENT instrument.

⛔ THE ONE THING THESE TESTS EXIST TO GUARANTEE: by default this probe sends
NOTHING. It fires attack signatures, so "dry-run unless Howie opted this asset
in AND set the env" is a safety property, not a preference, and it is pinned
here in the strongest form — the send function is counted, and the default path
must call it ZERO times.

⛔ NO VERDICT IS TESTED. 354a captures; 354b decides. There is deliberately no
"enforcing" assertion anywhere in this file — asserting one would mean the
verdict had been built a turn early, which is the sequencing error 355 forbids.
"""
from __future__ import annotations

import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import enforcement_probe as EP  # noqa: E402


# ── the pure gate ────────────────────────────────────────────────────────────

def test_dry_run_is_the_default_neither_flag_nor_env():
    assert EP.probe_is_authorised({}, env={}) is False
    assert EP.probe_is_authorised(None, env={}) is False


def test_env_alone_does_not_fire_a_host_nobody_opted_in():
    # ⛔ the fleet-wide kill switch on, but no per-asset opt-in -> still dry-run.
    assert EP.probe_is_authorised({}, env={EP.LIVE_ENV: "1"}) is False


def test_flag_alone_does_not_fire_on_cron():
    # ⛔ the asset opted in, but the env off -> still dry-run. Cron never sets it.
    assert EP.probe_is_authorised({EP.AUTH_FLAG: True}, env={}) is False


def test_both_gates_required_to_fire():
    assert EP.probe_is_authorised({EP.AUTH_FLAG: True},
                                  env={EP.LIVE_ENV: "1"}) is True


def test_the_flag_must_be_the_boolean_true_not_a_truthy_string():
    # A stray "false" string in a descriptor must not read as authorisation.
    for v in ("true", "1", 1, "yes", None, 0, "", "false"):
        assert EP.probe_is_authorised({EP.AUTH_FLAG: v},
                                      env={EP.LIVE_ENV: "1"}) is False, v


def test_the_env_accepts_the_usual_truthy_words_only():
    for on in ("1", "true", "TRUE", "yes"):
        assert EP.probe_is_authorised({EP.AUTH_FLAG: True},
                                      env={EP.LIVE_ENV: on}) is True, on
    for off in ("0", "false", "no", "", "off"):
        assert EP.probe_is_authorised({EP.AUTH_FLAG: True},
                                      env={EP.LIVE_ENV: off}) is False, off


# ── the plan ─────────────────────────────────────────────────────────────────

def test_the_plan_puts_baseline_and_attack_on_the_SAME_path():
    plan = EP.build_probe_plan("x.example", "/")
    assert plan.baseline_url == "https://x.example/"
    assert plan.attack_url.startswith("https://x.example/?")
    # ⛔ the attack URL is the baseline path plus the signature — same route.
    assert plan.attack_url[: len(plan.baseline_url)] == plan.baseline_url


def test_the_attack_signature_is_a_valid_encoded_CRS_tripwire():
    sqli = EP.build_probe_plan("x.example", "/", "sqli").attack_url
    xss = EP.build_probe_plan("x.example", "/", "xss").attack_url
    # URL-encoded, syntactically valid — no raw quotes/angle-brackets on the wire
    assert "%20OR%20" in sqli and "'" not in sqli.split("?", 1)[1]
    assert "%3Cscript%3E" in xss and "<" not in xss


def test_an_unknown_signature_is_refused_not_silently_dropped():
    try:
        EP.build_probe_plan("x.example", "/", "rce")
    except ValueError:
        return
    raise AssertionError("an unknown signature was accepted")


# ── the recorder — the artifact is a plan, never a verdict ────────────────────

def test_a_dry_run_artifact_is_marked_fired_false():
    arts: list = []
    plan = EP.build_probe_plan("x.example", "/")
    EP.record_probe_pair(arts, plan, None, None, None, fired=False)
    (name, fmt, body) = arts[0]
    import json
    rec = json.loads(body)
    assert name == EP.ENFORCEMENT_PROBE_ARTIFACT
    assert rec["fired"] is False
    # ⛔ a dry-run plan carries NO captured halves — it is not evidence.
    assert rec["baseline"] is None and rec["attack"] is None


def test_a_fired_artifact_carries_both_halves_and_no_verdict():
    arts: list = []
    plan = EP.build_probe_plan("x.example", "/")
    EP.record_probe_pair(
        arts, plan, "10.0.0.9",
        baseline={"status": 200, "content_type": "text/html", "body": "ok"},
        attack={"status": 403, "content_type": "text/html", "body": "denied"},
        fired=True,
    )
    import json
    rec = json.loads(arts[0][2])
    assert rec["fired"] is True
    assert rec["egress_ip"] == "10.0.0.9"
    assert rec["baseline"]["status"] == 200
    assert rec["attack"]["status"] == 403
    # ⛔ NO enforcement verdict field. That is 354b, from these bytes.
    assert "enforcing" not in rec and "verdict" not in rec


def test_recorded_bodies_are_bounded():
    arts: list = []
    plan = EP.build_probe_plan("x.example", "/")
    big = "A" * 5000
    EP.record_probe_pair(arts, plan, None,
                         baseline={"status": 200, "content_type": None, "body": big},
                         attack=None, fired=True, body_max=4096)
    import json
    rec = json.loads(arts[0][2])
    assert len(rec["baseline"]["body_snippet"]) == 4096
    assert rec["baseline"]["truncated"] is True


# ── the caller in run_light: DRY-RUN SENDS NOTHING ───────────────────────────

def _fake_ctx(descriptor):
    return types.SimpleNamespace(
        hostname="x.example", descriptor=descriptor, artifacts=[])


def test_the_caller_sends_nothing_when_not_authorised(monkeypatch):
    """⛔ THE SAFETY PIN. Default path: the send function is never called."""
    import run_light as L
    calls = []
    monkeypatch.setattr(L, "_probe_path_body",
                        lambda ctx, path: calls.append(path) or (200, "", None))
    monkeypatch.delenv(EP.LIVE_ENV, raising=False)
    ctx = _fake_ctx({})                    # no flag, no env
    L.probe_enforcement(ctx)
    assert calls == [], "an attack request was sent on the dry-run path"
    import json
    rec = json.loads(ctx.artifacts[0][2])
    assert rec["fired"] is False


def test_the_caller_fires_both_halves_only_when_fully_authorised(monkeypatch):
    import run_light as L
    calls = []
    def fake(ctx, path):
        calls.append(path)
        return (403 if "?" in path else 200), "body", "text/html"
    monkeypatch.setattr(L, "_probe_path_body", fake)
    monkeypatch.setenv(EP.LIVE_ENV, "1")
    ctx = _fake_ctx({EP.AUTH_FLAG: True})
    L.probe_enforcement(ctx)
    # exactly two requests: the benign path and the same path + signature
    assert len(calls) == 2, calls
    assert calls[0] == "/"
    assert calls[1].startswith("/?")
    import json
    rec = json.loads(ctx.artifacts[0][2])
    assert rec["fired"] is True
    assert rec["baseline"]["status"] == 200 and rec["attack"]["status"] == 403


def test_the_caller_still_dry_runs_when_env_set_but_asset_not_opted_in(monkeypatch):
    import run_light as L
    calls = []
    monkeypatch.setattr(L, "_probe_path_body",
                        lambda ctx, path: calls.append(path) or (200, "", None))
    monkeypatch.setenv(EP.LIVE_ENV, "1")
    ctx = _fake_ctx({})                    # env on, but no per-asset flag
    L.probe_enforcement(ctx)
    assert calls == [], "env alone fired a host that never opted in"


# ── the ROE inventory declares it, and agrees with the module ────────────────

def test_the_probe_is_declared_in_the_request_inventory():
    """The refusal probe follows this rule; so must the loudest request we send.
    What we put on the wire is one list, not a code read."""
    import roe_gate
    (p,) = [x for x in roe_gate.FOLLOWUP_PROBES if x["name"] == "enforcement_probe"]
    assert p["dry_run_default"] is True, "the inventory must say dry-run by default"
    assert p["method"] == "GET"
    assert p["requests_per_host_per_scan"] == 2  # baseline + one attack
    # the inventory's signature list and the module's must agree
    assert set(p["signatures"]) == {s for s, _ in EP.ATTACK_SIGNATURES}, (
        "the inventory and the code disagree on the attack signatures")
