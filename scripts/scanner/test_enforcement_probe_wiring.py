#!/usr/bin/env python3
"""(354a-live / relay 360) The ONE wire: poll_queue's descriptor -> the probe gate.

⛔ WHAT THIS TURN ADDED. The differential enforcement probe (354a) reads its
per-asset opt-in off ctx.descriptor via probe_is_authorised(ctx.descriptor).
poll_queue.build_descriptor now carries assets.enforcement_probe_authorized to
the descriptor so Howie's opt-in can actually reach the gate. Nothing else
changed; firing STILL needs the env too.

⛔ THE PIN THESE TESTS EXIST FOR — the producer and the consumer must agree on
the SAME key at the SAME level. If build_descriptor put the flag under the
nested "asset" block, or misnamed it, probe_is_authorised(descriptor) would
read None, deny, and a live opt-in would SILENTLY never fire. So the strongest
test here does not re-read build_descriptor's output by hand — it feeds that
output to the REAL probe_is_authorised and asserts the gate opens. A wrong key
or wrong nesting reds it.

⛔ AND IT MUST STILL FAIL SAFE. Flag selected but env unset -> the caller sends
nothing (dry-run). The flag alone opens NOTHING; that is the whole safety model
and it is asserted end to end below, through the real descriptor.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import enforcement_probe as EP  # noqa: E402
import poll_queue as PQ  # noqa: E402


# ── fixtures: the minimal shapes build_descriptor consumes ───────────────────

def _queue_row():
    return {
        "queue_id": "11111111-1111-1111-1111-111111111111",
        "asset_id": "22222222-2222-2222-2222-222222222222",
        "intensity": "light",
        "authenticated": False,
    }


def _asset(flag):
    # The keys build_descriptor reads by name; `flag` is whatever the DB row
    # carried in the enforcement_probe_authorized column (or absent -> KeyError
    # avoided by passing a dict without the key when flag is the sentinel).
    a = {
        "asset_id": "22222222-2222-2222-2222-222222222222",
        "name": "owned.example.com",
        "organization": "Prodex",
        "type": "domain",
    }
    if flag is not _ABSENT:
        a["enforcement_probe_authorized"] = flag
    return a


_ABSENT = object()


def _descriptor(flag):
    return PQ.build_descriptor(_queue_row(), "run-1", _asset(flag), None)


# ── the flag lands at the descriptor TOP LEVEL, as a real boolean ────────────

def test_flag_true_lands_top_level_as_boolean_true():
    d = _descriptor(True)
    assert d[EP.AUTH_FLAG] is True                 # top level, not under "asset"
    assert EP.AUTH_FLAG not in d["asset"], "flag must NOT be nested under asset"


def test_flag_false_lands_top_level_as_boolean_false():
    assert _descriptor(False)[EP.AUTH_FLAG] is False


def test_absent_column_becomes_false_not_missing():
    # No column value at all (no migration yet / brand-new asset) -> False,
    # and the key is PRESENT so the consumer never KeyErrors.
    d = _descriptor(_ABSENT)
    assert d[EP.AUTH_FLAG] is False


def test_a_truthy_nonbool_does_not_open_the_gate():
    # A stray "true"/1 in the column must not read as authorisation — `is True`
    # keeps it boolean-strict, matching probe_is_authorised's own check.
    for v in ("true", "1", 1, "yes", "false", 0, ""):
        assert _descriptor(v)[EP.AUTH_FLAG] is False, v


# ── THE INTEGRATION PIN: real producer -> real consumer ──────────────────────

def test_opted_in_asset_makes_the_real_gate_openable_with_env():
    d = _descriptor(True)
    # env set + descriptor from an opted-in asset -> the REAL gate opens.
    assert EP.probe_is_authorised(d, env={EP.LIVE_ENV: "1"}) is True


def test_opted_in_asset_still_dry_runs_without_env():
    # ⛔ FLAG BUT NO ENV -> the caller sends nothing. Cron never sets the env.
    d = _descriptor(True)
    assert EP.probe_is_authorised(d, env={}) is False


def test_not_opted_in_never_fires_even_with_env():
    for flag in (False, _ABSENT):
        d = _descriptor(flag)
        assert EP.probe_is_authorised(d, env={EP.LIVE_ENV: "1"}) is False, flag


def test_the_existing_caller_safety_holds_through_the_real_descriptor(monkeypatch):
    """The 354a safety pin, re-exercised with a REAL poll_queue descriptor:
    flag selected, env unset -> the send function is never called."""
    import run_light as L
    calls = []
    monkeypatch.setattr(L, "_probe_path_body",
                        lambda ctx, path: calls.append(path) or (200, "", None))
    monkeypatch.delenv(EP.LIVE_ENV, raising=False)
    import types
    ctx = types.SimpleNamespace(
        hostname="owned.example.com", descriptor=_descriptor(True), artifacts=[])
    L.probe_enforcement(ctx)
    assert calls == [], "flag-but-no-env must send nothing"
    import json
    assert json.loads(ctx.artifacts[0][2])["fired"] is False


# ── the source is real: FETCH_ASSET_SQL actually selects the column ──────────

def test_fetch_asset_sql_selects_the_column():
    # Guards the other half: build_descriptor could read the key perfectly, but
    # if the SELECT never fetched it, asset.get() is always None and the flag is
    # unreachable forever. Both edits must be present.
    assert "enforcement_probe_authorized" in PQ.FETCH_ASSET_SQL
