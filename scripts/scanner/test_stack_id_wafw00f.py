"""Unit tests for E1: persist_stack_id_wafw00f in run_medium.py (Obsidian 146).
Pure — duck-typed ctx, no DB/network. Confirms the structured wafw00f verdict
artifact (the clean field P1 reads instead of re-parsing wafw00f's raw text).
"""
import json
import types

import run_medium as m


def _ctx(detected, kind):
    return types.SimpleNamespace(waf_detected=detected, waf_kind=kind, artifacts=[])


def test_fortiweb_verdict_persisted_structured():
    ctx = _ctx(True, "fortiweb")
    m.persist_stack_id_wafw00f(ctx)
    assert len(ctx.artifacts) == 1
    name, ctype, blob = ctx.artifacts[0]
    assert name == "stack_id_wafw00f" and ctype == "json"
    assert json.loads(blob) == {
        "schema": 1, "wafw00f_detected": True, "wafw00f_kind": "fortiweb"}


def test_generic_verdict_is_kind_generic():
    ctx = _ctx(True, "generic")
    m.persist_stack_id_wafw00f(ctx)
    d = json.loads(ctx.artifacts[0][2])
    assert d["wafw00f_detected"] is True and d["wafw00f_kind"] == "generic"


def test_no_waf_still_emitted_as_signal():
    # "wafw00f ran and found no WAF" is itself a signal — must persist, not skip.
    ctx = _ctx(False, None)
    m.persist_stack_id_wafw00f(ctx)
    d = json.loads(ctx.artifacts[0][2])
    assert d["wafw00f_detected"] is False and d["wafw00f_kind"] is None


def test_persist_is_additive_only_one_artifact_no_tool_registration():
    # Persist-only: exactly one artifact appended; the function must not touch
    # tools_run / tool_status / findings (it only reads waf_* + appends).
    ctx = _ctx(True, "cloudflare")
    m.persist_stack_id_wafw00f(ctx)
    assert len(ctx.artifacts) == 1
    assert not hasattr(ctx, "tools_run")   # our duck-typed ctx has none; fn never set it
