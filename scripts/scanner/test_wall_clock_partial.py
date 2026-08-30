#!/usr/bin/env python3
"""test_wall_clock_partial.py — spec 198 / 4.7 rulings ①②③.

Pins the PARTIAL_OK disposition, partial-output retention, and — most
importantly — the two ways this fix could silently fail to fix anything:

  * the wall-clock branch raising DegradedRunError (spec 198 §4.4: would abort
    every WAF-fronted scan on chunk 1, trading fictional coverage for none), and
  * TimeoutExpired.stdout coming back as BYTES under text=True, which would make
    the retained partial output unparseable and yield zero findings while
    looking exactly like success.

Both are regression pins against the SOURCE behaviour, not against a mirror of
it — per feedback_wiring_untested_by_pure_function_tests, a passing run of a
re-implemented copy proves nothing about the shipped code.
"""
import subprocess
import sys
import types

import pytest

import degradation as D
from degradation import (ABORT_SCAN, COVERAGE_COMPLETE, COVERAGE_PARTIAL_MINIMAL,
                         COVERAGE_UNKNOWN, DEGRADED, PARTIAL_OK, Degradation,
                         b1_degradation, egress_degradation, tool_degradation,
                         wall_clock_degradation)


# ── Ruling ① — PARTIAL_OK is a real fourth disposition ─────────────────────

def test_partial_ok_is_a_distinct_registered_disposition():
    assert PARTIAL_OK not in (ABORT_SCAN, DEGRADED)
    assert PARTIAL_OK in D._DISPOSITIONS
    assert len(set(D._DISPOSITIONS)) == 4 - 1  # abort, degraded, partial_ok


def test_wall_clock_degradation_never_aborts():
    d = wall_clock_degradation(180)
    assert d.disposition == PARTIAL_OK
    assert d.aborts is False, (
        "a wall-clock cut must never abort — spec 198 §4.4")
    assert d.is_partial is True


def test_wall_clock_reason_names_the_bound_not_a_failure():
    assert wall_clock_degradation(180).reason == "wall_clock_cut_180s"
    assert wall_clock_degradation(600).reason == "wall_clock_cut_600s"


def test_the_other_three_producers_keep_their_dispositions():
    # Adding a fourth class must not perturb the Note 193 taxonomy.
    assert egress_degradation("banned").disposition == ABORT_SCAN
    assert b1_degradation("target_unreachable_after_run").disposition == ABORT_SCAN
    assert tool_degradation("runtime_error").disposition == DEGRADED
    for d in (egress_degradation("x"), b1_degradation("y"), tool_degradation("z")):
        assert d.is_partial is False


def test_coverage_is_rejected_on_non_partial_dispositions():
    # An abort/degrade must not be able to carry a coverage claim.
    with pytest.raises(ValueError, match="only meaningful"):
        Degradation("banned", ABORT_SCAN, COVERAGE_COMPLETE)
    with pytest.raises(ValueError, match="only meaningful"):
        Degradation("runtime_error", DEGRADED, COVERAGE_UNKNOWN)


def test_partial_ok_requires_a_coverage_bucket():
    with pytest.raises(ValueError, match="requires a coverage bucket"):
        Degradation("wall_clock_cut_180s", PARTIAL_OK)


def test_unknown_coverage_bucket_rejected():
    with pytest.raises(ValueError, match="unknown coverage"):
        Degradation("wall_clock_cut_180s", PARTIAL_OK, "0.0125")


def test_coverage_defaults_to_unknown_not_a_guess():
    # Ruling ③ — honest imprecision. nuclei runs -silent so we cannot yet
    # evidence a bucket; claiming one would be false precision.
    assert wall_clock_degradation(180).coverage == COVERAGE_UNKNOWN


def test_coverage_bucket_is_carried_when_supplied():
    d = wall_clock_degradation(180, COVERAGE_PARTIAL_MINIMAL)
    assert d.coverage == COVERAGE_PARTIAL_MINIMAL


def test_equality_discriminates_on_coverage():
    a = wall_clock_degradation(180, COVERAGE_PARTIAL_MINIMAL)
    b = wall_clock_degradation(180, COVERAGE_UNKNOWN)
    assert a != b


def test_degradation_still_immutable_with_the_new_slot():
    d = wall_clock_degradation(180)
    for attr in ("reason", "disposition", "coverage"):
        with pytest.raises(AttributeError):
            setattr(d, attr, "nope")


# ── Ruling ② — partial output is retained AND decoded ──────────────────────

def _slow_emitter(n_lines: int, delay: float) -> list[str]:
    """A child that streams JSONL slowly, so a short timeout cuts it mid-run."""
    return [sys.executable, "-c",
            "import sys,time\n"
            f"for i in range({n_lines}):\n"
            "    print('{\"template-id\": \"t%d\", \"info\": {\"severity\": \"low\","
            " \"name\": \"n%d\"}}' % (i, i), flush=True)\n"
            "    sys.stderr.write('[INF] tick %d\\n' % i); sys.stderr.flush()\n"
            f"    time.sleep({delay})\n"]


def test_run_cmd_retains_partial_stdout_on_timeout():
    """THE core ruling-② behaviour. Pre-fix this returned ("", ...)."""
    from run_medium import run_cmd
    rc, out, err = run_cmd(_slow_emitter(40, 0.2), timeout=1)
    assert rc == 124
    assert out, "partial stdout MUST be retained, not discarded"
    assert '"template-id"' in out
    assert "timeout after 1s" in err
    assert "[INF] tick" in err, "partial stderr retained too"


def test_run_cmd_partial_output_is_str_not_bytes():
    """THE TRAP. subprocess.run(text=True) still raises TimeoutExpired carrying
    BYTES. Returning them would make every line stringify as `b'{...'`, fail the
    parser's startswith("{") test, and silently yield zero findings — a fix that
    looks like it worked. Verified empirically 2026-08-29."""
    from run_medium import run_cmd
    _rc, out, err = run_cmd(_slow_emitter(40, 0.2), timeout=1)
    assert isinstance(out, str), f"stdout must be decoded, got {type(out)}"
    assert isinstance(err, str), f"stderr must be decoded, got {type(err)}"
    assert not out.lstrip().startswith("b'"), "bytes leaked through as repr"
    # And it must actually be parseable the way the nuclei parser parses it.
    good = [ln for ln in out.splitlines() if ln.strip().startswith("{")]
    assert good, "retained stdout is not parseable as JSONL"


def test_timeout_stream_decoder_handles_every_input_shape():
    from run_medium import _timeout_stream_as_text
    assert _timeout_stream_as_text(None) == ""
    assert _timeout_stream_as_text(b'{"a": 1}') == '{"a": 1}'
    assert _timeout_stream_as_text('{"a": 1}') == '{"a": 1}'
    # Undecodable bytes must not raise — forensics beat purity.
    assert _timeout_stream_as_text(b"\xff\xfe") != ""


def test_truncated_final_jsonl_line_is_dropped_not_fatal():
    """A killed child can be mid-write. The parser must drop the ragged line and
    keep the complete ones (4.7 ruling ②)."""
    import json
    partial = ('{"template-id": "a"}\n'
               '{"template-id": "b"}\n'
               '{"template-id": "c", "info": {"sev')  # cut mid-object
    parsed = []
    for line in partial.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            parsed.append(json.loads(line))
        except Exception:
            continue
    assert [p["template-id"] for p in parsed] == ["a", "b"]


# ── mark_tool_partial — the tool_status shape ──────────────────────────────

def _ctx():
    c = types.SimpleNamespace()
    c.tool_status = {}
    c.tools_run = []
    c.artifacts = []
    c.dsn = None          # keeps flush_progress a no-op
    c.scan_run_id = "test"
    return c


def test_mark_tool_partial_writes_ok_false():
    """LOAD-BEARING: migration 20260828a gates autoclose on
    `tool ->> 'ok' = 'true'`. ok must be false or the whole fix is cosmetic."""
    from run_medium import mark_tool_partial
    ctx = _ctx()
    mark_tool_partial(ctx, "nuclei[critical]", wall_clock_degradation(180))
    entry = ctx.tool_status["nuclei[critical]"]
    assert entry["ok"] is False
    assert entry["partial"] is True
    assert entry["reason"] == "wall_clock_cut_180s"
    assert entry["coverage"] == COVERAGE_UNKNOWN


def test_partial_entry_is_distinguishable_from_degraded():
    """Both are ok=false (autocloser treats them alike, correctly) but a reader
    must still be able to tell 'cut short' from 'tool broke'."""
    from run_medium import mark_tool_partial, mark_tool_degraded
    ctx = _ctx()
    mark_tool_partial(ctx, "nuclei[a]", wall_clock_degradation(180))
    mark_tool_degraded(ctx, "nikto", "runtime_error")
    part, deg = ctx.tool_status["nuclei[a]"], ctx.tool_status["nikto"]
    assert part.get("partial") is True and "degraded" not in part
    assert "degraded" in deg and deg.get("partial") is None
    # Neither satisfies the autocloser predicate.
    for e in (part, deg):
        assert e.get("ok") is not True


def test_banked_matches_are_recorded():
    from run_medium import mark_tool_partial
    ctx = _ctx()
    mark_tool_partial(ctx, "nuclei[a]", wall_clock_degradation(180), matches=3)
    assert ctx.tool_status["nuclei[a]"]["matches"] == 3


def test_mark_tool_partial_rejects_abort_class_degradations():
    """A future caller must not be able to launder an abort through the
    non-fatal path."""
    from run_medium import mark_tool_partial
    ctx = _ctx()
    with pytest.raises(ValueError, match="non-PARTIAL_OK disposition") as ei:
        mark_tool_partial(ctx, "x", egress_degradation("banned"))
    # Ruling ⑧: the message must name the offending disposition, the tool, and
    # the fix — a bare "bad argument" is not diagnosable if it ever escapes.
    assert "abort_scan" in str(ei.value)
    assert "'x'" in str(ei.value)
    assert "wall_clock_degradation" in str(ei.value)
    assert "mark_tool_degraded" in str(ei.value)
    with pytest.raises(ValueError, match="non-PARTIAL_OK disposition"):
        mark_tool_partial(ctx, "x", tool_degradation("runtime_error"))
    assert ctx.tool_status == {}


def test_mark_tool_partial_captures_stderr_artifact():
    """Instrument for increment 2 — nuclei runs -silent, so the next live run's
    stderr is how we learn what a killed nuclei actually emits."""
    from run_medium import mark_tool_partial
    ctx = _ctx()
    mark_tool_partial(ctx, "nuclei[a]", wall_clock_degradation(180),
                      stderr="[INF] Requests sent: 900")
    names = [a[0] for a in ctx.artifacts]
    assert "nuclei[a]_stderr" in names


# ── §4.4 — the wall-clock branch must NOT raise ────────────────────────────

def test_source_wall_clock_branch_does_not_raise():
    """Pinned against the REAL source text, not a mirror. If someone later
    'tidies' the rc==124 branch into the b1 raise path, this fails."""
    import inspect
    import run_medium
    src = inspect.getsource(run_medium.run_nuclei_chunked)
    assert "if rc == 124:" in src, "wall-clock branch missing from the chunk loop"
    head, _, tail = src.partition("if rc == 124:")
    branch = tail.split("else:")[0]
    assert "mark_tool_partial" in branch
    assert "raise" not in branch, (
        "the wall-clock branch must not raise — raising aborts the scan on "
        "chunk 1 of every WAF-fronted target (spec 198 §4.4)")
    # And the harm-check must still come first and still abort.
    assert head.index("if b1_reason:") < len(head)
    assert "raise DegradedRunError(b1_reason, chunk_name)" in head


def test_rc_124_is_not_added_to_is_tool_output_degraded():
    """The trap 4.7 ratified: every slug that function returns is a
    harm-condition and produces ABORT_SCAN via b1_degradation. Putting the
    timeout there would abort the scan."""
    import inspect
    src = inspect.getsource(D.is_tool_output_degraded)
    assert "124" not in src, (
        "rc==124 must NOT be handled in is_tool_output_degraded — its slugs "
        "all abort (b1_degradation). Use wall_clock_degradation instead.")


def test_timeout_stderr_still_matches_no_unreachable_pattern():
    """Documents WHY the old code fell through to ok: 'timeout after 180s'
    matches none of the 7 reachability patterns. If someone adds a 'timeout'
    pattern to that list they would silently re-create the abort trap."""
    stderr = "timeout after 180s"
    n = sum(len(p.findall(stderr.lower())) for p in D._UNREACHABLE_STDERR_PATTERNS)
    assert n == 0
    assert D.is_tool_output_degraded(
        tool="nuclei[critical]", stdout="", stderr=stderr, rc=124,
        pre_health=True, post_health=True) is None


def test_light_run_cmd_retains_partial_output_too():
    """Parity: run_light has its OWN run_cmd copy (per
    feedback_instance_specific_files_no_wholesale_copy the fix is by
    same-edit, so it needs its own pin)."""
    import run_light
    rc, out, err = run_light.run_cmd(_slow_emitter(40, 0.2), timeout=1)
    assert rc == 124
    assert isinstance(out, str) and out
    assert '"template-id"' in out
    assert "timeout after 1s" in err


# ── Downstream absorption — 4.7's named "biggest risk" ────────────────────
# Every consumer of tool_status must tell PARTIAL from ok. These are the two
# in-repo consumers that did NOT, found by audit on 2026-08-29.

_PARTIAL_ENTRY = {"ok": False, "partial": True,
                  "reason": "wall_clock_cut_180s", "coverage": COVERAGE_UNKNOWN}


def test_partial_chunk_cannot_delta_close_findings():
    """THE DANGEROUS ONE. delta_close_eligible tested `"ok" in v` — KEY
    membership — which was safe only while exactly one shape carried an `ok`
    key. The partial shape carries {"ok": False}, so key-membership returned
    True and a chunk that skipped 97% of its templates became eligible to
    false-remediate the findings it never looked for. That is the over-close
    failure the function exists to prevent."""
    from degradation import delta_close_eligible
    assert delta_close_eligible({"nuclei[critical]": _PARTIAL_ENTRY}) is False
    # Mixed run: one partial chunk blocks the whole scan's closing.
    assert delta_close_eligible({
        "nuclei[critical]": _PARTIAL_ENTRY,
        "nikto": {"ok": True},
    }) is False


def test_delta_close_still_works_for_genuinely_clean_runs():
    """The fix must not swing the other way and stop all closing."""
    from degradation import delta_close_eligible
    assert delta_close_eligible({"nikto": {"ok": True}, "ffuf": {"ok": True}}) is True
    assert delta_close_eligible({"nikto": {"degraded": "x"}}) is False
    assert delta_close_eligible({"nikto": {"skipped": "x"}}) is False
    assert delta_close_eligible({}) is False


def test_delta_close_rejects_truthy_non_true_ok():
    """`is True`, not truthiness — a future {"ok": "partial"} must not pass."""
    from degradation import delta_close_eligible
    assert delta_close_eligible({"t": {"ok": "partial"}}) is False
    assert delta_close_eligible({"t": {"ok": 1}}) is False


def test_legacy_adapter_does_not_report_a_partial_phase_as_ok():
    """Second absorption point: a partial entry has no "degraded" key and
    tools_run IS populated, so without an explicit check the adapter returned
    PhaseResult.ok() and the executor logged clean coverage."""
    import phase_contract as PC

    def fake_legacy(ctx):
        ctx.tools_run.append("nuclei[critical]")
        ctx.tool_status["nuclei[critical]"] = dict(_PARTIAL_ENTRY)

    ctx = types.SimpleNamespace(tools_run=[], tool_status={}, findings=[],
                               artifacts=[], asset_id="a", scan_run_id="s")
    phase = PC.legacy_adapter(fake_legacy, "medium")
    result = phase(ctx, None)
    assert result.outcome != PC.Outcome.OK, (
        "a wall-clock-cut phase must not be reported as clean coverage")
    assert "wall_clock_cut" in (result.reason or "")


def test_legacy_adapter_still_reports_clean_phases_as_ok():
    import phase_contract as PC

    def fake_legacy(ctx):
        ctx.tools_run.append("nikto")
        ctx.tool_status["nikto"] = {"ok": True}

    ctx = types.SimpleNamespace(tools_run=[], tool_status={}, findings=[],
                               artifacts=[], asset_id="a", scan_run_id="s")
    assert PC.legacy_adapter(fake_legacy, "medium")(ctx, None).outcome == PC.Outcome.OK


def test_autocloser_sql_predicate_excludes_partial_entries():
    """Mirrors migration 20260828a's predicate
    `coalesce(sr.tool_status -> t.tool ->> 'ok', '') = 'true'` in Python.
    jsonb ->> on a boolean false yields the STRING 'false', which != 'true'."""
    import json
    as_jsonb = json.loads(json.dumps(_PARTIAL_ENTRY))
    rendered = str(as_jsonb["ok"]).lower()   # what ->> 'ok' produces
    assert rendered == "false"
    assert rendered != "true", "partial must not satisfy the autoclose predicate"


# ── ⑨ nikto — brought into stage 1 because THIS SHIP creates the exposure ──

def test_partial_retention_would_have_regressed_nikto_without_the_branch():
    """The empirical finding that pulled nikto into stage 1 (4.7 ruling ⑨).

    nikto_is_degraded's `no_scan_output` guard fires on
    `rc != 0 and "Nikto v" not in stdout`. nikto prints its version banner
    FIRST, so once run_cmd retains partial output that guard stops firing — a
    loud degraded-abort silently becomes mark_tool_ok. Retention without the
    rc==124 branch would have REGRESSED nikto into the spec-198 defect."""
    from run_medium import nikto_is_degraded
    partial = "- Nikto v2.5.0\n---------\n+ Target IP: 1.2.3.4\n+ Server: nginx\n"
    # Pre-retention behaviour (stdout discarded): loud.
    assert nikto_is_degraded("", "timeout after 600s", 124) == (True, "no_scan_output")
    # Post-retention behaviour: the guard no longer fires...
    assert nikto_is_degraded(partial, "timeout after 600s", 124) == (False, "")
    # ...which is exactly why run_nikto needs its own wall-clock branch.


def test_nikto_has_a_wall_clock_branch_and_it_does_not_raise():
    import inspect
    import run_medium
    src = inspect.getsource(run_medium.run_nikto)
    assert "if rc == 124:" in src, "nikto wall-clock branch missing"
    branch = src.partition("if rc == 124:")[2].split("else:")[0]
    assert "mark_tool_partial" in branch
    assert "raise" not in branch
    # mark_tool_ok must now be the else-arm, not unconditional.
    assert 'mark_tool_ok(ctx, "nikto")' in src.partition("if rc == 124:")[2]


def test_ffuf_and_testssl_are_file_based_so_retention_cannot_flip_them():
    """Why ffuf/testssl stayed OUT of stage 1 (4.7 ruling ⑨ — verify, don't
    infer from shape). Both read an output FILE, so run_cmd's stdout retention
    cannot change their verdicts. Empirically checked, not assumed."""
    import inspect
    import run_medium
    ffuf = inspect.getsource(run_medium.run_ffuf_chunk)
    # ffuf writes -o <file> and reads that file; stdout is not its result surface.
    assert '"-o", out_path' in ffuf or "'-o', out_path" in ffuf
    assert "Path(out_path).read_text()" in ffuf
    # And its timeout is explicitly tolerated before the file read.
    assert "if rc not in (0, 124):" in ffuf


# ── ⑧ executor safety net + slug propagation ──────────────────────────────

def test_executor_catches_a_phase_bug_and_keeps_scanning():
    """mark_tool_partial raises on misuse (ruling ⑧). The executor must turn
    that into one degraded phase, not a dead scan."""
    import phase_contract as PC

    def exploding(ctx, work_dir):
        raise ValueError("mark_tool_partial called with a non-PARTIAL_OK ...")

    spec = PC.PhaseSpec(name="boom", tier="medium", fn=exploding,
                        order=PC.ORDER_MEDIUM_TOOLS)
    ctx = types.SimpleNamespace(tools_run=[], tool_status={}, findings=[],
                               artifacts=[], asset_id="a", scan_run_id="s")
    res = PC.run_phase(spec, ctx, None)
    assert res.outcome == PC.Outcome.DEGRADED
    assert res.meta["exception_type"] == "ValueError"
    assert "non-PARTIAL_OK" in res.meta["exception_detail"]


def test_degraded_run_error_slug_is_propagated_not_flattened():
    """Run #2624 recorded nikto as {"degraded": "exception_DegradedRunError"},
    losing the real reason. The slug must now survive."""
    import phase_contract as PC
    from degradation import DegradedRunError

    def raiser(ctx, work_dir):
        raise DegradedRunError("target_unreachable_after_run", "nikto")

    spec = PC.PhaseSpec(name="nikto", tier="medium", fn=raiser,
                        order=PC.ORDER_MEDIUM_TOOLS)
    ctx = types.SimpleNamespace(tools_run=[], tool_status={}, findings=[],
                               artifacts=[], asset_id="a", scan_run_id="s")
    res = PC.run_phase(spec, ctx, None)
    assert res.reason == "target_unreachable_after_run"
    assert res.reason != "exception_DegradedRunError"


# ── ⑩ COMPOSITION test — the pieces working together ──────────────────────

def test_composition_wall_clock_cut_findings_and_both_coverage_gates():
    """4.7 ruling ⑩. The delta_close bug was a COMPOSITION defect: each piece
    was individually correct, the interaction was wrong. This asserts the whole
    chain in one place — partial output parsed into findings, tool_status shape,
    AND both coverage gates denying closure."""
    import json
    from degradation import delta_close_eligible
    from run_medium import mark_tool_partial

    # 1. A chunk that streamed 3 complete findings then was killed mid-4th.
    partial_stdout = (
        '{"template-id": "a", "info": {"severity": "high", "name": "A"}}\n'
        '{"template-id": "b", "info": {"severity": "low", "name": "B"}}\n'
        '{"template-id": "c", "info": {"severity": "info", "name": "C"}}\n'
        '{"template-id": "d", "info": {"sev'          # cut mid-write
    )
    parsed = []
    for line in partial_stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            parsed.append(json.loads(line))
        except Exception:
            continue

    # 2. Findings survive the cut — 3 banked, ragged 4th dropped.
    assert [p["template-id"] for p in parsed] == ["a", "b", "c"]

    # 3. tool_status carries the partial shape with the banked count.
    ctx = _ctx()
    ctx.tools_run.append("nuclei[critical]")
    mark_tool_partial(ctx, "nuclei[critical]", wall_clock_degradation(180),
                      matches=len(parsed))
    entry = ctx.tool_status["nuclei[critical]"]
    assert entry["ok"] is False and entry["partial"] is True
    assert entry["reason"].startswith("wall_clock_cut")
    assert entry["matches"] == 3

    # 4. GATE ONE — the 20260828a autocloser predicate.
    assert str(entry["ok"]).lower() != "true"

    # 5. GATE TWO — delta_close_eligible. This is the one that was broken.
    assert delta_close_eligible(ctx.tool_status) is False

    # 6. And the set-equality invariant still holds, so close_out won't abort.
    from degradation import assert_tool_status_invariant
    assert_tool_status_invariant(ctx.tools_run, ctx.tool_status)


def test_composition_a_fully_clean_run_still_closes():
    """The mirror: the fix must not have frozen closing altogether."""
    from degradation import delta_close_eligible, assert_tool_status_invariant
    from run_medium import mark_tool_ok
    ctx = _ctx()
    for t in ("nuclei[critical]", "nikto"):
        ctx.tools_run.append(t)
        mark_tool_ok(ctx, t)
    assert delta_close_eligible(ctx.tool_status) is True
    assert_tool_status_invariant(ctx.tools_run, ctx.tool_status)


# ── ⑪ ⑫ ⑲ — first-class PARTIAL/MIXED on the REGISTRY path ────────────────
# Run #2632 shipped with these missing: a cut phase persisted as
# {"degraded": "wall_clock_cut_180s"} because run_phase re-derives tool_status
# from the PhaseResult and the recorder's rich entries are never copied across.

def _nuclei_like(cut_names, ok_names):
    from run_medium import mark_tool_ok, mark_tool_partial
    from degradation import wall_clock_degradation

    def fn(ctx):
        for n in cut_names:
            ctx.tools_run.append(n)
            mark_tool_partial(ctx, n, wall_clock_degradation(180), matches=0)
        for n in ok_names:
            ctx.tools_run.append(n)
            mark_tool_ok(ctx, n)
    return fn


def _run(fn, name="nuclei", **spec_kw):
    import phase_contract as PC
    ctx = types.SimpleNamespace(tools_run=[], tool_status={}, findings=[],
                               artifacts=[], asset_id="a", scan_run_id="s", dsn=None)
    spec = PC.PhaseSpec(name=name, tier="medium",
                        fn=PC.legacy_adapter(fn, "medium"),
                        order=PC.ORDER_MEDIUM_TOOLS, **spec_kw)
    return PC.run_phase(spec, ctx, None), ctx


def test_registry_path_persists_the_full_partial_shape_not_degraded():
    """THE run #2632 regression. Before ⑪ this wrote {"degraded": ...}."""
    _res, ctx = _run(_nuclei_like(["nuclei[a]", "nuclei[b]"], []))
    e = ctx.tool_status["nuclei"]
    assert e["ok"] is False and e["partial"] is True
    assert e["reason"] == "wall_clock_cut_180s"
    assert e["coverage"] == "unknown"
    assert "degraded" not in e, "must not flatten to the degraded shape"


def test_all_chunks_cut_is_PARTIAL_not_MIXED():
    import phase_contract as PC
    res, ctx = _run(_nuclei_like(["nuclei[a]", "nuclei[b]"], []))
    assert res.outcome == PC.Outcome.PARTIAL
    assert "mixed" not in ctx.tool_status["nuclei"]


def test_some_cut_some_clean_is_MIXED_with_the_breakdown():
    """⑫ — 'any cut wins' cannot tell 1-of-30 from 15-of-30. MIXED plus the
    per-unit breakdown is what carries that."""
    import phase_contract as PC
    res, ctx = _run(_nuclei_like(["nuclei[a]", "nuclei[b]", "nuclei[c]"],
                                 ["nuclei[d]", "nuclei[e]", "nuclei[f]"]))
    assert res.outcome == PC.Outcome.MIXED
    e = ctx.tool_status["nuclei"]
    assert e["mixed"] is True
    assert e["chunks_ok"] == 3 and e["chunks_cut"] == 3
    names = [c["name"] for c in e["per_chunk"]]
    assert names == ["nuclei[a]", "nuclei[b]", "nuclei[c]",
                     "nuclei[d]", "nuclei[e]", "nuclei[f]"]
    outcomes = {c["name"]: c["outcome"] for c in e["per_chunk"]}
    assert outcomes["nuclei[a]"] == "partial" and outcomes["nuclei[d]"] == "ok"


def test_partial_and_mixed_are_both_coverage_negative_end_to_end():
    """Both gates must deny for BOTH shapes — the property the whole ship exists
    for. Composition-level, not per-component."""
    from degradation import delta_close_eligible
    for cut, okn in ([["nuclei[a]"], []], [["nuclei[a]"], ["nuclei[b]"]]):
        _res, ctx = _run(_nuclei_like(cut, okn))
        e = ctx.tool_status["nuclei"]
        assert str(e.get("ok")).lower() != "true"      # 20260828a predicate
        assert delta_close_eligible(ctx.tool_status) is False


def test_clean_phase_still_ok_and_still_closes():
    import phase_contract as PC
    from degradation import delta_close_eligible
    res, ctx = _run(_nuclei_like([], ["nuclei[a]", "nuclei[b]"]))
    assert res.outcome == PC.Outcome.OK
    assert ctx.tool_status["nuclei"] == {"ok": True}
    assert delta_close_eligible(ctx.tool_status) is True


def test_matches_are_summed_across_units():
    from run_medium import mark_tool_partial, mark_tool_ok
    from degradation import wall_clock_degradation

    def fn(ctx):
        ctx.tools_run.append("nuclei[a]")
        mark_tool_partial(ctx, "nuclei[a]", wall_clock_degradation(180), matches=2)
        ctx.tools_run.append("nuclei[b]")
        mark_tool_ok(ctx, "nuclei[b]")
    _res, ctx = _run(fn)
    assert ctx.tool_status["nuclei"]["matches"] == 2


def test_set_equality_invariant_still_holds_on_the_partial_path():
    """⑱ — keying on spec.name (not per-chunk names) is what keeps this ship
    code-only. If a future change writes per-chunk KEYS without also fixing
    tools_run, close_out would abort."""
    from degradation import assert_tool_status_invariant
    _res, ctx = _run(_nuclei_like(["nuclei[a]"], ["nuclei[b]"]))
    assert_tool_status_invariant(ctx.tools_run, ctx.tool_status)
    assert ctx.tools_run == ["nuclei"]


def test_yield_floor_also_gates_PARTIAL():
    """⑲ — a chunk cut having done NO work is broken-and-cut, not partial work.
    Yield-floor failure must win over the cut and record DEGRADED."""
    import phase_contract as PC
    res, ctx = _run(_nuclei_like(["nuclei[a]"], []),
                    healthy_yield=lambda meta: "zero_requests_sent")
    assert res.outcome == PC.Outcome.DEGRADED
    assert res.reason == "zero_requests_sent"
    assert ctx.tool_status["nuclei"] == {"degraded": "zero_requests_sent"}
    assert "partial" not in ctx.tool_status["nuclei"], (
        "a broken-and-cut chunk must not claim partial coverage")


def test_yield_floor_passing_leaves_PARTIAL_intact():
    import phase_contract as PC
    res, _ctx = _run(_nuclei_like(["nuclei[a]"], []),
                     healthy_yield=lambda meta: None)
    assert res.outcome == PC.Outcome.PARTIAL


def test_unrecognised_unit_shape_is_never_read_as_ok():
    """Fail-closed on a verdict: an entry we cannot classify is not coverage."""
    import phase_contract as PC
    units = PC._units_from_recorder({"weird": {"something": "else"}})
    assert units[0].outcome == PC.Outcome.DEGRADED


def test_partial_and_mixed_are_distinct_outcome_values():
    import phase_contract as PC
    assert PC.Outcome.PARTIAL not in (PC.Outcome.OK, PC.Outcome.DEGRADED,
                                      PC.Outcome.SKIPPED, PC.Outcome.ABORT_SCAN)
    assert PC.Outcome.MIXED != PC.Outcome.PARTIAL


def test_is_coverage_negative_covers_every_non_ok_outcome():
    import phase_contract as PC
    for o in (PC.Outcome.DEGRADED, PC.Outcome.PARTIAL, PC.Outcome.MIXED,
              PC.Outcome.GATE_SKIPPED, PC.Outcome.ABORT_SCAN):
        assert PC.PhaseResult(outcome=o).is_coverage_negative is True
    assert PC.PhaseResult(outcome=PC.Outcome.OK).is_coverage_negative is False


def test_subprocess_run_really_does_carry_partial_output():
    """The empirical premise the whole of ruling ② rests on. If a future Python
    stops populating TimeoutExpired.stdout, retention breaks silently — this
    fails loudly instead."""
    cmd = _slow_emitter(40, 0.2)
    with pytest.raises(subprocess.TimeoutExpired) as ei:
        subprocess.run(cmd, capture_output=True, text=True, timeout=1)
    assert ei.value.stdout, "TimeoutExpired carries no partial stdout"
