"""(KB 12 C1, 2026-11-11) A tool that gives up keeps its real reason and its last words.

Howie, 2026-11-11 12:50: "Proceed with step one." (make the record honest first); 15:51, on the
picture: "Okay, I approve." Read that day: on 93 Prodex deep scans in 30 days nikto's entry said
only {"degraded": "nikto_specific_degradation"}; the phase had named the cause
("target_error_limit": 20 failed connections in a row) and kept nikto's stderr, and both were
lost when it raised inside the legacy adapter. No nikto artifact was saved.

Pinned here, through the real legacy_adapter and run_phase:
  - the outer label is unchanged; the phase's own reason rides beside it as `detail`;
  - the artifacts the phase recorded before it raised are persisted;
  - `detail` is a slug or it is nothing (lesson 114: what is saved is shown on the portal);
  - every other path writes exactly what it wrote before (no `detail`, nothing extra).
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import phase_contract as pc  # noqa: E402
from degradation import DegradedRunError  # noqa: E402
from phase_contract import PhaseResult, PhaseSpec, legacy_adapter, run_phase  # noqa: E402
from phase_source import HEAVY, MEDIUM  # noqa: E402

NIKTO_LAST_WORDS = ("+ ERROR: *** Error limit (20) reached for host, giving up. "
                    "Last error: opening stream: ssl connect failed. ***")


class Ctx:
    def __init__(self):
        self.tools_run, self.tool_status, self.artifacts, self.findings = [], {}, [], []
        self.active_probe_authorized, self.intensity, self.dsn = False, "heavy", None


def _markers():
    def ok(c, n):
        c.tool_status[n] = {"ok": True}

    def degraded(c, n, reason, **kw):
        c.tool_status[n] = {"degraded": reason}

    def skipped(c, n, reason):
        c.tool_status[n] = {"skipped": reason}
    return dict(mark_ok=ok, mark_degraded=degraded, mark_skipped=skipped)


def _mark_like_medium(ctx, tool, reason, stderr=None):
    """What run_medium.mark_tool_degraded does to the ctx it is handed."""
    ctx.tool_status[tool] = {"degraded": reason}
    if stderr:
        ctx.artifacts.append((f"{tool}_stderr", "text", stderr))


def _run(fn, name="nikto"):
    ctx = Ctx()
    spec = PhaseSpec(name=name, tier=MEDIUM, fn=legacy_adapter(fn, HEAVY, _phase_name=name))
    result = run_phase(spec, ctx, None, **_markers())
    return ctx, result


def _nikto_gives_up(inner="target_error_limit", outer="nikto_specific_degradation"):
    def fn(ctx):
        ctx.tools_run.append("nikto")
        ctx.artifacts.append(("nikto", "text", "- Nikto v2.5.0\n"))
        _mark_like_medium(ctx, "nikto", inner, stderr=NIKTO_LAST_WORDS)
        raise DegradedRunError(outer, f"nikto: {inner}")
    return fn


def test_the_real_reason_rides_beside_the_label():
    ctx, result = _run(_nikto_gives_up())
    assert ctx.tool_status == {"nikto": {"degraded": "nikto_specific_degradation",
                                         "detail": "target_error_limit"}}
    assert ctx.tools_run == ["nikto"]
    assert result.outcome == pc.Outcome.DEGRADED and result.reason == "nikto_specific_degradation"


def test_the_tools_last_words_are_persisted():
    ctx, _ = _run(_nikto_gives_up())
    assert ("nikto_stderr", "text", NIKTO_LAST_WORDS) in ctx.artifacts
    assert ("nikto", "text", "- Nikto v2.5.0\n") in ctx.artifacts
    assert len(ctx.artifacts) == 2, "each artifact once"


def test_no_inner_reason_no_detail():
    def fn(ctx):
        ctx.tools_run.append("nikto")
        raise DegradedRunError("egress_unstable", "nikto")
    ctx, _ = _run(fn)
    assert ctx.tool_status == {"nikto": {"degraded": "egress_unstable"}}
    assert ctx.artifacts == []


def test_an_inner_reason_that_says_nothing_new_adds_nothing():
    ctx, _ = _run(_nikto_gives_up(inner="nikto_specific_degradation"))
    assert ctx.tool_status == {"nikto": {"degraded": "nikto_specific_degradation"}}


@pytest.mark.parametrize("inner", [
    "could not reach 24.38.70.8 through us-chi-wg-304",   # free text, an address, an exit
    "Target Error Limit", "x" * 81, "", "reason with spaces", "_leading"])
def test_detail_is_a_slug_or_it_is_nothing(inner):
    ctx, _ = _run(_nikto_gives_up(inner=inner))
    assert ctx.tool_status == {"nikto": {"degraded": "nikto_specific_degradation"}}, inner
    assert ("nikto_stderr", "text", NIKTO_LAST_WORDS) in ctx.artifacts, "the last words are still kept"


@pytest.mark.parametrize("inner", ["target_error_limit", "runtime_error", "no_tls_handshake:246",
                                   "curl_exit_35_unmapped", "a"])
def test_slugs_the_scanner_writes_are_kept(inner):
    ctx, _ = _run(_nikto_gives_up(inner=inner))
    assert ctx.tool_status["nikto"].get("detail") == inner


def test_a_phase_that_is_not_legacy_is_unchanged():
    def boom(ctx, work_dir):
        raise ValueError("a bug")
    ctx = Ctx()
    run_phase(PhaseSpec(name="x", tier=MEDIUM, fn=boom), ctx, None, **_markers())
    assert ctx.tool_status == {"x": {"degraded": "exception_ValueError"}}
    assert ctx.artifacts == []


def test_a_forged_attribute_on_any_exception_is_held_to_the_same_rule():
    def boom(ctx, work_dir):
        e = ValueError("a bug")
        e.phase_detail = "24.38.70.8 refused us"
        e.phase_artifacts = "not a list"
        raise e
    ctx = Ctx()
    result = run_phase(PhaseSpec(name="x", tier=MEDIUM, fn=boom), ctx, None, **_markers())
    assert ctx.tool_status == {"x": {"degraded": "exception_ValueError"}} and ctx.artifacts == []
    assert "detail" not in result.meta, "free text never becomes the result's detail either"


def test_the_paths_that_do_not_raise_write_what_they_wrote_before():
    def degraded_no_raise(ctx):
        ctx.tools_run.append("wafw00f")
        _mark_like_medium(ctx, "wafw00f", "no_verdict")
    ctx, _ = _run(degraded_no_raise, name="wafw00f")
    assert ctx.tool_status == {"wafw00f": {"degraded": "no_verdict"}}

    def clean(ctx):
        ctx.tools_run.append("tls_check")
        ctx.tool_status["tls_check"] = {"ok": True}
        ctx.artifacts.append(("tls_check", "json", "{}"))
    ctx, _ = _run(clean, name="tls_check")
    assert ctx.tool_status["tls_check"].get("ok") is True and "detail" not in ctx.tool_status["tls_check"]
    assert ctx.artifacts == [("tls_check", "json", "{}")]


def test_the_adapter_re_raises_the_same_exception():
    err = DegradedRunError("nikto_specific_degradation", "nikto: target_error_limit")

    def fn(ctx):
        _mark_like_medium(ctx, "nikto", "target_error_limit", stderr=NIKTO_LAST_WORDS)
        raise err
    with pytest.raises(DegradedRunError) as got:
        legacy_adapter(fn, HEAVY)(Ctx(), None)
    assert got.value is err and err.phase_detail == "target_error_limit"
    assert err.phase_artifacts == [("nikto_stderr", "text", NIKTO_LAST_WORDS)]


def test_the_adapter_itself_carries_no_free_text():
    """Both gates hold alone: the adapter does not put free text on the exception at all."""
    def fn(ctx):
        _mark_like_medium(ctx, "nikto", "could not reach 24.38.70.8", stderr=NIKTO_LAST_WORDS)
        raise DegradedRunError("nikto_specific_degradation", "nikto")
    with pytest.raises(DegradedRunError) as got:
        legacy_adapter(fn, HEAVY)(Ctx(), None)
    assert not hasattr(got.value, "phase_detail")
    assert got.value.phase_artifacts == [("nikto_stderr", "text", NIKTO_LAST_WORDS)]


@pytest.mark.parametrize("meta_detail,written", [
    ("could not reach 24.38.70.8", None), ("Free Text", None), (7, None),
    ("the_label", None),                      # says nothing the label does not
    ("target_error_limit", "target_error_limit")])
def test_a_phase_that_returns_its_own_detail_is_held_to_the_same_rule(meta_detail, written):
    """The rule is checked where the record is written, whoever supplied the detail."""
    def phase(ctx, work_dir):
        return PhaseResult.degraded("the_label", meta={"detail": meta_detail})
    ctx = Ctx()
    run_phase(PhaseSpec(name="x", tier=MEDIUM, fn=phase), ctx, None, **_markers())
    want = {"degraded": "the_label"}
    if written:
        want["detail"] = written
    assert ctx.tool_status == {"x": want}


def _several(marks, name):
    def fn(ctx):
        for tool, reason in marks:
            _mark_like_medium(ctx, tool, reason)
        raise DegradedRunError("nikto_specific_degradation", "nikto")
    return _run(fn, name=name)[0].tool_status[name]


def test_with_several_tools_marked_the_phases_own_reason_is_the_one_kept():
    entry = _several([("whatweb", "timeout"), ("nikto", "target_error_limit")], "nikto")
    assert entry == {"degraded": "nikto_specific_degradation", "detail": "target_error_limit"}


def test_two_different_reasons_under_other_names_carry_nothing():
    entry = _several([("whatweb", "timeout"), ("wafw00f", "no_verdict")], "nikto")
    assert entry == {"degraded": "nikto_specific_degradation"}


def test_one_reason_under_another_name_is_kept():
    entry = _several([("nikto_scan", "target_error_limit"), ("nikto_tls", "target_error_limit")], "nikto")
    assert entry == {"degraded": "nikto_specific_degradation", "detail": "target_error_limit"}


def test_the_phases_own_free_text_is_not_replaced_by_another_tools_reason():
    entry = _several([("whatweb", "timeout"), ("nikto", "could not reach 24.38.70.8")], "nikto")
    assert entry == {"degraded": "nikto_specific_degradation"}


def test_a_recorder_that_cannot_be_read_never_hides_the_real_exception():
    class Broken:
        tool_status = None
        artifacts = None
    e = RuntimeError("the real one")
    pc._carry_recorded(e, Broken(), "nikto")  # must not raise
    assert not hasattr(e, "phase_detail")


def test_medium_names_this_exact_failure():
    """The reason is the scanner's own: run_medium.nikto_is_degraded on nikto's real last line."""
    run_medium = pytest.importorskip("run_medium")
    is_degraded, reason = run_medium.nikto_is_degraded("- Nikto v2.5.0\n", NIKTO_LAST_WORDS, 0)
    assert is_degraded and reason == "target_error_limit"
    assert pc._DETAIL_SLUG.fullmatch(reason)
