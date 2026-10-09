"""run_nikto under D-056 look-only (2026-10-09) — the wiring.

nikto_look_only.py decides WHAT nikto may send; these pin that run_nikto
always uses it, sends nothing when it refuses, and that delta-close stays off
while findings from nikto's retired attack tests can no longer be re-checked.
"""
import inspect
import types

import pytest

import degradation as D
import nikto_look_only as L
import run_medium as m


class _Sent(Exception):
    pass


GOOD = '"000001","r","2","/backup.zip","GET","200","m","",""'
BAD = '"000002","r","9","/x","GET","200","m","",""'


def _nikto_tree(tmp_path):
    prog = tmp_path / "program"
    (prog / "databases").mkdir(parents=True)
    (prog / "databases" / "db_tests").write_text("#h\n" + GOOD + "\n" + BAD + "\n")
    (prog / "databases" / "db_variables").write_text("@ADMIN=/admin/\n")
    (prog / "nikto.pl").write_text('$VARIABLES{\'version\'}   = "2.6.1";\n')
    (prog / "nikto.conf.default").write_text("CHECKMETHODS=GET\n")
    (prog / "plugins").mkdir()
    for n in L.ALLOWED_PLUGINS + tuple(L.REFUSED_PLUGINS):
        (prog / "plugins" / f"nikto_{n}.plugin").write_text(f'my $id = {{ name => "{n}" }};\n')
    return prog


def _ctx(**kw):
    base = dict(auth_gated=False, tools_run=[], tool_status={}, web_host="example.invalid",
                hostname="example.invalid", artifacts=[], findings=[], total_requests=0,
                rotation_count=0, dsn=None, asset_id="a")
    base.update(kw)
    return types.SimpleNamespace(**base)


def _drive(monkeypatch, prog, ctx=None, stdout="- Nikto v2.6.1\n+ 0 item(s) reported on remote host\n"):
    seen = {"cmd": None, "egress": 0, "env": None}

    def fake_egress(ctx, max_rotations=2):
        seen["egress"] += 1
        return True, ""

    def fake_run_cmd(cmd, timeout=None, **kw):
        seen["cmd"] = list(cmd)
        seen["env"] = kw.get("env_extra")
        return 0, stdout, ""

    monkeypatch.setattr(m, "NIKTO_PROGRAM_DIR", str(prog))
    monkeypatch.setattr(L, "REVIEWED_FILES", L.hashes_of(prog))   # trust the test tree
    monkeypatch.setattr(m, "ensure_healthy_egress", fake_egress)
    monkeypatch.setattr(m, "run_cmd", fake_run_cmd)
    ctx = ctx or _ctx()
    m.run_nikto(ctx)
    return seen, ctx


def _opts(cmd):
    return [(cmd[i], cmd[i + 1]) for i in range(len(cmd) - 1) if cmd[i].startswith("-")]


def test_nikto_always_runs_look_only(tmp_path, monkeypatch):
    prog = _nikto_tree(tmp_path)
    seen, ctx = _drive(monkeypatch, prog)
    cmd = seen["cmd"]
    assert cmd[:2] == ["perl", str(prog / "nikto.pl")], "the screened tree must be the one that runs"
    assert seen["env"] == {"PWD": str(prog)}, "nikto resolves its plugin folder from $PWD first"
    opts = _opts(cmd)
    assert ("-config", str(prog / "nikto.conf.default")) in opts
    assert ("-Plugins", L.plugins_arg()) in opts
    assert ("-Tuning", L.TUNING_ARG) in opts
    assert ("-Option", "SKIPIDS=000002") in opts
    assert ("-Option", "DBDIR=" + str(prog / "databases")) in opts
    assert [k for k, _ in opts].count("-Tuning") == 1, "a second -Tuning would override the first"
    assert [k for k, _ in opts].count("-Plugins") == 1
    assert ctx.tool_status["nikto"] == {"ok": True}


def test_look_only_does_not_depend_on_any_switch(tmp_path, monkeypatch):
    """NIKTO_LOOK_ONLY only keeps delta-close off. It is not a way back to the
    full test set: flipping it must not change what nikto is sent."""
    prog = _nikto_tree(tmp_path)
    monkeypatch.setattr(m, "NIKTO_LOOK_ONLY", False)
    seen, _ = _drive(monkeypatch, prog)
    assert ("-Tuning", L.TUNING_ARG) in _opts(seen["cmd"])
    assert "NIKTO_LOOK_ONLY" not in inspect.getsource(m.run_nikto)


def test_production_uses_the_pinned_file_list(tmp_path, monkeypatch):
    """Without the test override, a tree that is not the reviewed nikto refuses."""
    def boom(*a, **k):
        raise _Sent("nothing may be sent for an unreviewed nikto")
    monkeypatch.setattr(m, "NIKTO_PROGRAM_DIR", str(_nikto_tree(tmp_path)))
    monkeypatch.setattr(m, "ensure_healthy_egress", boom)
    monkeypatch.setattr(m, "run_cmd", boom)
    ctx = _ctx()
    m.run_nikto(ctx)
    assert ctx.tool_status["nikto"] == {"degraded": m.NIKTO_GUARD_REFUSED_REASON}


def test_old_full_tuning_is_gone():
    src = inspect.getsource(m.run_nikto)
    assert '"x6"' not in src and "'x6'" not in src


def test_a_refusal_sends_nothing_and_is_recorded(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise _Sent("nothing may be sent when the screen refuses")

    monkeypatch.setattr(m, "NIKTO_PROGRAM_DIR", str(tmp_path / "missing"))
    monkeypatch.setattr(m, "ensure_healthy_egress", boom)
    monkeypatch.setattr(m, "run_cmd", boom)
    ctx = _ctx()
    m.run_nikto(ctx)                                   # no exception: the scan goes on
    assert ctx.tool_status["nikto"] == {"degraded": m.NIKTO_GUARD_REFUSED_REASON}
    assert ctx.tools_run.count("nikto") == 1
    assert any(name == "nikto_stderr" for name, _, _ in ctx.artifacts), \
        "the refusal reason must be kept as evidence"


def test_a_screen_that_raises_is_a_refusal_not_a_crash_or_a_pass(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise _Sent("nothing may be sent when the screen breaks")

    def broken(*a, **k):
        raise RuntimeError("screen broke")

    monkeypatch.setattr(L, "look_only_args", broken)
    monkeypatch.setattr(m, "NIKTO_PROGRAM_DIR", str(_nikto_tree(tmp_path)))
    monkeypatch.setattr(m, "ensure_healthy_egress", boom)
    monkeypatch.setattr(m, "run_cmd", boom)
    ctx = _ctx()
    m.run_nikto(ctx)
    assert ctx.tool_status["nikto"] == {"degraded": m.NIKTO_GUARD_REFUSED_REASON}


def test_auth_gated_still_skips_before_anything_else(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "NIKTO_PROGRAM_DIR", str(tmp_path / "missing"))
    seen, ctx = _drive(monkeypatch, tmp_path / "missing", ctx=_ctx(auth_gated=True))
    assert seen["cmd"] is None and seen["egress"] == 0
    assert ctx.tool_status["nikto"] == {"skipped": "auth_gated"}


def test_refusal_reason_is_a_tool_cut():
    """A refusal means the installed nikto does not match the screen — a tool
    problem to fix, not a choice (review 2026-10-09)."""
    assert D.classify_cut_reason(m.NIKTO_GUARD_REFUSED_REASON) == D.CUT_TOOL


@pytest.mark.parametrize("nuclei,nikto,on", [
    (True, True, False), (True, False, False), (False, True, False), (False, False, True),
])
def test_delta_close_stays_off_while_either_tool_is_restricted(monkeypatch, nuclei, nikto, on):
    monkeypatch.setattr(m, "NUCLEI_DETECTION_ONLY", nuclei)
    monkeypatch.setattr(m, "NIKTO_LOOK_ONLY", nikto)
    assert m.delta_close_on() is on


def test_close_out_asks_delta_close_on():
    src = inspect.getsource(m)
    block = src.partition('"SELECT delta_close_for_scan_run(%s, %s) AS n_closed"')[0]
    gate = block.rstrip().splitlines()[-12:]
    assert any("if delta_close_on():" in line for line in gate), \
        "the open -> remediated close must be gated by delta_close_on()"
    assert "if not NUCLEI_DETECTION_ONLY:" not in src
