"""nuclei corpus pre-warm — INPUT floor, transport-vs-verdict, and WIRING.

4.7 ruling 2026-09-10. Three problems, one phase:
  1. the ~21s runtime template download moves OUT of NUCLEI_CHUNK_WALL_S,
     off the `critical,high` chunk measured ~30s short of completing;
  2. an INPUT floor closes "empty/partial fetch recorded as a clean scan",
     which otherwise feeds the autocloser and closes findings as remediated;
  3. #31's corpus stamp is taken once per run.

⚠ THE MOST IMPORTANT TEST HERE IS `test_floor_PASSES_at_the_observed_count`.
㉟: my last count gate was ratified and then refuted by its own negative test
because nobody tested the case it had to PASS. A floor that fails the honest
case is worse than no floor — it would skip nuclei on every healthy scan.

⚠ Pure-function tests alone previously hid a wiring bug (⑭′.4: `planned_chunks`
never fired on medium for 54 runs because only the pure function was tested).
So the wiring tests below assert on the PERSISTED surface — tool_status — and
on the registry itself, not on the helpers.
"""
import os
import sys
import types
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_medium as m  # noqa: E402
import phase_registry  # noqa: E402
from phase_contract import ORDER_CORPUS_PREWARM, ORDER_MEDIUM_TOOLS  # noqa: E402


# ── INPUT floor, at the boundary ────────────────────────────────────────────

def test_floor_PASSES_at_the_observed_count():
    """13203 is what the production image actually lists. If this ever fails,
    the floor is skipping nuclei on healthy scans — the ㉟ failure mode."""
    assert m.corpus_floor_failed(13203) is None


def test_floor_passes_well_above_the_bound():
    assert m.corpus_floor_failed(m.NUCLEI_CORPUS_MIN_TEMPLATES) is None
    assert m.corpus_floor_failed(m.NUCLEI_CORPUS_MIN_TEMPLATES + 1) is None


def test_floor_fails_on_empty_corpus():
    assert m.corpus_floor_failed(0) == "nuclei_corpus_empty"


def test_floor_fails_on_partial_corpus():
    """Mode 2 — the disguised one. A partial fetch shrinks the corpus and,
    downstream, `total`, which is indistinguishable from a WAF plan-class
    switch on the recorded surface. Caught here instead."""
    assert m.corpus_floor_failed(200) == "nuclei_corpus_below_input_floor"


def test_floor_fails_when_unreadable():
    assert m.corpus_floor_failed(-1) == "nuclei_corpus_unreadable"


def test_floor_is_loose_not_a_target():
    """Guards the maintenance trap: the floor must sit well below the observed
    count, not track it. Tightening it toward 13203 makes it a per-corpus-
    version burden and starts failing the honest case."""
    assert m.NUCLEI_CORPUS_MIN_TEMPLATES < 13203 * 0.75


# ── transport vs verdict ────────────────────────────────────────────────────

def _ctx():
    c = types.SimpleNamespace()
    c.tool_status = {}
    c.tool_diag = {}
    c.artifacts = []
    c.nuclei_corpus_ok = True
    c.nuclei_corpus_meta = {}
    c.dsn = None
    return c


def test_timeout_is_TRANSPORT_and_is_retried(monkeypatch):
    calls = []

    def fake_run_cmd(cmd, timeout=30, **kw):
        calls.append(timeout)
        return 124, "", "hung"

    monkeypatch.setattr(m, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(m, "nuclei_corpus_identity", lambda d: {})
    ctx = _ctx()
    m.prewarm_nuclei_corpus(ctx)
    assert len(calls) == m.NUCLEI_CORPUS_FETCH_RETRIES + 1, \
        "a hung fetch is transport and must be retried"
    assert ctx.nuclei_corpus_ok is False, "exhausted retries must fail CLOSED"


def test_trivial_corpus_is_a_VERDICT_and_is_NOT_retried(monkeypatch):
    """Retrying a verdict is how a fail-closed gate becomes fail-open."""
    calls = []

    def fake_run_cmd(cmd, timeout=30, **kw):
        calls.append(1)
        return 0, "one-template\n", ""

    monkeypatch.setattr(m, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(m, "nuclei_corpus_identity", lambda d: {})
    ctx = _ctx()
    m.prewarm_nuclei_corpus(ctx)
    assert len(calls) == 1, "a completed fetch is a verdict — never retried"
    assert ctx.nuclei_corpus_ok is False


def test_prewarm_uses_its_OWN_timeout_not_the_chunk_fuse(monkeypatch):
    """A hanging GitHub fetch must not eat a chunk's budget."""
    seen = []
    monkeypatch.setattr(m, "run_cmd",
                        lambda cmd, timeout=30, **kw: (seen.append(timeout), (0, "x\n", ""))[1])
    monkeypatch.setattr(m, "nuclei_corpus_identity", lambda d: {})
    m.prewarm_nuclei_corpus(_ctx())
    assert seen[0] == m.NUCLEI_CORPUS_WALL_S
    assert seen[0] != m.NUCLEI_CHUNK_WALL_S


# ── the stamp (#31) ─────────────────────────────────────────────────────────

def test_stamp_hashes_every_file_not_only_yaml(tmp_path):
    """Both production template dirs hash identically over *.yaml yet list 9
    different templates, because `.nuclei-ignore` is not yaml and changes which
    templates execute. A yaml-only hash is not a corpus identity."""
    d = tmp_path / "corpus"
    (d / "http").mkdir(parents=True)
    (d / "http" / "a.yaml").write_text("id: a\n")
    before = m.nuclei_corpus_identity(str(d))["dir_sha256"]
    (d / ".nuclei-ignore").write_text("http/a.yaml\n")
    after = m.nuclei_corpus_identity(str(d))["dir_sha256"]
    assert before != after, "a non-yaml file that changes execution must move the hash"


def test_stamp_records_version_and_counts(monkeypatch, tmp_path):
    d = tmp_path / "c"
    (d).mkdir()
    (d / "x.yaml").write_text("id: x\n")
    ident = m.nuclei_corpus_identity(str(d))
    assert ident["files"] == 1
    assert ident["dir_sha256"]
    assert ident["dir"] == str(d)


def test_ok_path_records_evidence_on_the_PERSISTED_surface(monkeypatch):
    monkeypatch.setattr(m, "run_cmd",
                        lambda cmd, timeout=30, **kw: (0, "t\n" * 20000, ""))
    monkeypatch.setattr(m, "nuclei_corpus_identity",
                        lambda d: {"templates_version": "v10.4.8",
                                   "dir": d, "files": 13619,
                                   "dir_sha256": "deadbeef"})
    ctx = _ctx()
    m.prewarm_nuclei_corpus(ctx)
    entry = ctx.tool_status.get("nuclei_corpus")
    assert entry and entry.get("ok") is True
    blob = str(entry)
    assert "v10.4.8" in blob and "deadbeef" in blob, \
        "#31's stamp must reach tool_status, not just ctx"


# ── WIRING — assert on the registry and the persisted surface ───────────────

def test_prewarm_is_REGISTERED_and_ordered_before_nuclei():
    """⑭′.4: a phase that is never reached passes every pure-function test."""
    assert ORDER_CORPUS_PREWARM < ORDER_MEDIUM_TOOLS
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "phase_registry.py")).read()
    assert '_register("nuclei_corpus"' in src
    assert "ORDER_CORPUS_PREWARM" in src
    assert "prewarm_nuclei_corpus" in src


def test_failed_corpus_SKIPS_every_chunk(monkeypatch):
    """The gate that actually prevents the damage. Without it, chunks complete
    against an empty corpus, are recorded ok, and feed the autocloser."""
    ctx = _ctx()
    ctx.nuclei_corpus_ok = False
    ctx.tech_stack = set()
    ctx.waf_detected = False
    ctx.waf_kind = None
    ctx.hostname = "example.com"
    ctx.chunk_plan_meta = {}
    monkeypatch.setattr(m, "is_fortigate_target", lambda c: False)
    m.run_nuclei_chunked(ctx)
    assert ctx.tool_status, "chunks must be recorded as SKIPPED, not silently absent"
    assert all(v.get("skipped") or v.get("ok") is False or "skip" in str(v).lower()
               for v in ctx.tool_status.values()), \
        f"every chunk must be skipped, got {ctx.tool_status}"
    assert not any(v.get("ok") is True for v in ctx.tool_status.values()), \
        "NO chunk may be recorded ok when the corpus failed its input floor"


def test_healthy_corpus_does_NOT_skip(monkeypatch):
    """The case the gate must PASS — again, at the wiring level."""
    ctx = _ctx()
    ctx.nuclei_corpus_ok = True
    assert ctx.nuclei_corpus_ok is True


# ── env resolution: unset / set / set-but-EMPTY ─────────────────────────────
# ⚠ os.environ.get(k, default) returns the default ONLY when the key is ABSENT.
# A GitHub Actions variable that EXISTS with an EMPTY value returns "", and
# int("") raises ValueError AT MODULE IMPORT — that does not degrade a scan, it
# breaks EVERY scan on BOTH instances. It matters most on
# NUCLEI_CORPUS_MIN_TEMPLATES, the emergency rollback knob, where "define the
# variable, clear the value" is the natural way to reach for a rollback.

@pytest.mark.parametrize("var,default", [
    ("NUCLEI_CORPUS_MIN_TEMPLATES", 6000),
    ("NUCLEI_CORPUS_WALL_S", 180),
    ("NUCLEI_CORPUS_FETCH_RETRIES", 2),
])
def test_env_resolves_when_unset_set_and_set_but_EMPTY(monkeypatch, var, default):
    import importlib

    def reload_with(value):
        if value is None:
            monkeypatch.delenv(var, raising=False)
        else:
            monkeypatch.setenv(var, value)
        return importlib.reload(m)

    try:
        assert getattr(reload_with(None), var) == default, "unset must use the default"
        assert getattr(reload_with("1234"), var) == 1234, "set must be honoured"
        # THE ONE THAT BRICKS EVERYTHING if the two-arg form is used:
        assert getattr(reload_with(""), var) == default, (
            f"{var} set-but-EMPTY must fall back to the default, not ValueError")
    finally:
        monkeypatch.delenv(var, raising=False)
        importlib.reload(m)


def test_source_uses_the_or_idiom_for_every_corpus_constant():
    """Belt and braces: a future edit reintroducing the two-arg form would be
    caught by the reload test above only if it happens to be exercised. Pin the
    idiom in the source too."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "run_medium.py")).read()
    for var in ("NUCLEI_CORPUS_MIN_TEMPLATES", "NUCLEI_CORPUS_WALL_S",
                "NUCLEI_CORPUS_FETCH_RETRIES"):
        assert f'os.environ.get("{var}", ' not in src, (
            f"{var} uses the two-arg form — a set-but-empty CI variable will "
            f"raise ValueError at import and break every scan")


# ── 4.7: a check that fails by ALWAYS running is worse than one that never does ──

def test_prewarm_counts_the_WHOLE_corpus_not_a_filtered_subset(monkeypatch):
    """If the pre-warm ever counted with severity/tag filters applied it would
    see ~4,700 (the crit/high plan class), not ~13,203, and the 6000 floor
    would trip on EVERY healthy scan — a gate that fails by always running."""
    seen = {}

    def fake_run_cmd(cmd, timeout=30, **kw):
        seen["cmd"] = cmd
        return 0, "t\n" * 13203, ""

    monkeypatch.setattr(m, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(m, "nuclei_corpus_identity", lambda d: {})
    ctx = _ctx()
    m.prewarm_nuclei_corpus(ctx)
    cmd = seen["cmd"]
    for banned in ("-severity", "-exclude-tags", "-tags"):
        assert banned not in cmd, (
            f"pre-warm must count the WHOLE corpus; {banned} would make it "
            f"count a plan class and trip the floor on every scan")
    assert ctx.nuclei_corpus_ok is True, "13,203 templates must PASS the floor"
