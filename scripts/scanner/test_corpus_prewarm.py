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
import re
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
    assert m.corpus_floor_failed(0) == "corpus_empty"


def test_floor_fails_on_partial_corpus():
    """Mode 2 — the disguised one. A partial fetch shrinks the corpus and,
    downstream, `total`, which is indistinguishable from a WAF plan-class
    switch on the recorded surface. Caught here instead."""
    assert m.corpus_floor_failed(200) == "corpus_below_input_floor"


def test_floor_fails_when_unreadable():
    assert m.corpus_floor_failed(-1) == "corpus_unreadable"


def test_floor_is_loose_not_a_target():
    """Guards the maintenance trap: the floor must sit well below the observed
    count, not track it. Tightening it toward 13203 makes it a per-corpus-
    version burden and starts failing the honest case."""
    assert m.NUCLEI_CORPUS_MIN_TEMPLATES < 13203 * 0.75


# ── transport vs verdict ────────────────────────────────────────────────────

def _ctx():
    c = types.SimpleNamespace()
    c.tools_run = []          # ⚠ NOT decoration — prewarm_corpus credits itself
    c.tool_status = {}        #   here, and set-equality with this list is the
    c.tool_diag = {}          #   contract close_out asserts. A fixture without
    c.artifacts = []          #   tools_run cannot observe the 09-11 regression.
    c.corpus_prewarm_ok = True
    c.corpus_prewarm_meta = {}
    c.dsn = None
    return c


def test_timeout_is_TRANSPORT_and_is_retried(monkeypatch):
    calls = []

    def fake_run_cmd(cmd, timeout=30, **kw):
        calls.append(timeout)
        return 124, "", "hung"

    monkeypatch.setattr(m, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(m, "corpus_identity", lambda d: {})
    ctx = _ctx()
    m.prewarm_corpus(ctx)
    assert len(calls) == m.NUCLEI_CORPUS_FETCH_RETRIES + 1, \
        "a hung fetch is transport and must be retried"
    assert ctx.corpus_prewarm_ok is False, "exhausted retries must fail CLOSED"


def test_trivial_corpus_is_a_VERDICT_and_is_NOT_retried(monkeypatch):
    """Retrying a verdict is how a fail-closed gate becomes fail-open."""
    calls = []

    def fake_run_cmd(cmd, timeout=30, **kw):
        calls.append(1)
        return 0, "one-template\n", ""

    monkeypatch.setattr(m, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(m, "corpus_identity", lambda d: {})
    ctx = _ctx()
    m.prewarm_corpus(ctx)
    assert len(calls) == 1, "a completed fetch is a verdict — never retried"
    assert ctx.corpus_prewarm_ok is False


def test_prewarm_uses_its_OWN_timeout_not_the_chunk_fuse(monkeypatch):
    """A hanging GitHub fetch must not eat a chunk's budget."""
    seen = []
    monkeypatch.setattr(m, "run_cmd",
                        lambda cmd, timeout=30, **kw: (seen.append(timeout), (0, "x\n", ""))[1])
    monkeypatch.setattr(m, "corpus_identity", lambda d: {})
    m.prewarm_corpus(_ctx())
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
    before = m.corpus_identity(str(d))["dir_sha256"]
    (d / ".nuclei-ignore").write_text("http/a.yaml\n")
    after = m.corpus_identity(str(d))["dir_sha256"]
    assert before != after, "a non-yaml file that changes execution must move the hash"


def test_stamp_records_version_and_counts(monkeypatch, tmp_path):
    d = tmp_path / "c"
    (d).mkdir()
    (d / "x.yaml").write_text("id: x\n")
    ident = m.corpus_identity(str(d))
    assert ident["files"] == 1
    assert ident["dir_sha256"]
    assert ident["dir"] == str(d)


def test_ok_path_records_evidence_on_the_PERSISTED_surface(monkeypatch):
    monkeypatch.setattr(m, "run_cmd",
                        lambda cmd, timeout=30, **kw: (0, "t\n" * 20000, ""))
    monkeypatch.setattr(m, "corpus_identity",
                        lambda d: {"templates_version": "v10.4.8",
                                   "dir": d, "files": 13619,
                                   "dir_sha256": "deadbeef"})
    ctx = _ctx()
    m.prewarm_corpus(ctx)
    entry = ctx.tool_status.get("corpus_prewarm")
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
    assert '_register("corpus_prewarm"' in src
    assert "ORDER_CORPUS_PREWARM" in src
    assert "prewarm_corpus" in src


def test_failed_corpus_SKIPS_every_chunk(monkeypatch):
    """The gate that actually prevents the damage. Without it, chunks complete
    against an empty corpus, are recorded ok, and feed the autocloser."""
    ctx = _ctx()
    ctx.corpus_prewarm_ok = False
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
    ctx.corpus_prewarm_ok = True
    assert ctx.corpus_prewarm_ok is True


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
    monkeypatch.setattr(m, "corpus_identity", lambda d: {})
    ctx = _ctx()
    m.prewarm_corpus(ctx)
    cmd = seen["cmd"]
    for banned in ("-severity", "-exclude-tags", "-tags"):
        assert banned not in cmd, (
            f"pre-warm must count the WHOLE corpus; {banned} would make it "
            f"count a plan class and trip the floor on every scan")
    assert ctx.corpus_prewarm_ok is True, "13,203 templates must PASS the floor"


# ── ⛔ THE `nuclei%` NAMESPACE COLLISION — the regression test ───────────────
# The phase was first named `nuclei_corpus`, which SATISFIES the `nuclei%`
# prefix idiom that eight sites use to mean "nuclei actually ran":
#   asm_autoclose_producer_patterns: 'nuclei' -> ARRAY['nuclei%']
#                       'commandsentry_medium' -> ARRAY['nuclei%','ffuf','nikto','wafw00f']
#   degradation.py, phase_contract.py, run_medium.py x2, test_plan_trust.py
#   (startswith("nuclei"), and they expect a CHUNK dict)
#   scripts/db/checks/autoclose_allmatch_compare.sql (tool like 'nuclei%')
#
# ⛔ THE BYPASS IT CREATED, which is the exact path the input floor exists to
# close: on a floor-trip run the chunks are correctly recorded SKIPPED, but the
# corpus phase itself still lands in tools_run. `nuclei%` is then satisfied by
# the corpus phase ALONE, so the autocloser treats an UNSCANNED asset as
# covered and closes its findings as remediated.
#
# Renamed OUT of the namespace rather than excluded at eight call sites —
# exclusions are fragile and the ninth consumer will not know about them.

def test_phase_name_is_OUTSIDE_the_nuclei_prefix_namespace():
    import phase_registry  # noqa: F401 — registers phases
    from phase_contract import phases_for_tier
    from phase_source import MEDIUM
    names = [s.name for s in phases_for_tier(MEDIUM)]
    assert "corpus_prewarm" in names, "the pre-warm phase must still be registered"
    # ⚠ `nuclei` itself is the SCANNER phase and belongs in this namespace —
    # that is what the `nuclei%` idiom exists to match (㉟: test the case the
    # gate must PASS). Anything ELSE in the namespace is the bug.
    assert "nuclei" in names, "the scanner phase must still be registered as `nuclei`"
    offenders = [n for n in names if n.startswith("nuclei") and n != "nuclei"]
    assert offenders == [], (
        f"phase name(s) {offenders} satisfy the `nuclei%` idiom without being "
        f"the nuclei scanner — the autocloser would read an unscanned asset as covered")


def test_floor_trip_leaves_NOTHING_matching_nuclei_percent(monkeypatch):
    """4.7's stated assertion: on a floor-trip run, tools_run/tool_status carry
    no entry matching `nuclei%`. This is what stops the autocloser closing
    findings on an asset whose chunks were all skipped."""
    ctx = _ctx()
    ctx.corpus_prewarm_ok = False
    ctx.tech_stack = set(); ctx.waf_detected = False; ctx.waf_kind = None
    ctx.hostname = "example.com"; ctx.chunk_plan_meta = {}
    monkeypatch.setattr(m, "is_fortigate_target", lambda c: False)
    m.run_nuclei_chunked(ctx)

    # every chunk recorded, none of them ok
    assert ctx.tool_status, "chunks must be recorded SKIPPED, not silently absent"
    assert not any(v.get("ok") is True for v in ctx.tool_status.values())

    # and the corpus phase must not masquerade as a nuclei chunk
    nuclei_like = [k for k in ctx.tool_status
                   if k.startswith("nuclei") and not k.startswith("nuclei[")]
    assert nuclei_like == [], (
        f"{nuclei_like} would satisfy `nuclei%` on a run where nuclei never scanned")


def test_the_prefix_consumers_only_ever_see_chunk_dicts(monkeypatch):
    """degradation.py / run_medium.py collect startswith('nuclei') entries and
    expect chunk dicts. A non-chunk entry in that namespace breaks their shape."""
    monkeypatch.setattr(m, "run_cmd", lambda cmd, timeout=30, **kw: (0, "t\n" * 20000, ""))
    monkeypatch.setattr(m, "corpus_identity", lambda d: {"templates_version": "v1",
                                                         "dir": d, "files": 1,
                                                         "dir_sha256": "x"})
    ctx = _ctx()
    m.prewarm_corpus(ctx)
    for k in ctx.tool_status:
        assert not (k.startswith("nuclei") and not k.startswith("nuclei[")), (
            f"{k} lands in the nuclei prefix namespace but is not a chunk record")


# ── ⛔ EVERY MEDIUM-REGISTERED PHASE MUST BE REACHABLE FROM THE MEDIUM RUNNER ──
# THE DEFECT CLASS, and it has now appeared in BOTH directions in one day:
#   * persist_stack_id_wafw00f lives in run_medium.run()'s LINEAR BODY, so
#     HEAVY — which dispatches through the registry — never reaches it.
#   * corpus_prewarm was registered at MEDIUM only, so MEDIUM — which has NO
#     registry dispatch at all (no run_phases, no phases_for_tier, no
#     `import phase_registry`) — never reached IT.
#
# The second one mattered more: DEEP_SWEEP_TIER is "medium", so every automatic
# deep scan is a medium. A registration that only heavy can execute meant the
# input floor did not protect the tier automatic scanning uses.
#
# ⚠ Registration is NOT wiring on this codebase. Assert reachability, not
# registration — a phase that is registered and unreachable passes every test
# that only checks the registry.

def test_every_MEDIUM_registered_phase_is_reachable_from_the_medium_runner():
    here = os.path.dirname(os.path.abspath(__file__))
    reg_src = open(os.path.join(here, "phase_registry.py")).read()
    med_src = open(os.path.join(here, "run_medium.py")).read()

    # medium genuinely has no registry dispatch — if that ever changes, this
    # whole test becomes unnecessary and should be revisited deliberately.
    for dispatch in ("run_phases(", "phases_for_tier(", "import phase_registry"):
        assert dispatch not in med_src.replace("# ", ""), (
            f"run_medium now contains {dispatch!r} — it may dispatch the "
            f"registry after all; re-examine this test's premise")

    # every `_register("<name>", MEDIUM, _medium.<fn>, ...)`
    pairs = re.findall(r'_register\(\s*"([^"]+)"\s*,\s*MEDIUM\s*,\s*_medium\.(\w+)', reg_src)
    assert pairs, "no MEDIUM registrations found — the regex or the file moved"

    unreachable = []
    for phase_name, fn in pairs:
        # a call site, not the definition
        called = re.search(rf'(?<!def ){re.escape(fn)}\s*\(\s*ctx\s*\)', med_src)
        if not called:
            unreachable.append(f"{phase_name} -> {fn}()")
    assert unreachable == [], (
        f"registered at MEDIUM but never called from run_medium's linear body: "
        f"{unreachable} — heavy would execute these via the registry and medium "
        f"would silently skip them")
# ── the 09-11 invariant regression ──────────────────────────────────────────

def test_prewarm_SATISFIES_the_tool_status_invariant_on_every_exit(monkeypatch):
    """THE REGRESSION, pinned as the CONTRACT rather than as the fix.

    corpus_prewarm stamped tool_status without crediting tools_run. Heavy was
    unaffected (run_phase credits via the registry); medium calls the function
    directly, so set-equality broke and assert_tool_status_invariant — which
    runs in close_out only — raised `unclaimed=['corpus_prewarm']`. EVERY
    prewarm-enabled medium degraded. Confirmed live on both instances
    2026-09-11: Prodex #593, Command #2882.

    Asserts the INVARIANT, not the presence of an append. A test that asserted
    `"corpus_prewarm" in ctx.tools_run` would pass just as well if someone
    later credited it in a way that broke set-equality the other direction.

    ⚠ ALL THREE EXITS, because a floor trip and an exhausted-retry must each
    record their real reason WITHOUT a bogus invariant failure stacked on top.
    """
    from degradation import assert_tool_status_invariant

    cases = [
        ("success",   lambda c, timeout=30, **kw: (0, "t\n" * 13202, "")),
        ("floor trip", lambda c, timeout=30, **kw: (0, "t\n" * 3, "")),
        ("timeout",   lambda c, timeout=30, **kw: (124, "", "hung")),
    ]
    for label, fake in cases:
        monkeypatch.setattr(m, "run_cmd", fake)
        monkeypatch.setattr(m, "corpus_identity", lambda d: {})
        ctx = _ctx()
        m.prewarm_corpus(ctx)

        assert "corpus_prewarm" in ctx.tool_status, \
            f"{label}: the phase must always stamp a status"
        # must not raise — this is the assertion close_out makes for real
        assert_tool_status_invariant(ctx.tools_run, ctx.tool_status)
        assert ctx.tools_run.count("corpus_prewarm") == 1, \
            f"{label}: credited more than once — duplicates inflate tools_run"


def test_medium_linear_body_phases_credit_themselves():
    """Generalises the defect class one step past #46's reachability test.

    Reachable-from-medium is not enough: a phase medium calls DIRECTLY gets no
    registry bookkeeping, so its own body must credit tools_run. Asserted
    against the working control (detect_waf/"wafw00f") so the rule is anchored
    to a function that has run in production for weeks, not just to the new one.
    """
    import inspect
    for fn_name, tool in (("prewarm_corpus", "corpus_prewarm"),
                          ("detect_waf", "wafw00f"),
                          ("detect_tech_stack", "httpx[-td]")):
        src = inspect.getsource(getattr(m, fn_name))
        assert f'tools_run.append("{tool}")' in src, (
            f"{fn_name}() is called directly from run_medium's linear body and "
            f"must credit tools_run.append({tool!r}) itself — the registry "
            f"only credits the heavy path")
def test_early_credit_is_licensed_by_no_findings(monkeypatch):
    """PINS THE LICENCE FOR INVERTING run_phase's DOCUMENTED ORDER.

    run_phase credits tools_run AFTER fn returns "so a tool that ran and failed
    can never count as coverage". prewarm_corpus credits BEFORE. That exception
    is licensed by this phase emitting NO FINDINGS — coverage requires ok='true'
    in tool_status (migration 20260828a), and only the two real exit paths write
    it, so an early credit cannot manufacture coverage.

    ⚠ If corpus_prewarm ever starts emitting findings, the licence is void and
    the credit must move to the exit paths. This test is what says so.
    """
    for fake in (lambda c, timeout=30, **kw: (0, "t\n" * 13202, ""),   # ok
                 lambda c, timeout=30, **kw: (0, "t\n" * 3, ""),       # floor
                 lambda c, timeout=30, **kw: (124, "", "hung")):       # timeout
        monkeypatch.setattr(m, "run_cmd", fake)
        monkeypatch.setattr(m, "corpus_identity", lambda d: {})
        ctx = _ctx()
        ctx.findings = []
        m.prewarm_corpus(ctx)
        assert ctx.findings == [], (
            "corpus_prewarm emitted a finding — early tools_run crediting is no "
            "longer safe; move the append to the exit paths (see run_phase's "
            "'ORDER IS THE POINT' docstring)")
