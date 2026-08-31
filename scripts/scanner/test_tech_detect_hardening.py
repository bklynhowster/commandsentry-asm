"""4.7 ruling ⑭′ — tech-detection hardening, all five fixes.

THE DEFECT, as observed on Command run #2647 (2026-08-31):

    run #2647 planned FOUR nuclei chunks; the four runs before it planned SIX.
    The two missing were exactly the stack-specific ones — medium:wordpress,cms
    and medium:php — on a WordPress target.

`detect_tech_stack` was the only writer of ctx.tech_stack, which
build_chunk_plan reads. It credited mark_tool_ok BEFORE parsing, took
stdout.splitlines()[0], overwrote rather than unioned, and had zero
status/title guards. A WAF block returns rc=0 with valid JSON
({"tech": ["Nginx"], "title": "403 Forbidden"}), so tech_stack collapsed to
{"nginx"}, the stack chunks were never planned, and the tool recorded
{"ok": true}.

The correct stack was IN THE SAME SCAN: light's check_httpx_tech had already
banked an httpx_tech artifact showing WordPress/PHP/MySQL. We built the plan
from the blocked observation while the clean one sat unused in ctx.artifacts.

Why this class of bug outranks a wall-clock shortfall: a chunk cut at 92%
LOOKED and ran out of time; a chunk never planned NEVER LOOKED. And nothing in
tool_status recorded it — chunks_ok/chunks_cut read like an ordinary partial
run. Silent coverage loss.

Fleet measurement backing the fallback (Command, 30 days to 2026-08-31):
  heavy: 15 runs, 4 with a blocked tech artifact, and ALL 15 also carrying a
         clean artifact with >= 2 techs.
  light: 187 runs, 22 blocked — one invocation by design, no chunk plan to
         shrink, but 22 bogus `tech-disclosure` findings describing the WAF's
         banner as the asset's technology.
"""

from __future__ import annotations

import json
import pathlib
import sys
import types

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import tech_detect as T                                        # noqa: E402
import run_medium as M                                         # noqa: E402
from run_medium import ScanContext, build_chunk_plan           # noqa: E402


# The exact row pair from run #2647.
BLOCKED_ROW = {"tech": ["Nginx"], "title": "403 Forbidden", "status_code": 403}
CLEAN_ROW = {"tech": ["WordPress", "PHP", "MySQL"],
             "title": "Home - Unimac, a Command Company", "status_code": 200}


def _ctx(**kw) -> ScanContext:
    """A ScanContext carrying only the fields these branches read."""
    ctx = ScanContext.__new__(ScanContext)
    ctx.hostname = kw.get("hostname", "example.com")
    ctx.waf_detected = kw.get("waf_detected", False)
    ctx.waf_kind = kw.get("waf_kind", None)
    ctx.tech_stack = set(kw.get("tech_stack", ()))
    ctx.tools_run = list(kw.get("tools_run", ()))
    ctx.artifacts = list(kw.get("artifacts", ()))
    ctx.tool_status = dict(kw.get("tool_status", {}))
    ctx.chunk_plan_meta = {}
    ctx.tool_diag = {}
    ctx.tech_detect_status = kw.get("tech_detect_status", "")
    ctx.target_proven_reachable = False
    ctx.dsn = None
    return ctx


def _run_detect(monkeypatch, ctx, *, stdout: str, rc: int = 0, stderr: str = ""):
    """Drive the SHIPPED detect_tech_stack with a canned httpx response.

    Calls the real function rather than re-deriving its logic — a mirror of
    the branch under test lets mutations walk straight through it (four
    survived that way on 2026-08-31).
    """
    monkeypatch.setattr(M, "run_cmd", lambda *a, **k: (rc, stdout, stderr))
    monkeypatch.setattr(M, "is_tool_output_degraded", lambda **k: None)
    monkeypatch.setattr(M, "flush_progress", lambda *a, **k: None)
    monkeypatch.setattr(M, "log", lambda *a, **k: None)
    M.detect_tech_stack(ctx)
    return ctx


# ── fix 1 — blocked and redirected responses are not tech detection ────────

@pytest.mark.parametrize("status", sorted(T.TECH_BLOCK_STATUSES))
def test_blocked_status_codes_are_rejected(status):
    """A denial describes the WAF's stack, not the target's."""
    valid, reason = T.is_tech_detection_valid(
        {"tech": ["Nginx"], "status_code": status})
    assert valid is False
    assert reason == f"blocked_status_{status}", reason


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirects_are_rejected(status):
    """A redirect body is not the target's page. Follow it or discard it —
    do not fingerprint it."""
    valid, reason = T.is_tech_detection_valid(
        {"tech": ["Nginx"], "status_code": status})
    assert valid is False
    assert reason == f"redirect_status_{status}", reason


def test_block_page_title_is_rejected_even_when_the_status_is_200():
    """🔴 THE ONE THAT ACTUALLY BIT. Some WAFs serve the interstitial with a
    200. Status alone would pass it; the title is what gives it away.
    Observed title, n=20 across 5 assets in 30 days."""
    valid, reason = T.is_tech_detection_valid({
        "tech": ["Nginx"],
        "title": "The URL you requested has been blocked",
        "status_code": 200,
    })
    assert valid is False, "a 200-status block page must still be rejected"
    assert reason.startswith("blocked_title_"), reason


def test_a_real_page_is_not_rejected():
    """The guard must not eat true detections — that would trade a silent
    false positive for a silent false negative."""
    assert T.is_tech_detection_valid(CLEAN_ROW) == (True, "")


def test_missing_status_code_does_not_reject():
    """httpx omits status_code on some paths. Absent evidence is not
    evidence of a block."""
    assert T.is_tech_detection_valid({"tech": ["WordPress", "PHP"]})[0] is True


# ── fix 2 — union of valid rows, not splitlines()[0] ───────────────────────

def test_mixed_validity_rows_union_only_the_valid_ones():
    """🔴 RUN #2647, EXACTLY. Blocked row first, clean row second. Under
    [0]-wins this yielded {'nginx'} and dropped WordPress and PHP."""
    techs, n_valid, rejects = T.merge_tech_detection([BLOCKED_ROW, CLEAN_ROW])
    assert techs == {"wordpress", "php", "mysql"}, techs
    assert n_valid == 1
    assert rejects == ["blocked_status_403"], rejects


def test_union_is_order_independent():
    """The whole point of fix 2: the outcome must not depend on which line
    httpx happened to emit first."""
    a = T.merge_tech_detection([BLOCKED_ROW, CLEAN_ROW])[0]
    b = T.merge_tech_detection([CLEAN_ROW, BLOCKED_ROW])[0]
    assert a == b, f"order changed the result: {a} vs {b}"


def test_union_spans_multiple_valid_rows():
    """Two clean observations of the same target contribute BOTH their
    signals — first-wins would have discarded the second."""
    r1 = {"tech": ["WordPress"], "status_code": 200}
    r2 = {"tech": ["PHP", "jQuery"], "status_code": 200}
    techs, n_valid, _ = T.merge_tech_detection([r1, r2])
    assert techs == {"wordpress", "php", "jquery"}, techs
    assert n_valid == 2


def test_parse_httpx_rows_reads_every_line_and_survives_junk():
    stdout = ("not json\n"
              + json.dumps(BLOCKED_ROW) + "\n"
              + json.dumps(CLEAN_ROW) + "\n")
    rows = T.parse_httpx_rows(stdout)
    assert len(rows) == 2, rows
    assert rows[0]["status_code"] == 403 and rows[1]["status_code"] == 200


# ── fix 5 — yield floor ────────────────────────────────────────────────────

def test_lone_server_banner_fails_the_yield_floor():
    """{'nginx'} from a block page is server-header echo, not detection."""
    assert T.tech_detection_meets_yield_floor({"nginx"}) is False


@pytest.mark.parametrize("banner", sorted(T.TECH_SERVER_BANNERS))
def test_every_lone_banner_fails_the_floor(banner):
    assert T.tech_detection_meets_yield_floor({banner}) is False


def test_empty_detection_fails_the_floor():
    assert T.tech_detection_meets_yield_floor(set()) is False


def test_server_banner_PLUS_an_app_signal_passes():
    """Conservative by ruling: only the LONE-banner case is rejected. nginx +
    WordPress is a real detection and must survive."""
    assert T.tech_detection_meets_yield_floor({"nginx", "wordpress"}) is True


def test_two_banners_without_an_app_signal_still_pass():
    """Pins the deliberate narrowness of the floor. Widening this to 'all
    tokens are banners' would start discarding true thin detections, which
    4.7 warned against — if that is ever changed, change it knowingly."""
    assert T.tech_detection_meets_yield_floor({"nginx", "cloudflare"}) is True


# ── fix 3 — reuse the detection an earlier phase already banked ────────────

def test_fallback_fires_when_our_own_probe_is_blocked(monkeypatch):
    """🔴 THE RECOVERY. Medium's probe is blocked; light's artifact from
    earlier in the SAME run carries the real stack. Measured: this situation
    occurred in 4 of 15 heavy runs, and a usable clean artifact was present
    in all 15."""
    prior = ("httpx_tech", "json", json.dumps(CLEAN_ROW))
    ctx = _ctx(artifacts=[prior])
    _run_detect(monkeypatch, ctx, stdout=json.dumps(BLOCKED_ROW))

    assert ctx.tech_stack == {"wordpress", "php", "mysql"}, ctx.tech_stack
    assert ctx.tool_status["httpx[-td]"]["ok"] is True
    assert ctx.tool_status["httpx[-td]"]["tech_source"] == "artifact_fallback"


def test_fallback_restores_the_two_chunks_that_went_missing(monkeypatch):
    """END TO END, against the shipped planner. This is the actual
    regression: same blocked response, and the plan must regain
    wordpress,cms and php."""
    ctx = _ctx(artifacts=[("httpx_tech", "json", json.dumps(CLEAN_ROW))])
    _run_detect(monkeypatch, ctx, stdout=json.dumps(BLOCKED_ROW))
    tags = [tag for _sev, tag, _d in build_chunk_plan(ctx)]
    assert "wordpress,cms" in tags, tags
    assert "php" in tags, tags


def test_without_the_fallback_data_the_plan_really_does_shrink(monkeypatch):
    """The discriminating case — proves the test above is measuring the
    fallback and not passing for some unrelated reason. Same blocked
    response, NO prior artifact."""
    ctx = _ctx(artifacts=[])
    _run_detect(monkeypatch, ctx, stdout=json.dumps(BLOCKED_ROW))
    tags = [tag for _sev, tag, _d in build_chunk_plan(ctx)]
    assert "wordpress,cms" not in tags, tags
    assert "php" not in tags, tags


def test_fallback_does_NOT_override_a_good_own_detection(monkeypatch):
    """Our own live observation wins when it is usable. The fallback is a
    recovery path, not a merge — the union-across-sources question is open
    with 4.7 and must not be answered here by accident."""
    stale = ("httpx_tech", "json", json.dumps(
        {"tech": ["Drupal"], "status_code": 200}))
    ctx = _ctx(artifacts=[stale])
    _run_detect(monkeypatch, ctx, stdout=json.dumps(CLEAN_ROW))
    assert ctx.tech_stack == {"wordpress", "php", "mysql"}, ctx.tech_stack
    assert ctx.tool_status["httpx[-td]"]["tech_source"] == "httpx[-td]"


def test_prior_techs_we_did_not_use_are_recorded_not_discarded(monkeypatch):
    """Measure the open question rather than assume it. When an earlier phase
    saw signals our own probe missed, bank them as evidence so the
    union-across-sources decision can be made from data."""
    stale = ("httpx_tech", "json", json.dumps(
        {"tech": ["Drupal", "Varnish"], "status_code": 200}))
    ctx = _ctx(artifacts=[stale])
    _run_detect(monkeypatch, ctx, stdout=json.dumps(CLEAN_ROW))
    unused = ctx.tool_status["httpx[-td]"]["unused_prior_techs"]
    assert unused == ["drupal", "varnish"], unused


def test_fallback_ignores_a_prior_artifact_that_was_also_blocked(monkeypatch):
    """If light was blocked too there is nothing to recover, and we must say
    so rather than adopt a second block page's banner."""
    prior = ("httpx_tech", "json", json.dumps(BLOCKED_ROW))
    ctx = _ctx(artifacts=[prior])
    _run_detect(monkeypatch, ctx, stdout=json.dumps(BLOCKED_ROW))
    assert ctx.tech_stack == set(), ctx.tech_stack
    assert ctx.tool_status["httpx[-td]"].get("ok") is not True


def test_tech_rows_from_artifacts_ignores_unrelated_artifacts():
    rows = T.tech_rows_from_artifacts([
        ("nuclei", "json", json.dumps({"tech": ["Nope"]})),
        ("httpx_tech", "text", "not json at all"),
        ("httpx_tech", "json", json.dumps(CLEAN_ROW)),
    ])
    assert len(rows) == 1 and rows[0]["status_code"] == 200, rows


def test_tech_rows_from_artifacts_survives_malformed_entries():
    """Artifacts are appended by many call sites; one bad tuple must not
    take down tech detection."""
    assert T.tech_rows_from_artifacts([(), ("only-one",), None]) == []


# ── crediting — "ok" must mean detected, not merely ran ────────────────────

def test_a_blocked_probe_with_no_fallback_is_NOT_credited_ok(monkeypatch):
    """🔴 THE ORIGINAL SILENT FAILURE. httpx[-td] recorded {"ok": true} on a
    403, so the shrunken plan read as coverage and could license autoclose."""
    ctx = _ctx(artifacts=[])
    _run_detect(monkeypatch, ctx, stdout=json.dumps(BLOCKED_ROW))
    entry = ctx.tool_status["httpx[-td]"]
    assert entry.get("ok") is not True, entry
    assert entry.get("degraded") == "tech_detect_blocked", entry


def test_a_blocked_probe_does_not_raise(monkeypatch):
    """Non-fatal by design. Raising here would abort the whole scan on the
    FIRST phase of every WAF-fronted target — trading fictional coverage for
    none. Same trap as the nuclei rc=124 path."""
    ctx = _ctx(artifacts=[])
    _run_detect(monkeypatch, ctx, stdout=json.dumps(BLOCKED_ROW))  # no raise
    assert ctx.tech_stack == set()


def test_reachability_is_still_established_by_a_block_page(monkeypatch):
    """A block page is still proof the target answered over the Go stack
    nuclei shares. Rejecting it as TECH evidence must not also discard it as
    REACHABILITY evidence — those are different claims."""
    ctx = _ctx(artifacts=[])
    _run_detect(monkeypatch, ctx, stdout=json.dumps(BLOCKED_ROW))
    assert ctx.target_proven_reachable is True


def test_a_clean_probe_is_credited_ok(monkeypatch):
    ctx = _ctx(artifacts=[])
    _run_detect(monkeypatch, ctx, stdout=json.dumps(CLEAN_ROW))
    assert ctx.tool_status["httpx[-td]"]["ok"] is True
    assert ctx.tool_status["httpx[-td]"]["tech_count"] == 3


def test_all_rows_are_persisted_so_a_later_phase_can_reuse_them(monkeypatch):
    """The artifact is the fallback's input. If detect_tech_stack banked only
    the row it chose, the evidence trail — and the recovery — would be gone."""
    ctx = _ctx(artifacts=[])
    stdout = json.dumps(BLOCKED_ROW) + "\n" + json.dumps(CLEAN_ROW)
    _run_detect(monkeypatch, ctx, stdout=stdout)
    banked = [a for a in ctx.artifacts if a[0] == "httpx_tech"]
    assert banked, ctx.artifacts
    assert len(T.parse_httpx_rows(banked[0][2])) == 2


# ── fix 4 — planned_chunks makes a shrunken plan visible ───────────────────

def test_upper_bound_counts_every_stack_chunk_that_could_have_been_planned():
    """4.7 ruled the bound is what the plan WOULD have been had detection
    succeeded, not what it was — otherwise a shrunken plan is internally
    consistent and invisible."""
    ctx = _ctx()
    upper = M.max_possible_chunk_count(ctx)
    assert upper == (len(M.BASE_CHUNKS) + len(M.STACK_CHUNKS)
                     + len(M.CLOSER_CHUNKS))
    assert upper > len(build_chunk_plan(_ctx(tech_stack=set()))), (
        "an empty stack must plan FEWER chunks than the bound, or "
        "planned_chunks can never reveal shrinkage")


def test_a_fully_detected_stack_reaches_the_upper_bound():
    """Discriminating case: with every marker present the plan and the bound
    must MEET. If they cannot, the bound is not a bound and
    planned > actual would fire on healthy runs."""
    every_marker = {markers[0] for markers, _t, _l in M.STACK_CHUNKS}
    ctx = _ctx(tech_stack=every_marker)
    assert len(build_chunk_plan(ctx)) == M.max_possible_chunk_count(ctx)


def test_the_bound_is_derived_from_the_same_tables_the_planner_uses():
    """Guards the drift that makes the bound lie: a stack chunk added to the
    planner but not to the bound would silently under-report shrinkage."""
    ctx = _ctx(tech_stack={markers[0] for markers, _t, _l in M.STACK_CHUNKS})
    plan_tags = {tag for _s, tag, _d in build_chunk_plan(ctx)}
    for _markers, tag, _label in M.STACK_CHUNKS:
        assert tag in plan_tags, (
            f"{tag} is in STACK_CHUNKS but the planner never emits it")


def test_fortigate_bound_matches_its_safe_only_plan():
    ctx = _ctx(waf_kind="fortiweb", waf_detected=True)
    assert M.max_possible_chunk_count(ctx) == M.SAFE_ONLY_CHUNK_COUNT
    assert len(build_chunk_plan(ctx)) == M.SAFE_ONLY_CHUNK_COUNT


# ── the three defects run #2649 exposed in the ⑭′ ship itself ─────────────

def test_diag_survives_the_credit_that_replaces_the_entry(monkeypatch):
    """🔴 DEFECT A, run #2649. mark_tool_ok does
    `ctx.tool_status[name] = {"ok": True}` — a REPLACEMENT. Under the registry
    path run_phase credits AGAIN after detect_tech_stack returns, so every
    tech field was wiped and the entry persisted as a bare {"ok": true}.
    The fallback would have been invisible the first time it ever fired."""
    from phase_contract import _merge_phase_diagnostics
    ctx = _ctx(artifacts=[])
    _run_detect(monkeypatch, ctx, stdout=json.dumps(CLEAN_ROW))

    # Simulate run_phase crediting the phase a second time.
    ctx.tool_status["httpx[-td]"] = {"ok": True}
    _merge_phase_diagnostics(ctx, "httpx[-td]")

    entry = ctx.tool_status["httpx[-td]"]
    assert entry["tech_source"] == "httpx[-td]", entry
    assert entry["tech_count"] == 3, entry
    assert entry["rows_valid"] == 1, entry


def test_plan_delta_reason_is_NOT_a_failure_when_detection_succeeded():
    """🔴 DEFECT B, run #2649 — the worst of the three. The run recorded
    plan_delta_reason='tech_detect_unusable' while detection had SUCCEEDED
    with 17 techs and the plan was correctly 6 of 9, because the target is
    not IIS/Drupal/Joomla.

    A field built to make silent failure visible was manufacturing failure on
    healthy targets. Every non-IIS WordPress asset in the fleet would have
    triaged as broken."""
    ctx = _ctx(tech_stack={"wordpress", "php", "mysql", "nginx"})
    ctx.tech_detect_status = "httpx[-td]"
    plan = build_chunk_plan(ctx)
    upper = M.max_possible_chunk_count(ctx)
    assert len(plan) < upper, "fixture must actually shrink the plan"

    reason = ("stack_not_applicable"
              if M.tech_detection_meets_yield_floor(ctx.tech_stack)
              else ctx.tech_detect_status)
    assert reason == "stack_not_applicable", reason


def test_plan_delta_reason_source_does_not_read_tool_status():
    """Pins the CAUSE, not just the symptom. Under cumulative heavy the phase
    writes through a recording proxy, so ctx.tool_status inside
    run_nuclei_chunked is not the dict detect_tech_stack credited. Deriving
    the reason from it is unreliable by construction — assert the lookup is
    gone from the source rather than trusting it stays gone.

    Comment lines are stripped first: the comments here DISCUSS tool_status
    at length while explaining why it must not be read."""
    src = (pathlib.Path(__file__).parent / "run_medium.py").read_text()
    body = src.split("def run_nuclei_chunked(")[1].split("\ndef ")[0]
    code = "\n".join(ln for ln in body.splitlines()
                     if not ln.lstrip().startswith("#"))
    plan_meta = code.split("chunk_plan_meta")[1][:1200]
    assert 'tool_status' not in plan_meta, (
        "plan_delta_reason must not be derived from tool_status — it is not "
        "the same dict across the recorder boundary (run #2649)")


def test_a_genuinely_blocked_detection_still_reports_the_failure():
    """The other half of B: when detection really did fail, the reason must
    be the failure slug, not the benign one."""
    ctx = _ctx(tech_stack=set())
    ctx.tech_detect_status = "tech_detect_blocked"
    reason = ("stack_not_applicable"
              if M.tech_detection_meets_yield_floor(ctx.tech_stack)
              else ctx.tech_detect_status)
    assert reason == "tech_detect_blocked", reason


def test_chunk_plan_meta_does_not_leak_onto_tools_without_chunks():
    """🔴 DEFECT C, run #2649. ctx.chunk_plan_meta lives on ctx for the whole
    run, so the unguarded merge stamped planned_chunks=9 onto nikto AND ffuf.
    Neither has chunks. A meaningless field that looks meaningful is how a
    reader gets misled."""
    from phase_contract import _merge_phase_diagnostics
    ctx = _ctx()
    ctx.chunk_plan_meta = {"planned_chunks": 9, "actual_chunks": 6}
    for tool in ("nuclei", "nikto", "ffuf"):
        ctx.tool_status[tool] = {"ok": True}
        _merge_phase_diagnostics(ctx, tool)

    assert ctx.tool_status["nuclei"]["planned_chunks"] == 9
    assert "planned_chunks" not in ctx.tool_status["nikto"], ctx.tool_status["nikto"]
    assert "planned_chunks" not in ctx.tool_status["ffuf"], ctx.tool_status["ffuf"]


def test_plan_meta_merges_into_the_entry_on_the_OK_path():
    """🔴 THE POINT OF FIX 4. A plan shrunk upstream can complete every chunk
    it did plan, so it reports ok with nothing cut. chunks_ok/chunks_cut
    cannot express 'two chunks were never planned' — planned > actual is the
    only surviving signal, so it has to be written when nothing was cut."""
    from phase_contract import _merge_phase_diagnostics
    ctx = _ctx()
    ctx.chunk_plan_meta = {"planned_chunks": 9, "actual_chunks": 4,
                           "plan_delta_reason": "tech_detect_blocked"}
    ctx.tool_status["nuclei"] = {"ok": True}
    _merge_phase_diagnostics(ctx, "nuclei")
    entry = ctx.tool_status["nuclei"]
    assert entry["ok"] is True
    assert entry["planned_chunks"] == 9 and entry["actual_chunks"] == 4
    assert entry["plan_delta_reason"] == "tech_detect_blocked"


def test_plan_meta_merge_is_a_noop_without_an_entry():
    from phase_contract import _merge_phase_diagnostics
    ctx = _ctx()
    ctx.chunk_plan_meta = {"planned_chunks": 9}
    _merge_phase_diagnostics(ctx, "nuclei")          # must not raise
    assert "nuclei" not in ctx.tool_status


def test_run_phase_merges_plan_meta_on_every_outcome_path():
    """Assert on CODE, not on prose: the comments in this area discuss the
    OK path at length, so a substring search for 'ok' would pass on the
    documentation alone."""
    src = (pathlib.Path(__file__).parent / "phase_contract.py").read_text()
    code = "\n".join(ln for ln in src.splitlines()
                     if not ln.lstrip().startswith("#"))
    body = code.split("def run_phase(")[1]
    assert "_merge_phase_diagnostics(ctx, spec.name)" in body, (
        "run_phase must merge the plan meta after the outcome branch")
    # The merge must sit AFTER the whole outcome branch (so it sees the entry
    # whichever marker wrote it) and BEFORE the function returns.
    branch = body.split("if result.outcome == Outcome.OK")[1]
    merge_at = branch.index("_merge_phase_diagnostics")
    assert merge_at < branch.rindex("return result"), (
        "the merge must run before run_phase returns")
    for marker in ("mark_ok(ctx, spec.name)", "mark_partial(ctx, spec.name",
                   "mark_degraded(ctx, spec.name"):
        assert branch.index(marker) < merge_at, (
            f"{marker} must run before the merge — the entry has to exist first")


# ── light tier — the bogus finding ─────────────────────────────────────────

def test_light_does_not_emit_a_tech_finding_from_a_block_page(monkeypatch):
    """🔴 22 light runs in 30 days announced the WAF's banner as the asset's
    technology. An INFO finding that is simply wrong is still wrong."""
    import run_light as L
    ctx = types.SimpleNamespace(
        hostname="example.com", tools_run=[], artifacts=[], findings=[],
        tool_status={}, dsn=None)
    monkeypatch.setattr(L, "run_cmd",
                        lambda *a, **k: (0, json.dumps(BLOCKED_ROW), ""))
    monkeypatch.setattr(L, "httpx_tech_is_degraded", lambda rc, out: (False, ""))
    monkeypatch.setattr(L, "mark_tool_ok", lambda c, n: c.tool_status.setdefault(n, {"ok": True}))
    monkeypatch.setattr(L, "mark_tool_degraded",
                        lambda c, n, r, **k: c.tool_status.setdefault(n, {"degraded": r}))
    monkeypatch.setattr(L, "log", lambda *a, **k: None)

    L.check_httpx_tech(ctx)

    assert ctx.findings == [], (
        f"a block page must not produce a tech-disclosure finding: {ctx.findings}")
    assert ctx.tool_status["httpx_tech"].get("ok") is not True


def test_light_still_emits_the_finding_for_a_real_page(monkeypatch):
    """The discriminating half — the guard must not silence true detections."""
    import run_light as L
    ctx = types.SimpleNamespace(
        hostname="example.com", tools_run=[], artifacts=[], findings=[],
        tool_status={}, dsn=None)
    monkeypatch.setattr(L, "run_cmd",
                        lambda *a, **k: (0, json.dumps(CLEAN_ROW), ""))
    monkeypatch.setattr(L, "httpx_tech_is_degraded", lambda rc, out: (False, ""))
    monkeypatch.setattr(L, "mark_tool_ok", lambda c, n: c.tool_status.setdefault(n, {"ok": True}))
    monkeypatch.setattr(L, "mark_tool_degraded",
                        lambda c, n, r, **k: c.tool_status.setdefault(n, {"degraded": r}))
    monkeypatch.setattr(L, "log", lambda *a, **k: None)

    L.check_httpx_tech(ctx)

    assert len(ctx.findings) == 1, ctx.findings
    assert ctx.tool_status["httpx_tech"]["ok"] is True


def test_light_banks_an_artifact_medium_can_actually_read_back(monkeypatch):
    """The two halves of the fallback have to agree on the artifact format.
    This is the boundary that lost the evidence three times in this
    workstream — assert the round trip, not each side alone."""
    import run_light as L
    ctx = types.SimpleNamespace(
        hostname="example.com", tools_run=[], artifacts=[], findings=[],
        tool_status={}, dsn=None)
    monkeypatch.setattr(L, "run_cmd",
                        lambda *a, **k: (0, json.dumps(CLEAN_ROW), ""))
    monkeypatch.setattr(L, "httpx_tech_is_degraded", lambda rc, out: (False, ""))
    monkeypatch.setattr(L, "mark_tool_ok", lambda c, n: c.tool_status.setdefault(n, {"ok": True}))
    monkeypatch.setattr(L, "mark_tool_degraded",
                        lambda c, n, r, **k: c.tool_status.setdefault(n, {"degraded": r}))
    monkeypatch.setattr(L, "log", lambda *a, **k: None)
    L.check_httpx_tech(ctx)

    recovered, _n, _r = T.merge_tech_detection(
        T.tech_rows_from_artifacts(ctx.artifacts))
    assert recovered == {"wordpress", "php", "mysql"}, recovered
