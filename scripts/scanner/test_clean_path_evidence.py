"""Wiring tests for clean-path nuclei evidence (spec 220, 4.7 83-87).

test_tool_evidence.py proves the Evidence TYPE is right. This proves it is
actually CONNECTED to nuclei's clean-completion path — the ⑭′ lesson, and the
one that bit again this week when _canonical_probe's body had no test and
raised NameError on every live call.

Run: python -m pytest scripts/scanner/test_clean_path_evidence.py -q
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import run_medium
from run_medium import ScanContext
from tool_evidence import Evidence, MEASURED, UNMEASURABLE

SRC = Path(__file__).with_name("run_medium.py").read_text()


def _strip_comments(src: str) -> str:
    """Assert on CODE, not prose (the .limit(1000) pin episode)."""
    out = []
    for line in src.splitlines():
        if line.strip().startswith("#"):
            continue
        out.append(line.split("  #", 1)[0])
    return "\n".join(out)


CODE = _strip_comments(SRC)


def mkctx():
    return ScanContext(
        descriptor={}, hostname="x.example", asset_id="x.example",
        scan_run_id="s", queue_id="q", intensity="medium",
    )


# ─── The primitive ───────────────────────────────────────────────────────


def test_evidenced_primitive_records_the_measurement():
    ctx = mkctx()
    run_medium.mark_tool_ok_evidenced(
        ctx, "nuclei[medium:cve]",
        Evidence.measured(requests=8225, total=9039, percent=90),
    )
    entry = ctx.tool_status["nuclei[medium:cve]"]
    assert entry["ok"] is True
    assert entry["evidence"]["kind"] == MEASURED
    assert entry["evidence"]["requests"] == 8225
    assert entry["evidence"]["completion_ratio"] == pytest.approx(0.90)


def test_evidenced_primitive_records_unmeasurable_explicitly():
    ctx = mkctx()
    run_medium.mark_tool_ok_evidenced(
        ctx, "sometool", Evidence.unmeasurable("tool_exposes_no_counts")
    )
    entry = ctx.tool_status["sometool"]
    assert entry["ok"] is True, "phase 1 changes no verdicts"
    assert entry["evidence"]["kind"] == UNMEASURABLE
    assert entry["evidence"]["reason"] == "tool_exposes_no_counts"


def test_evidence_is_required_no_default():
    """A caller cannot skip the decision — that is the whole point."""
    ctx = mkctx()
    with pytest.raises(TypeError):
        run_medium.mark_tool_ok_evidenced(ctx, "sometool")  # type: ignore[call-arg]


def test_phase1_does_not_downgrade_on_terrible_evidence():
    """4.7 (86): detection ships BEFORE autocloser impact. A dismal ratio must
    still record ok — flipping it would change closure behaviour on live data
    before the flip has been quantified."""
    ctx = mkctx()
    run_medium.mark_tool_ok_evidenced(
        ctx, "nuclei[critical,high]", Evidence.measured(requests=5, total=9039)
    )
    entry = ctx.tool_status["nuclei[critical,high]"]
    assert entry["ok"] is True
    assert "degraded" not in entry
    assert entry["evidence"]["completion_ratio"] < 0.001, (
        "…but the evidence must make the poverty of it visible"
    )


def test_evidence_does_not_collide_with_verdict_keys():
    """⑰ all-match reads tool_status->tool->>'ok'. Evidence must not disturb
    the keys the autoclose predicate branches on."""
    ctx = mkctx()
    run_medium.mark_tool_ok_evidenced(ctx, "t", Evidence.measured(items=1))
    entry = ctx.tool_status["t"]
    assert entry["ok"] is True
    assert set(entry) == {"ok", "evidence"}


# ─── Source pins: the wiring ─────────────────────────────────────────────


def test_stats_are_parsed_for_BOTH_branches():
    """The bug: `stats = parse_nuclei_stats(...)` lived INSIDE `if rc == 124`,
    so a completing chunk never had its stderr read.

    ⚠ The first version of this pin SURVIVED its own mutation. It was
    `parse_nuclei_stats\\(chunk_stderr\\)(.*?)if rc == 124:` with re.S over the
    whole file — and `run_nikto` has its OWN `if rc == 124:` 450 lines below.
    Pushing the parse back inside nuclei's branch still matched, against
    nikto's. Same family as the source pin that matched its own comment: a
    regex that spans further than the thing it claims to constrain.

    So: scoped to this function, and asserting INDENTATION (the parse must not
    be nested deeper than the branch) as well as order.
    """
    body = _nuclei_chunked_body()
    parse = re.search(
        r"^(?P<indent> *)stats = parse_nuclei_stats\(chunk_stderr\)\s*$",
        body, re.M,
    )
    assert parse, "the nuclei stats parse is gone from run_nuclei_chunked"
    cut = re.search(r"^(?P<indent> *)if rc == 124:\s*$", body, re.M)
    assert cut, "the rc==124 branch is gone from run_nuclei_chunked"

    assert len(parse.group("indent")) <= len(cut.group("indent")), (
        "stats parse is nested INSIDE the rc==124 branch — the clean path "
        "cannot see it. This is the 211-of-211 defect."
    )
    assert parse.start() < cut.start(), (
        "stats must be parsed BEFORE the rc==124 branch so the clean path "
        "can read it"
    )


def test_only_one_stats_parse_remains():
    """A second parse inside the cut branch would mean the hoist was additive
    rather than a move, and the two could drift."""
    assert CODE.count("parse_nuclei_stats(chunk_stderr)") == 1


def test_clean_path_uses_the_evidenced_primitive():
    assert re.search(
        r"mark_tool_ok_evidenced\(ctx, chunk_name, evidence\)", CODE
    ), "nuclei clean path must credit WITH evidence"


def _nuclei_chunked_body() -> str:
    """Just run_nuclei_chunked. Scoped deliberately: run_ffuf_chunked also has
    a `chunk_name` local, so a file-wide regex catches ffuf too and the pin
    stops meaning what it says."""
    m = re.search(
        r"def run_nuclei_chunked\(.*?\n(?=def [a-z_]+\()", CODE, re.S
    )
    assert m, "run_nuclei_chunked not found"
    return m.group(0)


def test_nuclei_clean_path_no_longer_calls_the_bare_primitive():
    """The specific regression: reverting nuclei's clean path to bare
    mark_tool_ok(ctx, chunk_name)."""
    body = _nuclei_chunked_body()
    assert not re.search(r"mark_tool_ok\(ctx, chunk_name\)", body), (
        "nuclei clean path reverted to the unevidenced primitive"
    )
    assert "mark_tool_ok_evidenced(ctx, chunk_name, evidence)" in body


# ─── Migration progress — 4.7 (84) phase-3 gate ──────────────────────────
#
# The named risk is the migration stalling half-done (both primitives alive,
# mixed usage, evidence not actually required). This pins the CURRENT count of
# unmigrated call sites so it can only ever be decremented DELIBERATELY, and
# the remaining list stays visible in CI instead of being forgotten.

BARE_CALL_SITES_REMAINING = 5  # wafw00f, httpx[-td], katana, nikto, ffuf


def test_migration_progress_is_tracked():
    # (?<!def ) excludes the definition itself; \b stops it matching
    # mark_tool_ok_evidenced.
    bare = re.findall(r"(?<!def )\bmark_tool_ok\((?!ctx: ScanContext)[^)]*\)", CODE)
    assert len(bare) == BARE_CALL_SITES_REMAINING, (
        f"unmigrated bare mark_tool_ok() call sites changed: expected "
        f"{BARE_CALL_SITES_REMAINING}, found {len(bare)}: {bare}. If you "
        f"MIGRATED one, decrement the constant. If you ADDED one, don't — "
        f"use mark_tool_ok_evidenced()."
    )


def test_old_primitive_is_marked_deprecated():
    """It still exists (phase 1 keeps it for the other 24 call sites) but must
    announce itself, so nobody adds a NEW bare call site by accident."""
    m = re.search(r"def mark_tool_ok\(ctx: ScanContext, tool_name: str\).*?\"\"\"(.*?)\"\"\"",
                  SRC, re.S)
    assert m, "old primitive not found"
    assert "DEPRECATED" in m.group(1)


def test_evidence_is_imported():
    assert re.search(r"from tool_evidence import Evidence", CODE)
