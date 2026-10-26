"""(KB 12 job 3t, S2, 2026-10-26) The went-dark writer runs LIVE, and only its own gates decide.

Howie, 18:52: "I would rather have this be some kind of an automated process". 18:53: "if a host
is unavailable after a certain amount of time, it's gone. It never has to be removed from the
database, but I don't want to see it on the portal anymore ... It doesn't require me to do
anything." 18:54: "Build S2." Switched on after the D9 read-back passed on both instances
(18:50): the dry-run log matched the portal's banner host for host.

Pins here:
  * asm-discover.yml runs the writer exactly once, with --write-enable, after the importer
    and the liveness probe worker, with its success() gate and its missing-DSN skip intact;
  * the flag the workflow passes is the flag the writer reads;
  * the gates that decide who leaves are the ruled ones: 7-day notice (D2), 5 per run and
    7 days live (July Q6), only a gone name or no answer at all (Howie 10-25 10:00), and a
    host nobody was warned about, or whose week is not up, is held;
  * nothing deletes: the writer's only write to a host is a status flip it audits.
"""
import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import demotion_writer as dw  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WORKFLOW = os.path.join(HERE, "..", "..", ".github", "workflows", "asm-discover.yml")
WRITER = os.path.join(HERE, "demotion_writer.py")


def _wf():
    return open(WORKFLOW, encoding="utf-8").read()


def _step(src, name_prefix):
    i = src.index(f"- name: {name_prefix}")
    j = src.find("\n      - name: ", i + 1)
    return src[i:j if j > 0 else len(src)]


def test_the_writer_runs_once_and_live():
    src = _wf()
    calls = re.findall(r"^\s*python3 scripts/db/demotion_writer\.py[^\n]*$", src, re.M)
    assert len(calls) == 1, calls
    assert calls[0].strip() == 'python3 scripts/db/demotion_writer.py --run-tag "${GITHUB_RUN_ID}" --write-enable'
    step = _step(src, "P2 demotion writer")
    assert step.startswith("- name: P2 demotion writer (LIVE")
    assert "if: success() && steps.targets.outputs.mode != 'skipped'" in step
    assert 'if [[ -z "${SUPABASE_DSN}" ]]; then' in step and "exit 0" in step
    assert src.count("--write-enable") == 2, "the flag on the command line, and its one comment"


def test_the_writer_runs_after_the_importer_and_the_liveness_worker():
    src = _wf()
    order = [src.index(s) for s in (
        "python3 scripts/db/import_asm_to_surface.py --source-tag asm_cron",
        "python3 scripts/db/asset_liveness_probe.py --run-tag",
        "python3 scripts/db/demotion_writer.py --run-tag",
    )]
    assert order == sorted(order)


def test_the_flag_the_workflow_passes_is_the_flag_the_writer_reads():
    w = open(WRITER, encoding="utf-8").read()
    assert 'ap.add_argument("--write-enable", action="store_true",' in w


def test_the_gates_are_the_ruled_ones():
    assert dw.NOTICE_DAYS == 7
    assert dw.DWELL_DAYS == {"dns_gone": 7, "service_gone": 7, "unreachable": 7}
    assert dw.REMOVABLE_REASONS == ("dns_gone", "unreachable")
    assert dw.RATE_LIMIT == 5 and dw.MIN_LIVE_DAYS == 7


def test_nobody_leaves_unwarned_early_or_over_the_limit():
    at = datetime(2026, 11, 2, 18, 0, tzinfo=timezone.utc)
    old = at - timedelta(days=90)
    week = at - timedelta(days=8)
    assert dw.flip_decision(notice_since=None, leaves_on=None, first_observed=old,
                            demoted_so_far=0, at=at) == "no_notice_yet"
    assert dw.flip_decision(notice_since=at - timedelta(days=3), leaves_on=at + timedelta(days=4),
                            first_observed=old, demoted_so_far=0, at=at) == "within_dwell"
    assert dw.flip_decision(notice_since=week, leaves_on=None, first_observed=old,
                            demoted_so_far=0, at=at) == "within_dwell"
    assert dw.flip_decision(notice_since=week, leaves_on=at - timedelta(hours=1),
                            first_observed=at - timedelta(days=2), demoted_so_far=0, at=at) == "not_eligible_7d"
    assert dw.flip_decision(notice_since=week, leaves_on=at - timedelta(hours=1),
                            first_observed=old, demoted_so_far=5, at=at) == "rate_limited"
    assert dw.flip_decision(notice_since=week, leaves_on=at - timedelta(hours=1),
                            first_observed=old, demoted_so_far=0, at=at) is None


def test_nothing_deletes():
    w = open(WRITER, encoding="utf-8").read()
    code = "\n".join(l for l in w.splitlines() if not l.lstrip().startswith("#"))
    assert not re.search(r"\bDELETE\s+FROM\b", code, re.I), "the writer never deletes a row"
    assert "discovery_status = 'went_dark'" in code, "a host that leaves is flipped, not removed"
