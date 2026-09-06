"""
test_degraded_persists_findings.py — the degraded heavy scan MUST still persist its findings.

WHY THIS EXISTS (2026-09-06). A degraded scan is the case where we most need the evidence:
the tool set partially failed, and whatever it DID collect is the only record of that attempt.
The except-DegradedRunError branch in run_heavy.run() therefore opens a FRESH connection,
re-runs the findings write, stamps the run degraded, and commits.

That safety net has never actually fired with data: all 8 degraded runs across the fleet recorded
findings_added=0, and `findings.scan_quality` is 'clean' for every row — so nothing has ever
exercised it end to end. That is NOT evidence it is broken (see the stamp semantics below), but it
does mean a regression here would be invisible in production until the day it matters.

These tests pin the wiring and the semantics so a reorder or deletion fails CI instead.

STAMP SEMANTICS (why no 'degraded' rows exist yet, and why that is correct):
STAMP_FINDINGS_DEGRADED_SQL keys on `first_detected_scan = scan_run_id` — it marks ONLY findings
FIRST DISCOVERED by the degraded run. A degraded run that merely RE-OBSERVES an existing finding
leaves it 'clean', which is right: that finding's original detection was clean. Every degraded run
so far added 0 new findings, so there was correctly nothing to stamp.
"""
import inspect
import re

import run_heavy
import run_medium


def _decomment(src: str) -> str:
    """Strip comments AND docstrings before source-pinning.

    A pin that matches its own explanatory comment passes with the defect present — that has
    bitten this repo before. Assert on CODE only.
    """
    src = re.sub(r'""".*?"""', "", src, flags=re.S)
    src = re.sub(r"'''.*?'''", "", src, flags=re.S)
    return "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))


# ── the load-bearing wiring: write findings BEFORE stamping degraded, then COMMIT ────────────
def test_degraded_branch_writes_findings_then_stamps_then_commits():
    src = _decomment(inspect.getsource(run_heavy.run))
    i_except = src.index("except DegradedRunError")
    branch = src[i_except:]
    # bound the branch at the next top-level except so we do not read the clean path
    nxt = branch.find("except Exception as e:")
    if nxt > 0:
        branch = branch[:nxt]

    i_write = branch.find("write_event_findings_and_artifacts")
    i_stamp = branch.find("degraded_out_heavy")
    i_commit = branch.find("conn.commit()")

    assert i_write > 0, (
        "the degraded branch MUST re-write findings — without it, everything the scan collected "
        "is rolled back with the aborted transaction and the degraded run records nothing")
    assert i_stamp > 0, "the degraded branch must call degraded_out_heavy"
    assert i_commit > 0, (
        "the degraded branch MUST commit — an uncommitted degraded write is identical to no write")
    assert i_write < i_stamp < i_commit, (
        f"order must be write -> degraded_out_heavy -> commit, got "
        f"write@{i_write} stamp@{i_stamp} commit@{i_commit}")


def test_degraded_branch_opens_its_own_connection():
    """The original conn's transaction is poisoned by the abort; reusing it would silently
    discard the write. The branch must open a fresh one."""
    src = _decomment(inspect.getsource(run_heavy.run))
    branch = src[src.index("except DegradedRunError"):]
    nxt = branch.find("except Exception as e:")
    if nxt > 0:
        branch = branch[:nxt]
    assert "psycopg.connect" in branch, (
        "degraded branch must open a FRESH connection — the aborted txn cannot be committed")


# ── degraded_out_heavy actually issues the stamp ─────────────────────────────────────────────
class _Cur:
    def __init__(self):
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        return None


class _Conn:
    def __init__(self, cur):
        self._cur = cur

    def cursor(self):
        return self._cur


class _Ctx:
    def __init__(self):
        self.tools_run = ["testssl"]
        self.tool_status = {"testssl": {"degraded": "wall_timeout"}}
        self.scan_run_id = "sr-degraded-test"
        self.queue_id = "q-degraded-test"
        self.asset_id = "example.test"
        self.hostname = "example.test"
        self.egress_ip_initial = None
        self.vpn_config_used = None
        self.rotation_count = 0
        self.egress_ips_seen = []
        self.ban_events = []
        self.healthcheck_failures = []
        self.rotation_storm = False


def test_degraded_out_heavy_stamps_findings_degraded():
    cur = _Cur()
    run_heavy.degraded_out_heavy(_Conn(cur), _Ctx(), "degraded: testssl wall_timeout",
                                 inserted=3, updated=0, Json=lambda x: x)
    stamps = [(s, p) for s, p in cur.executed if "SET scan_quality" in s]
    assert len(stamps) == 1, f"degraded_out_heavy must stamp findings exactly once, got {len(stamps)}"
    sql, params = stamps[0]
    assert params["scan_run_id"] == "sr-degraded-test"
    assert "validation_status = 'unvalidated'" in sql, "a degraded finding must not stay validated"


def test_stamp_keys_on_first_detected_scan_only():
    """Documents the semantic that explains why no 'degraded' findings exist yet: only findings
    FIRST DISCOVERED by the degraded run are demoted. Re-observations keep their clean origin."""
    sql = run_medium.STAMP_FINDINGS_DEGRADED_SQL
    assert "first_detected_scan = %(scan_run_id)s" in sql, (
        "stamp must key on first_detected_scan — keying on last_seen_scan_run would retroactively "
        "demote findings whose original detection was clean")
    assert "last_seen_scan_run" not in sql
