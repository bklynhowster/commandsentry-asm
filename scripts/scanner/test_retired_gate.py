"""test_retired_gate.py — KB 12 job 4 step 5 (plan v4.1 C5, 2026-11-08): RETIRED MEANS RETIRED.

A retired name (assets.discovery_status = 'retired') is never scanned, at any intensity, and
nothing that promotes or revives a name can bring it back. This file pins both halves:

  1. roe_gate.check_retired_or_block: the decision matrix (retired refused as a routine
     refusal at light, medium and heavy; a live name proceeds; a missing row or an unreadable
     status fails closed), and the rows are stamped failed with a plain message.
  2. Every runner calls it before anything is sent to the target (source pins: light before
     port_scan; medium and heavy right after the ROE ownership check, inside the same gate).
  3. Nothing lifts a retired name: the light scan's promote (run_light), the importer's two
     upserts (import_asm_to_surface) and the dark-name revival (asset_liveness) each name the
     statuses they change, and 'retired' is never one of them.

Offline: a mocked connection, no database, no network.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "common"))
sys.path.insert(0, str(HERE.parent / "db"))

import roe_gate  # noqa: E402
from roe_gate import GateResult, check_retired_or_block  # noqa: E402

SCANNER = HERE
DB = HERE.parent / "db"


def _conn(row: Any = "MISSING", raise_on_query: bool = False):
    conn = MagicMock()
    cur = MagicMock()
    if raise_on_query:
        cur.execute.side_effect = RuntimeError("simulated DB blip")
    elif row == "MISSING":
        cur.fetchone.return_value = None
    else:
        cur.fetchone.return_value = row
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=None)
    conn.cursor.return_value = cur
    return conn, cur


@pytest.fixture(autouse=True)
def _no_side_effects():
    """No DB write, no alert, no real sleep between retries."""
    real = roe_gate.run_with_transport_retry
    with patch.object(roe_gate, "_stamp_failed") as stamp, \
         patch.object(roe_gate, "_send_alert") as alert, \
         patch.object(roe_gate, "run_with_transport_retry",
                      side_effect=lambda fn, b, on_retry=None: real(fn, b, on_retry=on_retry, sleep=lambda s: None)):
        yield stamp, alert


def _call(conn, intensity="light"):
    return check_retired_or_block(conn=conn, asset_id="www.ghost.example.invalid",
                                  intensity=intensity, scan_run_id="sr-1", queue_id="q-1")


# ── 1. the decision matrix ──────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("intensity", ["light", "medium", "heavy"])
def test_a_retired_name_is_refused_at_every_intensity(intensity, _no_side_effects):
    conn, cur = _conn({"discovery_status": "retired"})
    r = _call(conn, intensity)
    assert isinstance(r, GateResult)
    assert r.reason == "asset_retired"
    assert r.is_routine_refusal(), "a retired name refused is routine (exit 0), not a broken gate"
    stamp, alert = _no_side_effects
    assert stamp.call_count == 1, "scan_run and scan_queue are stamped failed"
    assert alert.call_count == 0, "no alert email: a retired name refused is not an ROE event"
    msg = stamp.call_args[0][3]
    assert msg.startswith("retired_block:") and "Nothing was sent" in msg
    # the portal prints error_message as written (lesson 114): no addresses in it
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", msg)
    sql = cur.execute.call_args[0][0]
    assert "discovery_status" in sql and "public.assets" in sql


def test_tuple_rows_work_too(_no_side_effects):
    conn, _ = _conn(("retired",))
    assert _call(conn, "heavy").reason == "asset_retired"


@pytest.mark.parametrize("status", ["confirmed_live", "ct_ghost", "unverified", "dns_only",
                                    "went_dark", "confirmed_dark", None, "Retired", "retired "])
@pytest.mark.parametrize("intensity", ["light", "medium", "heavy"])
def test_anything_else_proceeds_untouched(status, intensity, _no_side_effects):
    """Only the exact value 'retired' refuses. (The column is written by code and migrations
    with that exact value; a near-miss proceeds as today rather than refusing on a guess.)"""
    conn, _ = _conn({"discovery_status": status})
    assert _call(conn, intensity) is None
    stamp, alert = _no_side_effects
    assert stamp.call_count == 0 and alert.call_count == 0


def test_a_missing_asset_row_fails_closed(_no_side_effects):
    conn, _ = _conn("MISSING")
    r = _call(conn, "light")
    assert r.reason == "asset_not_found" and not r.is_routine_refusal()
    assert _no_side_effects[0].call_count == 1


def test_an_unreadable_status_fails_closed_after_retries(_no_side_effects):
    conn, cur = _conn(raise_on_query=True)
    r = _call(conn, "light")
    assert r.reason == "db_unreadable" and not r.is_routine_refusal()
    assert cur.execute.call_count == roe_gate.SAFETY.attempts, "the SAFETY retry budget is used"
    assert _no_side_effects[0].call_count == 1


def test_routine_refusals_are_exactly_ownership_and_retired():
    def gr(reason):
        return GateResult("a", "light", None, reason, "m")
    assert gr("ownership_not_allowed").is_routine_refusal()
    assert gr("asset_retired").is_routine_refusal()
    for reason in ("asset_not_found", "db_unreadable", "anything_else"):
        assert not gr(reason).is_routine_refusal(), reason


# ── 2. every runner asks before anything is sent ────────────────────────────────────────────
def _src(name: str) -> str:
    return (SCANNER / name).read_text()


def test_light_asks_right_after_connecting_and_before_port_scan():
    s = _src("run_light.py")
    run = s[s.index("def run(descriptor_path: str, dsn: str) -> int:"):]
    i_conn = run.index("conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)")
    i_gate = run.index("block = check_retired_or_block(")
    i_scan = run.index('log("→ port_scan")')
    assert i_conn < i_gate < i_scan
    between = run[i_gate:i_scan]
    assert "return 0" in between and "return 1" in between and "is_routine_refusal()" in between
    # an exception in the check fails closed; a routine refusal (retired) exits 0
    exc = run[run.index('log(f"FATAL: retired check raised:', i_gate):run.index("if block is not None:", i_gate)]
    assert "return 1" in exc, "an exception in the retired check must fail closed (exit 1)"
    routine = between[between.index("if block.is_routine_refusal():"):]
    assert routine.split("return", 1)[1].lstrip().startswith("0"), "retired is a routine refusal: exit 0"
    # nothing target-bound happens before the gate in run()
    before = run[:i_gate]
    for call in ("port_scan(", "run_cmd(", "requests.", "socket.create_connection", "curl"):
        assert call not in before.replace('log("→ port_scan")', ""), call


@pytest.mark.parametrize("runner", ["run_medium.py", "run_heavy.py"])
def test_medium_and_heavy_ask_inside_the_roe_gate(runner):
    s = _src(runner)
    i_own = s.index("block = check_ownership_or_block(")
    i_ret = s.index("block = check_retired_or_block(", i_own)
    i_exc = s.index('log(f"FATAL: ROE gate raised:', i_own)
    i_clear = s.index("# ─── Gate cleared", i_own)
    assert i_own < i_ret < i_exc < i_clear, "retired check sits inside the gate's try, before the scan starts"
    assert "if block is None:" in s[i_own:i_ret]
    assert "from roe_gate import check_ownership_or_block, check_retired_or_block" in s


# ── 3. nothing lifts a retired name ─────────────────────────────────────────────────────────
def test_the_light_promote_never_lifts_a_retired_name():
    s = _src("run_light.py")
    m = re.search(r"SET discovery_status = 'confirmed_live'.*?AND discovery_status IN \(([^)]*)\)", s, re.S)
    assert m, "the light promote statement moved: re-pin it"
    statuses = {x.strip().strip("'") for x in m.group(1).split(",")}
    assert statuses == {"ct_ghost", "unverified", "dns_only"}
    assert "retired" not in statuses


def test_the_importer_upserts_never_lift_a_retired_name():
    s = (DB / "import_asm_to_surface.py").read_text()
    cases = re.findall(r"discovery_status = CASE\s+WHEN EXCLUDED\.discovery_status = 'confirmed_live'\s+"
                       r"AND public\.assets\.discovery_status IN \(([^)]*)\)\s+THEN 'confirmed_live'\s+"
                       r"ELSE public\.assets\.discovery_status", s)
    assert len(cases) == 2, "both upserts keep their promote-only CASE"
    for c in cases:
        statuses = {x.strip().strip("'") for x in c.split(",")}
        assert statuses == {"ct_ghost", "unverified", "dns_only"}


def test_dark_revival_never_touches_a_retired_name():
    import asset_liveness
    assert "retired" not in asset_liveness._DARK_STATUSES
    assert set(asset_liveness._DARK_STATUSES) == {"confirmed_dark", "went_dark"}
    assert "discovery_status = ANY(%(dark_statuses)s)" in asset_liveness.RESURRECT_ASSET_SQL
