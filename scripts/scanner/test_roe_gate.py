"""Pytest unit tests for roe_gate.check_ownership_or_block().

Per advisor 2026-06-11 ("an 'airtight' claim needs an automated assertion"),
covers the full decision matrix:

  - light intensity (no gate)
  - medium + ownership ∈ {owned, test_target}                  → proceed
  - medium + ownership ∈ {unknown, namesake, NULL, 'whatever'} → BLOCK
  - medium + asset row missing                                 → BLOCK
  - medium + DB error during ownership lookup                  → BLOCK
  - heavy follows the same gate (parametrized)

Run:  pytest scripts/scanner/test_roe_gate.py -v

These tests use unittest.mock to stub the psycopg connection so we never
touch a real database. The gate's side effects (_stamp_failed + _send_alert)
are also patched — this suite is about the decision logic, not delivery.
The alert-delivery and stamp-failed paths are tested via the live
acceptance bar B (direct INSERT + scanner dispatch) in note 84.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Make scripts/scanner importable for `from roe_gate import ...` semantic
# matching the way run_medium.py imports it (same directory).
sys.path.insert(0, str(Path(__file__).parent))

import roe_gate
from roe_gate import (
    ROE_OWNERSHIP_ALLOWLIST,
    GateResult,
    check_ownership_or_block,
)


# ─── Fixtures ──────────────────────────────────────────────────────────


def _mock_conn(ownership_row: Any = "MISSING", raise_on_query: bool = False):
    """Return a MagicMock connection whose cursor.fetchone() returns the
    given row (or raises if raise_on_query=True).

    `ownership_row`:
      - "MISSING" sentinel → fetchone returns None (asset row missing)
      - dict like {"ownership": "owned"} → fetchone returns the dict
      - tuple like ("owned",) → fetchone returns the tuple
      - any other value → wrapped in a {"ownership": value} dict
    """
    conn = MagicMock()
    cursor = MagicMock()

    if raise_on_query:
        cursor.execute.side_effect = RuntimeError("simulated DB blip")
    elif ownership_row == "MISSING":
        cursor.fetchone.return_value = None
    elif isinstance(ownership_row, (dict, tuple, list)):
        cursor.fetchone.return_value = ownership_row
    else:
        cursor.fetchone.return_value = {"ownership": ownership_row}

    # Support `with conn.cursor() as cur:` context-manager pattern.
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=None)
    conn.cursor.return_value = cursor

    return conn


@pytest.fixture(autouse=True)
def _stub_side_effects():
    """Stub _stamp_failed and _send_alert so unit tests focus on decision
    logic. The live Bar B verifies the side-effect paths end-to-end."""
    with patch.object(roe_gate, "_stamp_failed") as stamp, patch.object(
        roe_gate, "_send_alert"
    ) as alert:
        yield stamp, alert


# ─── Light → no gate (no DB hit) ───────────────────────────────────────


def test_light_short_circuits_with_no_db_hit():
    conn = MagicMock()  # would raise if anyone tried to use it
    result = check_ownership_or_block(
        conn=conn,
        asset_id="any-asset.invalid",
        intensity="light",
        scan_run_id="sr-1",
        queue_id="qid-1",
    )
    assert result is None
    # Critical: light must NOT touch the DB. Any access on `conn` here
    # would mean we accidentally regressed and added DB cost to light.
    assert not conn.cursor.called


# ─── Allowed ownership → proceed ───────────────────────────────────────


@pytest.mark.parametrize("ownership", sorted(ROE_OWNERSHIP_ALLOWLIST))
@pytest.mark.parametrize("intensity", ["medium", "heavy"])
def test_allowed_ownership_proceeds(ownership, intensity, _stub_side_effects):
    conn = _mock_conn(ownership_row=ownership)
    result = check_ownership_or_block(
        conn=conn,
        asset_id="ok-asset.example.com",
        intensity=intensity,
        scan_run_id="sr-2",
        queue_id="qid-2",
    )
    assert result is None
    # Allowed paths do NOT call _stamp_failed or _send_alert.
    stamp, alert = _stub_side_effects
    assert stamp.call_count == 0
    assert alert.call_count == 0


# ─── Blocked ownership values → block ──────────────────────────────────


@pytest.mark.parametrize(
    "ownership",
    [
        "unknown",
        "namesake",
        "anything-else",
        "owned ",   # trailing-space typo — strict match, should block
        " owned",   # leading-space typo
        "OWNED",    # case-sensitive: enum is lowercase
        None,       # NULL ownership column
    ],
)
@pytest.mark.parametrize("intensity", ["medium", "heavy"])
def test_blocked_ownership_returns_gate_result(
    ownership, intensity, _stub_side_effects
):
    conn = _mock_conn(ownership_row=ownership)
    result = check_ownership_or_block(
        conn=conn,
        asset_id="blocked.example.com",
        intensity=intensity,
        scan_run_id="sr-3",
        queue_id="qid-3",
    )
    assert isinstance(result, GateResult)
    assert result.reason == "ownership_not_allowed"
    assert result.intensity == intensity
    assert result.asset_id == "blocked.example.com"
    # Ownership echoed back so the alert + log can name the offender.
    assert result.ownership == ownership
    # Block paths MUST trigger both side effects.
    stamp, alert = _stub_side_effects
    assert stamp.call_count == 1
    assert alert.call_count == 1


# ─── Asset row missing → block (fail-closed) ───────────────────────────


@pytest.mark.parametrize("intensity", ["medium", "heavy"])
def test_missing_asset_blocks_fail_closed(intensity, _stub_side_effects):
    conn = _mock_conn(ownership_row="MISSING")  # fetchone → None
    result = check_ownership_or_block(
        conn=conn,
        asset_id="never-existed.invalid",
        intensity=intensity,
        scan_run_id="sr-4",
        queue_id="qid-4",
    )
    assert isinstance(result, GateResult)
    assert result.reason == "asset_not_found"
    assert result.ownership is None
    stamp, alert = _stub_side_effects
    assert stamp.call_count == 1
    assert alert.call_count == 1


# ─── DB error on lookup → block (fail-closed) ──────────────────────────


@pytest.mark.parametrize("intensity", ["medium", "heavy"])
def test_db_error_during_lookup_blocks_fail_closed(intensity, _stub_side_effects):
    conn = _mock_conn(raise_on_query=True)
    result = check_ownership_or_block(
        conn=conn,
        asset_id="db-flake.example.com",
        intensity=intensity,
        scan_run_id="sr-5",
        queue_id="qid-5",
    )
    assert isinstance(result, GateResult)
    assert result.reason == "db_error"
    assert result.ownership is None
    stamp, alert = _stub_side_effects
    assert stamp.call_count == 1
    assert alert.call_count == 1


# ─── Tuple-style cursor rows (in case psycopg config changes) ──────────


@pytest.mark.parametrize("intensity", ["medium", "heavy"])
def test_tuple_row_shape_also_works(intensity, _stub_side_effects):
    """psycopg can return tuple rows or dict rows depending on row_factory.
    The gate handles both; if this test breaks, the row-shape branch in
    roe_gate.py needs to be widened."""
    conn = _mock_conn(ownership_row=("owned",))
    result = check_ownership_or_block(
        conn=conn,
        asset_id="ok.example.com",
        intensity=intensity,
        scan_run_id="sr-6",
        queue_id="qid-6",
    )
    assert result is None


# ─── Allowlist invariants (catch silent drift) ─────────────────────────


def test_allowlist_is_exactly_owned_and_test_target():
    """Lock-in test: if anyone expands the allowlist without updating
    this assertion, CI fails. The corresponding portal-side allowlist
    in commandsentry-portal/src/lib/roe.ts must be updated TOGETHER
    with this list."""
    assert ROE_OWNERSHIP_ALLOWLIST == frozenset({"owned", "test_target"})


def test_is_routine_refusal_split_by_reason():
    """Lock-in for the 2026-06-11 QA fix that splits exit code by reason.
    Routine refusals (ownership_not_allowed) are SUCCESS — the scanner
    did its job. Fail-closed cases (asset_not_found, db_error) are
    FAILURE — the gate refused because something was broken.

    If you add a new reason code, decide explicitly which side of this
    line it belongs on and add a row here. Don't let an unrouted reason
    silently take the False (non-routine) default and start spamming
    Howie's failure-email channel."""
    assert GateResult(
        asset_id="x", intensity="medium", ownership="namesake",
        reason="ownership_not_allowed", message="m",
    ).is_routine_refusal() is True
    assert GateResult(
        asset_id="x", intensity="medium", ownership=None,
        reason="asset_not_found", message="m",
    ).is_routine_refusal() is False
    assert GateResult(
        asset_id="x", intensity="medium", ownership=None,
        reason="db_error", message="m",
    ).is_routine_refusal() is False


def test_unknown_intensity_short_circuits_as_non_active():
    """KNOWN gap worth pinning: any intensity NOT in {medium, heavy}
    short-circuits as 'not active'. In production the DB enum constrains
    intensity to {light, medium, heavy} so this case shouldn't reach the
    gate. But if a future caller (or migration) introduces a new
    intensity tier, the gate will skip it silently — and we'll want to
    catch that in CI by failing this test the moment _ACTIVE_INTENSITIES
    changes shape.

    If you add a new active tier (e.g. 'deep' for M9), update both:
      1. roe_gate.py::_ACTIVE_INTENSITIES (asm)
      2. roe.ts::ACTIVE_INTENSITIES (portal)
    Then update this test to reflect the new shape."""
    conn = _mock_conn(ownership_row="namesake")
    result = check_ownership_or_block(
        conn=conn,
        asset_id="anything.example.com",
        intensity="deep",  # not yet a real tier
        scan_run_id="sr-7",
        queue_id="qid-7",
    )
    # Today this returns None (skipped as non-active). When 'deep' becomes
    # real, flip this to expect a GateResult and add 'deep' to
    # _ACTIVE_INTENSITIES.
    assert result is None
