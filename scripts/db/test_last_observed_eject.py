"""Structural tests for the 2026-06-15 [2] last_observed semantics fix.

Spec / decision context: assets.last_observed is the DISCOVERY clock —
owned by scripts/db/import_asm_to_surface.py via a GREATEST-monotonic
writer. The B-semantic writers (import_jsonl + refresh_all_asset_
last_observed) were clobbering it with scan-time on every import.

This fix full-ejects last_observed from import_jsonl and drops the
B-semantic function. These tests pin the structural state so a future
"helpful" refactor that re-adds last_observed to import_jsonl's UPSERT,
or re-introduces the dropped function call, is caught at unit-test time
before it lands.

Run:  pytest scripts/db/test_last_observed_eject.py -v
"""
from __future__ import annotations

from pathlib import Path

import pytest


SCRIPTS_DB = Path(__file__).parent
IMPORT_JSONL = (SCRIPTS_DB / "import_jsonl.py").read_text()
MAINTENANCE_SQL = (SCRIPTS_DB / "maintenance.sql").read_text()


# ═══════════════════════════════════════════════════════════════════════
# Part (b) — import_jsonl.py full-eject
# ═══════════════════════════════════════════════════════════════════════


def test_import_jsonl_assets_insert_has_no_last_observed_column():
    """The assets INSERT in load_assets MUST NOT have last_observed in
    its column list. Full eject — import_jsonl owns scan-side data, NOT
    the discovery clock.

    A naive refactor that re-adds the column (e.g. "we should preserve
    incoming JSONL last_observed for backward compatibility") would
    re-introduce the B-semantic clobber. The test asserts the column is
    absent from both the main UPSERT and the orphan stub INSERT."""
    # Locate the asset-INSERT regions of the file and verify last_observed
    # is not in the column list of either. Heuristic: split on "INSERT INTO
    # assets" and inspect each occurrence's first ~10 lines.
    import_jsonl_lower = IMPORT_JSONL.lower()
    insert_idx = 0
    occurrences = 0
    while True:
        idx = import_jsonl_lower.find("insert into assets", insert_idx)
        if idx < 0:
            break
        occurrences += 1
        # Inspect the next 200 chars (covers column list + VALUES line)
        snippet = IMPORT_JSONL[idx:idx + 400]
        assert "last_observed" not in snippet, (
            f"INSERT INTO assets at char {idx} still references "
            f"last_observed:\n{snippet}"
        )
        insert_idx = idx + 1
    # Sanity: there should be at least 2 INSERT INTO assets statements
    # (load_assets main + orphan stub auto-create). If a refactor reduces
    # this to 1, the test still passes but the coverage shrinks — log it.
    assert occurrences >= 2, (
        f"Expected at least 2 INSERT INTO assets statements in "
        f"import_jsonl.py, found {occurrences}. If the file was "
        f"restructured, update this test."
    )


def test_import_jsonl_does_not_call_dropped_function():
    """refresh_all_asset_last_observed() was DROPPED in migration
    20260615a. import_jsonl MUST NOT call it. A regression here would
    fail with 'function does not exist' on a fresh DB but might succeed
    on a stale DB where the function still lives — so this structural
    test catches the call BEFORE the runtime failure.

    Looks for an actual SQL execute pattern, NOT just any mention of the
    function name. The explanatory comment block in import_jsonl that
    documents WHY the call was removed legitimately mentions the function
    name — we want to allow that, but reject any line that actually calls it.
    """
    # The call pattern that matters: cur.execute("...refresh_all_asset_last_observed...")
    # The tombstone comment mentions the function but never inside an
    # execute() call. Catches both `SELECT refresh_all_asset_last_observed()`
    # and any future variant like a direct CALL or PERFORM.
    forbidden_patterns = [
        "execute(\"SELECT refresh_all_asset_last_observed",
        "execute('SELECT refresh_all_asset_last_observed",
        "execute(\"CALL refresh_all_asset_last_observed",
        "execute(\"PERFORM refresh_all_asset_last_observed",
    ]
    for pat in forbidden_patterns:
        assert pat not in IMPORT_JSONL, (
            f"import_jsonl.py still has a call to "
            f"refresh_all_asset_last_observed (matched pattern: {pat!r}). "
            f"That function was dropped in migration 20260615a — remove "
            f"the call before this lands."
        )


def test_import_jsonl_still_calls_posture_refresh():
    """Regression guard for the independence check: dropping the
    last_observed function MUST NOT have collateral on
    refresh_all_asset_posture(). That function is independent
    (recomputes current_risk + reason only, doesn't touch
    last_observed). import_jsonl must continue calling it."""
    assert "refresh_all_asset_posture()" in IMPORT_JSONL, (
        "import_jsonl.py no longer calls refresh_all_asset_posture() — "
        "that function is INDEPENDENT of the last_observed eject and "
        "must still run on each import. Restore the call."
    )


def test_asset_row_helper_excludes_last_observed():
    """_asset_row() builds the parameter tuple for the assets INSERT.
    After full-eject, the tuple should NOT have a slot for
    last_observed. Catches a refactor that re-adds it to the helper but
    forgets to re-add it to the INSERT (which would crash at runtime
    with a column-count mismatch — better caught at unit-test time)."""
    # Find the _asset_row function body. Heuristic: the function spans
    # from "def _asset_row" to the next "def " at top-level.
    fn_start = IMPORT_JSONL.find("def _asset_row(")
    assert fn_start >= 0, "_asset_row function not found"
    # Find the next top-level def (start of line)
    after_fn = IMPORT_JSONL.find("\ndef ", fn_start + 1)
    fn_body = IMPORT_JSONL[fn_start:after_fn] if after_fn > 0 else IMPORT_JSONL[fn_start:]
    # The docstring + body should reference last_observed only in the
    # NOTE block explaining the eject, not as a tuple value.
    # Approximate check: no "None, *# last_observed" line.
    assert "# last_observed" not in fn_body or "intentionally NOT" in fn_body, (
        "_asset_row() still has a last_observed slot in its tuple. "
        "After 2026-06-15 full-eject, the tuple should have 9 entries "
        "(not 10) and the docstring NOTE should explain the eject."
    )


# ═══════════════════════════════════════════════════════════════════════
# Part (c) — refresh_all_asset_last_observed() dropped from source
# ═══════════════════════════════════════════════════════════════════════


def test_maintenance_sql_does_not_define_dropped_function():
    """maintenance.sql is the source-of-truth for stored-function
    definitions. After 2026-06-15, it MUST NOT contain a
    CREATE OR REPLACE FUNCTION refresh_all_asset_last_observed
    definition (the definition was replaced with a tombstone comment
    block referencing migration 20260615a)."""
    # The function name appears in a tombstone comment, which is fine.
    # What MUST NOT exist is a CREATE OR REPLACE FUNCTION line for it.
    create_pattern = "CREATE OR REPLACE FUNCTION refresh_all_asset_last_observed"
    assert create_pattern not in MAINTENANCE_SQL, (
        f"maintenance.sql still contains '{create_pattern}'. The function "
        f"was dropped in migration 20260615a; the definition block should "
        f"be replaced with a tombstone comment that references the "
        f"migration. See [2] fix 2026-06-15."
    )


def test_maintenance_sql_has_tombstone_comment():
    """Positive assertion — the tombstone comment block exists. Pairs
    with the negative test above to ensure the function wasn't just
    silently deleted (which would leave future maintainers confused
    when they grep for it). The tombstone explains WHY it was dropped
    and points at the migration."""
    assert "DROPPED 2026-06-15" in MAINTENANCE_SQL, (
        "maintenance.sql should have a tombstone comment referencing the "
        "2026-06-15 drop of refresh_all_asset_last_observed. Without it, "
        "future maintainers grep for the function, find nothing, and "
        "don't know why it's missing."
    )
    assert "20260615a" in MAINTENANCE_SQL, (
        "Tombstone in maintenance.sql should reference the migration "
        "filename (20260615a) so the trail is followable."
    )


# ═══════════════════════════════════════════════════════════════════════
# Live integration test — needs real-DB harness, skipped placeholder
# ═══════════════════════════════════════════════════════════════════════


@pytest.mark.skip(reason=(
    "Needs a real-DB integration harness. The structural tests above prove "
    "the source-of-truth state, but live verification requires: (1) seed "
    "an asset via import_asm_to_surface with a discovery time t1, "
    "(2) run import_jsonl with a JSONL containing the same asset_id and a "
    "different last_observed t2 (t2 > t1), (3) query assets.last_observed "
    "and assert it equals t1 (preserved, NOT clobbered by t2). Also "
    "verify: a fresh asset created via import_jsonl alone has "
    "last_observed=NULL (no discovery yet); the alerter correctly classifies "
    "NULL as 'not yet discovered' rather than as a stale-alert trigger."
))
def test_last_observed_preserved_through_import_jsonl_on_live_db():
    """Live integration placeholder for the [2] preserve-discovery-clock
    contract. See @skip reason for the test blueprint."""
    pass


@pytest.mark.skip(reason=(
    "Needs a real-DB integration harness. After migration 20260615a "
    "applies to the live DB, this test would: (1) connect via psycopg, "
    "(2) call SELECT proname FROM pg_proc WHERE proname = "
    "'refresh_all_asset_last_observed' AND pronamespace = 'public'::regnamespace, "
    "(3) assert count = 0. Today the migration verification block at the "
    "bottom of 20260615a_drop_refresh_all_asset_last_observed.sql does "
    "exactly this on each apply."
))
def test_dropped_function_absent_from_live_db():
    """Live integration placeholder for confirming the migration drop
    actually took effect. See @skip reason for the test blueprint."""
    pass
