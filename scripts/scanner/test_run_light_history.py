"""
test_run_light_history.py — regression guards for run_light's finding_history
wiring (4.7 H1-H9, LIGHT_SCAN_FINDING_HISTORY_SPEC.md, 2026-07-13).

Pure-logic/static by necessity: the scanner suite has no DB harness, so the
DB-LEVEL behaviors 4.7 named (go-forward self-heal, cross-tier separation,
mixed pre/post-fix scan, degraded zero-write at the row level) are validated
LIVE (run a light scan, watch the finding-page Scan history populate; run a
degraded one, confirm zero rows) or in a future integration-test PR.

What we CAN pin here without a DB — and what matters most — is the H2 upsert
wiring (4.7's #2 risk: a missing ON CONFLICT SET bump silently underwrites
history on re-observations) and the H3 gate wiring (run_light has no
degraded_out, so the write MUST be gated on delta_close_eligible). The gate's
own clean-vs-degraded DECISION is already covered by test_degradation.py's
test_delta_close_eligible_* suite.
"""
import run_light


def test_upsert_stamps_last_seen_scan_run_on_insert_and_conflict():
    """H2 — BOTH the insert and the re-observation (ON CONFLICT) paths must set
    last_seen_scan_run. The writer selects `WHERE f.last_seen_scan_run =
    scan_run_id`, so a missing bump on the conflict path means re-observations
    write zero history (4.7's #2 risk — silent underwrite)."""
    sql = run_light.UPSERT_FINDING_SQL
    assert "last_seen_scan_run" in sql, "H2: last_seen_scan_run absent from upsert"
    assert "%(scan_run_id)s" in sql, "H2: scan_run_id not bound in VALUES"
    assert "last_seen_scan_run = EXCLUDED.last_seen_scan_run" in sql, (
        "H2 #2 risk: the ON CONFLICT SET must bump last_seen_scan_run on the "
        "conflict path — without it, re-observations write zero history."
    )


def test_history_write_gated_and_wired():
    """H3/H4 — run_light imports the gate (delta_close_eligible) and the shared
    writer (write_finding_history_for_scan_run). run_light has no degraded_out,
    so the write is gated; the gate's decision is covered by test_degradation."""
    assert hasattr(run_light, "delta_close_eligible"), "H3: gate not imported"
    assert hasattr(run_light, "write_finding_history_for_scan_run"), (
        "H4: shared writer not imported"
    )


def test_finding_source_is_tier_scoped_h1():
    """H1 — light findings are tier-scoped: a light finding's source is the
    DECLARED light tier, so it accumulates only its own light observations.

    As of spec 190 / 4.7 ruling 191 Q1 the source is tagged by declared tier via
    source_for_tier(LIGHT), NOT derived from run intensity
    (the old f"commandsentry_{ctx.intensity}"). Same tier-scoping — now invariant
    to which run invokes the phase, which is the prerequisite for cumulative
    tiers to dedup correctly (source is part of stable_finding_id). Pin BOTH the
    new mechanism and the ABSENCE of the old one, so a revert to
    intensity-derivation fails here."""
    import inspect
    from phase_source import source_for_tier, LIGHT
    src = inspect.getsource(run_light)
    assert "source_for_tier(LIGHT)" in src, (
        "H1: light source must be tagged by declared tier (source_for_tier(LIGHT))"
    )
    assert 'f"commandsentry_{ctx.intensity}"' not in src, (
        "H1: light source must NOT be re-derived from run intensity (spec 190/191 Q1)"
    )
    assert source_for_tier(LIGHT) == "commandsentry_light", (
        "H1: the light tier source value must remain commandsentry_light"
    )
