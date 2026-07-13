"""
finding_history_writer.py — shared per-scan finding_history writer.

Extracted from run_medium.py (4.7 ruling H4, LIGHT_SCAN_FINDING_HISTORY_SPEC.md,
2026-07-13): the writer is shared functionality, not medium-specific. All three
scan tiers (run_light / run_medium / run_heavy) import it and call it from their
CLEAN-path close-out, GATED on the tier's completeness signal
(delta_close_eligible(tool_status), 4.7 H3) — a degraded/partial scan must NOT
stamp history, because its observations can't be trusted (some tools ran, some
didn't; we can't tell which "observations" are real).

Note 129 round 7 (FINDING_HISTORY_FIX_SPEC.md) landed the writer for medium/heavy;
LIGHT_SCAN_FINDING_HISTORY_SPEC.md (4.7 H1-H9) extended it to run_light.
"""
from __future__ import annotations


INSERT_FINDING_HISTORY_FOR_SCAN_RUN_SQL = """
INSERT INTO public.finding_history
    (finding_id, scan_id, observed_at, status, severity_at_scan, notes)
SELECT
    f.finding_id,
    %(scan_run_id)s,
    now(),
    -- Round 7 follow-up #2: EXPLICIT enum → text → target-enum cast.
    -- findings.current_status is finding_status_t; finding_history.status
    -- is history_status_t — two distinct enum types with no direct
    -- cast between them. Postgres ALSO has no IMPLICIT text → enum
    -- assignment cast (live #811 proved my round-7-follow-up
    -- assumption wrong); the target column required an explicit
    -- cast. The double-cast pattern is the supported idiom:
    --   source_enum::text::target_enum
    -- Migration 20260629c made sure every finding_status_t label
    -- exists in history_status_t so the text → history_status_t
    -- cast cannot fail on a valid input.
    -- ('absent' is history-only — write_finding_history never emits
    -- it; it's reserved for offline reconciliation paths.)
    f.current_status::text::history_status_t,
    -- severity_at_scan is enum severity_t — SAME type as
    -- findings.severity — so no cast needed (would be a no-op
    -- round-trip if added).
    f.severity,
    %(notes)s
  FROM public.findings f
 WHERE f.last_seen_scan_run = %(scan_run_id)s
ON CONFLICT (finding_id, scan_id) DO NOTHING;
"""


def write_finding_history_for_scan_run(
    conn, scan_run_id: str, notes: str | None = None,
) -> int:
    """Stamp finding_history with one row per finding re-emitted this
    scan. status = the FINAL current_status (post-close, post-regress).
    Returns the count of rows actually inserted (ON CONFLICT DO NOTHING
    will not count collisions). Safe to call multiple times — second
    call inserts nothing because of the unique constraint.

    Note 129 round 7 (FINDING_HISTORY_FIX_SPEC.md). All scan tiers
    (light/medium/heavy) call this from their clean-path close-out so the
    per-finding observation timeline keeps growing on every re-scan.
    """
    with conn.cursor() as cur:
        cur.execute(
            INSERT_FINDING_HISTORY_FOR_SCAN_RUN_SQL,
            {"scan_run_id": scan_run_id, "notes": notes},
        )
        # psycopg's rowcount reflects the rows actually inserted;
        # ON CONFLICT skips are not counted (good — we want the
        # post-dedup count for forensics).
        return cur.rowcount if cur.rowcount is not None else 0
