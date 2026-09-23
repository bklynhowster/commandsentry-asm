"""relay 459 — wire coverage_cursor into the nuclei chunk loop.

This is the GLUE between the pure planner (coverage_cursor.py) and the live scan:
it reads/writes the asset_template_cursor row and writes the next slice to a temp
file. It lives OUT of run_medium so the run_medium edit stays a few wrapped calls.

⛔ FAIL-SAFE IS THE CONTRACT (relay 459). Every entry point may raise, and the
CALLER in run_medium treats ANY exception as "no cursor available — run the full
filtered corpus exactly as before." So on Command (table absent until its
migration lands), on a DB blip, or on an empty list, the scan behaves identically
to today. Nothing here can fail a scan; the worst case is "no slice, no advance."

⛔ ADVANCE ONLY ON COMPLETION. record_completion advances the stored cursor only
when the chunk finished its slice (completed=True). A wall-cut chunk writes no
advance, so the next run re-dispatches the same window — never marking unexecuted
templates as covered (the honesty rule from 454/456; matches fold_dispatch).
"""
from __future__ import annotations

import os
import tempfile

import coverage_cursor as cc

_TABLE = "public.asset_template_cursor"


def _connect(dsn):
    """One psycopg3 connection with dict rows. Raises if psycopg or the DB is
    unavailable — callers catch and degrade."""
    import psycopg
    from psycopg.rows import dict_row
    return psycopg.connect(dsn, connect_timeout=10, row_factory=dict_row)


def read_cursor(dsn, asset_id, chunk_label):
    """Stored cursor row for (asset_id, chunk_label), or None if never run.

    Raises on a MISSING TABLE or DB error — that is the signal the caller uses to
    degrade to a full-corpus run (Command has no table yet). A present table with
    no row for this (asset, chunk) returns None and is treated as 'start at 0'.
    """
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "select last_dispatched, pass_count, corpus_identity, corpus_size "
            f"from {_TABLE} where asset_id = %s and chunk_label = %s",
            (asset_id, chunk_label),
        )
        return cur.fetchone()


def _cursor_state(row):
    """Translate a DB row (or None) into the coverage_cursor state dict."""
    if not row:
        return None
    return {
        "last_dispatched": row.get("last_dispatched"),
        "pass_count": int(row.get("pass_count") or 0),
    }


def plan_and_write_slice(dsn, asset_id, chunk_label, filtered_templates, *,
                         size=cc.DEFAULT_SLICE_SIZE, tmp_dir=None):
    """Order the chunk's filtered corpus, resume from the stored cursor, and
    write the next slice to a temp file.

    Returns (slice_file_path, plan). `plan` carries corpus_size so the caller can
    hand it back to record_completion. Raises (caller degrades) when there is
    nothing to dispatch or the DB/table is unavailable.

    The caller adds `-t <slice_file_path>` to the nuclei command and, AFTER the
    run, calls record_completion(plan=plan, completed=<rc == 0>).
    """
    ordered = cc.order_templates(filtered_templates)
    if not ordered:
        raise cc.CoveragePlanError("empty filtered corpus")
    cursor = _cursor_state(read_cursor(dsn, asset_id, chunk_label))
    plan = cc.plan_slice(ordered, cursor=cursor, size=size)
    if plan.get("exhausted") or not plan.get("templates"):
        raise cc.CoveragePlanError("nothing to dispatch")
    plan["corpus_size"] = len(ordered)
    fd, path = tempfile.mkstemp(
        prefix="nuclei-slice-" + chunk_label.replace("/", "_").replace("[", "").replace("]", "") + "-",
        suffix=".txt", dir=tmp_dir,
    )
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(plan["templates"]) + "\n")
    return path, plan


def corpus_id_from_meta(meta):
    """Scope label for a cursor position: version + dir_sha256 via the approved
    coverage_cursor.corpus_identity() (relay 456/464 F3). The templates_version
    string alone can hold still while the corpus CONTENT moves, so the sha is
    what actually pins the identity. Returns None on missing meta."""
    meta = meta or {}
    return cc.corpus_identity(meta.get("dir_sha256"), meta.get("templates_version"))


def record_completion(dsn, asset_id, chunk_label, *, plan, completed,
                      corpus_id=None, corpus_size=None):
    """Persist the cursor after a run. Advances ONLY on completed=True.

    A cut chunk (completed=False) leaves last_dispatched where it was, so the next
    run re-dispatches the same slice. Best-effort: any failure here must not fail
    the scan (worst case: the cursor doesn't advance and the same slice re-runs).
    """
    prior = None
    try:
        prior = read_cursor(dsn, asset_id, chunk_label)
    except Exception:
        prior = None
    new = cc.fold_dispatch(_cursor_state(prior) or {}, plan,
                           completed=completed, corpus_id=corpus_id)
    csize = corpus_size if corpus_size is not None else plan.get("corpus_size")
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            f"insert into {_TABLE} "
            "(asset_id, chunk_label, last_dispatched, pass_count, "
            " corpus_identity, corpus_size, updated_at) "
            "values (%s, %s, %s, %s, %s, %s, now()) "
            "on conflict (asset_id, chunk_label) do update set "
            "  last_dispatched = excluded.last_dispatched, "
            "  pass_count      = excluded.pass_count, "
            "  corpus_identity = excluded.corpus_identity, "
            "  corpus_size     = excluded.corpus_size, "
            "  updated_at      = now()",
            (asset_id, chunk_label, new.get("last_dispatched"),
             int(new.get("pass_count") or 0), corpus_id, csize),
        )
        conn.commit()
