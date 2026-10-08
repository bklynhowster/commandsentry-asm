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
    # ⛔ consecutive_holds MUST be named here. Omit it and every read
    # comes back without it, the fold starts from 0, and the counter can
    # never pass 1 — while every individual write looks correct. That is
    # #39b's defect (a field dropped at a translation boundary) in the
    # other direction. test_coverage_wire pins it with a fake that
    # returns ONLY the columns this SELECT names, as a real DB does.
    #
    # 270 Change 2: last_cut_fraction is named too — same rule, same reason.
    # ⚠ BUT the column arrives by migration 20261007a, which ships SEPARATELY
    # (never a .sql in a code push) and may land on one instance before the
    # other. A SELECT naming a column the table lacks raises, and read_cursor
    # raising is the signal the caller uses to DEGRADE TO A FULL-CORPUS RUN —
    # so a naive add here would switch the whole cursor OFF until the migration
    # lands. Instead: try with it; on exactly that column being missing, read
    # without it. The row then lacks the key, _cursor_state yields None, and
    # sizing falls back to the blind backoff — today's behaviour, byte for byte.
    with _connect(dsn) as conn, conn.cursor() as cur:
        try:
            cur.execute(
                "select last_dispatched, pass_count, corpus_identity, corpus_size, "
                "consecutive_holds, last_cut_fraction "
                f"from {_TABLE} where asset_id = %s and chunk_label = %s",
                (asset_id, chunk_label),
            )
            return cur.fetchone()
        except Exception as e:
            if not _is_missing_cut_fraction_column(e):
                raise
            # ⛔ PostgreSQL has ABORTED this transaction: without a rollback the
            # fallback SELECT below is refused (InFailedSqlTransaction), read_cursor
            # raises, and the caller degrades to a full-corpus run — the cursor
            # switched off until the migration lands, which is the exact outcome
            # this fallback exists to prevent. Measured 2026-10-08 against PG 16
            # with the live table definition. Nothing else ran on this connection.
            conn.rollback()
        cur.execute(
            "select last_dispatched, pass_count, corpus_identity, corpus_size, "
            "consecutive_holds "
            f"from {_TABLE} where asset_id = %s and chunk_label = %s",
            (asset_id, chunk_label),
        )
        return cur.fetchone()


def _is_missing_cut_fraction_column(exc) -> bool:
    """True ONLY for 'the last_cut_fraction column does not exist'. Anything
    else (missing table, DB down, bad DSN) must keep raising, because those are
    the degrade-to-full-run signals and must not be swallowed here."""
    msg = str(exc).lower()
    if "last_cut_fraction" not in msg:
        return False
    return ("does not exist" in msg or "undefined" in msg
            or isinstance(exc, KeyError))


def _cursor_state(row):
    """Translate a DB row (or None) into the coverage_cursor state dict."""
    if not row:
        return None
    return {
        "last_dispatched": row.get("last_dispatched"),
        "pass_count": int(row.get("pass_count") or 0),
        # ⛔ the field-by-field translation IS the boundary where #39b's value
        # died. Every field fold_dispatch reads must be carried across here.
        "consecutive_holds": int(row.get("consecutive_holds") or 0),
        # 270 Change 2. Absent pre-migration (the fallback SELECT does not name
        # it) → None → blind backoff. .get, never [], for exactly that reason.
        "last_cut_fraction": row.get("last_cut_fraction"),
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
                      corpus_id=None, corpus_size=None, cut_fraction=None):
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
                           completed=completed, corpus_id=corpus_id,
                           cut_fraction=cut_fraction)
    csize = corpus_size if corpus_size is not None else plan.get("corpus_size")
    base_vals = (asset_id, chunk_label, new.get("last_dispatched"),
                 int(new.get("pass_count") or 0), corpus_id, csize,
                 int(new.get("consecutive_holds") or 0))
    # 270 Change 2: write last_cut_fraction; pre-migration, write the old row
    # shape. Same column-missing test as read_cursor; everything else raises.
    sql_with = (
        f"insert into {_TABLE} "
        "(asset_id, chunk_label, last_dispatched, pass_count, "
        " corpus_identity, corpus_size, consecutive_holds, last_cut_fraction, updated_at) "
        "values (%s, %s, %s, %s, %s, %s, %s, %s, now()) "
        "on conflict (asset_id, chunk_label) do update set "
        "  last_dispatched   = excluded.last_dispatched, "
        "  pass_count        = excluded.pass_count, "
        "  corpus_identity   = excluded.corpus_identity, "
        "  corpus_size       = excluded.corpus_size, "
        # ⛔ the UPDATE clause, not just the insert column list. Miss this
        # line and the first write is right and every later one is silently
        # ignored — the version of the bug whose first observation passes.
        "  consecutive_holds = excluded.consecutive_holds, "
        "  last_cut_fraction = excluded.last_cut_fraction, "
        "  updated_at        = now()")
    sql_without = (
        f"insert into {_TABLE} "
        "(asset_id, chunk_label, last_dispatched, pass_count, "
        " corpus_identity, corpus_size, consecutive_holds, updated_at) "
        "values (%s, %s, %s, %s, %s, %s, %s, now()) "
        "on conflict (asset_id, chunk_label) do update set "
        "  last_dispatched   = excluded.last_dispatched, "
        "  pass_count        = excluded.pass_count, "
        "  corpus_identity   = excluded.corpus_identity, "
        "  corpus_size       = excluded.corpus_size, "
        "  consecutive_holds = excluded.consecutive_holds, "
        "  updated_at        = now()")
    with _connect(dsn) as conn, conn.cursor() as cur:
        try:
            cur.execute(sql_with, base_vals + (new.get("last_cut_fraction"),))
        except Exception as e:
            if not _is_missing_cut_fraction_column(e):
                raise
            conn.rollback()   # ⛔ same as read_cursor: the failed INSERT aborted the txn
            cur.execute(sql_without, base_vals)
        conn.commit()
