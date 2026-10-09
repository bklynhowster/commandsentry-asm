#!/usr/bin/env python3
"""test_coverage_cut_fraction.py — 270 Change 2: size the next slice from how
far the last one got.

⛔ WHAT THIS PINS. Measured 2026-10-07: nuclei[critical,high] held at
consecutive_holds=3 on uat and 1 on prod, pass_count 0 on both, because the
blind 0.85-per-hold backoff needs 4-5 wasted heavy scans to shrink a 2000
template slice to one that fits a ~7 req/s site inside the 400s wall. The cut
stats already say how far the window got. One measured correction replaces N
blind ones.

⚠ THE CASE THAT MATTERS MOST IS THE PRE-MIGRATION ONE. The column arrives by
migration 20261007a, shipped separately. Until it lands, read_cursor raising
would switch the whole cursor OFF (the caller degrades to a full-corpus run).
So: with the column absent the code must behave exactly as today, and the
real degrade signals (missing table) must still raise.
"""
from __future__ import annotations

import math
import os
import re
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import coverage_cursor as cc  # noqa: E402
import coverage_wire as cw    # noqa: E402

CORPUS = 4352          # nuclei[critical,high] on Prodex, 2026-10-07
WALL_S = 400
UNITS_PER_TEMPLATE = 2.07   # 4147 units / 2000 templates, prod 17:47 run
RPS = 7                     # measured on that run


# ── pure: usable_cut_fraction ─────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [None, 0, 0.0, 1, 1.0, 1.5, -0.2, "abc", "", float("nan")])
def test_unusable_fractions_are_none(bad):
    assert cc.usable_cut_fraction(bad) is None


@pytest.mark.parametrize("good,want", [(0.67, 0.67), ("0.5", 0.5), (0.01, 0.01), (0.99, 0.99)])
def test_usable_fractions_pass_through(good, want):
    assert cc.usable_cut_fraction(good) == pytest.approx(want)


# ── pure: effective_slice_size ────────────────────────────────────────────────

def _base_eff():
    return min(cc.DEFAULT_SLICE_SIZE, math.ceil(CORPUS * cc.SLICE_CORPUS_CAP))


def test_no_fraction_is_byte_identical_to_the_blind_backoff():
    for holds in (0, 1, 2, 3, 5):
        blind = cc.effective_slice_size(cc.DEFAULT_SLICE_SIZE, CORPUS, holds=holds)
        assert cc.effective_slice_size(cc.DEFAULT_SLICE_SIZE, CORPUS, holds=holds,
                                       last_cut_fraction=None) == blind


def test_a_fraction_is_ignored_without_a_hold():
    assert cc.effective_slice_size(cc.DEFAULT_SLICE_SIZE, CORPUS, holds=0,
                                   last_cut_fraction=0.3) == _base_eff()


def test_one_hold_with_a_measured_fraction_sizes_from_it():
    eff = _base_eff()
    want = math.floor(eff * 0.67 * cc.SLICE_CUT_SAFETY)
    got = cc.effective_slice_size(cc.DEFAULT_SLICE_SIZE, CORPUS, holds=1,
                                  last_cut_fraction=0.67)
    assert got == want
    assert got < math.floor(eff * cc.SLICE_HOLD_BACKOFF), "must beat the blind step"


def test_a_fraction_near_one_never_outsizes_the_blind_step():
    eff = _base_eff()
    got = cc.effective_slice_size(cc.DEFAULT_SLICE_SIZE, CORPUS, holds=1,
                                  last_cut_fraction=0.99)
    assert got <= math.floor(eff * cc.SLICE_HOLD_BACKOFF)


def test_the_safety_margin_is_pinned_by_value_not_by_the_constant():
    """Rule-14 sweep 2026-10-08, mutant M7 (SLICE_CUT_SAFETY 0.85 -> 1.0)
    SURVIVED: the test above derives `want` FROM cc.SLICE_CUT_SAFETY, so changing
    the constant moved the expectation with it — a mirror, not a test. The 0.85
    headroom is a design decision (rps varies 4-7 run to run); pin its effect
    with literals."""
    got = cc.effective_slice_size(2000, CORPUS, holds=1, last_cut_fraction=0.67)
    assert got == math.floor(2000 * 0.67 * 0.85)   # literals, on purpose


def test_the_blind_step_cap_holds_even_if_the_safety_margin_is_raised(monkeypatch):
    """Rule-14 sweep 2026-10-08, mutant M2 (cap removed) SURVIVED, and could not
    have been killed: with today's constants (SAFETY == BACKOFF == 0.85, fraction
    < 1) the min(..., blind step) cap never binds. It exists for the day someone
    raises SLICE_CUT_SAFETY — a 99% cut must still not out-size the 15% step.
    Make that day observable."""
    monkeypatch.setattr(cc, "SLICE_CUT_SAFETY", 1.0)
    got = cc.effective_slice_size(2000, CORPUS, holds=1, last_cut_fraction=0.99)
    assert got == math.floor(2000 * 0.85)   # the blind step, NOT floor(2000*0.99) = 1980


def test_measured_sizing_respects_floor_and_corpus():
    assert cc.effective_slice_size(cc.DEFAULT_SLICE_SIZE, CORPUS, holds=1,
                                   last_cut_fraction=0.001) >= min(cc.MIN_SLICE_SIZE, _base_eff())
    assert cc.effective_slice_size(cc.DEFAULT_SLICE_SIZE, 30, holds=1,
                                   last_cut_fraction=0.5) <= 30


def test_the_measured_case_converges_in_one_hold_where_blind_does_not():
    """⭐ THE POINT. uat was cut at 53% with slice 2000. Blind next = 1700, still
    too big at 7 rps. Measured next fits inside the wall."""
    cut = 0.53
    blind_next = cc.effective_slice_size(cc.DEFAULT_SLICE_SIZE, CORPUS, holds=1)
    measured_next = cc.effective_slice_size(cc.DEFAULT_SLICE_SIZE, CORPUS, holds=1,
                                            last_cut_fraction=cut)
    def seconds(n): return n * UNITS_PER_TEMPLATE / RPS
    assert seconds(blind_next) > WALL_S, "the blind step would be cut again"
    assert seconds(measured_next) <= WALL_S, "the measured size completes"


# ── pure: fold_dispatch + plan_slice ─────────────────────────────────────────

def test_a_hold_records_the_fraction_and_an_advance_clears_it():
    plan = {"templates": ["a", "b"], "last": "b", "wrapped": False}
    s1 = cc.fold_dispatch(cc.NEW_CURSOR, plan, completed=False, cut_fraction=0.67)
    assert s1["consecutive_holds"] == 1 and s1["last_cut_fraction"] == pytest.approx(0.67)
    s2 = cc.fold_dispatch(s1, plan, completed=False, cut_fraction=None)
    assert s2["consecutive_holds"] == 2 and s2["last_cut_fraction"] == pytest.approx(0.67), \
        "an unmeasured hold keeps the last measurement"
    s3 = cc.fold_dispatch(s2, plan, completed=True)
    assert s3["consecutive_holds"] == 0 and s3["last_cut_fraction"] is None


def test_plan_slice_uses_the_stored_fraction():
    ordered = [f"http/x/t{i:05d}.yaml" for i in range(CORPUS)]
    cur = dict(cc.NEW_CURSOR, consecutive_holds=1, last_cut_fraction=0.53)
    plan = cc.plan_slice(ordered, cursor=cur)
    assert plan["slice_size"] == cc.effective_slice_size(
        cc.DEFAULT_SLICE_SIZE, CORPUS, holds=1, last_cut_fraction=0.53)
    assert len(plan["templates"]) == plan["slice_size"]


def test_new_cursor_carries_the_key():
    assert "last_cut_fraction" in cc.NEW_CURSOR and cc.NEW_CURSOR["last_cut_fraction"] is None


# ── wire: a fake table WITH and WITHOUT the column ───────────────────────────

BASE_COLS = ("asset_id", "chunk_label", "last_dispatched", "pass_count",
             "corpus_identity", "corpus_size", "consecutive_holds", "updated_at")


class _Store:
    def __init__(self, columns, missing_table=False):
        self.columns = set(columns)
        self.missing_table = missing_table
        self.rows = {}


class _Cur:
    def __init__(self, store, conn):
        self.store, self.conn, self._result = store, conn, None
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def execute(self, sql, params=()):
        # ⛔ PostgreSQL ABORTS the transaction on any error: every later statement
        # on that connection is refused until rollback(). A fake that lets the
        # next statement through hides the exact bug a column-missing fallback
        # invites — measured 2026-10-08 against PG 16 with the live schema: both
        # fallbacks raised InFailedSqlTransaction and the write never landed,
        # while all 30 tests passed on the old fake. Model it.
        if self.conn.aborted:
            raise RuntimeError("current transaction is aborted, "
                               "commands ignored until end of transaction block")
        try:
            self._execute(sql, params)
        except Exception:
            self.conn.aborted = True
            raise
    def _execute(self, sql, params=()):
        if self.store.missing_table:
            raise RuntimeError('relation "public.asset_template_cursor" does not exist')
        s = " ".join(sql.split()).lower()
        if s.startswith("select"):
            cols = [c.strip() for c in re.match(r"select (.*?) from", s).group(1).split(",")]
            for c in cols:
                if c not in self.store.columns:
                    raise RuntimeError(f'column "{c}" does not exist')
            row = self.store.rows.get((params[0], params[1]))
            self._result = None if row is None else {c: row.get(c) for c in cols}
        elif s.startswith("insert"):
            cols = [c.strip() for c in re.search(r"\((.*?)\) values", s).group(1).split(",")]
            for c in cols:
                if c not in self.store.columns:
                    raise RuntimeError(f'column "{c}" of relation "asset_template_cursor" does not exist')
            vals = [v.strip() for v in re.search(r"values \((.*?)\)", s).group(1).split(",")]
            assert len(cols) == len(vals)
            it = iter(params)
            rec = {c: (next(it) if v == "%s" else None) for c, v in zip(cols, vals)}
            assert next(it, "<end>") == "<end>"
            key = (rec.pop("asset_id"), rec.pop("chunk_label")); rec.pop("updated_at", None)
            if key in self.store.rows:
                for col, src in re.findall(r"(\w+) = excluded\.(\w+)", s):
                    self.store.rows[key][col] = rec[src]
            else:
                self.store.rows[key] = rec
    def fetchone(self): return self._result


class _Conn:
    def __init__(self, store): self.store, self.aborted = store, False
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def cursor(self): return _Cur(self.store, self)
    def commit(self): pass
    def rollback(self): self.aborted = False


PLAN = {"templates": ["a", "b"], "last": "b", "wrapped": False, "corpus_size": CORPUS}


def test_pre_migration_read_and_hold_write_behave_as_today(monkeypatch):
    st = _Store(BASE_COLS)                      # no last_cut_fraction column
    monkeypatch.setattr(cw, "_connect", lambda dsn: _Conn(st))
    cw.record_completion("dsn", "uat", "nuclei[critical,high]", plan=PLAN,
                         completed=False, cut_fraction=0.53)   # must not raise
    row = cw.read_cursor("dsn", "uat", "nuclei[critical,high]")
    assert row["consecutive_holds"] == 1 and "last_cut_fraction" not in row
    state = cw._cursor_state(row)
    assert state["last_cut_fraction"] is None
    assert cc.effective_slice_size(cc.DEFAULT_SLICE_SIZE, CORPUS, holds=1,
                                   last_cut_fraction=state["last_cut_fraction"]) \
        == cc.effective_slice_size(cc.DEFAULT_SLICE_SIZE, CORPUS, holds=1)


def test_a_missing_table_still_raises_the_degrade_signal(monkeypatch):
    st = _Store(BASE_COLS + ("last_cut_fraction",), missing_table=True)
    monkeypatch.setattr(cw, "_connect", lambda dsn: _Conn(st))
    with pytest.raises(RuntimeError, match="does not exist"):
        cw.read_cursor("dsn", "uat", "nuclei[critical,high]")
    with pytest.raises(RuntimeError, match="does not exist"):
        cw.record_completion("dsn", "uat", "x", plan=PLAN, completed=False, cut_fraction=0.5)


def test_post_migration_round_trip_and_clear(monkeypatch):
    st = _Store(BASE_COLS + ("last_cut_fraction",))
    monkeypatch.setattr(cw, "_connect", lambda dsn: _Conn(st))
    cw.record_completion("dsn", "uat", "c", plan=PLAN, completed=False, cut_fraction=0.53)
    row = cw.read_cursor("dsn", "uat", "c")
    assert row["last_cut_fraction"] == pytest.approx(0.53) and row["consecutive_holds"] == 1
    cw.record_completion("dsn", "uat", "c", plan=PLAN, completed=True)
    row = cw.read_cursor("dsn", "uat", "c")
    assert row["last_cut_fraction"] is None and row["consecutive_holds"] == 0


def test_only_the_cut_fraction_column_is_tolerated():
    assert cw._is_missing_cut_fraction_column(RuntimeError('column "last_cut_fraction" does not exist'))
    assert cw._is_missing_cut_fraction_column(KeyError("last_cut_fraction"))
    assert not cw._is_missing_cut_fraction_column(RuntimeError('relation "x" does not exist'))
    assert not cw._is_missing_cut_fraction_column(RuntimeError('column "consecutive_holds" does not exist'))
    assert not cw._is_missing_cut_fraction_column(RuntimeError("connection refused"))


# ── runner: run_nuclei_chunk hands the fraction to the cursor ────────────────

def _drive_chunk(monkeypatch, rc, stderr):
    import tempfile
    import run_medium as m
    captured = {}
    tl_list = "\n".join(f"http/x/t{i}.yaml" for i in range(50)) + "\n"
    # Since the D-056 fail-closed guard (2026-10-08) every listed template is
    # READ before nuclei runs, so the listing must name real, benign files.
    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, "http", "x"))
    for i in range(50):
        with open(os.path.join(root, "http", "x", f"t{i}.yaml"), "w") as fh:
            fh.write(f"id: t{i}\ninfo:\n  name: Acme t{i} - Detect\n  severity: high\n")
    monkeypatch.setattr(m, "nuclei_templates_dir", lambda: root)

    def fake_run_cmd(cmd, timeout=None, **kw):
        if "-tl" in cmd:
            return 0, tl_list, ""
        return rc, "", stderr

    def fake_plan(dsn, asset_id, chunk_label, filtered, **kw):
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as fh:      # the guard refuses an empty slice
            fh.write("\n".join(filtered[:10]) + "\n")
        return path, {"templates": filtered[:10], "last": filtered[9], "wrapped": False,
                      "start": 0, "end": 10, "corpus_size": len(filtered)}

    def fake_record(dsn, asset_id, chunk_label, **kw):
        captured.update(kw)

    monkeypatch.setattr(m, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(cw, "plan_and_write_slice", fake_plan)
    monkeypatch.setattr(cw, "record_completion", fake_record)
    monkeypatch.setattr(cw, "corpus_id_from_meta", lambda meta: "cid")
    ctx = types.SimpleNamespace(waf_detected=False, dsn="postgres://fake", asset_id="uat",
                                corpus_prewarm_meta=None, artifacts=[], findings=[],
                                total_requests=0)
    m.run_nuclei_chunk(ctx, "https://example.invalid/", "critical,high", None)
    return captured


STATS_CUT = '{"requests":"2807","total":"4147","percent":"67","rps":"7"}\n'


def test_a_cut_chunk_passes_requests_over_total(monkeypatch):
    got = _drive_chunk(monkeypatch, 124, STATS_CUT)
    assert got["completed"] is False
    assert got["cut_fraction"] == pytest.approx(2807 / 4147)


def test_a_completed_chunk_passes_no_fraction(monkeypatch):
    got = _drive_chunk(monkeypatch, 0, STATS_CUT)
    assert got["completed"] is True and got["cut_fraction"] is None


def test_a_cut_chunk_with_no_stats_passes_none(monkeypatch):
    got = _drive_chunk(monkeypatch, 124, "")
    assert got["completed"] is False and got["cut_fraction"] is None
