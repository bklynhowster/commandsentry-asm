"""relay 459 — tests for coverage_wire (the cursor glue).

No real DB and no nuclei: a tiny in-memory fake stands in for
asset_template_cursor via monkeypatching coverage_wire._connect. These pin the
three properties the wiring MUST hold: the slice file is exactly the planned
window, the cursor advances ONLY on a completed run, and a missing table raises
(so the run_medium caller degrades to a full-corpus run).
"""
import os
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "normalize"))

import coverage_wire as cw  # noqa: E402


# ── in-memory fake of public.asset_template_cursor ──────────────────────────
# ⛔ STRICT ON PURPOSE (262 ruling B, 2026-09-24). The first version of this
# fake returned the WHOLE stored row for any SELECT and overwrote the WHOLE row
# on any INSERT. That made it more forgiving than Postgres in exactly the two
# ways the consecutive_holds writer can fail:
#   - a column missing from read_cursor's SELECT list still came back, and
#   - a column missing from the ON CONFLICT DO UPDATE SET clause still updated.
# A test double more permissive than the thing it stands in for cannot catch
# the bug it exists for (rule 14). So now: SELECT returns ONLY the columns it
# names, and an upsert on an existing row changes ONLY the columns its UPDATE
# clause lists. Columns absent from an insert take the table's defaults.
_TABLE_DEFAULTS = {
    "last_dispatched": None, "pass_count": 0, "corpus_identity": None,
    "corpus_size": None, "consecutive_holds": 0,
}


class _Store:
    def __init__(self, missing_table=False):
        self.missing_table = missing_table
        self.rows = {}          # (asset_id, chunk_label) -> row dict


class _Cur:
    def __init__(self, store):
        self.store = store
        self._result = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        if self.store.missing_table:
            raise RuntimeError('relation "public.asset_template_cursor" does not exist')
        s = " ".join(sql.split()).lower()
        if s.startswith("select"):
            cols = [c.strip() for c in re.match(r"select (.*?) from", s).group(1).split(",")]
            row = self.store.rows.get((params[0], params[1]))
            # a column the table lacks raises, as Postgres would
            self._result = None if row is None else {c: row[c] for c in cols}
        elif s.startswith("insert"):
            cols = [c.strip() for c in re.search(r"\((.*?)\) values", s).group(1).split(",")]
            vals = [v.strip() for v in re.search(r"values \((.*?)\)", s).group(1).split(",")]
            assert len(cols) == len(vals), "insert column/value count mismatch"
            it = iter(params)
            rec = {c: (next(it) if v == "%s" else None) for c, v in zip(cols, vals)}
            assert next(it, "<end>") == "<end>", "more params than placeholders"
            key = (rec.pop("asset_id"), rec.pop("chunk_label"))
            rec.pop("updated_at", None)
            if key in self.store.rows:
                for col, src in re.findall(r"(\w+) = excluded\.(\w+)", s):
                    self.store.rows[key][col] = rec[src]
            else:
                row = dict(_TABLE_DEFAULTS)
                row.update(rec)
                self.store.rows[key] = row

    def fetchone(self):
        return self._result


class _Conn:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _Cur(self.store)

    def commit(self):
        pass


@pytest.fixture
def store(monkeypatch):
    st = _Store()
    monkeypatch.setattr(cw, "_connect", lambda dsn: _Conn(st))
    return st


CORPUS = [f"t{i:03d}.yaml" for i in range(10)]
CHUNK = "nuclei[critical,high]"


def _read_slice(path):
    txt = pathlib.Path(path).read_text()
    return [ln for ln in txt.splitlines() if ln.strip()]


def test_slice_file_is_exactly_the_planned_window(store):
    path, plan = cw.plan_and_write_slice("dsn", "a", CHUNK, CORPUS, size=4)
    try:
        assert _read_slice(path) == CORPUS[:4]        # first 4, in order
        assert plan["start"] == 0 and plan["end"] == 4
        assert plan["corpus_size"] == 10
    finally:
        os.remove(path)


def test_cursor_advances_only_on_completion(store):
    # run 1: dispatch [0:4], COMPLETE -> cursor advances to t003
    p1, plan1 = cw.plan_and_write_slice("dsn", "a", CHUNK, CORPUS, size=4)
    os.remove(p1)
    cw.record_completion("dsn", "a", CHUNK, plan=plan1, completed=True,
                         corpus_id="v1", corpus_size=10)
    assert store.rows[("a", CHUNK)]["last_dispatched"] == "t003.yaml"

    # run 2: dispatch [4:8]
    p2, plan2 = cw.plan_and_write_slice("dsn", "a", CHUNK, CORPUS, size=4)
    os.remove(p2)
    assert plan2["start"] == 4 and _read_slice_from_plan(plan2) == CORPUS[4:8]
    # run 2 is CUT -> cursor must NOT advance past t003
    cw.record_completion("dsn", "a", CHUNK, plan=plan2, completed=False,
                         corpus_id="v1", corpus_size=10)
    assert store.rows[("a", CHUNK)]["last_dispatched"] == "t003.yaml"

    # run 3: because run 2 did not advance, it re-dispatches the SAME window
    p3, plan3 = cw.plan_and_write_slice("dsn", "a", CHUNK, CORPUS, size=4)
    os.remove(p3)
    assert plan3["start"] == 4 and _read_slice_from_plan(plan3) == CORPUS[4:8]


def _read_slice_from_plan(plan):
    return plan["templates"]


def test_consecutive_completed_runs_cover_the_WHOLE_corpus(store):
    seen = set()
    for _ in range(20):
        path, plan = cw.plan_and_write_slice("dsn", "a", CHUNK, CORPUS, size=4)
        seen |= set(_read_slice(path))
        os.remove(path)
        cw.record_completion("dsn", "a", CHUNK, plan=plan, completed=True,
                             corpus_id="v1", corpus_size=10)
        if seen == set(CORPUS):
            break
    assert seen == set(CORPUS)


def test_missing_table_raises_so_caller_degrades(monkeypatch):
    st = _Store(missing_table=True)
    monkeypatch.setattr(cw, "_connect", lambda dsn: _Conn(st))
    # plan_and_write_slice must raise (run_medium's try/except then runs full set)
    with pytest.raises(Exception):
        cw.plan_and_write_slice("dsn", "a", CHUNK, CORPUS, size=4)


def test_empty_corpus_raises(store):
    with pytest.raises(cw.cc.CoveragePlanError):
        cw.plan_and_write_slice("dsn", "a", CHUNK, [], size=4)


# ── 262 ruling B: consecutive_holds, end to end through the (strict) store ───
def test_the_fake_is_as_strict_as_postgres(store):
    """Guard the double itself: if it ever goes back to returning whole rows,
    the tests below stop being able to fail."""
    store.rows[("a", CHUNK)] = dict(_TABLE_DEFAULTS, pass_count=7)
    with cw._connect("dsn") as conn, conn.cursor() as cur:
        cur.execute("select pass_count from t where asset_id = %s and chunk_label = %s",
                    ("a", CHUNK))
        assert cur.fetchone() == {"pass_count": 7}


def _cut_run(size=4):
    p, plan = cw.plan_and_write_slice("dsn", "a", CHUNK, CORPUS, size=size)
    os.remove(p)
    cw.record_completion("dsn", "a", CHUNK, plan=plan, completed=False,
                         corpus_id="v1", corpus_size=10)


def test_holds_ACCUMULATE_across_runs_in_the_db(store):
    """⛔ The defect this pins: drop consecutive_holds from the SELECT, from
    _cursor_state, or from the UPDATE clause, and the stored value sticks at 1
    forever — each run reads 0, adds 1, writes 1. Every write looks right."""
    p, plan = cw.plan_and_write_slice("dsn", "a", CHUNK, CORPUS, size=4)
    os.remove(p)
    cw.record_completion("dsn", "a", CHUNK, plan=plan, completed=True,
                         corpus_id="v1", corpus_size=10)
    assert store.rows[("a", CHUNK)]["consecutive_holds"] == 0
    for expected in (1, 2, 3):
        _cut_run()
        assert store.rows[("a", CHUNK)]["consecutive_holds"] == expected
    # and the position really did hold the whole time
    assert store.rows[("a", CHUNK)]["last_dispatched"] == "t003.yaml"


def test_a_completed_advance_resets_holds_in_the_db(store):
    _cut_run()
    _cut_run()
    assert store.rows[("a", CHUNK)]["consecutive_holds"] == 2
    p, plan = cw.plan_and_write_slice("dsn", "a", CHUNK, CORPUS, size=4)
    os.remove(p)
    cw.record_completion("dsn", "a", CHUNK, plan=plan, completed=True,
                         corpus_id="v1", corpus_size=10)
    row = store.rows[("a", CHUNK)]
    assert row["consecutive_holds"] == 0
    assert row["last_dispatched"] == "t003.yaml"


def test_a_first_ever_run_that_is_cut_records_one_hold(store):
    """A chunk cut on its very first run (medium:cve's life story) must still
    be counted — no prior row, no position, one hold."""
    _cut_run()
    row = store.rows[("a", CHUNK)]
    assert row["consecutive_holds"] == 1
    assert row["last_dispatched"] is None
