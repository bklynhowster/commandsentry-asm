"""relay 459 — tests for coverage_wire (the cursor glue).

No real DB and no nuclei: a tiny in-memory fake stands in for
asset_template_cursor via monkeypatching coverage_wire._connect. These pin the
three properties the wiring MUST hold: the slice file is exactly the planned
window, the cursor advances ONLY on a completed run, and a missing table raises
(so the run_medium caller degrades to a full-corpus run).
"""
import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "normalize"))

import coverage_wire as cw  # noqa: E402


# ── in-memory fake of public.asset_template_cursor ──────────────────────────
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
            self._result = self.store.rows.get((params[0], params[1]))
        elif s.startswith("insert"):
            asset, chunk, last, pc, cid, csize = params
            self.store.rows[(asset, chunk)] = {
                "last_dispatched": last, "pass_count": pc,
                "corpus_identity": cid, "corpus_size": csize,
            }

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
