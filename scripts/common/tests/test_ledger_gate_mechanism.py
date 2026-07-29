"""Mechanism tests for the migration-ledger gate (G5).

Gate under test: scripts/db/check_migrations_applied.py (PROGRESS tier).

2026-07-29 — REWRITTEN. The original version of this file was committed on
07-26 in ebb9832 and had NEVER been runnable. It did:

    sys.path.insert(0, "common")
    SHAS = {... for f in glob.glob("migs/*.sql")}
    mod = importlib.import_module("gate")

None of `common/`, `migs/`, or a module named `gate` exist in this repo. It was
written against a scratch directory where the real files had been copied under
short names, and committed without them — so `SHAS` was always `{}` and line 29
died on IndexError before a single assertion ran. It sat red for three days and
nobody learned anything, because nothing runs the tests.

That is the argument for CI in one file. The assertions below were always
correct; only the wiring was fictional. They now target the real module and
build their own fixtures in a temp dir.
"""
import contextlib
import hashlib
import importlib
import io
import os
import pathlib
import sys
import tempfile
import time
import types

# ─── Neutralise backoff BEFORE anything imports gate_retry ───────────
# gate_retry declares `def run_with_transport_retry(..., sleep=time.sleep)`.
# That default is bound at DEF time, so the usual `gate_retry.time.sleep =
# lambda: None` after import never reaches it — the function already holds a
# reference to the real sleep. The original file did exactly that and the
# stub was a silent no-op; the suite spent 26 of its 26 seconds asleep,
# which nobody saw because the file could not run at all.
#
# Patching time.sleep here, before the first import of gate_retry, means the
# def-time default binds to the stub. Assert real backoff behaviour by
# counting on_retry calls, never by wall-clock.
_SLEPT: list = []
time.sleep = lambda s=0: _SLEPT.append(s)

_HERE = pathlib.Path(__file__).resolve().parent
_REPO = _HERE.parent.parent.parent                      # scripts/common/tests -> repo root
sys.path.insert(0, str(_REPO / "scripts" / "db"))
sys.path.insert(0, str(_REPO / "scripts" / "common"))

# Real fixtures, created here rather than assumed to exist on disk.
_TMP = tempfile.mkdtemp(prefix="ledger_gate_test_")
_MIGS = pathlib.Path(_TMP) / "migs"
_MIGS.mkdir()
for _name, _body in (
    ("0001_init.sql", "create table a(id int);\n"),
    ("0002_add_col.sql", "alter table a add column b text;\n"),
    ("0003_index.sql", "create index on a(b);\n"),
):
    (_MIGS / _name).write_text(_body)

SHAS = {
    f.name: hashlib.sha256(f.read_bytes()).hexdigest()
    for f in sorted(_MIGS.glob("*.sql"))
}
assert SHAS, "fixture migrations were not created — the bug this rewrite fixes"

full = [(f, SHAS[f]) for f in SHAS]                     # ledger matches disk
part = [(list(SHAS)[0], SHAS[list(SHAS)[0]])]           # only 1 of 3 applied
bad = [(f, "dead") for f in SHAS]                       # applied but SHA differs


class Cur:
    def __init__(s, te, rows): s.te, s.rows = te, rows
    def execute(s, q): pass
    def fetchone(s): return ("x" if s.te else None,)
    def fetchall(s): return s.rows


class Conn:
    def __init__(s, c): s.c = c
    def cursor(s): return s.c
    def close(s): pass


def run(script, argv=None):
    """Drive the gate with a scripted sequence of connect outcomes.
    Returns (exit_code, combined_output, connect_attempts)."""
    if argv is None:
        argv = ("--dsn", "x", "--migrations-dir", str(_MIGS))
    mod = importlib.import_module("check_migrations_applied")
    importlib.reload(mod)
    n = {"i": 0}
    m = types.ModuleType("psycopg")

    def connect(dsn, connect_timeout=None):
        i = n["i"]; n["i"] += 1
        st = script[i] if i < len(script) else script[-1]
        if st == "boom":
            raise Exception("connection timeout expired")
        return Conn(Cur(st[1], st[2]))

    m.connect = connect
    sys.modules["psycopg"] = m
    import gate_retry
    gate_retry.time.sleep = lambda *_: None
    mod.run_with_transport_retry.__globals__["time"].sleep = lambda *_: None
    sys.argv = ["gate"] + list(argv)
    o, e = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        rc = mod.main()
    return rc, o.getvalue() + e.getvalue(), n["i"]


F = []


def ck(n, c, x=""):
    print(f"{'PASS' if c else 'FAIL'}  {n}" + ("" if c else f"  {x}"))
    if not c:
        F.append(n)


# ─── verdicts vs transport ───────────────────────────────────────────
r = run([("ok", True, full)])
ck("OUTCOME_clean_ledger_exit0_one_attempt", r[0] == 0 and r[2] == 1, r)
r = run(["boom", "boom", ("ok", True, full)])
ck("MECHANISM_transient_then_ok_retries_to_3", r[0] == 0 and r[2] == 3, r)
r = run(["boom"])
ck("MECHANISM_all_transport_exit2_exactly_3_attempts", r[0] == 2 and r[2] == 3, r)
r = run(["boom"])
ck("OUTCOME_unreadable_says_NOT_ledger_drift",
   "UNREADABLE" in r[1] and "NOT ledger drift" in r[1])
r = run(["boom"])
ck("OUTCOME_transport_msg_has_no_drift_words",
   "SHA-MISMATCH" not in r[1] and "UNAPPLIED" not in r[1])
r = run([("ok", False, [])])
ck("MECHANISM_missing_table_verdict_NOT_retried", r[0] == 2 and r[2] == 1, r)
r = run([("ok", True, part)])
ck("OUTCOME_unapplied_still_exit1", r[0] == 1 and "UNAPPLIED" in r[1], r)
r = run([("ok", True, bad)])
ck("OUTCOME_sha_mismatch_still_exit1", r[0] == 1 and "SHA-MISMATCH" in r[1], r)
r = run(["boom", ("ok", False, [])])
ck("MECHANISM_transient_then_verdict_verdict_wins", r[0] == 2 and r[2] == 2, r)

# ─── PROGRESS tier: fail-open exists, but only by operator decision ──
os.environ["LEDGER_GATE_TRANSPORT_MODE"] = "fail_open"
r = run(["boom"])
ck("OUTCOME_operator_fail_open_proceeds_loudly",
   r[0] == 0 and "PROCEEDING UNVERIFIED" in r[1], r)
del os.environ["LEDGER_GATE_TRANSPORT_MODE"]
r = run(["boom"])
ck("MECHANISM_fail_open_is_not_the_default", r[0] == 2, r)

# ─── the fixtures are real (guards against the original bug) ─────────
ck("MECHANISM_fixtures_exist_and_are_hashed", len(SHAS) == 3, SHAS)
ck("MECHANISM_sha_is_of_actual_file_content",
   SHAS["0001_init.sql"] == hashlib.sha256(b"create table a(id int);\n").hexdigest())

# ─── the backoff stub is real, and the backoff itself is real ────────
# Two distinct claims. First: this suite must not be sleeping through its
# own runtime. Second: the gate must still be backing off 1s then 3s — the
# stub records the requested durations, so we verify the SCHEDULE without
# waiting for it. Asserting only "it was fast" would pass equally well if
# retry had been removed entirely.
_SLEPT.clear()
r = run(["boom"])
ck("MECHANISM_backoff_is_stubbed_not_slept", sum(_SLEPT) >= 4 and r[2] == 3,
   f"requested={_SLEPT} attempts={r[2]}")
ck("MECHANISM_backoff_schedule_is_1s_then_3s", _SLEPT == [1, 3], f"requested={_SLEPT}")

print("\n" + ("ALL PASS" if not F else "FAILURES: " + ", ".join(F)))
sys.exit(1 if F else 0)
