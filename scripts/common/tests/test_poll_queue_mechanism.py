import pathlib
"""poll_queue connect retry — MECHANISM tests (4.7 G1/G4/G5).
Asserts attempt COUNTS; an exit code alone cannot prove retry fired."""
import io, sys, types, contextlib, importlib
sys.path.insert(0, ".")
import gate_retry; gate_retry.time.sleep = lambda *_: None

F = []
def ck(n, c, x=""):
    print(f"{'PASS' if c else 'FAIL'}  {n}" + ("" if c else f"   {x}")); (F.append(n) if not c else None)

class Conn:
    def __init__(s): s.rolled = 0
    def cursor(s, *a, **k): raise RuntimeError("claim path not under test")
    def rollback(s): s.rolled += 1
    def close(s): pass

def run(script):
    """script: list of 'boom' | 'ok'"""
    mod = importlib.import_module("poll_queue"); importlib.reload(mod)
    mod.time = getattr(mod, "time", None)
    n = {"i": 0}
    pg = types.ModuleType("psycopg")
    def connect(dsn, row_factory=None, autocommit=None):
        i = n["i"]; n["i"] += 1
        st = script[i] if i < len(script) else script[-1]
        if st == "boom": raise Exception("connection timeout expired")
        return Conn()
    pg.connect = connect
    rows = types.ModuleType("psycopg.rows"); rows.dict_row = object()
    sys.modules["psycopg"] = pg; sys.modules["psycopg.rows"] = rows
    # claim_next_scan raises -> run() hits its own except; we only care about connect
    mod.claim_next_scan = lambda conn: None
    o, e = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        rc = mod.run("postgresql://x")
    return rc, o.getvalue() + e.getvalue(), n["i"]

rc, out, calls = run(["ok"])
ck("MECHANISM_healthy_connect_is_single_attempt", calls == 1, f"calls={calls}")
ck("OUTCOME_no_work_exits_0", rc == 0, f"rc={rc}")

rc, out, calls = run(["boom", "boom", "ok"])
ck("MECHANISM_transient_connect_retries_then_succeeds", calls == 3 and rc == 0, f"calls={calls} rc={rc}")
ck("OUTCOME_recovered_blip_is_not_reported_as_failure", "UNREACHABLE" not in out)

rc, out, calls = run(["boom"])
ck("MECHANISM_exhausts_exactly_3_attempts", calls == 3, f"calls={calls}")
ck("OUTCOME_unreadable_still_exits_nonzero_no_scan_claimed", rc == 1, f"rc={rc}")
ck("OUTCOME_message_says_UNREACHABLE_not_a_queue_verdict", "UNREACHABLE" in out and "no scan claimed" in out)

src = (pathlib.Path(__file__).parent.parent.parent / "scanner" / "poll_queue.py").read_text()
ck("MECHANISM_progress_gate_has_no_fail_open_switch", "fail_open" not in src.lower())
ck("MECHANISM_uses_shared_framework_not_handrolled", "run_with_transport_retry" in src and "time.sleep" not in src)

print("\n" + ("ALL PASS" if not F else "FAILURES: " + ", ".join(F)))
sys.exit(1 if F else 0)
