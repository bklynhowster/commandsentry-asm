import pathlib
import sys, types, importlib
sys.path.insert(0,".")
import gate_retry; gate_retry.time.sleep=lambda *_:None
import roe_gate as R
R.SAFETY = gate_retry.GateBudget("safety_test",3,(0,0),1,99)

F=[]
def ck(n,c,x=""): print(f"{'PASS' if c else 'FAIL'}  {n}"+("" if c else f"   {x}")); (F.append(n) if not c else None)

class Cur:
    def __init__(s,beh): s.beh=beh
    def __enter__(s): return s
    def __exit__(s,*a): return False
    def execute(s,q,p=None):
        s.q=q
        if "assets" in q:
            b=s.beh.pop(0) if s.beh else ("boom",)
            if b[0]=="boom": raise Exception("connection timeout expired")
            s._row=b[1]
    def fetchone(s): return getattr(s,"_row",None)
class Conn:
    def __init__(s,beh): s.beh=beh; s.cursor_calls=0; s.rollbacks=0
    def cursor(s): s.cursor_calls+=1; return Cur(s.beh)
    def rollback(s): s.rollbacks+=1
    def commit(s): pass

alerts=[]; stamps=[]
R._send_alert=lambda *a,**k: alerts.append(a[0].reason)
R._stamp_failed=lambda *a,**k: stamps.append(a[3] if len(a)>3 else "")

def call(beh, intensity="heavy"):
    alerts.clear(); stamps.clear()
    c=Conn(list(beh))
    r=R.check_ownership_or_block(conn=c,asset_id="a1",intensity=intensity,
                                 scan_run_id="s1",queue_id="q1")
    return r,c

# ── MECHANISM: a real answer is never retried ──
r,c=call([("ok",{"ownership":"owned"})])
ck("MECHANISM_allowed_verdict_single_attempt", c.cursor_calls==1 and r is None, f"cursor={c.cursor_calls} r={r}")

r,c=call([("ok",{"ownership":"third_party"})])
ck("MECHANISM_denial_verdict_not_retried", c.cursor_calls==1, f"cursor={c.cursor_calls}")
ck("OUTCOME_denial_is_routine_refusal_exit0", r.reason=="ownership_not_allowed" and r.is_routine_refusal())

r,c=call([("ok",None)])
ck("MECHANISM_asset_not_found_verdict_not_retried", c.cursor_calls==1, f"cursor={c.cursor_calls}")
ck("OUTCOME_asset_not_found_is_not_routine_exit1", r.reason=="asset_not_found" and not r.is_routine_refusal())

# ── MECHANISM: transport retries ──
r,c=call([("boom",),("boom",),("ok",{"ownership":"owned"})])
ck("MECHANISM_transient_db_retries_then_proceeds", c.cursor_calls==3 and r is None, f"cursor={c.cursor_calls} r={r}")
ck("MECHANISM_rollback_between_attempts", c.rollbacks==2, f"rollbacks={c.rollbacks}")
ck("OUTCOME_transient_blip_fires_NO_alert", alerts==[], f"alerts={alerts}")

r,c=call([("boom",)])
ck("MECHANISM_exhausts_exactly_3_attempts", c.cursor_calls==3, f"cursor={c.cursor_calls}")
ck("OUTCOME_unreadable_blocks_fail_closed", r is not None and not r.is_routine_refusal())
ck("MECHANISM_unreadable_reason_distinct_from_denial", r.reason=="db_unreadable", f"reason={r.reason}")
ck("OUTCOME_unreadable_says_NOT_an_ROE_denial", "NOT an ROE denial" in r.message)
ck("OUTCOME_alert_fires_ONLY_after_exhausted_retries", alerts==["db_unreadable"], f"alerts={alerts}")

# ── OUTCOME: light never gates ──
r,c=call([("boom",)],intensity="light")
ck("OUTCOME_light_short_circuits_no_db_hit", r is None and c.cursor_calls==0, f"cursor={c.cursor_calls}")

# ── G4: safety gate exposes NO fail-open switch ──
src=(pathlib.Path(__file__).parent.parent.parent / "scanner" / "roe_gate.py").read_text()
ck("MECHANISM_safety_gate_has_no_fail_open_env", "fail_open" not in src.lower().replace("no fail-open switch",""))
print("\n"+("ALL PASS" if not F else "FAILURES: "+", ".join(F))); sys.exit(1 if F else 0)
