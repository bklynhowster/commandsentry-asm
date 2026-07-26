import hashlib,glob,os,sys,io,types,contextlib,importlib
sys.path.insert(0,"common")
SHAS={os.path.basename(f):hashlib.sha256(open(f,'rb').read()).hexdigest() for f in glob.glob("migs/*.sql")}
class Cur:
    def __init__(s,te,rows): s.te,s.rows=te,rows
    def execute(s,q): pass
    def fetchone(s): return ("x" if s.te else None,)
    def fetchall(s): return s.rows
class Conn:
    def __init__(s,c): s.c=c
    def cursor(s): return s.c
    def close(s): pass
def run(script,argv=("--dsn","x","--migrations-dir","migs")):
    mod=importlib.import_module("gate"); importlib.reload(mod)
    n={"i":0}
    m=types.ModuleType("psycopg")
    def connect(dsn,connect_timeout=None):
        i=n["i"]; n["i"]+=1
        st=script[i] if i<len(script) else script[-1]
        if st=="boom": raise Exception("connection timeout expired")
        return Conn(Cur(st[1],st[2]))
    m.connect=connect; sys.modules["psycopg"]=m
    import gate_retry; gate_retry.time.sleep=lambda *_:None
    mod.run_with_transport_retry.__globals__["time"].sleep=lambda *_:None
    sys.argv=["gate"]+list(argv)
    o,e=io.StringIO(),io.StringIO()
    with contextlib.redirect_stdout(o),contextlib.redirect_stderr(e): rc=mod.main()
    return rc,o.getvalue()+e.getvalue(),n["i"]
full=[(f,SHAS[f]) for f in SHAS]; part=[(list(SHAS)[0],SHAS[list(SHAS)[0]])]; bad=[(f,"dead") for f in SHAS]
F=[]
def ck(n,c,x=""): print(f"{'PASS' if c else 'FAIL'}  {n}"+("" if c else f"  {x}")); F.append(n) if not c else None
r=run([("ok",True,full)]);   ck("OUTCOME_clean_ledger_exit0_one_attempt", r[0]==0 and r[2]==1, r)
r=run(["boom","boom",("ok",True,full)]); ck("MECHANISM_transient_then_ok_retries_to_3", r[0]==0 and r[2]==3, r)
r=run(["boom"]);             ck("MECHANISM_all_transport_exit2_exactly_3_attempts", r[0]==2 and r[2]==3, r)
r=run(["boom"]);             ck("OUTCOME_unreadable_says_NOT_ledger_drift", "UNREADABLE" in r[1] and "NOT ledger drift" in r[1])
r=run(["boom"]);             ck("OUTCOME_transport_msg_has_no_drift_words", "SHA-MISMATCH" not in r[1] and "UNAPPLIED" not in r[1])
r=run([("ok",False,[])]);    ck("MECHANISM_missing_table_verdict_NOT_retried", r[0]==2 and r[2]==1, r)
r=run([("ok",True,part)]);   ck("OUTCOME_unapplied_still_exit1", r[0]==1 and "UNAPPLIED" in r[1], r)
r=run([("ok",True,bad)]);    ck("OUTCOME_sha_mismatch_still_exit1", r[0]==1 and "SHA-MISMATCH" in r[1], r)
r=run(["boom",("ok",False,[])]); ck("MECHANISM_transient_then_verdict_verdict_wins", r[0]==2 and r[2]==2, r)
os.environ["LEDGER_GATE_TRANSPORT_MODE"]="fail_open"
r=run(["boom"]);             ck("OUTCOME_operator_fail_open_proceeds_loudly", r[0]==0 and "PROCEEDING UNVERIFIED" in r[1], r)
del os.environ["LEDGER_GATE_TRANSPORT_MODE"]
r=run(["boom"]);             ck("MECHANISM_fail_open_is_not_the_default", r[0]==2, r)
print("\n"+("ALL PASS" if not F else "FAILURES: "+", ".join(F))); sys.exit(1 if F else 0)
