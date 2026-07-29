"""M6 canary — mechanism tests."""
import os, sys, io, contextlib
sys.path.insert(0, ".")
import mailer, mail_canary as mc
F=[]
def ck(n,c,x=""): print(f"{'PASS' if c else 'FAIL'}  {n}"+("" if c else f"   {x}")); (F.append(n) if not c else None)
class A:  instance=""; max_age_hours=26
def clean():
    for k in ("MAIL_PROVIDER","SMTP_HOST","SMTP_USER","SMTP_PASS","SENDGRID_API_KEY",
              "MAIL_CANARY_ADDRESS","MAIL_CANARY_LAST_RECEIVED","ALERTER_FROM"): os.environ.pop(k,None)

clean(); e=io.StringIO()
with contextlib.redirect_stderr(e): rc = mc.cmd_send(A())
ck("M6_no_canary_address_is_warning_not_failure", rc==0 and "::warning::" in e.getvalue())

clean(); os.environ["MAIL_CANARY_ADDRESS"]="howiehow@mac.com"; os.environ["MAIL_PROVIDER"]="smtp"
e=io.StringIO()
with contextlib.redirect_stderr(e): rc = mc.cmd_send(A())
ck("M6_unconfigured_transport_fails_loudly", rc==1 and "::error::" in e.getvalue(), e.getvalue().strip()[:70])

clean(); os.environ.update({"MAIL_CANARY_ADDRESS":"x@y.z","MAIL_PROVIDER":"sendgrid",
                            "SENDGRID_API_KEY":"k","ALERTER_FROM":"f@c.com"})
sent={}
def fake(**kw): sent.update(kw); return True, "ok"
mc.send_email = fake
o=io.StringIO()
with contextlib.redirect_stdout(o): rc = mc.cmd_send(A())
ck("M6_sends_when_configured", rc==0)
ck("M6_canary_header_set", sent.get("headers",{}).get("X-Mail-Canary")=="1")
ck("M6_targets_monitored_address", sent.get("to_addrs")==["x@y.z"])

mc.send_email = lambda **kw: (False, "smtp auth failed")
e=io.StringIO()
with contextlib.redirect_stderr(e): rc = mc.cmd_send(A())
ck("M6_send_failure_is_error_exit1", rc==1 and "::error::" in e.getvalue())

# watchdog
clean(); e=io.StringIO()
with contextlib.redirect_stderr(e): rc = mc.cmd_watch(A())
ck("M6_watch_admits_delivery_unverified_rather_than_faking_green",
   rc==0 and "DELIVERY is" in e.getvalue() and "NOT" in e.getvalue())
from datetime import datetime, timezone, timedelta
os.environ["MAIL_CANARY_LAST_RECEIVED"]=(datetime.now(timezone.utc)-timedelta(hours=2)).isoformat()
o=io.StringIO()
with contextlib.redirect_stdout(o): rc = mc.cmd_watch(A())
ck("M6_recent_receipt_ok", rc==0 and "receipt OK" in o.getvalue())
os.environ["MAIL_CANARY_LAST_RECEIVED"]=(datetime.now(timezone.utc)-timedelta(hours=40)).isoformat()
e=io.StringIO()
with contextlib.redirect_stderr(e): rc = mc.cmd_watch(A())
ck("M6_overdue_receipt_errors_and_names_likely_cause",
   rc==1 and "::error::" in e.getvalue() and "app-specific password" in e.getvalue())
print("\n"+("ALL PASS" if not F else "FAILURES: "+", ".join(F)))
sys.exit(1 if F else 0)
