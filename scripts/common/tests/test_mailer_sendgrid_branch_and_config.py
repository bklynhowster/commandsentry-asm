"""M2: BOTH provider branches tested — this suite runs on BOTH instances' CI,
so a bug in the branch an instance doesn't use in prod is still caught."""
import os, sys, types, io, contextlib, json
sys.path.insert(0, ".")
import mailer
F=[]
def ck(n,c,x=""): print(f"{'PASS' if c else 'FAIL'}  {n}"+("" if c else f"   {x}")); (F.append(n) if not c else None)
def clean():
    for k in ("MAIL_PROVIDER","SMTP_HOST","SMTP_PORT","SMTP_USER","SMTP_PASS","SENDGRID_API_KEY"):
        os.environ.pop(k, None)

# ── M5: differentiated startup messages ──
clean()
ok,m = mailer.check_config()
ck("M5_default_sendgrid_missing_key_says_so", not ok and "SENDGRID_API_KEY missing" in m and "by default" in m, m)
os.environ["MAIL_PROVIDER"]="sendgrid"
ok,m = mailer.check_config()
ck("M5_explicit_sendgrid_missing_key_distinct_wording", not ok and "selected but" in m, m)
os.environ["MAIL_PROVIDER"]="smtp"
ok,m = mailer.check_config()
ck("M5_smtp_names_the_missing_vars", not ok and "SMTP_HOST" in m and "SMTP_USER" in m and "SMTP_PASS" in m, m)
os.environ.update({"SMTP_HOST":"smtp.mail.me.com","SMTP_USER":"u","SMTP_PASS":"p"})
ok,m = mailer.check_config()
ck("M5_smtp_configured_reports_target", ok and "smtp.mail.me.com" in m, m)
os.environ["MAIL_PROVIDER"]="pigeon"
ok,m = mailer.check_config()
ck("M5_unknown_provider_names_the_value", not ok and "pigeon" in m, m)

# warn emits ::warning:: not ::error::  (M5: must never fail the workflow)
clean(); err=io.StringIO()
with contextlib.redirect_stderr(err): configured = mailer.warn_if_unconfigured("prodex")
out = err.getvalue()
ck("M5_warns_not_errors", "::warning::" in out and "::error::" not in out, out.strip()[:80])
ck("M5_warning_tagged_greppable", "[MAIL_UNCONFIGURED]" in out)
ck("M5_returns_configured_bool", configured is False)

# ── M2: SendGrid branch — tested even though Prodex never uses it ──
clean(); os.environ.update({"MAIL_PROVIDER":"sendgrid","SENDGRID_API_KEY":"sg-key"})
cap={}
class FakeResp:
    status=202; headers={"X-Message-Id":"msg-1"}
    def __enter__(s): return s
    def __exit__(s,*a): return False
def fake_urlopen(req, timeout=None):
    cap["url"]=req.full_url; cap["body"]=json.loads(req.data.decode())
    cap["auth"]=req.headers.get("Authorization"); return FakeResp()
mailer.urllib.request.urlopen = fake_urlopen
ok,d = mailer.send_email(to_addrs=["a@x.com","b@y.com"], subject="S", html="<b>h</b>",
                         text="t", from_addr="from@c.com", from_name="COMMANDsentry",
                         headers={"List-Unsubscribe":"<u>"})
ck("M2_sendgrid_sends_ok", ok, d)
ck("M2_sendgrid_correct_endpoint", cap["url"]=="https://api.sendgrid.com/v3/mail/send")
ck("M2_sendgrid_bearer_auth", cap["auth"]=="Bearer sg-key")
ck("M2_sendgrid_all_recipients", [t["email"] for t in cap["body"]["personalizations"][0]["to"]]==["a@x.com","b@y.com"])
ck("M2_sendgrid_text_part_before_html", [c["type"] for c in cap["body"]["content"]]==["text/plain","text/html"])
ck("M2_sendgrid_from_name_carried", cap["body"]["from"]=={"email":"from@c.com","name":"COMMANDsentry"})
ck("M2_sendgrid_headers_passed", cap["body"].get("headers")=={"List-Unsubscribe":"<u>"})

class HTTPErr(Exception):
    code=401
    def read(s): return b'{"errors":[{"message":"bad key"}]}'
mailer.urllib.error.HTTPError = HTTPErr
def boom(req, timeout=None): raise HTTPErr()
mailer.urllib.request.urlopen = boom
ok,d = mailer.send_email(to_addrs=["a@x.com"], subject="s", html="h", from_addr="f@c.com")
ck("M2_sendgrid_http_error_returns_false_never_raises", not ok and "401" in d, d)

print("\n"+("ALL PASS" if not F else "FAILURES: "+", ".join(F)))
sys.exit(1 if F else 0)
