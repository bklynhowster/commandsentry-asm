import os, sys, types, smtplib
sys.path.insert(0, ".")
import mailer

F=[]
def ck(n,c,x=""): print(f"{'PASS' if c else 'FAIL'}  {n}"+("" if c else f"   {x}")); (F.append(n) if not c else None)

# ── provider selection ──
os.environ.pop("MAIL_PROVIDER", None)
ck("OUTCOME_default_provider_is_sendgrid_command_unchanged", mailer.provider_name()=="sendgrid")
os.environ["MAIL_PROVIDER"]="smtp"
ck("OUTCOME_smtp_selected_when_set", mailer.provider_name()=="smtp")
os.environ["MAIL_PROVIDER"]="SendGrid"
ck("MECHANISM_provider_is_case_insensitive", mailer.provider_name()=="sendgrid")

# ── guards ──
os.environ["MAIL_PROVIDER"]="smtp"
ok,d = mailer.send_email(to_addrs=[], subject="s", html="h", from_addr="a@b.c")
ck("OUTCOME_no_recipients_refuses", not ok and "no recipients" in d, d)
ok,d = mailer.send_email(to_addrs=["x@y.z"], subject="s", html="h", from_addr="")
ck("OUTCOME_no_from_refuses", not ok and "ALERTER_FROM" in d, d)
for k in ("SMTP_HOST","SMTP_USER","SMTP_PASS"): os.environ.pop(k, None)
ok,d = mailer.send_email(to_addrs=["x@y.z"], subject="s", html="h", from_addr="a@b.c")
ck("OUTCOME_smtp_unconfigured_returns_false_not_raise", not ok and "SMTP_HOST/USER/PASS" in d, d)
os.environ["MAIL_PROVIDER"]="carrier-pigeon"
ok,d = mailer.send_email(to_addrs=["x@y.z"], subject="s", html="h", from_addr="a@b.c")
ck("OUTCOME_unknown_provider_refuses_loudly", not ok and "unknown MAIL_PROVIDER" in d, d)

# ── SMTP: real send against a fake server, asserting the wire behaviour ──
sent = {}
class FakeSMTP:
    def __init__(s, host, port, timeout=None): sent["host"]=host; sent["port"]=port; sent["ssl"]=False
    def __enter__(s): return s
    def __exit__(s,*a): return False
    def ehlo(s): pass
    def starttls(s, context=None): sent["starttls"]=True
    def login(s,u,p): sent["user"]=u
    def send_message(s,m):
        sent["msg"]=m; sent["to"]=m["To"]; sent["from"]=m["From"]; sent["subj"]=m["Subject"]
        sent["types"]=[part.get_content_type() for part in m.walk()]
class FakeSMTP_SSL(FakeSMTP):
    def __init__(s, host, port, timeout=None, context=None):
        super().__init__(host,port,timeout); sent["ssl"]=True
mailer.smtplib.SMTP = FakeSMTP
mailer.smtplib.SMTP_SSL = FakeSMTP_SSL

os.environ.update({"MAIL_PROVIDER":"smtp","SMTP_HOST":"smtp.mail.me.com","SMTP_PORT":"587",
                   "SMTP_USER":"howiehow@mac.com","SMTP_PASS":"app-specific"})
ok,d = mailer.send_email(to_addrs=["a@x.com","b@y.com"], subject="Subj", html="<b>H</b>",
                         text="T", from_addr="howiehow@mac.com", from_name="PRODEXsentry",
                         headers={"List-Unsubscribe":"<https://p/x>"})
ck("MECHANISM_smtp_587_uses_STARTTLS_not_implicit_TLS", ok and sent.get("starttls") and not sent.get("ssl"), d)
ck("OUTCOME_smtp_sends_to_icloud_host", sent.get("host")=="smtp.mail.me.com" and sent.get("port")==587)
ck("OUTCOME_from_header_carries_display_name", sent.get("from")=="PRODEXsentry <howiehow@mac.com>", sent.get("from"))
ck("OUTCOME_all_recipients_present", sent.get("to")=="a@x.com, b@y.com", sent.get("to"))
ck("MECHANISM_multipart_alternative_text_and_html",
   "multipart/alternative" in sent.get("types",[]) and "text/plain" in sent.get("types",[]) and "text/html" in sent.get("types",[]),
   sent.get("types"))
ck("OUTCOME_custom_headers_preserved", sent["msg"]["List-Unsubscribe"]=="<https://p/x>")

os.environ["SMTP_PORT"]="465"
ok,d = mailer.send_email(to_addrs=["a@x.com"], subject="s", html="<b>h</b>", from_addr="a@b.c")
ck("MECHANISM_port_465_uses_implicit_TLS", ok and sent.get("ssl") is True, d)

# ── failure never raises ──
class Boom(FakeSMTP):
    def login(s,u,p): raise OSError("connection refused")
mailer.smtplib.SMTP = Boom; os.environ["SMTP_PORT"]="587"
ok,d = mailer.send_email(to_addrs=["a@x.com"], subject="s", html="h", from_addr="a@b.c")
ck("OUTCOME_transport_failure_returns_false_never_raises", not ok and "smtp error" in d, d)

print("\n"+("ALL PASS" if not F else "FAILURES: "+", ".join(F)))
sys.exit(1 if F else 0)
