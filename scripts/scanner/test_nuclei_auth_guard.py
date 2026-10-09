#!/usr/bin/env python3
"""test_nuclei_auth_guard.py — D-056 FAIL-CLOSED: no login-type attack reaches a target.

⛔ D-056 (Howie, 2026-09-29, ABSOLUTE; scope confirmed 2026-10-08): no
default/hardcoded-credential logins, no password guessing, no login- or
auth-bypass probes, on any asset at any tier. Relay 549's tag denylist
(#46) failed OPEN: 51 templates TITLED as authentication bypass or hardcoded
credentials carried none of its tags and ran in every heavy. These tests pin:

  1. all 51 are refused (the regression corpus 4.7 measured on 2026-10-07);
  2. the request shapes Prodex's own logs caught on 2026-10-07 are refused;
  3. exposure and detection checks are NOT refused (the product is
     attack-surface mapping; a guard that blinds it is its own failure);
  4. it fails CLOSED: unreadable, unparseable, no PyYAML, or a wrong corpus
     directory refuses rather than passes;
  5. through the REAL run_nuclei_chunk: nuclei only ever runs with
     `-t <checked list>`, a refused template never reaches that list, and a
     guard failure means nuclei is not run at all;
  6. nothing else in the repo launches nuclei at a target unguarded.
"""
from __future__ import annotations

import ast
import os
import re
import sys
import types

import pytest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import nuclei_auth_guard as g  # noqa: E402
import run_medium as m  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

# ── 1. the regression corpus: 4.7's list A, nuclei-templates 4907f78, 2026-10-07
# (relay 550; _relay/_staging/d056-auth-templates-still-allowed-2026-10-07.txt).
THE_51 = [
    ('critical', 'http/cves/2016/CVE-2016-7552.yaml', 'Trend Micro Threat Discovery Appliance 2.6.1062r1 - Authentication Bypass'),
    ('critical', 'http/cves/2017/CVE-2017-5689.yaml', 'Intel Active Management - Authentication Bypass'),
    ('critical', 'http/cves/2018/CVE-2018-3810.yaml', 'Oturia WordPress Smart Google Code Inserter <3.5 - Authentication Bypass'),
    ('critical', 'http/cves/2019/CVE-2019-13101.yaml', 'D-Link DIR-600M - Authentication Bypass'),
    ('critical', 'http/cves/2019/CVE-2019-20933.yaml', 'InfluxDB <1.7.6 - Authentication Bypass'),
    ('critical', 'http/cves/2019/CVE-2019-4716.yaml', 'IBM Planning Analytics - Authentication Bypass & Remote Code Execution Version Detection'),
    ('critical', 'http/cves/2019/CVE-2019-9733.yaml', 'JFrog Artifactory 6.7.3 - Admin Login Bypass'),
    ('critical', 'http/cves/2020/CVE-2020-17506.yaml', 'Artica Web Proxy 4.30 - Authentication Bypass/SQL Injection'),
    ('high', 'http/cves/2020/CVE-2020-24579.yaml', 'D-Link DSL 2888a - Authentication Bypass/Remote Command Execution'),
    ('high', 'http/cves/2020/CVE-2020-27986.yaml', 'SonarQube - Authentication Bypass'),
    ('critical', 'http/cves/2020/CVE-2020-29583.yaml', 'ZyXel USG - Hardcoded Credentials'),
    ('critical', 'http/cves/2020/CVE-2020-5777.yaml', 'Magento Mass Importer  <0.7.24 - Remote Auth Bypass'),
    ('critical', 'http/cves/2020/CVE-2020-8771.yaml', 'WordPress Time Capsule < 1.21.16 - Authentication Bypass'),
    ('high', 'http/cves/2021/CVE-2021-20167.yaml', 'Netgear RAX43 1.0.3.96 - Command Injection/Authentication Bypass Buffer Overrun'),
    ('critical', 'http/cves/2021/CVE-2021-24175.yaml', 'The Plus Addons for Elementor Page Builder < 4.1.7 - Authentication Bypass'),
    ('critical', 'http/cves/2021/CVE-2021-25281.yaml', 'SaltStack Salt <3002.5 - Auth Bypass'),
    ('critical', 'http/cves/2021/CVE-2021-29203.yaml', 'HPE Edgeline Infrastructure Manager <1.22 - Authentication Bypass'),
    ('critical', 'http/cves/2021/CVE-2021-37580.yaml', 'Apache ShenYu Admin JWT - Authentication Bypass'),
    ('high', 'http/cves/2021/CVE-2021-39226.yaml', 'Grafana Snapshot - Authentication Bypass'),
    ('critical', 'http/cves/2021/CVE-2021-41266.yaml', 'MinIO Operator Console Authentication Bypass'),
    ('critical', 'http/cves/2022/CVE-2022-1162.yaml', 'GitLab CE/EE - Hard-Coded Credentials'),
    ('critical', 'http/cves/2022/CVE-2022-1388.yaml', 'F5 BIG-IP iControl - REST Auth Bypass RCE'),
    ('high', 'http/cves/2022/CVE-2022-2551.yaml', 'WordPress Duplicator <1.4.7 - Authentication Bypass'),
    ('critical', 'http/cves/2022/CVE-2022-32429.yaml', 'MSNSwitch Firmware MNT.2408 - Authentication Bypass'),
    ('critical', 'http/cves/2023/CVE-2023-29357.yaml', 'Microsoft SharePoint - Authentication Bypass'),
    ('critical', 'http/cves/2023/CVE-2023-35078.yaml', 'Ivanti Endpoint Manager Mobile (EPMM) - Authentication Bypass'),
    ('critical', 'http/cves/2023/CVE-2023-37265.yaml', 'CasaOS  < 0.4.4 - Authentication Bypass via Internal IP'),
    ('critical', 'http/cves/2023/CVE-2023-37266.yaml', 'CasaOS  < 0.4.4 - Authentication Bypass via Random JWT Token'),
    ('high', 'http/cves/2023/CVE-2023-38433.yaml', 'Fujitsu IP Series - Hardcoded Credentials'),
    ('high', 'http/cves/2023/CVE-2023-4415.yaml', 'Ruijie RG-EW1200G Router Background - Login Bypass'),
    ('critical', 'http/cves/2024/CVE-2024-0012.yaml', 'PAN-OS Management Web Interface - Authentication Bypass'),
    ('critical', 'http/cves/2024/CVE-2024-28200.yaml', 'N-able N-central < 2024.2 - Authentication Bypass Detection'),
    ('critical', 'http/cves/2024/CVE-2024-28987.yaml', 'SolarWinds Web Help Desk - Hardcoded Credential'),
    ('high', 'http/cves/2024/CVE-2024-33288.yaml', 'Prison Management System - SQL Injection Authentication Bypass'),
    ('critical', 'http/cves/2024/CVE-2024-55591.yaml', 'Fortinet - Authentication Bypass'),
    ('critical', 'http/cves/2024/CVE-2024-7332.yaml', 'TOTOLINK CP450 v4.1.0cu.747_B20191224 - Hard-Coded Password Vulnerability'),
    ('critical', 'http/cves/2025/CVE-2025-14611.yaml', 'Gladinet CentreStack & Triofox - Hardcoded Credentials'),
    ('high', 'http/cves/2025/CVE-2025-3102.yaml', 'SureTriggers – All-in-One Automation Platform ≤ 1.0.78 - Authentication Bypass'),
    ('high', 'http/cves/2025/CVE-2025-34509.yaml', 'Sitecore Experience Manager (XM) and Experience Platform (XP) - Hardcoded Credentials'),
    ('critical', 'http/cves/2025/CVE-2025-48827.yaml', 'vBulletin 5.0.0-6.0.3 - Authentication Bypass'),
    ('critical', 'http/cves/2026/CVE-2026-10580.yaml', 'Hippoo Mobile App for WooCommerce <= 1.9.4 - Authentication Bypass to Admin Account Takeover'),
    ('critical', 'http/misconfiguration/aem/aem-crx-bypass.yaml', 'AEM Package Manager - Authentication Bypass'),
    ('critical', 'http/misconfiguration/marimo-auth-bypass.yaml', 'motionEye Partial - Authentication Bypass'),
    ('critical', 'http/misconfiguration/unauthorized-plastic-scm.yaml', 'Plastic Admin Console - Authentication Bypass'),
    ('critical', 'http/vulnerabilities/ntopng-auth-bypass.yaml', 'Ntopng Authentication Bypass'),
    ('critical', 'http/vulnerabilities/wordpress/wp-woocommerce-email-verification.yaml', 'Email Verification for WooCommerce < 1.8.2 - Loose Comparison to Authentication Bypass'),
    ('medium', 'http/cves/2015/CVE-2015-4050.yaml', 'Symfony - Authentication Bypass'),
    ('medium', 'http/cves/2024/CVE-2024-5947.yaml', 'Deep Sea Electronics DSE855 - Authentication Bypass'),
    ('medium', 'http/cves/2025/CVE-2025-27112.yaml', 'Navidrome <=0.54.5 - Authentication Bypass in Subsonic API'),
    ('medium', 'http/cves/2025/CVE-2025-4302.yaml', 'Stop User Enumeration WordPress plugin - Authentication Bypass'),
    ('medium', 'http/cves/2025/CVE-2025-9316.yaml', 'N-central - Authentication Bypass'),
]


def test_the_regression_corpus_is_complete():
    assert len(THE_51) == 51
    assert sum(1 for s, _, _ in THE_51 if s in ("critical", "high")) == 46


@pytest.mark.parametrize("sev,path,title", THE_51, ids=[p.rsplit("/", 1)[-1] for _, p, _ in THE_51])
def test_every_one_of_the_51_titled_login_attacks_is_refused(sev, path, title):
    doc = {"id": path.rsplit("/", 1)[-1][:-5], "info": {"name": title, "severity": sev}}
    assert g.classify_doc(doc, path), f"D-056: {path} ({title}) would run"


# ── 2. what Prodex's load-balancer and Cloud IDS logs caught on 2026-10-07
def _http(**blk):
    return {"id": "t", "info": {"name": "Some Product - Detect", "severity": "high"}, "http": [blk]}


INCIDENT_SHAPES = {
    "jellyfin authenticatebyname": _http(raw=['POST /Users/authenticatebyname HTTP/1.1\nHost: {{Hostname}}\n\n{"Username":"root","Pw":""}']),
    "jboss j_security_check": _http(method="POST", path=["{{BaseURL}}/jbpm-console/j_security_check"], body="j_username=admin&j_password=admin"),
    "lutron literal password": _http(method="POST", path=["{{BaseURL}}/cgi-bin/x"], body="login=lutron&password=lutron"),
    "json password": _http(method="POST", path=["{{BaseURL}}/api/x"], body='{"user":"admin","password":"admin"}'),
    "xml password": _http(method="POST", path=["{{BaseURL}}/rpc"], body="<user>admin</user><password>admin</password>"),
    "literal basic header": _http(method="GET", path=["{{BaseURL}}/"], headers={"Authorization": "Basic YWRtaW46YWRtaW4="}),
    "base64 helper basic": _http(raw=["GET / HTTP/1.1\nHost: {{Hostname}}\nAuthorization: Basic {{base64(username + ':' + password)}}\n"]),
    "literal bearer token": _http(raw=["GET /api HTTP/1.1\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc\n"]),
    "log-in-first variable": _http(method="POST", path=["{{BaseURL}}/login"], body="user={{username}}&pw={{password}}"),
    "credential payload list": _http(method="POST", path=["{{BaseURL}}/login"], body="u=§u§",
                                     payloads={"username": ["admin"], "password": ["admin", "1234"]}, attack="pitchfork"),
    "socket USER/PASS": {"id": "t", "info": {"name": "FTP - Detect", "severity": "info"},
                         "network": [{"inputs": [{"data": "USER anonymous\r\nPASS anonymous\r\n"}], "host": ["{{Hostname}}"]}]},
    "javascript password": {"id": "t", "info": {"name": "SSH - Detect", "severity": "info"},
                            "javascript": [{"code": "c.Connect(Host, Port, Username, Password)", "args": {"Password": "root"}}]},
    "credential variables": {"id": "t", "info": {"name": "Panel", "severity": "high"},
                             "variables": {"username": "admin", "password": "admin"},
                             "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]},
    "default-logins directory": ({"id": "t", "info": {"name": "Panel", "severity": "high"},
                                  "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]}, "http/default-logins/x/x.yaml"),
    "login-attack tag": {"id": "t", "info": {"name": "Panel", "severity": "high", "tags": "panel,default-login"},
                         "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]},
    "auth CWE": {"id": "t", "info": {"name": "Product - RCE", "severity": "critical",
                                     "classification": {"cwe-id": "CWE-288,NVD-CWE-Other"}},
                 "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]},
    "bypass in the description": {"id": "t", "info": {"name": "Product - RCE", "severity": "critical",
                                  "description": "Attackers can bypass the REST authentication and run commands."},
                                  "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]},
    # ── the independent review's misses (2026-10-08), as minimal shapes ──
    "wordpress password-reset submission": _http(raw=[
        "POST /wp-login.php?action=lostpassword HTTP/1.1\nHost: {{Hostname}}\n\nuser_login={{wp_user}}&password_1={{rp_token}}\n"]),
    "account takeover in the description": {"id": "t", "info": {
        "name": "Plugin 1.0.7 - Privilege Escalation", "severity": "critical",
        "description": "Unauthenticated attackers can change the admin e-mail, leading to account takeover."},
        "http": [{"raw": ["POST /wp-admin/admin-ajax.php HTTP/1.1\n\naction=x&user_id={{userid}}&email-update={{email}}\n"]}]},
    "credential enumeration title": {"id": "t", "info": {"name": "Strapi <=5.36.x - Admin Credential Enumeration",
                                     "severity": "critical"}, "http": [{"method": "GET", "path": ["{{BaseURL}}/api"]}]},
    "prefixed password field (userPsw)": _http(raw=["POST /rep/x HTTP/1.1\n\nuserID=admin&userPsw=123\n"]),
    "empty password": _http(raw=["POST /ok.html HTTP/1.1\n\nusername=anonymous&password=\n"]),
    "json pass key, empty": _http(raw=['POST /spcgi.cgi HTTP/1.1\n\n{"module":"auth","arguments":{"user":"","pass":""}}\n']),
    "bracketed password field": _http(raw=["POST / HTTP/1.1\n\nauth[driver]=server&auth[username]=x&auth[password]=\n"]),
    "digit-suffixed password field": _http(method="POST", path=["{{BaseURL}}/reset"], body="password_1=x&password_2=x"),
    "identity cookie (guest login)": _http(method="GET", path=["{{BaseURL}}/web/xml/webuser-auth.xml"],
                                           headers={"Cookie": "login=1; auth=Z3Vlc3Q6Z3Vlc3Q%3D; user=guest"}),
    "forged admin cookie": _http(raw=["GET /Server/CmxUser.php HTTP/1.1\ncookie: RAS_Admin_UserInfo_UserName=admin\n"]),
    "superuser cookie": _http(raw=["POST /rest/x HTTP/1.1\nCookie: AuthToken=; AuthGroup=superuser; UserName=admin\n\n{}\n"]),
    "custom Auth header": _http(raw=['GET /ws/msw/tenant/x HTTP/1.1\nAuth: {"user": "system", "hash": "abc"}\n']),
    "hex socket login": {"id": "t", "info": {"name": "FTP - Detect", "severity": "info"},
                         "network": [{"inputs": [{"type": "hex", "data": "USER root\r\n".encode().hex()}]}]},
    "password in the flow": {"id": "t", "info": {"name": "Panel", "severity": "high"},
                             "flow": "set('password', 'admin'); http(1)",
                             "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]},
    "apostrophe in a bypass description": {"id": "t", "info": {
        "name": "UTM 12.x Session ID Leak", "severity": "high",
        "description": "Attackers can bypass the device's authentication and read the admin config."},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]},
    "authentication override title": {"id": "t", "info": {"name": "RAS System Cookie - Authentication Override",
                                      "severity": "high"}, "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]},
    "authorization CWE-863": {"id": "t", "info": {"name": "Product - Info Leak", "severity": "high",
                              "classification": {"cwe-id": "CWE-863"}},
                              "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]},
    # ── the review's second pass (2026-10-08) ──
    "a POST to a login path, whatever the fields are called": _http(raw=[
        'POST /api/logon HTTP/1.1\nHost: {{Hostname}}\n\n{"usr":"a","secret":"b"}\n']),
    "a password-change form": _http(raw=["POST /password_change.cgi HTTP/1.1\n\nuser=root&pam=&expired=2&old=x&new1=y\n"]),
    "rememberMe cookie": _http(raw=["GET / HTTP/1.1\nCookie: rememberMe=dGVzdA==\n"]),
    "credential field": _http(method="POST", path=["{{BaseURL}}/api/x"], body="credential=admin:admin"),
    "a cookie value BUILT from literals": _http(raw=['GET / HTTP/1.1\nCookie: auth={{base64("admin:admin")}}\n']),
    "a custom auth header BUILT from literals": _http(raw=['GET / HTTP/1.1\nX-Api-Key: {{md5("default")}}\n']),
    "admin account creation": {"id": "t", "info": {
        "name": "Eventin <= 4.0.26 - Privilege Escalation", "severity": "critical",
        "description": "Unauthenticated attackers can import users with arbitrary roles, including administrator."},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]},
    "a blank-password account the product ships with": {"id": "t", "info": {
        "name": "Horde Groupware Unauthenticated Admin Access", "severity": "critical",
        "description": "Horde Groupware contains an administrative account with a blank password."},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/horde/admin"]}]},
}


@pytest.mark.parametrize("label", sorted(INCIDENT_SHAPES))
def test_the_login_attack_shapes_are_refused(label):
    doc = INCIDENT_SHAPES[label]
    rel = ""
    if isinstance(doc, tuple):
        doc, rel = doc
    assert g.classify_doc(doc, rel), f"D-056: a template shaped like '{label}' would run"


# ── 3. the product is attack-surface mapping: these must keep running
ALLOWED_SHAPES = {
    "login panel detect (info, mentions default creds)": {
        "id": "t", "info": {"name": "Acme Router Panel - Detect", "severity": "info",
                            "description": "Acme panel was detected. Default credentials are admin/admin."},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/login"],
                  "matchers": [{"type": "word", "words": ["password"]}]}]},
    ".env exposure (password only in the matcher)": {
        "id": "t", "info": {"name": "Laravel .env - Exposure", "severity": "high"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/.env"],
                  "matchers": [{"type": "word", "words": ["DB_PASSWORD=", "APP_KEY="]}]}]},
    "disclosure of hardcoded credentials": {
        "id": "t", "info": {"name": "TestRail files.md5 - Exposure", "severity": "high",
                            "description": "Files can be fetched and in some cases result in the disclosure of hardcoded credentials."},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/files.md5"]}]},
    "plugin named after brute force (info)": {
        "id": "t", "info": {"name": "Limit Login Attempts – Brute Force Protection Detect", "severity": "info"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/wp-content/plugins/x/readme.txt"]}]},
    "plain RCE": {
        "id": "t", "info": {"name": "Acme - Remote Code Execution", "severity": "critical",
                            "classification": {"cwe-id": "CWE-78"}},
        "http": [{"method": "POST", "path": ["{{BaseURL}}/api/exec"], "body": "cmd=id"}]},
    "missing authentication, CWE-306": {
        "id": "t", "info": {"name": "Jenkins - Unauthenticated Script Console", "severity": "high",
                            "classification": {"cwe-id": "CWE-306"}},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/script"]}]},
    "/etc/passwd traversal": {
        "id": "t", "info": {"name": "Acme - Path Traversal", "severity": "high"},
        "http": [{"raw": ["GET /download?file=../../../../etc/passwd HTTP/1.1\nHost: {{Hostname}}\n"]}]},
    "wordpress login panel detect": {
        "id": "t", "info": {"name": "WordPress Login Panel - Detect", "severity": "info"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/wp-login.php"],
                  "matchers": [{"type": "word", "words": ["user_login"]}]}]},
    "locale cookie": {
        "id": "t", "info": {"name": "Acme - Version Detect", "severity": "medium"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/"], "headers": {"Cookie": "UserCulture=en-US; lang=en"}}]},
    "session cookie handed back by an earlier request": {
        "id": "t", "info": {"name": "Acme - Info Leak", "severity": "medium"},
        "http": [{"raw": ["GET /api HTTP/1.1\nCookie: PHPSESSID={{session}}; AuthToken={{token}}\n"]}]},
    "fetching a forgot-password page": {
        "id": "t", "info": {"name": "Acme - Panel", "severity": "medium"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/forgot-password"]}]},
    "a config file that leaks hardcoded credentials": {
        "id": "t", "info": {"name": "Acme config.json - Exposure", "severity": "low",
                            "description": "The config.json file is world-readable and leaks hardcoded credentials."},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/config.json"]}]},
}


@pytest.mark.parametrize("label", sorted(ALLOWED_SHAPES))
def test_exposure_and_detection_checks_are_not_refused(label):
    assert g.classify_doc(ALLOWED_SHAPES[label], "http/exposures/x.yaml") == [], (
        f"the guard would blind the scanner to '{label}', which is not a login attack")


# ── 4. fail CLOSED
def test_an_unparseable_template_is_refused(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("id: [unclosed\n  info: {{{\n")
    assert g.classify_file(str(p))


def test_a_template_with_no_info_block_is_refused():
    assert g.classify_doc({"id": "x", "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]})


def test_a_missing_template_is_refused(tmp_path):
    allowed, refused = g.screen(["http/nope.yaml"], str(tmp_path))
    assert allowed == [] and refused and "unreadable" in refused[0][1][0]


def test_no_pyyaml_refuses_everything(tmp_path, monkeypatch):
    p = tmp_path / "ok.yaml"
    p.write_text("id: ok\ninfo:\n  name: ok\n  severity: info\n")
    monkeypatch.setattr(g, "yaml", None)
    assert g.classify_file(str(p))
    assert g.refusal_reason(1, ["ok.yaml"], []) is not None


def test_a_chunk_is_refused_when_the_corpus_cannot_be_read():
    refused = [(f"t{i}.yaml", ["unreadable (missing)"]) for i in range(20)]
    assert g.refusal_reason(100, ["x"] * 80, refused) is not None
    assert g.refusal_reason(100, ["x"] * 95, refused[:5]) is None


def test_a_chunk_is_refused_when_nothing_is_listed_or_nothing_survives():
    assert g.refusal_reason(0, [], []) is not None
    assert g.refusal_reason(3, [], [("a", ["tag x"])] * 3) is not None


def test_the_guard_tags_cover_every_tag_the_run_excludes():
    run_tags = {t for t in m.NUCLEI_AUTH_EXCLUDE_TAGS.split(",") if t}
    assert run_tags <= g.AUTH_TAGS, f"guard misses {sorted(run_tags - g.AUTH_TAGS)}"


# ── 5. through the REAL run_nuclei_chunk
GOOD = "id: acme-config-exposure\ninfo:\n  name: Acme config.json - Exposure\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/x'\n"
# An exploit check that is otherwise clean: detection-only (Howie, 2026-10-09)
# keeps it away from nuclei by policy, not by the guard's content rules.
EXPLOIT = "id: CVE-2099-0003\ninfo:\n  name: Acme - Remote Code Execution\n  severity: critical\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/z'\n"
BAD = ("id: CVE-2099-0002\ninfo:\n  name: Acme - Authentication Bypass\n  severity: critical\n"
       "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/y'\n")
GOOD_REL = "http/exposures/configs/acme-config-exposure.yaml"
BAD_REL = "http/misconfiguration/acme-bypass.yaml"
EXPLOIT_REL = "http/cves/2099/CVE-2099-0003.yaml"


class _Stop(Exception):
    pass


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    root = tmp_path / "nuclei-templates"
    for rel, text in ((GOOD_REL, GOOD), (BAD_REL, BAD), (EXPLOIT_REL, EXPLOIT)):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    monkeypatch.setattr(m, "nuclei_templates_dir", lambda: str(root))
    monkeypatch.delenv("SUPABASE_DSN", raising=False)
    return root


def _drive(monkeypatch, *, listing=(GOOD_REL, BAD_REL), tl_rc=0, dsn=None,
           url_list_file=None, scan_rc=None):
    """Drive the real run_nuclei_chunk. Returns (scan_argv or None, t_file_lines, result, ctx)."""
    seen = {"scan": None, "tfile": None}

    def fake_run_cmd(cmd, timeout=None, **kw):
        if cmd and cmd[0] == "nuclei" and "-tl" in cmd:
            return tl_rc, "\n".join(listing) + "\n", ""
        seen["scan"] = list(cmd)
        if "-t" in cmd:
            seen["tfile"] = open(cmd[cmd.index("-t") + 1]).read().split()
        if scan_rc is None:
            raise _Stop()
        return scan_rc, "", ""

    monkeypatch.setattr(m, "run_cmd", fake_run_cmd)
    ctx = types.SimpleNamespace(waf_detected=False, dsn=dsn, asset_id="test-asset",
                                corpus_prewarm_meta=None, artifacts=[])
    result = None
    try:
        result = m.run_nuclei_chunk(ctx, "https://example.invalid/", "critical,high", None,
                                    url_list_file=url_list_file)
    except _Stop:
        pass
    return seen["scan"], seen["tfile"], result, ctx


def test_nuclei_only_runs_with_the_checked_list_and_the_bypass_is_not_on_it(corpus, monkeypatch):
    argv, tfile, _, ctx = _drive(monkeypatch)
    assert argv is not None, "nuclei should still run the allowed templates"
    assert argv.count("-t") == 1
    assert tfile == [str(corpus / GOOD_REL)], f"the -t list must be exactly the allowed templates, got {tfile}"
    assert all(os.path.isabs(x) for x in tfile), "nuclei must be handed absolute paths"
    assert any(name.endswith("_d056_refused") for name, _, _ in ctx.artifacts), \
        "what the guard refused must be kept as evidence"


def test_crawl_mode_is_guarded_too(corpus, monkeypatch, tmp_path):
    urls = tmp_path / "urls.txt"
    urls.write_text("https://example.invalid/a\n")
    argv, tfile, _, _ = _drive(monkeypatch, url_list_file=str(urls))
    assert argv is not None and "-list" in argv
    assert tfile == [str(corpus / GOOD_REL)]


def test_the_coverage_cursor_slices_only_the_allowed_list(corpus, monkeypatch, tmp_path):
    got = {}

    def plan_and_write_slice(dsn, asset_id, chunk_label, filtered):
        got["lines"] = list(filtered)
        p = tmp_path / "slice.txt"
        p.write_text("\n".join(filtered) + "\n")
        return str(p), {"start": 0, "end": len(filtered), "wrapped": False}

    monkeypatch.setitem(sys.modules, "coverage_wire",
                        types.SimpleNamespace(plan_and_write_slice=plan_and_write_slice))
    argv, tfile, _, _ = _drive(monkeypatch, dsn="postgresql://fake")
    assert got["lines"] == [GOOD_REL], "the cursor must never be handed a refused template"
    assert tfile == [str(corpus / GOOD_REL)], "the slice handed to nuclei must be the checked, absolute list"


def _slice_writer(tmp_path, lines):
    def plan_and_write_slice(dsn, asset_id, chunk_label, filtered):
        p = tmp_path / "slice.txt"
        p.write_text("".join(ln + "\n" for ln in lines))
        return str(p), {"start": 0, "end": len(lines), "wrapped": False}
    return types.SimpleNamespace(plan_and_write_slice=plan_and_write_slice)


def test_a_slice_naming_a_refused_template_means_nuclei_is_not_run(corpus, monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "coverage_wire", _slice_writer(tmp_path, [GOOD_REL, BAD_REL]))
    argv, _, result, _ = _drive(monkeypatch, dsn="postgresql://fake")
    assert argv is None and result[0] == m.NUCLEI_GUARD_REFUSED_RC


def test_an_empty_slice_means_nuclei_is_not_run(corpus, monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "coverage_wire", _slice_writer(tmp_path, []))
    argv, _, result, _ = _drive(monkeypatch, dsn="postgresql://fake")
    assert argv is None and result[0] == m.NUCLEI_GUARD_REFUSED_RC, \
        "an empty -t list may make nuclei fall back to its whole library"


def test_an_empty_allowed_list_is_never_written(tmp_path):
    with pytest.raises(ValueError):
        g.write_list([], str(tmp_path))


def test_finalize_refuses_an_empty_or_stray_slice_and_absolutizes_a_good_one(tmp_path):
    f = tmp_path / "s.txt"
    f.write_text("")
    assert g.finalize_list_file(str(f), ["a.yaml"], str(tmp_path)) is not None
    f.write_text("a.yaml\nb.yaml\n")
    assert g.finalize_list_file(str(f), ["a.yaml"], str(tmp_path)) is not None
    f.write_text("a.yaml\n")
    assert g.finalize_list_file(str(f), ["a.yaml"], str(tmp_path)) is None
    assert f.read_text().split() == [str(tmp_path / "a.yaml")]


def test_run_medium_itself_refuses_an_empty_list_even_if_the_guard_let_it_through(corpus, monkeypatch, tmp_path):
    """Defence in depth: the last check in run_nuclei_chunk does not trust the guard."""
    monkeypatch.setitem(sys.modules, "coverage_wire", _slice_writer(tmp_path, []))
    monkeypatch.setattr(g, "finalize_list_file", lambda *a, **k: None)
    argv, _, result, _ = _drive(monkeypatch, dsn="postgresql://fake")
    assert argv is None and result[0] == m.NUCLEI_GUARD_REFUSED_RC


def test_a_cursor_failure_falls_back_to_the_allowed_list_not_the_library(corpus, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setitem(sys.modules, "coverage_wire", types.SimpleNamespace(plan_and_write_slice=boom))
    argv, tfile, _, _ = _drive(monkeypatch, dsn="postgresql://fake")
    assert argv is not None and tfile == [str(corpus / GOOD_REL)]


def test_a_failed_listing_means_nuclei_is_not_run(corpus, monkeypatch):
    argv, _, result, _ = _drive(monkeypatch, tl_rc=1)
    assert argv is None, "D-056: nuclei ran even though its templates could not be checked"
    assert result[0] == m.NUCLEI_GUARD_REFUSED_RC
    assert result[4].startswith(m.NUCLEI_GUARD_REFUSED_REASON)


def test_a_missing_guard_means_nuclei_is_not_run(corpus, monkeypatch):
    monkeypatch.setitem(sys.modules, "nuclei_auth_guard", None)
    argv, _, result, _ = _drive(monkeypatch)
    assert argv is None and result[0] == m.NUCLEI_GUARD_REFUSED_RC


def test_a_wrong_corpus_directory_means_nuclei_is_not_run(corpus, monkeypatch, tmp_path):
    monkeypatch.setattr(m, "nuclei_templates_dir", lambda: str(tmp_path / "elsewhere"))
    argv, _, result, _ = _drive(monkeypatch)
    assert argv is None and result[0] == m.NUCLEI_GUARD_REFUSED_RC


BANNER = "Listing available v10.5.0 nuclei templates for /github/home/nuclei-templates"


def test_the_listing_banner_is_not_a_template():
    """Measured in production 2026-10-09: `nuclei -tl -silent` prints this line on stdout."""
    templates, other = g.template_lines([BANNER, GOOD_REL, "", "  " + BAD_REL + "  "])
    assert templates == [GOOD_REL, BAD_REL] and other == [BANNER]


def test_a_two_template_chunk_with_the_banner_still_runs(corpus, monkeypatch):
    """The 2026-10-09 production failure: banner + 1 template made medium:tech look
    50% unreadable, and the guard refused the chunk. The banner must be ignored,
    and must never reach nuclei's -t list."""
    argv, tfile, result, _ = _drive(monkeypatch, listing=(BANNER, GOOD_REL))
    assert argv is not None, f"refused: {result}"
    assert tfile == [str(corpus / GOOD_REL)]


def test_a_listing_with_only_the_banner_is_refused(corpus, monkeypatch):
    argv, _, result, _ = _drive(monkeypatch, listing=(BANNER,))
    assert argv is None and result[0] == m.NUCLEI_GUARD_REFUSED_RC


def test_a_partly_unreadable_corpus_means_nuclei_is_not_run_even_if_some_pass(corpus, monkeypatch):
    """3 of 4 listed templates missing: the guard is not looking where nuclei looks.
    Running the one it could read would hide that. Refuse the chunk instead."""
    listing = (GOOD_REL, "http/exposures/gone-1.yaml", "http/exposures/gone-2.yaml", "http/exposures/gone-3.yaml")
    argv, _, result, _ = _drive(monkeypatch, listing=listing)
    assert argv is None and result[0] == m.NUCLEI_GUARD_REFUSED_RC


def test_when_every_template_is_refused_nuclei_is_not_run(corpus, monkeypatch):
    argv, _, result, _ = _drive(monkeypatch, listing=(BAD_REL,))
    assert argv is None and result[0] == m.NUCLEI_GUARD_REFUSED_RC


def test_the_allowed_list_file_is_removed_after_the_run(corpus, monkeypatch):
    argv, _, result, _ = _drive(monkeypatch, scan_rc=0)
    assert result[0] == 0
    assert not os.path.exists(argv[argv.index("-t") + 1])


# ── 5b. DETECTION ONLY (Howie, 2026-10-09, after the 10-09 load-balancer log
# showed exploit checks still reaching demo.prodexlabs.com): nuclei runs only
# checks that LOOK — exposed files, misconfiguration, technology and panel
# detection, TLS and DNS. Exploit checks (cves/, vulnerabilities/, ...) are
# never handed to nuclei, whatever the guard's content rules say about them.
def test_detection_only_is_on():
    assert m.NUCLEI_DETECTION_ONLY is True, "turning exploit checks back on is Howie's call, not a default"


DETECTION_LINES = ["http/exposures/configs/a.yaml", "http/misconfiguration/b.yaml",
                   "http/technologies/c.yaml", "http/exposed-panels/d.yaml", "ssl/e.yaml", "dns/f.yaml"]
EXPLOIT_LINES = ["http/cves/2023/x.yaml", "http/vulnerabilities/y.yaml", "http/default-logins/z.yaml",
                 "http/cnvd/2020/w.yaml", "http/iot/v.yaml", "http/osint/u.yaml", "http/token-spray/t.yaml",
                 "http/fuzzing/s.yaml", "http/takeovers/r.yaml", "network/cves/q.yaml", "javascript/cves/p.yaml",
                 "javascript/enumeration/o.yaml", "code/n.yaml", "headless/m.yaml", "dast/l.yaml", "file/k.yaml"]


def test_detection_only_keeps_detection_folders_and_drops_everything_else(tmp_path):
    kept, dropped = g.detection_only(DETECTION_LINES + EXPLOIT_LINES, str(tmp_path))
    assert kept == DETECTION_LINES
    assert dropped == EXPLOIT_LINES


def test_detection_only_reads_absolute_lines_against_the_corpus_and_fails_closed(tmp_path):
    root = str(tmp_path / "nuclei-templates")
    lines = [root + "/http/exposures/a.yaml", root + "/http/cves/2023/b.yaml",
             "/elsewhere/http/exposures/c.yaml", "http/exposures/../cves/2023/d.yaml",
             root + "Xhttp/exposures/e.yaml"]   # a sibling path that merely starts with the corpus name
    kept, dropped = g.detection_only(lines, root)
    assert kept == [root + "/http/exposures/a.yaml"]
    assert dropped == lines[1:], "outside the corpus or climbing out of a folder must not count as detection"


def test_detection_only_never_hands_an_exploit_check_to_nuclei(corpus, monkeypatch):
    argv, tfile, _, _ = _drive(monkeypatch, listing=(GOOD_REL, EXPLOIT_REL, BAD_REL))
    assert argv is not None
    assert tfile == [str(corpus / GOOD_REL)], f"only detection checks may reach nuclei, got {tfile}"


def test_a_chunk_with_only_exploit_checks_is_skipped_and_sends_nothing(corpus, monkeypatch):
    argv, _, result, _ = _drive(monkeypatch, listing=(EXPLOIT_REL,))
    assert argv is None, "nuclei must not run when policy leaves nothing to run"
    assert result[0] == m.NUCLEI_POLICY_SKIP_RC
    assert result[4].startswith(m.NUCLEI_POLICY_SKIP_REASON)


def test_the_caller_records_a_policy_skip_as_skipped_not_degraded():
    body = _caller_src()
    gate = body.index("if rc == NUCLEI_POLICY_SKIP_RC:")
    assert gate < body.index("is_tool_output_degraded("), "the skip must be handled before the outcome logic"
    block = body[gate:body.index("continue", gate) + len("continue")]
    assert "mark_tool_skipped(ctx, chunk_name, NUCLEI_POLICY_SKIP_REASON)" in block
    assert "mark_tool_degraded" not in block and "mark_tool_ok" not in block


def test_detection_only_never_closes_a_finding_it_no_longer_looks_for():
    """A clean scan delta-closes open findings it did not re-observe. With exploit
    checks off, every exploit-check finding would be 'not re-observed' and get
    falsely marked remediated. The close must not run while detection-only is on."""
    src = open(m.__file__, encoding="utf-8").read()
    i = src.index('"SELECT delta_close_for_scan_run(%s, %s) AS n_closed"')
    guard_line = src.rfind("\n", 0, src.rfind("cur.execute(", 0, i))
    window = src[src.rfind("if ", 0, guard_line):i]
    assert "if delta_close_on():" in window, "delta-close must be gated on delta_close_on()"
    # ...and delta_close_on() is off whenever detection-only is on (nikto look-only
    # adds a second reason; test_run_nikto_look_only.py covers the full table).
    assert m.NUCLEI_DETECTION_ONLY and not m.delta_close_on()


def test_a_policy_skip_does_not_stop_the_steps_that_only_touch_re_observed_findings():
    """settle-regressed, regress-on-observed and finding-history act only on
    findings this scan DID see. A chunk skipped by detection-only must not turn
    them off; any other skip or a degradation still does."""
    ok = {"ok": True}
    assert m.close_out_eligible({"wafw00f": ok, "nuclei[medium:cve]": {"skipped": m.NUCLEI_POLICY_SKIP_REASON}})
    # close_out decorates entries (cut_class, plan meta) BEFORE it asks; those keys must not matter
    assert m.close_out_eligible({"wafw00f": ok, "nuclei[medium:cve]": {
        "skipped": m.NUCLEI_POLICY_SKIP_REASON, "cut_class": "policy", "planned_chunks": 4, "actual_chunks": 4}})
    assert not m.close_out_eligible({"wafw00f": ok, "nikto": {"skipped": "auth_gated"}})
    assert not m.close_out_eligible({"wafw00f": ok, "nikto": {"degraded": "x"}})
    assert not m.close_out_eligible({})
    src = open(m.__file__, encoding="utf-8").read()
    assert "eligible = close_out_eligible(ctx.tool_status)" in src


def test_a_detection_only_skip_is_classed_as_policy():
    import degradation as d
    assert d.classify_cut_reason(m.NUCLEI_POLICY_SKIP_REASON) == d.CUT_POLICY


# ── 5c. credential shapes the 10-09 log and review showed the reader missed
CRED_SHAPES_20261009 = {
    # CVE-2023-20198 (on the wire 2026-10-09): a credential inside a namespaced XML element
    "namespaced XML password": _http(raw=["POST /x HTTP/1.1\n\n<wsse:Username>a</wsse:Username><wsse:Password>b</wsse:Password>\n"]),
    "empty self-closing password element": _http(raw=["POST /x HTTP/1.1\n\n<a:User>a</a:User><b:Password/>\n"]),
    "multipart password field": _http(raw=[
        "POST /x HTTP/1.1\nContent-Type: multipart/form-data; boundary=b\n\n"
        "--b\nContent-Disposition: form-data; name=\"password\"\n\nx\n--b--\n"]),
    # CVE-2021-25899 (on the wire 2026-10-09): an @timeout line hid the POST line
    "login POST behind an annotation": _http(raw=["@timeout: 15s\nPOST /app/svc-login.php HTTP/1.1\n\na=1&b=2\n"]),
    "api key field": _http(method="POST", path=["{{BaseURL}}/x"], body="action=y&api_key=&v=1"),
    "token field in json": _http(raw=['POST /x HTTP/1.1\n\n{"access_token":"abc","v":1}\n']),
    "privilege escalation in the title": {"id": "t", "info": {"name": "Plugin 1.0 - Privilege Escalation", "severity": "high"},
                                          "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]},
    # isolates the account-creation text rule (the older shape's title now also
    # trips the title rule, so it no longer proves this one on its own)
    "admin account creation, neutral title": {"id": "t", "info": {
        "name": "Plugin 2.0 - Info", "severity": "high",
        "description": "Unauthenticated attackers can create an administrator account."},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]},
    "a login PUT with neutral fields": _http(raw=['PUT /api/v1/session HTTP/1.1\n\n{"a":1}\n']),
    # the independent review's misses (fix 299):
    "a token defined in variables, sent as a variable": {"id": "t", "info": {"name": "Acme - Info", "severity": "high"},
                                                         "variables": {"api_token": "abc123"},
                                                         "http": [{"raw": ["GET /x HTTP/1.1\nX-Thing: {{api_token}}\n"]}]},
    "a key list in payloads": _http(method="GET", path=["{{BaseURL}}/x?k={{api_key}}"], payloads={"api_key": ["a", "b"]}),
    "Authorization with another scheme": _http(raw=["GET / HTTP/1.1\nAuthorization: Token abc123\n"]),
    "a token header by name (raw)": _http(raw=["GET / HTTP/1.1\nPrivate-Token: abc123\n"]),
    "a token header by name (headers)": _http(method="GET", path=["{{BaseURL}}/"], headers={"X-API-Token": "abc123"}),
    "a variable named just token, holding a literal": {"id": "t", "info": {"name": "Acme - Info", "severity": "high"},
                                                       "variables": {"token": "abc123"},
                                                       "http": [{"raw": ["GET /x HTTP/1.1\nAuthorization: Bearer {{token}}\n"]}]},
    "a payload list named just key": _http(method="GET", path=["{{BaseURL}}/x?k={{key}}"], payloads={"key": ["a", "b"]}),
    "a json key value that starts with a variable": _http(raw=['POST /x HTTP/1.1\n\n{"api_key":"{{p}}abcd1234"}\n']),
}


@pytest.mark.parametrize("label", sorted(CRED_SHAPES_20261009))
def test_the_10_09_credential_shapes_are_refused(label):
    assert g.classify_doc(CRED_SHAPES_20261009[label]), f"D-056: a template shaped like '{label}' would run"


# A check that finds a key on the target and then LOGS IN to the key's service
# with it (Stripe, GitLab, Slack, ...) sends a credential, and sends it to a
# host that is not the target at all. Any request addressed to a literal outside
# host is refused (fix 299; 12 such checks sat in the detection folders).
OFF_TARGET = {
    "a literal outside Host header": _http(raw=["GET /v1/x HTTP/1.1\nHost: api.example-service.com\nAuthorization: Bearer {{token}}\n"]),
    "an absolute outside URL in path": _http(method="GET", path=["https://api.example-service.com/v1/files?key={{k}}"]),
    # the independent review's misses (fix 299):
    "an @Host annotation to an outside host": _http(raw=["@Host: https://api.example-service.com\nGET /v1/x HTTP/1.1\nHost: {{Hostname}}\n"]),
    "an absolute outside URL on the request line": _http(raw=["GET https://api.example-service.com/v1 HTTP/1.1\nHost: {{Hostname}}\n"]),
    "an outside Host with a port": _http(raw=["GET / HTTP/1.1\nHost: api.example-service.com:8443\n"]),
    "an upper-case scheme in path": _http(method="GET", path=["HTTPS://api.example-service.com/x"]),
    "an IP-literal outside host": _http(raw=["GET / HTTP/1.1\nHost: 203.0.113.7\n"]),
    "an outside host defined in variables": {"id": "t", "info": {"name": "Acme - Info", "severity": "high"},
                                             "variables": {"svc": "https://api.example-service.com"},
                                             "http": [{"method": "GET", "path": ["{{svc}}/v1/x"]}]},
    "a scheme then an outside host variable": {"id": "t", "info": {"name": "Acme - Info", "severity": "high"},
                                               "variables": {"h": "api.example-service.com"},
                                               "http": [{"method": "GET", "path": ["https://{{h}}/v1/x"]},
                                                        {"raw": ["GET https://{{h}}/v1 HTTP/1.1\nHost: {{Hostname}}\n"]}]},
}


@pytest.mark.parametrize("label", sorted(OFF_TARGET))
def test_a_request_to_a_host_other_than_the_target_is_refused(label):
    assert g.classify_doc(OFF_TARGET[label]), f"'{label}' sends traffic somewhere other than the target"


def test_requests_addressed_to_the_target_or_a_callback_are_not_off_target():
    for doc in (_http(raw=["GET / HTTP/1.1\nHost: {{Hostname}}\n"]),
                _http(raw=["GET / HTTP/1.1\nHost: {{Hostname}}:{{Port}}\n"]),
                _http(raw=["@Host: {{RootURL}}\nGET / HTTP/1.1\nHost: {{Hostname}}\n"]),
                _http(raw=["GET / HTTP/1.1\nHost: {{interactsh-url}}\n"]),
                _http(method="GET", path=["{{BaseURL}}/x", "{{RootURL}}/y", "http://{{interactsh-url}}"])):
        assert g.classify_doc(doc) == [], doc


def test_a_token_handed_back_by_an_earlier_request_is_not_a_credential():
    for doc in (_http(raw=["GET /api?access_token={{token}} HTTP/1.1\nCookie: AuthToken={{tok}}\n"]),
                _http(raw=['POST /api HTTP/1.1\n\n{"access_token":"{{tok}}","v":1}\n']),
                _http(raw=["GET /api HTTP/1.1\nAuthorization: Token {{token}}\nPrivate-Token: {{t}}\n"])):
        assert g.classify_doc(doc) == [], doc


def test_a_listing_outside_the_corpus_is_refused_not_skipped(corpus, monkeypatch):
    """If nuclei lists templates somewhere the guard does not read, that is the
    guard looking in the wrong place: a refusal (degraded), never a quiet skip."""
    argv, _, result, _ = _drive(monkeypatch, listing=("/elsewhere/http/exposures/x.yaml",))
    assert argv is None and result[0] == m.NUCLEI_GUARD_REFUSED_RC


# The 2026-10-09 review: every allowed template that one of 25 independent nets
# flagged (527 of 4,494 in the production chunks, nuclei-templates v10.5.0) was
# read in full by separate reviewers against D-056. 76 BLOCK + 19 UNSURE;
# UNSURE stays refused until Howie rules. Pinned by id. D-065 (2026-10-09):
# Howie allowed the Jellyfin public-user-list check, so it left the list (107).
THE_107 = """
CNVD-2020-63964 CVE-2015-3224 CVE-2017-15944 CVE-2018-0296 CVE-2018-11759 CVE-2019-11886
CVE-2019-12583 CVE-2019-9880 CVE-2020-14750 CVE-2020-14882 CVE-2020-14883 CVE-2020-36723
CVE-2020-5902 CVE-2020-6287 CVE-2021-22017 CVE-2021-24219 CVE-2021-24915 CVE-2021-28480
CVE-2021-28481 CVE-2021-35464 CVE-2021-45967 CVE-2021-45968 CVE-2022-0952 CVE-2022-33891
CVE-2022-47966 CVE-2023-20073 CVE-2023-20198 CVE-2023-20887 CVE-2023-41265 CVE-2023-4966
CVE-2024-0235 CVE-2024-13985 CVE-2024-20767 CVE-2024-2771 CVE-2024-30269 CVE-2024-31848
CVE-2024-31849 CVE-2024-32238 CVE-2024-4885 CVE-2024-53991 CVE-2024-8698 CVE-2025-12480
CVE-2025-12841 CVE-2025-13342 CVE-2025-15403 CVE-2025-54249 CVE-2025-54251 CVE-2025-5701
CVE-2025-8943 CVE-2026-27542 CVE-2026-34910 CVE-2026-40217 CVE-2026-4631 CVE-2026-54917
CVE-2026-63077 slack-bot-token hikvision-cam-info-exposure aem-anonymous-write aem-secrets
hikvision-env intercom-identity-misconfiguration java-melody-exposed cisco-implant-detect
hikvision-js-files-upload livebos-file-read rconfig-file-upload zhiyuan-file-upload
smartbi-deserialization springblade-info-leak unifi-create-user yonyou-u8-crm-lfi
yonyou-ufida-cloud-sqli CVE-2025-12101 perforce-remote-depot-unauth unauth-vnc-server-detect
CVE-2022-24706
CVE-2020-11514 CVE-2020-20627 CVE-2021-25899 CVE-2021-33544 CVE-2023-22478 CVE-2023-3139
CVE-2023-31446 CVE-2024-34257 CVE-2025-24813 CVE-2025-36604 CVE-2026-17532 CVE-2026-27174
CVE-2026-34413 CVE-2026-34486 CVE-2026-46339 CVE-2026-50160 CVE-2026-5032
piwik-unauthenticated-access
seeyon-unauth symfony-rce zenscrape-api-key zenserp-api-key telegram-bot-token
gitlab-personal-token stripe-secret-key npm-access-token stackhawk-api slack-user-token
rubygems-api-key mapbox-token-disclosure square-access
""".split()


def test_the_review_list_is_complete():
    """95 from the first review + 13 from the review of the detection folders'
    non-GET checks (the checks detection-only keeps), less the one D-065 allowed."""
    assert len(THE_107) == 107 and len(set(THE_107)) == 107


def test_the_guard_refuses_exactly_the_reviewed_list():
    """The guard's own list is the reviewed list: nothing added or dropped silently."""
    assert set(g.REVIEWED_REFUSE_IDS) == set(THE_107)


# The template as nuclei-templates v10.5.0 ships it (http/misconfiguration/,
# sha256 0f9b74a9ac9124b3...): two plain GETs of the server's own public page.
JELLYFIN_PUBLIC_USERS = {
    "id": "jellyfin-public-users-exposure",
    "info": {"name": "Jellyfin Public Users - Exposure", "severity": "medium",
             "description": "The Jellyfin media server exposed user information via the public users "
                            "API endpoint. This endpoint could have leaked sensitive data including "
                            "usernames, user IDs, server IDs, administrator status, password "
                            "configuration, login activity, and user policies without authentication.",
             "classification": {"cwe-id": "CWE-200,CWE-306"},
             "tags": "misconfig,jellyfin,exposure,api,disclosure,vuln"},
    "http": [{"method": "GET", "path": ["{{BaseURL}}/Users/Public", "{{BaseURL}}/jellyfin/Users/Public"],
              "stop-at-first-match": True}],
}


def test_d065_the_jellyfin_public_user_list_check_may_run():
    """D-065: one plain read of a page the server publishes to everyone."""
    assert g.classify_doc(JELLYFIN_PUBLIC_USERS,
                          "http/misconfiguration/jellyfin-public-users-exposure.yaml") == []


def test_d065_the_matomo_anonymous_token_check_stays_refused():
    """D-065: it puts a value in a login field, so it stays refused."""
    doc = {"id": "piwik-unauthenticated-access", "info": {"name": "Matomo - Info", "severity": "high"},
           "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]}
    assert g.classify_doc(doc)


@pytest.mark.parametrize("tid", THE_107)
def test_every_template_the_10_09_review_refused_is_refused(tid):
    doc = {"id": tid, "info": {"name": "Acme - Info", "severity": "high"},
           "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}]}
    assert g.classify_doc(doc), f"D-056: {tid} was refused by the 10-09 review but would run"


def _caller_src():
    src = open(m.__file__, encoding="utf-8").read()
    i = src.index("rc, matches, _, chunk_stdout, chunk_stderr = run_nuclei_chunk(")
    return src[i:src.index("\ndef ", i)]   # to the end of the calling function


def test_the_caller_records_a_refusal_as_degraded_and_never_as_ok():
    body = _caller_src()
    gate = body.index("if rc == NUCLEI_GUARD_REFUSED_RC:")
    assert gate < body.index("is_tool_output_degraded("), "the refusal must be handled before the outcome logic"
    assert gate < body.index("mark_tool_ok_evidenced("), "a refused chunk must never reach mark_tool_ok"
    block = body[gate:body.index("continue", gate) + len("continue")]
    assert "mark_tool_degraded(ctx, chunk_name, NUCLEI_GUARD_REFUSED_REASON" in block


# ── 6. nothing else launches nuclei at a target unguarded
_SH_LAUNCH = re.compile(r"(?<![\w./-])nuclei\s+(?:[^\n|;&]*\s)?-(?:u|l|list|target)\s+(\S+)")
_TARGET_FLAGS = {"-u", "-l", "-list", "-target", "-target-file"}
ALLOWED_LAUNCHERS = {"scripts/scanner/run_medium.py"}  # guarded by d056_screen_templates
# Retired launchers (Command only). Each must PROVE it is retired, not just say so.
RETIRED = {
    "scripts/diag/fortigate_threshold_probe.py": "py",
    ".github/workflows/fortigate-recipe-canary.yml": "yml",
    ".github/workflows/fortigate-threshold-probe.yml": "yml",
}


def _repo_files():
    for dp, dn, fs in os.walk(REPO):
        dn[:] = [d for d in dn if d not in (".git", "node_modules", "__pycache__", "data", "web")]
        for f in fs:
            if f.endswith((".py", ".sh", ".yml", ".yaml")) and not f.startswith("test_"):
                yield os.path.join(dp, f)


def _py_launches(src: str) -> bool:
    """A top-level statement (function, class, or module code) that builds a
    list starting with "nuclei" AND uses a target flag anywhere in it. Catches
    `cmd = ["nuclei"]; cmd += ["-u", t]`, which a one-line regex cannot."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return True   # cannot prove it is safe
    for node in tree.body:
        has_list = has_flag = False
        for n in ast.walk(node):
            if isinstance(n, ast.List) and n.elts and isinstance(n.elts[0], ast.Constant) and n.elts[0].value == "nuclei":
                has_list = True
            if isinstance(n, ast.Constant) and n.value in _TARGET_FLAGS:
                has_flag = True
        if has_list and has_flag:
            return True
    return False


def _retired_ok(path: str, kind: str) -> bool:
    if kind == "yml":
        d = yaml.safe_load(open(path, encoding="utf-8"))
        on = d.get(True, d.get("on"))
        triggers = set(on) if isinstance(on, dict) else ({on} if isinstance(on, str) else set(on or []))
        if triggers != {"workflow_dispatch"}:
            return False
        return all("D-056-RETIRED" in j["steps"][0].get("name", "")
                   and j["steps"][0].get("run", "").rstrip().endswith("exit 1")
                   for j in d["jobs"].values())
    tree = ast.parse(open(path, encoding="utf-8").read())
    mains = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main"]
    if len(mains) != 1:
        return False
    for stmt in mains[0].body:
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue   # docstring
        if (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)
                and getattr(stmt.value.func, "id", "") == "print"):
            continue   # the refusal message
        return isinstance(stmt, ast.Return) and getattr(stmt.value, "value", None) == 2
    return False


def test_the_census_sees_the_way_run_medium_builds_its_command():
    assert _py_launches(open(m.__file__, encoding="utf-8").read()), \
        "the launcher census must recognise run_medium's own pattern, or it can't see a copy of it"


def test_nothing_else_in_the_repo_launches_nuclei_at_a_target_unguarded():
    offenders = []
    for path in _repo_files():
        rel = os.path.relpath(path, REPO).replace(os.sep, "/")
        if rel in ALLOWED_LAUNCHERS or rel.startswith("scripts/db/migrations/"):
            continue
        if rel in RETIRED:
            if not _retired_ok(path, RETIRED[rel]):
                offenders.append(f"{rel}: listed as retired but does not refuse first")
            continue
        try:
            text = open(path, encoding="utf-8").read()
        except Exception:
            continue
        if path.endswith(".py"):
            if _py_launches(text):
                offenders.append(f"{rel}: builds a nuclei command with a target flag")
            continue
        for n, ln in enumerate(text.splitlines(), 1):
            st = ln.strip()
            if st.startswith("#"):
                continue
            mm = _SH_LAUNCH.search(st)
            if mm and not mm.group(1).strip("\"'").startswith("127.0.0.1"):
                offenders.append(f"{rel}:{n}: {st[:120]}")
    assert not offenders, "D-056: nuclei launched at a target without the guard:\n" + "\n".join(offenders)
