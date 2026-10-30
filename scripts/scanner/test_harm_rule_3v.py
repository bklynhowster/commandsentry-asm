"""Job 3v / D-074 (2026-10-29): High and Critical mean it could actually be exploited.

Howie, 2026-10-29 19:30: "It has to be something that could actually be exploited. I love it.
Implement it." HIGH or CRITICAL needs (1) seen directly (job 3r) and (2) a way in, or a way to
read or change data, that someone on the internet could use. Everything else seen directly is
MODERATE at most. Every writer applies it; the FTP check no longer logs in (no attempted logins
whatsoever, Howie's standing rule).
"""
from __future__ import annotations

import inspect
import itertools
import os
import random
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "db"))
sys.path.insert(0, os.path.join(HERE, "..", "normalize"))

import evidence  # noqa: E402
import run_heavy  # noqa: E402
import run_light  # noqa: E402
import run_medium  # noqa: E402

HR = evidence.harm_rating

# ── the rule ─────────────────────────────────────────────────────────────────────────
# Today's open HIGHs on Command (read 2026-10-29), plus every other kind the inventory found.
CAPPED = [
    ("52.119.65.6:testssl:cert_extlifeSpan:33ad838", "testssl", []),
    ("52.119.65.5:testssl:cert_revocation:33ad838", "testssl", []),
    ("demo.testfire.net:testssl:LOGJAM-common_primes:33ad838", "testssl", []),
    ("h:testssl:BEAST:1", "testssl", []), ("h:testssl:SWEET32:1", "testssl", []),
    ("h:testssl:POODLE_SSL:1", "testssl", []), ("h:testssl:CCS:1", "testssl", []),
    ("h:testssl:SSLv3:1", "testssl", []), ("h:testssl:DROWN:1", "testssl", []),
    ("h:testssl:cert_chain_of_trust:1", "testssl", []), ("h:testssl:OCSP_stapling:1", "testssl", []),
    ("h:light:tls-cert-expired", "commandsentry_light", ["tls", "cert", "expired"]),
    ("h:light:method-put-enabled", "commandsentry_light", ["methods", "put"]),
    ("h:light:method-delete-enabled", "commandsentry_light", ["methods", "delete"]),
    ("h:medium:ffuf-env", "commandsentry_medium", ["ffuf", "secret"]),        # status code only
    ("h:exposure:open-mysql-3306", "commandsentry_exposure", ["exposure"]),   # a port, not a way in
    ("h:medium:nuclei-tech-detect", "commandsentry_medium", ["nuclei", "tech", "cve"]),
    ("h:medium:nuclei-some-panel", "commandsentry_medium", ["nuclei", "panel", "login"]),
    ("h:commandsentry_heavy:waf-absent-differential:abc", "commandsentry_heavy", []),
    ("h:light:wpvuln-cve-2026-6728", "commandsentry_light", ["wordpress", "version-cve"]),
    ("h:probe:env", "probe", []), ("", "", []),
]
KEPT = [
    ("h:testssl:heartbleed:1", "testssl", []), ("h:testssl:ticketbleed:1", "testssl", []),
    ("h:testssl:ROBOT:1", "testssl", []), ("h:sslyze:heartbleed", "sslyze", []),
    ("h:light:exposed-path-env", "commandsentry_light", ["exposed-path"]),
    ("ip:1.2.3.4:light:exposed-path-git-config", "commandsentry_light", []),
    ("u:commandsentry_heavy:waf-absent-exposed:992e678", "commandsentry_heavy", []),
    ("h:medium:nuclei-cve-2025-29927", "commandsentry_medium", ["nuclei", "auth", "middleware-bypass", "cve"]),
] + [(f"h:medium:nuclei-t{i}", "commandsentry_medium", ["nuclei", t]) for i, t in enumerate(sorted(evidence.EXPLOITABLE_TAGS))]


@pytest.mark.parametrize("sev", ["HIGH", "CRITICAL", "high"])
@pytest.mark.parametrize("fid,src,tags", CAPPED)
def test_seen_but_no_way_in_is_moderate(sev, fid, src, tags):
    out, why = HR(sev, finding_id=fid, source=src, tags=tags)
    assert out == "MODERATE" and why and "D-074" in why


@pytest.mark.parametrize("sev", ["HIGH", "CRITICAL"])
@pytest.mark.parametrize("fid,src,tags", KEPT)
def test_a_way_in_keeps_its_rating(sev, fid, src, tags):
    assert HR(sev, finding_id=fid, source=src, tags=tags) == (sev, None)


@pytest.mark.parametrize("sev", ["MODERATE-HIGH", "MODERATE", "LOW", "INFO", None, ""])
def test_below_high_is_never_touched(sev):
    for fid, src, tags in CAPPED + KEPT:
        assert HR(sev, finding_id=fid, source=src, tags=tags) == (sev, None)


def test_a_persons_hand_test_rating_stands():
    assert HR("HIGH", finding_id="ftp.sciimage.com:manual:F-01", source="manual_named") == ("HIGH", None)


def test_the_rule_as_a_property_no_unlisted_kind_can_be_high():
    """An allow-list: whatever a tool invents tomorrow, at HIGH or CRITICAL, lands on MODERATE
    unless it is one of the named ways in (the #037 ceiling's lesson, note 243)."""
    rnd = random.Random(3)
    tiers = ["light", "medium", "heavy", "exposure", "testssl", "sslyze", "commandsentry_heavy", "x"]
    for _ in range(3000):
        tier = rnd.choice(tiers)
        check = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz-_") for _ in range(rnd.randint(1, 18)))
        fid = f"host.example:{tier}:{check}:h"
        tags = rnd.sample(["nuclei", "tech", "cve", "panel", "misconfig", "config", "ssl", "dns"], 3)
        out, _ = HR("CRITICAL", finding_id=fid, source=tier, tags=tags)
        allowed = evidence.harm_exploitable(fid, tier, tags)
        assert (out == "CRITICAL") == allowed
        if allowed:
            low = check.lower()
            assert (tier == "light" and low.startswith("exposed-path-")) or "waf-absent-exposed" in low \
                or (tier in ("testssl", "sslyze") and low in evidence.EXPLOITABLE_TESTSSL_IDS)


def test_the_tier_is_found_by_name_even_when_the_asset_holds_colons():
    assert evidence._check_of("ip:24.38.70.14:testssl:ROBOT:abc") == ("testssl", "ROBOT:abc")
    assert evidence._check_of("light.example.com:medium:nuclei-x") == ("medium", "nuclei-x")
    assert evidence._check_of("nothing-here") == ("", "")


def test_harm_rating_never_raises(monkeypatch):
    monkeypatch.setattr(evidence, "harm_exploitable", lambda *a, **k: 1 / 0)
    assert HR("HIGH", finding_id="h:testssl:heartbleed:1", source="testssl")[0] == "MODERATE"


# ── every writer applies it ──────────────────────────────────────────────────────────
class FakeJson:
    def __init__(self, obj):
        self.obj = obj


class FakeCur:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.calls.append((" ".join(str(sql).split())[:60], params))

    def fetchone(self):
        return {"inserted": True}

    def fetchall(self):
        return []


class FakeConn:
    def __init__(self):
        self.cur = FakeCur()

    def cursor(self, *a, **k):
        return self.cur


def _upserts(conn, marker="INSERT INTO public.findings"):
    return [p for s, p in conn.cur.calls if s.startswith(marker)]


def _quiet(monkeypatch, mod):
    monkeypatch.setattr(mod, "get_scanner_version", lambda: "sha-test")
    monkeypatch.setattr(mod, "derive_validation_status", lambda *a, **k: "unvalidated")
    monkeypatch.setattr(mod, "log", lambda *a, **k: None)


def test_the_light_writer_caps_what_it_writes(monkeypatch):
    _quiet(monkeypatch, run_light)
    monkeypatch.setattr(run_light.software_inventory, "record_from_artifacts", lambda *a, **k: None)
    ctx = run_light.ScanContext(descriptor={}, hostname="h", asset_id="h", scan_run_id="run-1",
                                queue_id="q", intensity="light")
    mk = lambda check, sev: run_light.LightFinding(check_name=check, title=check, severity=sev,
                                                   category="tls", description="d")
    ctx.findings = [mk("tls-cert-expired", "HIGH"), mk("exposed-path-env", "HIGH"), mk("missing-header-hsts", "MODERATE")]
    conn = FakeConn()
    run_light.write_findings_and_artifacts(conn, ctx, FakeJson)
    got = {p["finding_id"]: p["severity"] for p in _upserts(conn)}
    assert got == {"h:light:tls-cert-expired": "MODERATE", "h:light:exposed-path-env": "HIGH",
                   "h:light:missing-header-hsts": "MODERATE"}
    assert ctx.findings[0].severity == "HIGH", "the finding object is untouched; only the write is capped"


def test_the_medium_writer_caps_nuclei_by_its_tags(monkeypatch):
    _quiet(monkeypatch, run_medium)
    monkeypatch.setattr(run_medium.software_inventory, "record_from_artifacts", lambda *a, **k: None)
    ctx = run_medium.ScanContext(descriptor={}, hostname="h", asset_id="h", scan_run_id="run-1",
                                 queue_id="q", intensity="medium")
    mk = lambda check, sev, tags: run_medium.MediumFinding(check_name=check, title=check, severity=sev,
                                                           category="dast", description="d", tags=tags)
    ctx.findings = [mk("nuclei-tech-x", "CRITICAL", ["nuclei", "tech"]),
                    mk("nuclei-cve-2025-29927", "CRITICAL", ["nuclei", "middleware-bypass"]),
                    mk("ffuf-env", "HIGH", ["ffuf"])]
    conn = FakeConn()
    try:
        run_medium.write_findings_and_artifacts(conn, ctx, FakeJson)
    except Exception:
        pass                      # anything after the upserts is not this test's business
    got = {p["finding_id"]: p["severity"] for p in _upserts(conn)}
    assert got == {"h:medium:nuclei-tech-x": "MODERATE", "h:medium:nuclei-cve-2025-29927": "CRITICAL",
                   "h:medium:ffuf-env": "MODERATE"}


def test_an_open_port_is_not_a_way_in(monkeypatch):
    """Prodex's exposure engine writes through the medium writer (an open database port is
    CRITICAL by its base severity). An open port is seen, not shown to let anyone in: MODERATE."""
    import dataclasses
    _quiet(monkeypatch, run_medium)
    monkeypatch.setattr(run_medium.software_inventory, "record_from_artifacts", lambda *a, **k: None)
    ctx = run_medium.ScanContext(descriptor={}, hostname="h", asset_id="h", scan_run_id="run-1",
                                 queue_id="q", intensity="medium")
    kw = dict(check_name="open-mysql-3306", title="MySQL open", severity="CRITICAL", category="config",
              description="d", tags=["exposure-engine", "database"])
    if "source" in {fl.name for fl in dataclasses.fields(run_medium.MediumFinding)}:
        kw["source"] = "commandsentry_exposure"
    ctx.findings = [run_medium.MediumFinding(**kw)]
    conn = FakeConn()
    try:
        run_medium.write_findings_and_artifacts(conn, ctx, FakeJson)
    except Exception:
        pass
    got = [p["severity"] for p in _upserts(conn)]
    assert got == ["MODERATE"]


def test_the_heavy_writer_caps_testssl_and_reads_inherited_tags(monkeypatch):
    """Heavy writes testssl events and the light / medium phases it runs (their tags ride in
    params.legacy_tags, phase_contract)."""
    from types import SimpleNamespace as NS
    import software_inventory
    _quiet(monkeypatch, run_heavy)
    monkeypatch.setattr(software_inventory, "record_from_artifacts", lambda *a, **k: None)
    ev = lambda fid, src, sev, params=None: NS(finding_id=fid, asset_id="h", source=src, title=fid, severity=sev,
                                               category="tls", description="d", cwe=[], cve=[], references=[],
                                               normalized_key=None, params=params)
    ctx = NS(intensity="heavy", scan_run_id="run-1", artifacts=[], findings=[
        ev("52.119.65.6:testssl:cert_extlifeSpan:33ad838", "testssl", "HIGH"),
        ev("h:testssl:heartbleed:1", "testssl", "CRITICAL"),
        ev("h:medium:nuclei-cve-2025-29927", "commandsentry_medium", "CRITICAL",
           {"legacy_tags": ["nuclei", "middleware-bypass"]}),
        ev("h:medium:nuclei-tech-x", "commandsentry_medium", "CRITICAL", {"legacy_tags": ["nuclei", "tech"]}),
        ev("u:commandsentry_heavy:waf-absent-exposed:9", "commandsentry_heavy", "HIGH", {}),
    ])
    conn = FakeConn()
    run_heavy.write_event_findings_and_artifacts(conn, ctx, FakeJson)
    got = {p["finding_id"]: p["severity"] for p in _upserts(conn)}
    assert got == {"52.119.65.6:testssl:cert_extlifeSpan:33ad838": "MODERATE", "h:testssl:heartbleed:1": "CRITICAL",
                   "h:medium:nuclei-cve-2025-29927": "CRITICAL", "h:medium:nuclei-tech-x": "MODERATE",
                   "u:commandsentry_heavy:waf-absent-exposed:9": "HIGH"}


def test_the_heavy_reopen_obeys_the_rule_too(monkeypatch):
    """The one place a scanner sets a severity outside the upsert: reopening a sign-in row 311
    retracted. Absence-family rows only; were one ever HIGH without a way in, it reopens MODERATE."""
    from types import SimpleNamespace as NS
    monkeypatch.setattr(run_heavy, "log", lambda *a, **k: None)
    fid = run_heavy.stable_finding_id("h", "commandsentry_heavy", run_heavy.WAF_ABSENT_CHECK_ID, "h")
    fx = run_heavy.stable_finding_id("h", "commandsentry_heavy", run_heavy.WAF_EXPOSED_CHECK_ID, "h")
    ctx = NS(waf_signin_measured=True, asset_id="h", hostname="h", scan_run_id="r", findings=[
        NS(finding_id=fid, source="commandsentry_heavy", severity="HIGH"),
        NS(finding_id=fx, source="commandsentry_heavy", severity="HIGH")])
    conn = FakeConn()
    try:
        run_heavy.reopen_signin_rows_retracted_by_311(conn, ctx, FakeJson)
    except Exception:
        pass                      # the audit insert after it is not this test's business
    sevs = {p["finding_id"]: p["severity"] for s, p in conn.cur.calls
            if isinstance(p, dict) and "retraction_action" in p}
    assert sevs.get(fid) == "MODERATE"
    if fx in sevs:
        assert sevs[fx] == "HIGH"


def test_the_offline_import_caps_what_it_loads(tmp_path):
    import json
    import import_jsonl
    recs = [{"finding_id": "52.119.65.5:testssl:cert_revocation:33ad838", "asset_id": "52.119.65.5",
             "source": "testssl", "severity": "HIGH"},
            {"finding_id": "h:testssl:heartbleed:1", "asset_id": "h", "source": "testssl", "severity": "CRITICAL"}]
    f = tmp_path / "findings.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in recs) + "\n")

    class Cur:
        rows = None

        def executemany(self, sql, rows):
            if "INSERT INTO findings" in sql:
                Cur.rows = list(rows)

    import_jsonl.load_findings(Cur(), f)
    assert {r[0]: r[3] for r in Cur.rows} == {"52.119.65.5:testssl:cert_revocation:33ad838": "MODERATE",
                                              "h:testssl:heartbleed:1": "CRITICAL"}


def test_the_offline_import_caps_too():
    import import_jsonl
    assert import_jsonl._harm({"finding_id": "52.119.65.5:testssl:cert_revocation:33ad838",
                               "source": "testssl", "severity": "HIGH"}) == "MODERATE"
    assert import_jsonl._harm({"finding_id": "h:testssl:heartbleed:1", "source": "testssl",
                               "severity": "CRITICAL"}) == "CRITICAL"
    assert import_jsonl._harm({"finding_id": "x:manual:F-01", "source": "manual_named",
                               "severity": "HIGH"}) == "HIGH"
    assert import_jsonl._harm({"finding_id": "x", "source": "nikto"}) == "INFO"


# ── no attempted logins whatsoever ───────────────────────────────────────────────────
class FakeSock:
    def __init__(self, banner=b"220 ProFTPD ready\r\n"):
        self.sent, self.banner, self.closed = [], banner, False

    def settimeout(self, t):
        pass

    def recv(self, n):
        return self.banner

    def send(self, b):
        self.sent.append(b)
        return len(b)

    def sendall(self, b):
        self.sent.append(b)

    def close(self):
        self.closed = True


def test_the_ftp_check_reads_the_banner_and_never_logs_in(monkeypatch):
    import socket
    s = FakeSock()
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: s)
    ctx = run_light.ScanContext(descriptor={}, hostname="h", asset_id="h", scan_run_id="r",
                                queue_id="q", intensity="light")
    run_light.check_ftp(ctx, 21)
    assert s.sent == [], "nothing is sent: no USER, no PASS"
    assert s.closed
    assert [f.check_name for f in ctx.findings] == ["ftp-service-on-port-21"]
    assert ctx.findings[0].severity == "INFO"
    src = inspect.getsource(run_light.check_ftp)
    assert "USER" not in src.split('"""', 2)[2] and "PASS" not in src.split('"""', 2)[2]
