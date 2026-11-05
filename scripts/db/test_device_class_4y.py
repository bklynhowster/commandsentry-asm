"""KB 12 job 4y (2026-11-05): Sentry names what each device is — the classifier side.

The cases are real (trial 4w, 2026-11-05 08:33 ET; plan 2026-11-05 0845, v2):
  * ftp.sciimage.com read "web firewall": the row that took "SSH-2.0-8.1.0.0_openssh SCI"
    for an edge appliance. Globalscape documents that greeting (KB 11439), and its web
    side lands on /Web/Account/Login.htm, EFT's own login page (Globalscape's manual).
  * insite.sciimage.com was unknown; it sets classic ASP's ASPSESSIONID... cookie.
  * eight unimacgraphics names serve Pressable's own certificate.

Pinned:
  * EFT confirms only with its web login AND its SSH greeting (two requests, two artifacts,
    two dedupe_keys); either alone, and every new row alone, is 'suspected';
  * the old fingerprintx artifact and the deep scan's greeting are one tell, never two;
  * R4: every new vendor-identifying artifact is cited; a missing or mismatched citation
    makes the classifier refuse to start;
  * capability is NOT-NULL on landing_path: no answer cannot demote, a real page can;
  * the newest device_clues artifact decides, inside the freshness window; an asset with
    none is unchanged; testssl's certificate reading stays first;
  * Cisco gets no new row (job 3c's rows already name it).
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "normalize"))
import device_class_runner as dcr  # noqa: E402
from derive_device_class import (classify, load_artifact_signatures, load_fingerprints,  # noqa: E402
                                 load_thresholds, validate_artifact_citations, validate_fingerprints)

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
CLUES, GREET, FPX, TESTSSL = "device_clues", "service_greeting", "fingerprintx_ssh", "testssl_json"
EFT_GREETING = "SSH-2.0-8.1.0.0_openssh SCI"
NEW_SIGNALS = ("globalscape_eft_web_login_path", "globalscape_eft_ssh_greeting",
               "microsoft_classic_asp_session_cookie", "pressable_self_named_certificate")


def _clues(paths=("/Web/Account/Login.htm",), subject="C=US, O=Strategic Content Imaging, CN=*.sciimage.com",
           cookies=(), none=False):
    return json.dumps({"schema": 1, "tier": "light", "hostname": "h", "addresses": {},
                       "landing_paths": None if none else list(paths),
                       "cert_subject": subject, "set_cookie_names": list(cookies)})


def _greeting(line=EFT_GREETING):
    return json.dumps([{"greeting": line, "port": 22, "protocol": "ssh", "product": None}], sort_keys=True)


class Cur:
    """Serves gather_observations and the capability probes from one artifact table,
    recording every statement (to check the freshness window)."""

    def __init__(self, artifacts):
        self.artifacts = artifacts
        self.sql = []
        self._r = []

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        self.sql.append(s)
        if "scan_run_artifacts" not in s or not params:
            self._r = []
            return
        wanted = [params[1]] + ([params[2]] if "or a.tool_name" in s else [])
        rows = []
        for name, entries in self.artifacts.items():
            ok = any(name.startswith(t[:-1]) if t.endswith("%") else name == t for t in wanted)
            if ok:
                rows += [{"raw": b, "blob": b, "completed_at": w} for b, w in entries]
        rows.sort(key=lambda r: r["completed_at"], reverse=True)
        limit = int(s.rsplit("limit", 1)[1].strip()) if "limit" in s else len(rows)
        self._r = rows[:limit]

    def fetchall(self):
        return self._r

    def fetchone(self):
        return self._r[0] if self._r else None


def _obs(arts, cur=None):
    return dcr.gather_observations(cur or Cur(arts), "ftp.sciimage.com", 30, "^nuclei:fortinet")


def _classify(arts):
    return classify(_obs(arts), load_fingerprints(), load_thresholds())


# ── the verdicts ─────────────────────────────────────────────────────────────
def test_eft_is_confirmed_only_by_its_login_page_and_its_greeting():
    both = _classify({GREET: [(_greeting(), NOW)], CLUES: [(_clues(), NOW)]})
    assert both["device_class"] == "origin_host" and both["device_class_confidence"] == "confirmed"
    assert both["vendor_product"] == {"vendor": "Globalscape", "product": "EFT"}
    assert both["vendor_product_confidence"] == "confirmed"
    for one in ({GREET: [(_greeting(), NOW)]}, {CLUES: [(_clues(), NOW)]},
                {GREET: [(_greeting("SSH-2.0-1.82_sshlib Globalscape"), NOW)]},
                {CLUES: [(_clues(paths=["/EFTClient/Account/Login.htm"]), NOW)]}):
        r = _classify(one)
        assert r["device_class"] == "origin_host" and r["device_class_confidence"] == "suspected", one
        assert r["vendor_product"] == {"vendor": "Globalscape", "product": "EFT"}


def test_the_old_firewall_reading_of_the_eft_greeting_is_gone():
    r = _classify({FPX: [(EFT_GREETING, NOW)]})
    assert r["device_class"] == "origin_host" and r["vendor_product"]["vendor"] == "Globalscape"
    fps = load_fingerprints()
    assert not any("_openssh sci" in json.dumps(f).lower() for f in fps)
    assert not any((f.get("vendor_product") or {}).get("managed_by") for f in fps)


def test_the_old_artifact_and_the_greeting_are_one_tell():
    """fingerprintx (gone since 4l, still fresh for a while) and the greeting read the same
    first line: one observation, one dedupe_key, so together still 'suspected'."""
    r = _classify({FPX: [(EFT_GREETING, NOW - timedelta(days=3))], GREET: [(_greeting(), NOW)]})
    assert r["device_class_confidence"] == "suspected"
    keys = {e["dedupe_key"] for e in r["evidence"]}
    assert keys == {"ssh_greeting"}


def test_every_new_row_alone_is_suspected():
    cases = {
        "globalscape_eft_web_login_path": {"landing_path": ["/Web/Account/Login.htm"]},
        "globalscape_eft_ssh_greeting": {"ssh_banner": "SSH-2.0-1.82_sshlib x"},
        "microsoft_classic_asp_session_cookie": {"set_cookie_names": ["ASPSESSIONIDCECCAQAT"]},
        "pressable_self_named_certificate": {"cert_subject": "CN=*.pressable.com"},
    }
    for sig, obs in cases.items():
        r = classify(obs, load_fingerprints(), load_thresholds())
        assert [e["signal"] for e in r["evidence"]] == [sig]
        assert r["device_class_confidence"] == "suspected" and r["vendor_product_confidence"] == "suspected", sig


def test_iis_from_the_device_clues_cookie_names():
    r = _classify({CLUES: [(_clues(paths=["/PortalSite/"], cookies=["ASPSESSIONIDCECCAQAT"]), NOW)]})
    assert r["device_class"] == "origin_host"
    assert r["vendor_product"] == {"vendor": "Microsoft", "product": "IIS (classic ASP)"}


def test_pressable_reads_hosting_and_corroborates_with_x_ac():
    for subject in ("*.pressable.com", "CN=*.pressable.com", "C=US, CN=pressable.com"):
        r = classify({"cert_subject": subject}, load_fingerprints(), load_thresholds())
        assert r["device_class"] == "hosting_edge", subject
        assert r["vendor_product"] == {"vendor": "Automattic", "product": "Pressable"}
    for not_it in ("CN=notpressable.com", "CN=pressable.com.evil.test", "CN=www.pressable.co"):
        assert classify({"cert_subject": not_it}, load_fingerprints(), load_thresholds())["device_class"] == "unknown"
    both = classify({"cert_subject": "*.pressable.com", "http_headers": "x-ac: 1.ewr _atomic_dca"},
                    load_fingerprints(), load_thresholds())
    assert both["device_class"] == "hosting_edge" and both["vendor_product_confidence"] == "confirmed"


def test_ordinary_greetings_and_pages_name_nothing():
    for obs in ({"ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"}, {"ssh_banner": "SSH-2.0-OpenSSH_for_Windows_8.1"},
                {"landing_path": ["/"]}, {"landing_path": ["/web/account/login.html"]},
                {"set_cookie_names": ["ASP.NET_SessionId"]}):
        assert classify(obs, load_fingerprints(), load_thresholds())["device_class"] == "unknown", obs


# ── the observations ─────────────────────────────────────────────────────────
def test_the_newest_clues_artifact_decides_inside_the_freshness_window():
    arts = {CLUES: [(_clues(), NOW - timedelta(days=2)), (_clues(paths=["/"]), NOW)]}
    cur = Cur(arts)
    assert _obs(arts, cur)["landing_path"] == ["/"]
    reads = [s for s in cur.sql if "scan_run_artifacts" in s]
    assert reads and all("now() - interval '30 days'" in s for s in reads)


def test_no_answer_emits_nothing_and_an_asset_with_no_clues_is_unchanged():
    base = {FPX: [(EFT_GREETING, NOW)]}
    before = _obs(base)
    assert "landing_path" not in before
    after = _obs(dict(base, **{CLUES: [(_clues(none=True, subject=None), NOW)]}))
    assert after == before


def _r5_decision(arts, prior_class, prior_conf, prior_sigs):
    """The runner's own R5 path for one asset (classify_asset's else-branch), from the real
    gather, classify, signal_capable and apply_r5_confidence_rule."""
    cur = Cur(arts)
    obs = dcr.gather_observations(cur, "ftp.sciimage.com", 30, "^nuclei:fortinet")
    fps = load_fingerprints()
    res = classify(obs, fps, load_thresholds())
    still = dcr.signals_in(res["evidence"])
    sig2obs = dcr.signal_observation_map(fps)
    incapable = [s for s in prior_sigs if s not in still
                 and not dcr.signal_capable(cur, "ftp.sciimage.com", s, sig2obs, 30)]
    return res, incapable, dcr.apply_r5_confidence_rule(
        prior_class, prior_conf, res["device_class"], res["device_class_confidence"], prior_sigs, incapable)


def test_an_older_login_page_then_a_newer_no_answer_keeps_the_confirmed_class():
    """Code review 2026-11-05, minor 4: the plan's key edge, end to end. EFT was confirmed
    by its login page and its greeting; the newest clues pass got no answer. The class must
    be KEPT (EVIDENCE_AGED), not lowered: a timeout is not evidence."""
    prior = ["globalscape_eft_ssh_greeting", "globalscape_eft_web_login_path"]
    arts = {GREET: [(_greeting(), NOW)],
            CLUES: [(_clues(), NOW - timedelta(days=3)), (_clues(none=True, subject=None), NOW)]}
    res, incapable, decision = _r5_decision(arts, "origin_host", "confirmed", prior)
    assert res["device_class_confidence"] == "suspected"          # what this pass alone shows
    assert incapable == ["globalscape_eft_web_login_path"]
    assert decision == dcr._DECISION_PRESERVE_AGED


def test_an_older_login_page_then_a_newer_ordinary_page_may_lower_it():
    """The contrast: the newest pass DID load the front page, and it is not EFT's login.
    That is a real 'no', so R5 lets the confidence drop."""
    prior = ["globalscape_eft_ssh_greeting", "globalscape_eft_web_login_path"]
    arts = {GREET: [(_greeting(), NOW)],
            CLUES: [(_clues(), NOW - timedelta(days=3)), (_clues(paths=["/"]), NOW)]}
    res, incapable, decision = _r5_decision(arts, "origin_host", "confirmed", prior)
    assert incapable == [] and decision == dcr._DECISION_WRITE


def test_testssl_reads_the_certificate_first():
    ts = json.dumps([{"id": "cert_commonName", "finding": "*.pressable.com"}])
    o = _obs({TESTSSL: [(ts, NOW)], CLUES: [(_clues(subject="CN=other.test"), NOW)]})
    assert o["cert_subject"] == "*.pressable.com"
    o2 = _obs({CLUES: [(_clues(subject="C=US, CN=*.pressable.com"), NOW)]})
    assert o2["cert_subject"] == "C=US, CN=*.pressable.com"


def test_clue_cookie_names_merge_with_the_passive_reads():
    passive = json.dumps({"set_cookie_names": ["cookiesession1"]})
    o = _obs({"stack_id_passive": [(passive, NOW - timedelta(days=1))],
              CLUES: [(_clues(cookies=["ASPSESSIONIDCECCAQAT"]), NOW)]})
    assert set(o["set_cookie_names"]) == {"cookiesession1", "ASPSESSIONIDCECCAQAT"}


def test_the_greeting_feeds_ssh_banner():
    assert dcr.extract_ssh_banner(_greeting()) == EFT_GREETING
    assert _obs({GREET: [(_greeting(), NOW)]})["ssh_banner"] == EFT_GREETING
    # the newer of the two sources wins
    o = _obs({FPX: [("SSH-2.0-OpenSSH_9.3", NOW - timedelta(days=5))], GREET: [(_greeting(), NOW)]})
    assert o["ssh_banner"] == EFT_GREETING


# ── capability ───────────────────────────────────────────────────────────────
def _cap(obs_name, blob):
    return dcr._cap_satisfied(dcr.OBSERVATION_CAPABILITY[obs_name], {"raw": blob})


def test_landing_path_capability_is_not_null():
    assert not _cap("landing_path", _clues(none=True)), "no answer to GET / = did not look"
    assert _cap("landing_path", _clues(paths=["/"])), "an answered page that is not EFT's is a real 'no'"
    cap = dcr.OBSERVATION_CAPABILITY["landing_path"]
    assert cap.mode == dcr._CAP_JSON_KEY_NOT_NULL and cap.sources == (CLUES,) and cap.depth == 1


def test_the_second_sources_are_capable_only_when_they_carry_the_value():
    assert _cap("cert_subject", _clues())
    assert not _cap("cert_subject", _clues(subject=None))
    assert _cap("set_cookie_names", _clues(cookies=["x"]))
    assert not _cap("set_cookie_names", _clues())
    assert _cap("ssh_banner", _greeting())
    assert not _cap("ssh_banner", json.dumps([{"greeting": "220 ftp ready", "port": 21}]))
    caps = dcr.OBSERVATION_CAPABILITY
    assert caps["ssh_banner"].sources == (dcr._ART_FINGERPRINT, GREET)
    assert caps["cert_subject"].sources == (dcr._ART_TESTSSL, CLUES)
    assert caps["set_cookie_names"].sources == dcr._PASSIVE_TOOL_NAMES + (CLUES,)


# ── the startup guards ───────────────────────────────────────────────────────
def test_registry_guards_pass_and_the_new_signals_are_high():
    fps, th = load_fingerprints(), load_thresholds()
    assert validate_fingerprints(fps, th["weight"]) == []
    assert validate_artifact_citations(fps) == []
    assert dcr.validate_capability_coverage(fps) == []
    for s in NEW_SIGNALS:
        assert th["weight"][s] == "high", s


def test_r4_refuses_a_missing_or_mismatched_citation():
    fps, sigs = load_fingerprints(), load_artifact_signatures()
    for name in ("/web/account/login.htm", "/eftclient/account/login.htm", "aspsessionid", "_openssh", "1.82_sshlib"):
        assert name in sigs and sigs[name]["citation"]["url"] and sigs[name]["citation"]["quote"], name
        missing = {k: v for k, v in sigs.items() if k != name}
        errs = validate_artifact_citations(fps, missing)
        assert errs and any(repr(sigs[name]["name"]) in e or name in e.lower() for e in errs), name
        wrong = dict(sigs)
        wrong[name] = dict(sigs[name], vendor="Someone Else")
        assert any("corpus vendor" in e for e in validate_artifact_citations(fps, wrong)), name


def test_cisco_gets_no_new_row():
    cisco = sorted(f["signal"] for f in load_fingerprints() if (f.get("vendor_product") or {}).get("vendor") == "Cisco")
    assert cisco == ["cisco_asa_anyconnect_hello", "cisco_asa_webvpn_login_page"]
