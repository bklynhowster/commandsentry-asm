"""test_caa_verdict.py — the CAA verdict shim in run_heavy.py (2026-10-19).

WHY THIS EXISTS. testssl 3.3dev commits from 06-22 on broke DNS_CAArecord (the
check's guard reads an always-integer `tmp`; the call site still calls the
pre-rename function name). Every target now emits
`not checked IP address scan, no domain to query` as INFO and no real verdict.
The shim restores the verdict with a dig CAA walk-up, emitted under testssl's
own identity so the existing finding rows re-observe instead of duplicating.
These tests pin the shim's edge cases:
  - no CAA anywhere  -> LOW "--"
  - CAA at the apex  -> OK (parser drops it)
  - CNAME-only       -> treated as no CAA (walk up)
  - SERVFAIL         -> unmeasurable (no record; artifact records the failure)
  - no-reply (rc!=0) -> unmeasurable
  - a real testssl verdict -> left alone (shim does not fire)
  - IP-literal target -> left alone
  - the stable finding id ends :testssl:DNS_CAArecord:33ad838 (the 31 rows)
Fixture dig output mirrors real `dig +noall +comments +answer -t CAA`.
"""

import json

import run_heavy as h


def _ctx(hostname="a.b.example.com"):
    return h.HeavyScanContext(
        descriptor={}, hostname=hostname, asset_id="a.b.example.com",
        scan_run_id="00000000-0000-0000-0000-000000000001",
        queue_id="00000000-0000-0000-0000-000000000002",
        intensity="heavy",
    )


def _skip_record():
    return {"id": "DNS_CAArecord", "ip": "a.b.example.com/1.2.3.4", "port": "443",
            "severity": "INFO", "finding": h._CAA_SKIP_FINDING}


def _dig_out(status="NOERROR", rrs=()):
    out = f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 1\n"
    for rr in rrs:
        out += rr + "\n"
    return out


# ─── _is_ip_literal ─────────────────────────────────────────────────────────

def test_is_ip_literal():
    assert h._is_ip_literal("1.2.3.4")
    assert h._is_ip_literal("2001:db8::1")
    assert not h._is_ip_literal("a.example.com")
    assert not h._is_ip_literal("localhost")


# ─── _caa_walk_nodes ────────────────────────────────────────────────────────

def test_caa_walk_nodes():
    assert h._caa_walk_nodes("a.b.example.com") == [
        "a.b.example.com", "b.example.com", "example.com"]
    assert h._caa_walk_nodes("example.com") == ["example.com"]
    assert h._caa_walk_nodes("example.com.") == ["example.com"]
    assert h._caa_walk_nodes("com") == []


# ─── _parse_caa_answer ──────────────────────────────────────────────────────

def test_parse_noerror_no_caa():
    status, caa = h._parse_caa_answer(0, _dig_out("NOERROR"))
    assert status == "noerror" and caa == []


def test_parse_noerror_with_caa():
    out = _dig_out("NOERROR", rrs=['example.com.\t59\tIN\tCAA\t0 issue "letsencrypt.org"'])
    status, caa = h._parse_caa_answer(0, out)
    assert status == "noerror"
    assert caa == ['0 issue "letsencrypt.org"']


def test_parse_cname_only_is_not_caa():
    # A CNAME-only answer carries a CNAME line but no CAA — ignore it (walk up).
    out = _dig_out("NOERROR", rrs=["www.example.com.\t59\tIN\tCNAME\texample.com."])
    status, caa = h._parse_caa_answer(0, out)
    assert status == "noerror" and caa == []


def test_parse_servfail_is_unmeasurable():
    status, caa = h._parse_caa_answer(0, _dig_out("SERVFAIL"))
    assert status == "unmeasurable" and caa == []


def test_parse_nonzero_rc_is_unmeasurable():
    # dig no-reply / timeout surfaces as a non-zero exit code.
    status, caa = h._parse_caa_answer(9, "")
    assert status == "unmeasurable" and caa == []


# ─── _lookup_caa (with _dig_caa stubbed) ────────────────────────────────────

def _stub_dig(answers):
    def fake(node):
        return answers.get(node, (0, _dig_out("NOERROR")))
    return fake


def test_lookup_no_caa_anywhere(monkeypatch):
    monkeypatch.setattr(h, "_dig_caa", _stub_dig({}))
    verdict, details = h._lookup_caa("a.b.example.com")
    assert verdict == "no_caa"
    assert [w["node"] for w in details["walk"]] == [
        "a.b.example.com", "b.example.com", "example.com"]


def test_lookup_caa_at_apex(monkeypatch):
    apex = _dig_out("NOERROR", rrs=['example.com.\t59\tIN\tCAA\t0 issue "pki.goog"'])
    monkeypatch.setattr(h, "_dig_caa", _stub_dig({"example.com": (0, apex)}))
    verdict, details = h._lookup_caa("a.b.example.com")
    assert verdict == "caa_present"
    assert details["node"] == "example.com"
    assert details["caa"] == ['0 issue "pki.goog"']


def test_lookup_cname_only_walks_up(monkeypatch):
    values = {
        "www.example.com": (0, _dig_out(
            "NOERROR", rrs=["www.example.com.\t59\tIN\tCNAME\texample.com."])),
        "example.com": (0, _dig_out(
            "NOERROR", rrs=['example.com.\t59\tIN\tCAA\t0 issue "sectigo.com"'])),
    }
    monkeypatch.setattr(h, "_dig_caa", _stub_dig(values))
    verdict, details = h._lookup_caa("www.example.com")
    assert verdict == "caa_present" and details["node"] == "example.com"


def test_lookup_servfail_is_unmeasurable(monkeypatch):
    monkeypatch.setattr(h, "_dig_caa", _stub_dig({"a.b.example.com": (0, _dig_out("SERVFAIL"))}))
    verdict, _ = h._lookup_caa("a.b.example.com")
    assert verdict == "unmeasurable"


def test_lookup_no_reply_is_unmeasurable(monkeypatch):
    monkeypatch.setattr(h, "_dig_caa", _stub_dig({"a.b.example.com": (9, "")}))
    verdict, _ = h._lookup_caa("a.b.example.com")
    assert verdict == "unmeasurable"


# ─── _apply_caa_shim ────────────────────────────────────────────────────────

def test_shim_no_caa_rewrites_to_low(monkeypatch, tmp_path):
    monkeypatch.setattr(h, "_lookup_caa", lambda host: ("no_caa", {"walk": []}))
    jf = tmp_path / "testssl.json"
    jf.write_text(json.dumps([
        _skip_record(),
        {"id": "service", "ip": "/", "port": "443", "severity": "INFO", "finding": "HTTPS"},
    ]))
    parse_path, artifact = h._apply_caa_shim(_ctx(), jf)
    assert artifact is not None and artifact["verdict"] == "no_caa"
    data = json.loads(parse_path.read_text())
    caa_rec = [r for r in data if r["id"] == "DNS_CAArecord"][0]
    assert caa_rec["severity"] == "LOW" and caa_rec["finding"] == "--"
    # the raw artifact is untouched
    raw = json.loads(jf.read_text())
    assert raw[0]["severity"] == "INFO"


def test_shim_caa_present_writes_ok(monkeypatch, tmp_path):
    monkeypatch.setattr(h, "_lookup_caa", lambda host: (
        "caa_present", {"node": "example.com", "caa": ['0 issue "pki.goog"'], "walk": []}))
    jf = tmp_path / "testssl.json"
    jf.write_text(json.dumps([_skip_record()]))
    parse_path, artifact = h._apply_caa_shim(_ctx(), jf)
    assert artifact["verdict"] == "caa_present"
    rec = json.loads(parse_path.read_text())[0]
    assert rec["severity"] == "OK"


def test_shim_unmeasurable_emits_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(h, "_lookup_caa", lambda host: ("unmeasurable", {"reason": "x", "walk": []}))
    jf = tmp_path / "testssl.json"
    jf.write_text(json.dumps([
        _skip_record(),
        {"id": "service", "ip": "/", "port": "443", "severity": "INFO", "finding": "HTTPS"},
    ]))
    parse_path, artifact = h._apply_caa_shim(_ctx(), jf)
    assert artifact["verdict"] == "unmeasurable"
    data = json.loads(parse_path.read_text())
    assert all(r["id"] != "DNS_CAArecord" for r in data)


def test_shim_real_testssl_verdict_left_alone(monkeypatch, tmp_path):
    def fail_if_called(host):
        raise AssertionError("shim ran against a real testssl verdict")
    monkeypatch.setattr(h, "_lookup_caa", fail_if_called)
    jf = tmp_path / "testssl.json"
    jf.write_text(json.dumps([{
        "id": "DNS_CAArecord", "ip": "a.b.example.com/1.2.3.4", "port": "443",
        "severity": "LOW", "finding": "--",
    }]))
    parse_path, artifact = h._apply_caa_shim(_ctx(), jf)
    assert artifact is None and parse_path == jf


def test_shim_ip_literal_left_alone(monkeypatch, tmp_path):
    def fail_if_called(host):
        raise AssertionError("shim ran against an IP-literal target")
    monkeypatch.setattr(h, "_lookup_caa", fail_if_called)
    jf = tmp_path / "testssl.json"
    jf.write_text(json.dumps([_skip_record()]))
    parse_path, artifact = h._apply_caa_shim(_ctx(hostname="1.2.3.4"), jf)
    assert artifact is None and parse_path == jf


# ─── identity pin — a shim LOW mint must re-observe, not duplicate ──────────

def test_stable_finding_id_suffix_pinned():
    fid = h.stable_finding_id("asset", "testssl", "DNS_CAArecord", "port-443")
    assert fid.endswith(":testssl:DNS_CAArecord:33ad838"), fid


def test_shim_low_mints_canonical_finding(monkeypatch, tmp_path):
    monkeypatch.setattr(h, "_lookup_caa", lambda host: ("no_caa", {"walk": []}))
    jf = tmp_path / "testssl.json"
    jf.write_text(json.dumps([_skip_record()]))
    parse_path, _ = h._apply_caa_shim(_ctx(), jf)
    events = h.parse_testssl_file(
        json_path=parse_path, asset_id="a.b.example.com",
        scan_id="s", scan_root=tmp_path, fallback_observed_at="2026-01-01T00:00:00Z",
    )
    assert len(events) == 1
    ev = events[0]
    assert ev.source == "testssl"
    assert ev.severity == "LOW"
    assert ev.finding_id.endswith(":testssl:DNS_CAArecord:33ad838"), ev.finding_id


# ─── D1 regression — the shim is non-fatal ───────────────────────────────────

def test_shim_survives_lookup_error(monkeypatch, tmp_path):
    """An unexpected error in the guarded block (here: the lookup) must return
    (jsonfile, None) — never raise, never fail the whole heavy run (which would
    skip httpx/gau/naabu/fingerprintx)."""
    def boom(host):
        raise OSError("simulated resolver failure")
    monkeypatch.setattr(h, "_lookup_caa", boom)
    jf = tmp_path / "testssl.json"
    jf.write_text(json.dumps([_skip_record()]))
    parse_path, artifact = h._apply_caa_shim(_ctx(), jf)
    assert artifact is None and parse_path == jf


# ─── mutation pass (Design #4 bullet 3) — the trigger is exact ───────────────

def test_shim_trigger_is_exact_against_mutations(monkeypatch, tmp_path):
    """Mutate one field of a genuine skip record at a time and confirm the
    shim does NOT fire: the trigger is the exact (id, severity, finding)
    triple, so a typo'd id, a wrong severity, or the pre-08-26 skip text must
    all leave the record untouched."""
    monkeypatch.setattr(h, "_lookup_caa", lambda host: ("no_caa", {"walk": []}))
    base = _skip_record()
    mutations = [
        ("id", "DNS_CAA_record"),                      # typo in the id
        ("severity", "WARN"),                          # wrong severity bucket
        ("finding", "not checked (IP address scan)"),  # the pre-08-26 skip text
    ]
    for field, value in mutations:
        rec = dict(base)
        rec[field] = value
        jf = tmp_path / f"testssl_{field}.json"
        jf.write_text(json.dumps([rec]))
        parse_path, artifact = h._apply_caa_shim(_ctx(), jf)
        assert artifact is None, f"{field} mutation fired the shim"
        assert parse_path == jf, f"{field} mutation rewrote the parse input"