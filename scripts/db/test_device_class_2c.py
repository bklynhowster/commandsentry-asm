#!/usr/bin/env python3
"""Device-class phase 2c — R5 confidence-preserve + R12 content-bearing capability.
Relay 236 (the rulings), 231/233 (the evidence they rest on). 2026-09-17.

⛔ THE DEFECT 2b DID NOT CLOSE. 2b gave the CLASS a preserve rule: an asset does not
fall to `unknown` on evidence nobody could have collected. It said nothing about
CONFIDENCE, so the same failure one level down still writes:

    commandcommcentral.com, heavy #2697, 2026-09-03
      20:11:34  wafw00f      OK   -> waf_vendor fires, the WAF class survives
      20:13:32  nikto        starts on the same egress
      20:14:21  nikto rc=-13      <- the FortiGate ban lands
      20:14:56  stack_id_passive  -> {schema, collected_at, hostname}, cookies=0

    computed: waf/suspected        prior: waf/confirmed
    -> TRANSITION_DOWNGRADE, written, soak clock reset

Nothing about that host got weaker. `cookiesession1` and the cert were not absent —
they were never collected, because the collector ran on a banned egress. The class
was protected; its confidence was not.

⭐ AND THE NAME-KEYED CAPABILITY TEST WOULD HAVE MISSED IT. That run DID write a
`stack_id_passive` artifact. Capability keyed on the artifact's NAME says "this run
could see cookies", so the missing cookie reads as evidence of absence. Only the
CONTENTS tell the two apart — which is Ruling 12, and which is why
scripts/scanner/test_passive_collector_runs_first.py pins that both a healthy and a
banned run produce an artifact with the SAME NAME differing only in content.

    name-keyed:    `stack_id_passive` exists              -> capable    ❌ downgrades
    content-keyed: does it CARRY set_cookie_names?        -> not capable ✅ preserves

⚠ THE FOUR BRANCHES BELOW ARE ONE HOST ACROSS FOUR REAL RUNS, plus one synthetic.
The synthetic is not decoration: without a capable-and-absent case the rule is
indistinguishable from "always preserve", which is a ratchet, not a rule.

⚠ FIXTURE SCOPE. `commandcommcentral.com` only. ftp.sciimage.com and
ftp.unimacgraphics.com show the same empty envelopes and are EXCLUDED — they are the
SFTP pair with no HTTPS surface, where an empty envelope may be correct.

⚠ FAILING-FIRST. Every test here is written against symbols that must EXIST for the
file to import, so the pre-fix run is a collection error, not a red. The honest
pre-fix measurement is therefore taken with the 2c block reverted and recorded in the
relay entry as such — see the entry, not this docstring, for the counts.
"""

from __future__ import annotations

import ast
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "normalize"))

import device_class_runner as dcr  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
NOW = datetime.now(timezone.utc)


def _ago(days):
    return NOW - timedelta(days=days)


# ── the real envelopes, by shape ────────────────────────────────────────────
# 2026-09-03, heavy #2697, AFTER the nikto ban. Verbatim key set.
ENVELOPE_0903_EMPTY = json.dumps({
    "schema": 1, "collected_at": "2026-09-03T20:14:56Z",
    "hostname": "commandcommcentral.com"})

# 2026-08-28, the last heavy BEFORE the cumulative cutover put nikto in front.
ENVELOPE_0828_FULL = json.dumps({
    "schema": 1, "collected_at": "2026-08-28T22:09:00Z",
    "hostname": "commandcommcentral.com",
    "set_cookie_names": ["cookiesession1", "ASP.NET_SessionId"],
    "headers": {"server": "nginx", "strict-transport-security": "max-age=31536000"},
    "cert": "subject=CN = *.commandcommcentral.com"})

# the synthetic: collection SUCCEEDED, and cookiesession1 is genuinely not there.
ENVELOPE_CAPABLE_ABSENT = json.dumps({
    "schema": 1, "hostname": "commandcommcentral.com",
    "set_cookie_names": ["ASP.NET_SessionId"],
    "headers": {"server": "nginx"}})

WAFW00F_FORTIWEB = json.dumps({"schema": 1, "wafw00f_detected": True,
                               "wafw00f_kind": "fortiweb"})
WAFW00F_NEGATIVE = json.dumps({"schema": 1, "wafw00f_detected": False,
                               "wafw00f_kind": None})

PRIOR_EVIDENCE_CONFIRMED = [
    {"signal": "wafw00f_high_confidence", "weight": "high"},
    {"signal": "fortiweb_cookiesession1", "weight": "high"},
    {"signal": "cert_issuer_subject_pattern", "weight": "medium"},
]


class CapCursor:
    """A cursor fake that answers capability probes per TOOL NAME.

    Keyed on the tool_name PARAMETER, not on substrings of the SQL — the query text
    is one `select ... from scan_run_artifacts` for every observation, so matching on
    it would make every probe return the same rows and every test vacuously pass.
    """

    def __init__(self, artifacts=None, surface=None):
        # {tool_name: [(raw, completed_at), ...]}  newest first
        self.artifacts = artifacts or {}
        self.surface = surface
        self._result = []
        self.probed = []

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        if "asset_surface" in s:
            self._result = [{"surface_data": self.surface}] if self.surface else []
            return
        if "scan_run_artifacts" not in s:
            self._result = []
            return
        tool = params[1] if params and len(params) > 1 else None
        self.probed.append(tool)
        rows = []
        for name, entries in self.artifacts.items():
            if tool and tool.endswith("%"):
                if not name.startswith(tool[:-1]):
                    continue
            elif name != tool:
                continue
            for raw, when in entries:
                rows.append({"raw": raw, "completed_at": when})
        rows.sort(key=lambda r: r["completed_at"] or NOW, reverse=True)
        self._result = rows

    def fetchall(self):
        return self._result

    def fetchone(self):
        return self._result[0] if self._result else None


# ═══════════════════════════════════════════════════════════════════════════
# ⭐ THE FOUR BRANCHES — one host, four collection states
# ═══════════════════════════════════════════════════════════════════════════

def test_branch1_0903_waf_capable_cookies_not_capable_preserves():
    """⛔ THE ONE THIS EXISTS FOR. 2026-09-03: wafw00f ran and named FortiWeb, so
    waf_vendor IS capable and the class holds. The passive collector ran on a banned
    egress, so set_cookie_names is NOT capable — the artifact is there, the field is
    not. waf/confirmed must be PRESERVED, not downgraded to suspected."""
    cur = CapCursor(artifacts={
        "stack_id_wafw00f": [(WAFW00F_FORTIWEB, _ago(1))],
        "stack_id_passive": [(ENVELOPE_0903_EMPTY, _ago(1))],
    })
    assert dcr.observation_capable(cur, "commandcommcentral.com", "waf_vendor", 30) is True
    assert dcr.observation_capable(cur, "commandcommcentral.com", "set_cookie_names", 30) is False, (
        "an artifact carrying {schema, collected_at, hostname} is not a collection of "
        "cookies — this is the name-vs-content distinction Ruling 12 rests on")
    sig2obs = {"wafw00f_high_confidence": frozenset({"waf_vendor"}),
               "fortiweb_cookiesession1": frozenset({"set_cookie_names"})}
    incapable = [s for s in ("wafw00f_high_confidence", "fortiweb_cookiesession1")
                 if not dcr.signal_capable(cur, "commandcommcentral.com", s, sig2obs, 30)]
    assert incapable == ["fortiweb_cookiesession1"]
    assert dcr.apply_r5_confidence_rule(
        "waf", "confirmed", "waf", "suspected",
        ["wafw00f_high_confidence", "fortiweb_cookiesession1"], incapable
    ) == dcr._DECISION_PRESERVE_AGED


def test_branch2_0828_everything_capable_and_present():
    """The contrast run, 2026-08-28 — the last heavy before the cumulative cutover put
    nikto ahead of the collector. All three observations collectible, so nothing is
    preserved and nothing needs to be: the verdict rests on current evidence."""
    cur = CapCursor(artifacts={
        "stack_id_wafw00f": [(WAFW00F_FORTIWEB, _ago(20))],
        "stack_id_passive": [(ENVELOPE_0828_FULL, _ago(20))],
        "testssl_json": [('[{"id":"cert_caIssuers","finding":"Go Daddy Secure '
                          'Certificate Authority - G2"}]', _ago(20))],
    })
    for obs in ("waf_vendor", "set_cookie_names", "http_headers", "cert_issuer"):
        assert dcr.observation_capable(cur, "commandcommcentral.com", obs, 30) is True, obs


def test_branch3_capable_and_absent_writes_the_downgrade():
    """⭐ THE DOESN'T-FIRE HALF, and the reason this rule is a rule rather than a
    ratchet. Collection SUCCEEDED — a non-empty cookie list came back — and
    `cookiesession1` is genuinely not in it. That is a real observation of weaker
    evidence and it MUST write, or a confidence can rise and never fall."""
    cur = CapCursor(artifacts={
        "stack_id_wafw00f": [(WAFW00F_FORTIWEB, _ago(1))],
        "stack_id_passive": [(ENVELOPE_CAPABLE_ABSENT, _ago(1))],
    })
    assert dcr.observation_capable(cur, "commandcommcentral.com", "set_cookie_names", 30) is True
    assert dcr.apply_r5_confidence_rule(
        "waf", "confirmed", "waf", "suspected",
        ["wafw00f_high_confidence", "fortiweb_cookiesession1"], []
    ) == dcr._DECISION_WRITE


def test_branch4_post_3050_all_present_in_window():
    """Heavy #3050, 2026-09-17, on the reorder (f8cc3a3e). The collector ran FIRST and
    came back with cert + headers + 4 cookies, and wafw00f read fortiweb live. Every
    observation capable and present, so R5 is a no-op — confirmed on CURRENT evidence,
    not preserved. Relay 236."""
    env_3050 = json.dumps({
        "schema": 1, "hostname": "commandcommcentral.com",
        "set_cookie_names": ["cookiesession1", "ASP.NET_SessionId",
                             "__RequestVerificationToken", ".SCI.Session"],
        "headers": {"server": "nginx"},
        "cert": "subject=CN = *.commandcommcentral.com"})
    cur = CapCursor(artifacts={
        "stack_id_wafw00f": [(WAFW00F_FORTIWEB, _ago(0))],
        "stack_id_passive": [(env_3050, _ago(0))],
    })
    assert dcr.observation_capable(cur, "commandcommcentral.com", "set_cookie_names", 30) is True
    # confidence did not drop -> the rule does not engage at all
    assert dcr.apply_r5_confidence_rule(
        "waf", "confirmed", "waf", "confirmed",
        ["wafw00f_high_confidence", "fortiweb_cookiesession1"], []
    ) == dcr._DECISION_WRITE


# ═══════════════════════════════════════════════════════════════════════════
# R12 — capability is CONTENT-bearing
# ═══════════════════════════════════════════════════════════════════════════

def test_a_wafw00f_negative_verdict_is_still_capable():
    """⛔ THE KEY-PRESENT / NON-EMPTY SPLIT, and it cuts the other way from cookies.
    `wafw00f_detected: false` is a REAL verdict — the tool ran, probed, found no WAF.
    Testing it for truthiness would call every genuine negative 'not capable' and make
    a WAF class UNFALSIFIABLE: once confirmed, no wafw00f run could ever lower it."""
    cur = CapCursor(artifacts={"stack_id_wafw00f": [(WAFW00F_NEGATIVE, _ago(1))]})
    assert dcr.observation_capable(cur, "x", "waf_vendor", 30) is True


def test_a_wafw00f_artifact_missing_the_verdict_key_is_not_capable():
    """The other side of the same split: an artifact with no `wafw00f_detected` key
    never carried a verdict at all."""
    cur = CapCursor(artifacts={"stack_id_wafw00f": [(json.dumps({"schema": 1}), _ago(1))]})
    assert dcr.observation_capable(cur, "x", "waf_vendor", 30) is False


def test_either_passive_producer_satisfies_capability():
    """light_stack_passive carries cookies and headers but no cert, by design. If
    heavy's envelope is empty and light's is not, cookies WERE collectible — the same
    per-signal merge gather_observations does, applied to capability."""
    cur = CapCursor(artifacts={
        "stack_id_passive": [(ENVELOPE_0903_EMPTY, _ago(1))],
        "light_stack_passive": [(json.dumps(
            {"set_cookie_names": ["cookiesession1"], "headers": {"server": "nginx"}}), _ago(3))],
    })
    assert dcr.observation_capable(cur, "x", "set_cookie_names", 30) is True


def test_an_empty_cookie_list_is_absence_not_evidence_of_absence():
    """`[]` is the shape a banned collector writes when it writes the key at all."""
    cur = CapCursor(artifacts={
        "stack_id_passive": [(json.dumps({"set_cookie_names": [], "headers": {}}), _ago(1))]})
    assert dcr.observation_capable(cur, "x", "set_cookie_names", 30) is False
    assert dcr.observation_capable(cur, "x", "http_headers", 30) is False


def test_no_artifact_at_all_is_not_capable():
    assert dcr.observation_capable(CapCursor(), "x", "set_cookie_names", 30) is False


def test_an_unmapped_observation_fails_closed():
    """⚠ FAIL CLOSED. Reaching this branch means the startup guard was bypassed.
    'Not capable' preserves the prior — recoverable. 'Capable' strips a real label on
    absent evidence, which is the entire defect family this rule closes."""
    assert dcr.observation_capable(CapCursor(), "x", "no_such_observation", 30) is False


def test_the_depth_constant_is_behaviourally_load_bearing():
    """⚠ Not just a number that matches — a number that DOES something. Newest
    envelope empty, the one behind it full, both from the SAME producer inside the
    window. At depth 3 (what the gather reads) cookies were collectible; at depth 1
    they read as absent and the FortiWeb confirmation is downgraded. A structural
    assert alone would let `depth=1` slip through as a cosmetic edit."""
    cur = CapCursor(artifacts={"stack_id_passive": [
        (ENVELOPE_0903_EMPTY, _ago(1)),
        (ENVELOPE_0828_FULL, _ago(6)),
    ]})
    assert dcr._PASSIVE_MERGE_DEPTH >= 2, "depth 1 cannot see past an empty envelope"
    assert dcr.observation_capable(cur, "commandcommcentral.com", "set_cookie_names", 30) is True


def test_capability_read_depth_matches_the_gather():
    """⚠ If capability looked DEEPER than gather_observations reads, a 4th-newest
    artifact could make a signal 'capable' that the gather never saw — a
    capable-but-unseen downgrade, which is fail-open wearing the new rule's clothes.
    One constant, both consumers."""
    assert dcr.OBSERVATION_CAPABILITY["set_cookie_names"].depth == dcr._PASSIVE_MERGE_DEPTH
    assert dcr.OBSERVATION_CAPABILITY["http_headers"].depth == dcr._PASSIVE_MERGE_DEPTH
    src = open(os.path.join(HERE, "device_class_runner.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "gather_observations")
    body = ast.get_source_segment(src, fn)
    code = "\n".join(l for l in body.split("\n") if not l.lstrip().startswith("#"))
    assert "limit=_PASSIVE_MERGE_DEPTH" in code, (
        "gather_observations no longer reads the shared depth constant — capability "
        "and the gather can now drift apart silently")
    assert "limit: int = 3" not in code and "limit=3" not in code, (
        "a literal 3 is back in the gather; that is the drift this constant removes")


# ═══════════════════════════════════════════════════════════════════════════
# R12 — the coverage guard (keyed on observation, registry is the SSOT)
# ═══════════════════════════════════════════════════════════════════════════

def test_every_registry_observation_is_covered_or_declared_dormant():
    """The startup condition run() enforces, asserted against the REAL registry."""
    from derive_device_class import load_fingerprints
    errs = dcr.validate_capability_coverage(load_fingerprints())
    assert errs == [], "; ".join(errs)


def test_the_coverage_guard_reports_an_unmapped_observation():
    """Its doesn't-fire half — a guard that never fires is not a guard."""
    errs = dcr.validate_capability_coverage(
        [{"signal": "s", "observation": "invented_observation"}])
    assert len(errs) == 1 and "invented_observation" in errs[0]


def test_the_dormant_set_is_declared_not_discovered():
    """waf_present_differential is a ratified registry row with no producer in
    gather_observations. Declaring it keeps the guard honest; an `else: assume
    capable` fallback would be the fail-open shape being removed fleet-wide."""
    assert "waf_present_differential" in dcr.DORMANT_OBSERVATIONS
    from derive_device_class import load_fingerprints
    obs = {r["observation"] for r in load_fingerprints() if r.get("observation")}
    assert dcr.DORMANT_OBSERVATIONS <= obs, (
        "a dormant declaration for an observation the registry no longer names — "
        "delete it rather than carrying a dead exemption")


def test_the_map_is_keyed_on_observations_the_registry_names():
    """⚠ KEYED ON OBSERVATION, NOT SIGNAL, and this pins it. A signal->artifact table
    here would be a second home for a mapping device_fingerprints.yaml already owns,
    and the two would drift with nothing failing."""
    from derive_device_class import load_fingerprints
    fps = load_fingerprints()
    observations = {r["observation"] for r in fps if r.get("observation")}
    signals = {r["signal"] for r in fps if r.get("signal")}
    assert set(dcr.OBSERVATION_CAPABILITY) <= observations, (
        f"capability keys that are not registry observations: "
        f"{sorted(set(dcr.OBSERVATION_CAPABILITY) - observations)}")
    assert not (set(dcr.OBSERVATION_CAPABILITY) & signals), (
        "a SIGNAL name has appeared as a capability key — the map has started "
        "duplicating the registry's signal->observation mapping")


def test_signal_observation_map_is_multivalued():
    """cert_issuer_subject_pattern fires from cert_issuer OR cert_subject; three
    signals read http_headers. A signal is capable if ANY of its observations is —
    the question is 'could this signal have fired again', not 'was every input there'."""
    from derive_device_class import load_fingerprints
    m = dcr.signal_observation_map(load_fingerprints())
    assert m["cert_issuer_subject_pattern"] == frozenset({"cert_issuer", "cert_subject"})
    assert m["fortiweb_cookiesession1"] == frozenset({"set_cookie_names"})


def test_a_signal_is_capable_when_any_of_its_observations_is():
    """cert_subject collectible, cert_issuer not -> the signal could still have fired."""
    cur = CapCursor(artifacts={
        "testssl_json": [('[{"id":"cert_commonName","finding":"*.commandcommcentral.com"}]',
                          _ago(2))]})
    m = {"cert_issuer_subject_pattern": frozenset({"cert_issuer", "cert_subject"})}
    assert dcr.observation_capable(cur, "x", "cert_issuer", 30) is False
    assert dcr.observation_capable(cur, "x", "cert_subject", 30) is True
    assert dcr.signal_capable(cur, "x", "cert_issuer_subject_pattern", m, 30) is True


def test_the_2b_tuple_and_the_capability_map_differ_only_by_the_known_delta():
    """⚠ A GAP RECORDED, NOT SILENTLY CLOSED. EVIDENCE_ARTIFACT_PATTERNS — 2b's
    class-level 'any evidence' test, reviewed and shipped — does NOT list
    stack_id_fwbbot_check, though gather_observations reads it. So a run producing
    ONLY that artifact does not count as evidence-capable for 2b.

    Deriving the 2b tuple from the capability map would fix it as a side effect of a
    refactor — changing an approved rule's behaviour without review. It is pinned here
    instead, so the difference is a decision on the record rather than a discovery."""
    cap_sources = {s for c in dcr.OBSERVATION_CAPABILITY.values() for s in c.sources}
    delta = cap_sources - set(dcr.EVIDENCE_ARTIFACT_PATTERNS)
    assert delta == {"stack_id_fwbbot_check"}, (
        f"the 2b/capability delta changed: {sorted(delta)}. If that is intended, it is "
        f"a change to a shipped rule and belongs in a relay turn, not in this assert.")


# ═══════════════════════════════════════════════════════════════════════════
# R5 — the pure rule, and its interaction with 2b
# ═══════════════════════════════════════════════════════════════════════════

# ⚠ LITERALS IN THE DECORATOR, NOT `dcr.` ATTRIBUTES, AND THAT IS ON PURPOSE.
# A `dcr._DECISION_PRESERVE_AGED` at module scope makes the pre-fix run a COLLECTION
# ERROR — the whole file never executes and "red" means nothing was measured. With
# literals every test runs on the pre-fix tree and FAILS on its assertion, which is a
# real red. The constants' values are pinned separately, below.
@pytest.mark.parametrize("prior_c,prior_f,new_c,new_f,prior_s,incap,want", [
    ("waf", "confirmed", "waf", "suspected", ["a", "b"], ["b"], "preserve_aged"),
    ("waf", "confirmed", "waf", "suspected", ["a", "b"], [],    "write"),
    ("waf", "confirmed", "cdn", "suspected", ["a"],      ["a"], "write"),
    ("waf", "suspected", "waf", "confirmed", ["a"],      ["a"], "write"),
    ("waf", "confirmed", "waf", "confirmed", ["a"],      ["a"], "write"),
    ("waf", "confirmed", "waf", "suspected", [],         ["a"], "write"),
    ("waf", "confirmed", "waf", "suspected", ["a"],      ["b"], "write"),
])
def test_the_r5_matrix(prior_c, prior_f, new_c, new_f, prior_s, incap, want):
    assert dcr.apply_r5_confidence_rule(
        prior_c, prior_f, new_c, new_f, prior_s, incap) == want


def test_the_decision_constants_have_the_values_the_matrix_asserts():
    """Pins what the literals above stand for, so the matrix is not merely
    self-consistent with a renamed constant."""
    assert dcr._DECISION_PRESERVE_AGED == "preserve_aged"
    assert dcr._DECISION_WRITE == "write"
    assert dcr._R5_REASON == "EVIDENCE_AGED"


def test_an_empty_prior_basis_writes_so_confidence_is_not_a_ratchet():
    """An asset whose stored class carries no evidence rows did not get there through
    this runner, so there is nothing to call aged. Preserving would build a confidence
    that can rise and never fall — and _routing_bucket already pins that a same-class
    confidence move changes no routing decision, so the blast radius is bounded."""
    assert dcr.apply_r5_confidence_rule(
        "waf", "confirmed", "waf", "suspected", [], ["anything"]) == dcr._DECISION_WRITE


def test_r5_and_2b_are_mutually_exclusive_by_construction():
    """⛔ A computed `unknown` is 2b's, always. If both rules could narrow the same
    decision, whichever ran second would silently win. The runner's structure — not a
    convention — is what keeps them apart, so the structure is what gets pinned."""
    src = open(os.path.join(HERE, "device_class_runner.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "run")
    r5_calls, unknown_ifs = [], []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "apply_r5_confidence_rule":
            r5_calls.append(node)
        if isinstance(node, ast.If):
            t = ast.dump(node.test)
            if "'unknown'" in t or '"unknown"' in t:
                unknown_ifs.append(node)
    assert len(r5_calls) == 1, f"apply_r5_confidence_rule called {len(r5_calls)}x in run()"
    host = next((n for n in unknown_ifs
                 if any(c is r5_calls[0] for b in n.orelse for c in ast.walk(b))), None)
    assert host is not None, (
        "apply_r5_confidence_rule is no longer in the `else` of the computed-unknown "
        "branch — R5 and the 2b matrix can now both narrow one decision")


def test_prior_signals_are_read_from_the_stored_evidence_blob():
    """No migration: device_class_evidence is the column every --write pass already
    stores. The runner starts reading what it has been writing."""
    assert dcr.prior_signals_of(PRIOR_EVIDENCE_CONFIRMED) == [
        "wafw00f_high_confidence", "fortiweb_cookiesession1", "cert_issuer_subject_pattern"]
    assert dcr.prior_signals_of(json.dumps(PRIOR_EVIDENCE_CONFIRMED))[0] == \
        "wafw00f_high_confidence"
    assert dcr.prior_signals_of(None) == []
    assert dcr.prior_signals_of("not json") == []
    assert dcr.prior_signals_of([{"no_signal_key": 1}]) == []


def test_the_run_loop_selects_device_class_evidence():
    """The R5 read has to be IN the assets query or prior_signals_of always sees None
    and the rule silently degrades to 'never preserve' — passing every unit test."""
    src = open(os.path.join(HERE, "device_class_runner.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "run")
    body = ast.get_source_segment(src, fn)
    code = "\n".join(l for l in body.split("\n") if not l.lstrip().startswith("#"))
    assert "device_class_evidence" in code and "from public.assets" in code


def test_the_preserve_gate_still_blocks_the_new_decision():
    """The assets write is gated on `decision == _DECISION_WRITE`. A new non-write
    decision must be blocked by that same gate — if the gate were ever rewritten as
    `decision != _DECISION_PRESERVE`, R5's preserve would write."""
    src = open(os.path.join(HERE, "device_class_runner.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "run")
    body = ast.get_source_segment(src, fn)
    assert "if write and decision == _DECISION_WRITE:" in body, (
        "the preserve gate is no longer an equality test against _DECISION_WRITE — a "
        "negative test would let any new non-write decision through")
    assert dcr._DECISION_PRESERVE_AGED != dcr._DECISION_WRITE


def test_observation_age_days_reports_the_newest_carrying_collection():
    """The number an operator wants when a verdict is preserved. Newest CARRYING
    collection — an empty envelope in between must not reset it to 0."""
    cur = CapCursor(artifacts={"stack_id_passive": [
        (ENVELOPE_0903_EMPTY, _ago(1)),          # newer, carries nothing
        (ENVELOPE_0828_FULL, _ago(14)),          # older, carries the cookies
    ]})
    assert dcr.observation_age_days(cur, "x", "set_cookie_names") == 14


def test_observation_age_days_is_none_when_never_collected():
    assert dcr.observation_age_days(CapCursor(), "x", "set_cookie_names") is None
