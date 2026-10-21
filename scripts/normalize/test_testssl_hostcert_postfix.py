#!/usr/bin/env python3
"""328 (2026-10-21) — testssl per-certificate postfix ids + two demotions.

WHY THIS EXISTS. testssl 3.3dev enumerates per-certificate records when an
endpoint presents more than one host cert (email.commandcompanies.com: the
10-19 heavy carried two outlook.com leaf PEMs after Microsoft rotated the
leaf on 2026-10-13). The per-cert postfix tokens ("<hostCert#1>", "<#1>",
bracket-less "hostCert#1") rode the record id verbatim, so one real
name-mismatch minted THREE findings (one MODERATE + two HIGH) and one
wildcard fact three rows — and the postfixed rows escaped the #037 ceiling,
the plain-English titles and the bare-IP guard.

Pinned here:
  - _normalize_id strips every measured postfix form and leaves every
    non-postfixed id untouched (incl. cipher grouping and digit-suffixed ids)
  - parse_testssl_file: plain + postfixed records of one fact collapse into
    ONE event at the plain row's finding_id, at the ceiling's MODERATE
  - T2 (relay 152; wired by Howie's question-3 ruling, 2026-10-21): the
    wildcard fact resolves INFO, not LOW
  - ruling C (question 2, 2026-10-21, refined the same day): cloud_endpoint
    demotes the cert-hygiene family to INFO only when the served certificate
    does not name the scanned host (the provider's own cert) — and never for
    cert_expirationStatus — and touches nothing else
  - the 4.7 bare-IP guard's id arm now catches postfixed records whose text
    lacks the mismatch phrase (the text arm already caught the real form)
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cs_parsers.testssl import (  # noqa: E402
    CERT_HYGIENE_IDS,
    _normalize_id,
    parse_testssl_file,
)


def _rec(rid, sev="HIGH", finding="certificate does not match supplied URI",
         ip="a.b.example.com/1.2.3.4", port="443"):
    return {"id": rid, "ip": ip, "port": port, "severity": sev,
            "finding": finding}


def _events(tmp_path, records, cloud_endpoint=False,
            asset_id="a.b.example.com"):
    jf = tmp_path / "testssl.json"
    jf.write_text(json.dumps(records))
    return parse_testssl_file(
        json_path=jf,
        asset_id=asset_id,
        scan_id="scan",
        scan_root=tmp_path,
        fallback_observed_at="2026-10-19T21:43:58Z",
        cloud_endpoint=cloud_endpoint,
    )


# ══ _normalize_id — every measured postfix form strips ═════════════════════

def test_hostcert_postfix_strips_to_the_plain_id():
    assert _normalize_id("cert_trust <hostCert#1>") == ("cert_trust", False)


def test_double_postfix_strips_both_tokens():
    assert _normalize_id("intermediate_cert <#1> <hostCert#2>") \
        == ("intermediate_cert", False)


def test_bracketless_upstream_form_strips():
    # testssl.sh:9468 form, cited by the push-326 code review
    assert _normalize_id("DNS_CAArecord hostCert#1") == ("DNS_CAArecord", False)


def test_ids_without_a_postfix_are_untouched():
    # ⛔ regression guard: the strict pattern must not eat any of these
    assert _normalize_id("cert_trust") == ("cert_trust", False)
    assert _normalize_id("DNS_CAArecord") == ("DNS_CAArecord", False)
    assert _normalize_id("TLS1_2") == ("TLS1_2", False)  # digits, no whitespace+#
    assert _normalize_id("clientsimulation-java_80442") \
        == ("clientsimulation-java_80442", False)
    assert _normalize_id("cert_trust 443") == ("cert_trust 443", False)  # no #


def test_cipher_grouping_survives_the_postfix_strip():
    gid, is_cipher = _normalize_id("cipher-tls1_2_xc028")
    assert (gid, is_cipher) == ("cipher-tls1_2", True)
    # a postfixed cipher id strips to the same grouped id
    assert _normalize_id("cipher-tls1_2_xc028 <hostCert#1>") \
        == ("cipher-tls1_2", True)


# ══ parse_testssl_file — one fact, one event ══════════════════════════════

def test_three_cert_trust_records_collapse_to_one_moderate_event(tmp_path):
    events = _events(tmp_path, [
        _rec("cert_trust"),
        _rec("cert_trust <hostCert#1>"),
        _rec("cert_trust <hostCert#2>"),
    ])
    assert len(events) == 1, [e.finding_id for e in events]
    ev = events[0]
    # the #037 ceiling now applies (the ids normalize): HIGH → MODERATE
    assert ev.severity == "MODERATE", ev.severity
    # the PLAIN row's finding_id — all three records hash the same canonical inputs
    assert ev.finding_id == "a.b.example.com:testssl:cert_trust:33ad838", ev.finding_id


def test_wildcard_facts_resolve_INFO_not_LOW(tmp_path):
    """T2 (relay 152), wired by Howie's question-3 ruling (2026-10-21): the
    wildcard demotion actually executes. Before 328 the policy demotion inside
    _cert_hygiene_severity was dead code behind the CERT_HYGIENE_IDS
    membership gate (since the T2 commit, 2026-09-18) and this resolved
    LOW."""
    events = _events(tmp_path, [
        _rec("cert_trust_wildcard", sev="LOW", finding="wildcard certificate"),
        _rec("cert_trust_wildcard <hostCert#1>", sev="LOW",
             finding="wildcard certificate"),
    ])
    assert len(events) == 1, [e.finding_id for e in events]
    assert events[0].severity == "INFO", events[0].severity
    assert events[0].finding_id.endswith(":testssl:cert_trust_wildcard:33ad838")


def test_the_t2_wiring_is_membership_in_the_gate_set():
    """The wiring IS this membership: the CERT_HYGIENE_IDS membership gate
    lets _cert_hygiene_severity — the only reader of _CERT_POLICY_IDS — run
    for cert_trust_wildcard."""
    assert "cert_trust_wildcard" in CERT_HYGIENE_IDS


# ══ ruling C — cloud-endpoint demotion ════════════════════════════════════

# Howie's refinement (2026-10-21, same day as the ruling): "demote cert
# findings on cloud endpoints only when the certificate does not name the
# host (the provider's own cert), and never demote cert_expirationStatus."
# The evidence is the cert's own name records in the same artifact
# (cert_commonName / cert_subjectAltName — the live email.commandcompanies.com
# shape: CN outlook.com, SANs all Microsoft).

_PROVIDER_CERT = [
    {"id": "cert_commonName", "severity": "INFO",
     "ip": "a.b.example.com/1.2.3.4", "port": "443", "finding": "outlook.com"},
    {"id": "cert_subjectAltName", "severity": "INFO",
     "ip": "a.b.example.com/1.2.3.4", "port": "443",
     "finding": "outlook.com *.outlook.com *.office365.com"},
]


def test_cloud_endpoint_demotes_when_the_cert_does_not_name_host(tmp_path):
    # the provider's own cert (CN outlook.com, no SAN covers the host — the
    # live email.commandcompanies.com shape) → deployment fact → INFO
    events = _events(tmp_path, [_rec("cert_trust")] + _PROVIDER_CERT,
                     cloud_endpoint=True)
    assert len(events) == 1
    assert events[0].severity == "INFO", events[0].severity


def test_cloud_endpoint_keeps_severity_when_the_cert_names_the_host(tmp_path):
    # the cert WAS issued for this host (CN = the host — the live
    # portal-tims.unimacgraphics.com shape) → owner's finding → #037 ceiling
    own_cert = [
        {"id": "cert_commonName", "severity": "INFO",
         "ip": "a.b.example.com/1.2.3.4", "port": "443",
         "finding": "a.b.example.com"},
    ]
    events = _events(tmp_path, [_rec("cert_trust")] + own_cert,
                     cloud_endpoint=True)
    assert len(events) == 1
    assert events[0].severity == "MODERATE", events[0].severity


def test_wildcard_san_covers_only_the_leftmost_label(tmp_path):
    # RFC 6125: "*.example.com" does NOT cover a.b.example.com (two labels)
    # → demote; "*.b.example.com" DOES cover it → no demotion.
    one_label_only = [
        {"id": "cert_subjectAltName", "severity": "INFO",
         "ip": "a.b.example.com/1.2.3.4", "port": "443",
         "finding": "*.example.com"},
    ]
    ev = _events(tmp_path, [_rec("cert_trust")] + one_label_only,
                 cloud_endpoint=True)
    assert ev[0].severity == "INFO", ev[0].severity
    covers = [
        {"id": "cert_subjectAltName", "severity": "INFO",
         "ip": "a.b.example.com/1.2.3.4", "port": "443",
         "finding": "*.b.example.com"},
    ]
    ev = _events(tmp_path, [_rec("cert_trust")] + covers,
                 cloud_endpoint=True)
    assert ev[0].severity == "MODERATE", ev[0].severity


def test_cloud_endpoint_never_demotes_cert_expirationStatus(tmp_path):
    # ⛔ the line the refinement draws: even on the provider's own cert the
    # expiry early-warning keeps its severity (HIGH in → #037 ceiling
    # MODERATE out, never INFO)
    events = _events(tmp_path, [
        _rec("cert_expirationStatus", sev="HIGH",
             finding="certificate expires < 60 days (56)"),
    ] + _PROVIDER_CERT, cloud_endpoint=True)
    assert len(events) == 1
    assert events[0].severity == "MODERATE", events[0].severity


def test_cloud_endpoint_without_cert_name_evidence_demotes_nothing(tmp_path):
    # no cert_commonName / cert_subjectAltName records in the artifact →
    # "the certificate does not name the host" is UNPROVEN → no demotion
    # (identify from what was observed, never from absence)
    events = _events(tmp_path, [_rec("cert_trust")], cloud_endpoint=True)
    assert len(events) == 1
    assert events[0].severity == "MODERATE", events[0].severity


def test_cloud_endpoint_leaves_non_cert_hygiene_alone(tmp_path):
    # ⛔ the line it must not cross: security_headers keeps its MODERATE
    # (KEEP_MEDIUM_IDS) on a cloud endpoint — the demotion is cert-hygiene only
    events = _events(tmp_path, [
        _rec("security_headers", sev="MEDIUM",
             finding="Content Security Policy missing"),
    ], cloud_endpoint=True)
    assert len(events) == 1
    assert events[0].severity == "MODERATE", events[0].severity


def test_cloud_endpoint_is_opt_in_per_asset(tmp_path):
    # default False — the offline normalizer and every unstamped asset unchanged
    events = _events(tmp_path, [_rec("cert_trust")], cloud_endpoint=False)
    assert events[0].severity == "MODERATE", events[0].severity


# ══ the 4.7 bare-IP guard, post-fix ════════════════════════════════════════

def test_postfixed_bare_ip_record_without_the_phrase_is_dropped(tmp_path):
    """Pre-fix the verbatim postfixed id escaped HOSTNAME_DEPENDENT_CHECKS, so
    only the text arm caught it — and only when the phrase was present. Post-fix
    the stripped id hits the id arm even without the phrase."""
    events = _events(tmp_path, [
        _rec("cert_trust <hostCert#1>", finding="some other text entirely",
             ip="1.2.3.4/1.2.3.4"),
    ])
    assert events == []


def test_bare_ip_record_with_the_phrase_stays_dropped(tmp_path):
    # the text arm (unchanged, pre-existing) — the real-world form
    events = _events(tmp_path, [
        _rec("cert_trust", ip="1.2.3.4/1.2.3.4"),
    ])
    assert events == []