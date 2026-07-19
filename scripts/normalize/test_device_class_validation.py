"""
test_device_class_validation.py — 4.7 R6 evidence-class enforcement guards
(EMPIRICAL_EVIDENCE_TAXONOMY, Obsidian 145, 2026-07-18).

The registry two-bar test (vendor_identifying vs presence_only) is only worth
anything if it's machine-enforced — a YAML comment lets the next contributor put
`family: fortinet_suspected` right back. These tests pin the enforcement:
  * the LIVE registry satisfies the schema (and stays weight-consistent), and
  * the validator actually REJECTS each way a row can smuggle an inferred brand.
Pure/static: no DB, no network. Runs in the normal pytest sweep = the CI layer
4.7 asked for, on top of the load-time raise in load_fingerprints().
"""
import pytest

import derive_device_class as d


def test_live_registry_passes_full_validation():
    """The shipped device_fingerprints.yaml is schema-clean AND every signal is a
    ratified weight (rule 6). validate_registry() raises structurally or returns
    weight errors; either is a failure."""
    assert d.validate_registry() == []


def test_live_registry_loads_without_raising():
    """load_fingerprints() runs the structural validator and raises on any bad
    row — so a clean load is itself the load-time guard proving the registry ok."""
    fps = d.load_fingerprints()
    assert fps, "registry unexpectedly empty"
    assert all("evidence_class" in fp for fp in fps), "every row must declare evidence_class"


def test_ip_in_vendor_mgmt_range_signal_type_is_gone():
    """4.7 R1: the insider signal type is deleted from BOTH the registry rows and
    the threshold weights — not merely neutered — so it can't be reused."""
    fps = d.load_fingerprints()
    assert not any(fp.get("signal") == "ip_in_vendor_mgmt_range" for fp in fps)
    th = d.load_thresholds()
    assert "ip_in_vendor_mgmt_range" not in th["weight"]


def test_no_row_carries_an_inferred_family_field():
    """The exact bug that started this: `family: *_suspected` inferred a brand.
    No surviving row may carry a `family` key in vendor_product."""
    for fp in d.load_fingerprints():
        assert "family" not in (fp.get("vendor_product") or {}), fp.get("signal")


def test_presence_only_row_may_not_name_a_vendor():
    bad = [{"signal": "s", "observation": "o", "device_class": "waf",
            "evidence_class": "presence_only",
            "vendor_product": {"vendor": "Fortinet", "product": "FortiWeb"}}]
    errs = d.validate_fingerprints(bad)
    assert errs and "presence_only" in errs[0]


def test_presence_only_row_may_carry_operator_metadata():
    """V4 default: managed_by (e.g. SCI = the owner naming itself) is operator
    metadata, allowed under presence_only — it is not a vendor claim."""
    ok = [{"signal": "s", "observation": "ssh_banner", "device_class": "edge_firewall",
           "evidence_class": "presence_only", "vendor_product": {"managed_by": "SCI"}}]
    assert d.validate_fingerprints(ok) == []


def test_vendor_identifying_row_must_actually_name_a_vendor():
    bad = [{"signal": "s", "observation": "o", "device_class": "waf",
            "evidence_class": "vendor_identifying", "vendor_product": {}}]
    errs = d.validate_fingerprints(bad)
    assert errs and "vendor_identifying" in errs[0]


def test_missing_evidence_class_is_rejected():
    bad = [{"signal": "s", "observation": "o", "device_class": "waf"}]
    errs = d.validate_fingerprints(bad)
    assert errs and "evidence_class" in errs[0]


def test_bad_device_class_is_rejected():
    bad = [{"signal": "s", "observation": "o", "device_class": "firewall_thing",
            "evidence_class": "presence_only", "vendor_product": {}}]
    errs = d.validate_fingerprints(bad)
    assert any("device_class" in e for e in errs)


def test_unknown_signal_flagged_only_when_weights_supplied():
    """Rule 6 needs the weight map; without it we don't false-flag (structural
    load path has no thresholds), with it an off-registry signal is caught."""
    row = [{"signal": "totally_made_up", "observation": "o", "device_class": "waf",
            "evidence_class": "presence_only", "vendor_product": {}}]
    assert d.validate_fingerprints(row) == []                      # no weight map -> silent
    assert d.validate_fingerprints(row, {"real_sig": "high"})      # weight map -> flagged


def test_load_fingerprints_raises_on_broken_registry(tmp_path):
    """Load-time guard: a registry with a bad row makes load_fingerprints RAISE,
    so the classifier refuses to start rather than mislabel an asset."""
    p = tmp_path / "bad.yaml"
    p.write_text(
        "fingerprints:\n"
        "  - signal: s\n"
        "    observation: o\n"
        "    device_class: waf\n"
        "    evidence_class: vendor_identifying\n"
        "    vendor_product: {}\n"
    )
    with pytest.raises(d.RegistryValidationError):
        d.load_fingerprints(p)
