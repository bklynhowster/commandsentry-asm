"""Tests for the role matrix loader + selection (P1).

Run:  pytest scripts/scanner/test_matrix_loader.py -v
"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from matrix_loader import MatrixError, load_matrix, match_roles  # noqa: E402


# ── the shipped matrix must load + validate clean ───────────────────────
def test_real_matrix_loads_and_validates():
    m = load_matrix()
    assert m["version"] == 1
    assert "web-spa" in m["roles"] and "rdp" in m["roles"] and "db" in m["roles"]
    assert m["baseline"]["staleness_hours"] == 72
    assert m["unmatched_port"]["base_severity"] == "MODERATE"


def _write(tmp_path, body: str) -> str:
    p = tmp_path / "roles.yaml"
    p.write_text(textwrap.dedent(body))
    return str(p)


_MIN_HEAD = """\
version: 1
severity_levels: [CRITICAL, HIGH, MODERATE, LOW, INFO]
engines: [http, network, none]
baseline: {read_from_discovery: [ports], fresh: [tls_audit], staleness_hours: 72, light_cache_only: true}
unmatched_port: {engine: network, base_severity: MODERATE}
roles:
"""


# ── invalid shapes must FAIL LOUD (4.7 fleet-scale #4) ───────────────────
def test_missing_file_fails_loud(tmp_path):
    with pytest.raises(MatrixError, match="not found"):
        load_matrix(str(tmp_path / "nope.yaml"))


def test_bad_version_fails_loud(tmp_path):
    p = _write(tmp_path, "version: 2\nseverity_levels: [LOW]\nengines: [http]\n")
    with pytest.raises(MatrixError, match="version"):
        load_matrix(p)


def test_role_with_bad_engine_fails_loud(tmp_path):
    p = _write(tmp_path, _MIN_HEAD + "  x: {engine: quantum, match: {http: true}}\n")
    with pytest.raises(MatrixError, match="engine"):
        load_matrix(p)


def test_role_with_bad_severity_fails_loud(tmp_path):
    p = _write(tmp_path, _MIN_HEAD + "  x: {engine: network, match: {ports: [3389]}, base_severity: SPICY}\n")
    with pytest.raises(MatrixError, match="severity"):
        load_matrix(p)


def test_role_without_match_fails_loud(tmp_path):
    p = _write(tmp_path, _MIN_HEAD + "  x: {engine: http}\n")
    with pytest.raises(MatrixError, match="match"):
        load_matrix(p)


def test_missing_unmatched_port_fails_loud(tmp_path):
    body = "version: 1\nseverity_levels: [LOW]\nengines: [http]\n" \
           "baseline: {read_from_discovery: [ports], fresh: [tls_audit], staleness_hours: 72, light_cache_only: true}\n" \
           "roles: {x: {engine: http, match: {http: true}}}\n"
    with pytest.raises(MatrixError, match="unmatched_port"):
        load_matrix(_write(tmp_path, body))


# ── match_roles: the per-host selection (role is a vector) ───────────────
M = load_matrix()


def test_rdp_port_matches_rdp_only():
    matched, unmatched = match_roles(M, [3389])
    assert matched == ["rdp"] and unmatched == []


def test_db_port_matches_db():
    matched, _ = match_roles(M, [5432])
    assert matched == ["db"]


def test_spa_fingerprint_picks_web_spa():
    matched, unmatched = match_roles(M, [443], ["nginx", "react", "unpkg"])
    assert "web-spa" in matched and "web-generic" not in matched
    assert unmatched == []          # 443 covered by the web role


def test_wordpress_fingerprint_wins_over_generic():
    matched, _ = match_roles(M, [443], ["wordpress", "php"])
    assert "wordpress" in matched
    assert "web-spa" not in matched and "web-generic" not in matched  # exactly one web role


def test_http_no_specific_fingerprint_falls_to_web_generic():
    matched, _ = match_roles(M, [80], ["nginx"])
    assert matched == ["web-generic"]


def test_multi_service_host_unions_packs():
    # DC-ish: ssh + smb + rdp + https-with-spa → union of all, nothing unmatched.
    matched, unmatched = match_roles(M, [22, 445, 3389, 443], ["react"])
    assert set(matched) == {"ssh", "smb", "rdp", "web-spa"}
    assert unmatched == []


def test_unmatched_port_is_surfaced_not_swallowed():
    # 1234 has no matrix row → surfaced for the fallback, never silent.
    matched, unmatched = match_roles(M, [1234])
    assert matched == [] and unmatched == [1234]


def test_dead_kind_marks_but_skips_web():
    # dead host serving http → marker + NO web packs; http ports not "unmatched".
    matched, unmatched = match_roles(M, [80, 443], ["react"], kind="dead")
    assert matched == ["dead"] and unmatched == []


def test_dead_kind_STILL_covers_open_network_port():
    # 4.7 ruling 2 — THE silent-narrowing guard: a 'dead'-labelled host with a
    # live 3389 must STILL match rdp (mis-derivation can't drop the exposure).
    matched, unmatched = match_roles(M, [3389, 80], ["react"], kind="dead")
    assert "rdp" in matched          # network coverage survives the dead label
    assert "web-spa" not in matched  # web depth is what the label removes
    assert "dead" in matched and unmatched == []


def test_dual_stack_host_unions_web_roles():
    # 4.7 ruling 2 — WordPress site with a React admin: BOTH web roles, so the
    # SPA tools (retire.js/trufflehog) aren't lost on the WP host.
    matched, _ = match_roles(M, [443], ["wordpress", "react"])
    assert "wordpress" in matched and "web-spa" in matched
    assert "web-generic" not in matched


def test_port_collision_fails_loud(tmp_path):
    # Two roles claiming 3389 → LOUD (this is the guard that catches a 9200-style clash).
    body = _MIN_HEAD + \
        "  a: {engine: network, match: {ports: [3389]}, base_severity: HIGH}\n" \
        "  b: {engine: network, match: {ports: [3389]}, base_severity: HIGH}\n"
    with pytest.raises(MatrixError, match="claimed by both"):
        load_matrix(_write(tmp_path, body))


def test_empty_discovery_does_not_crash():
    # No ports, no fingerprint → no roles, no unmatched. Fail-safe for empty reads.
    assert match_roles(M, [], []) == ([], [])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
