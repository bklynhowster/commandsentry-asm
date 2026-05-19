"""
sslyze.py — Parse sslyze JSON output into FindingEvents.

sslyze emits a deeply-nested structure under `server_scan_results[].scan_result`,
with one subkey per test category (heartbleed, robot, tls_compression, etc.).

Strategy: focus on high-signal vuln checks. testssl already handles cipher
enumeration, so we don't duplicate that here. We surface findings only when
sslyze reports an actual problem (vulnerable, weak protocol offered,
missing security control).

Tests we emit findings for:
- heartbleed (CVE-2014-0160) — HIGH if vulnerable
- openssl_ccs_injection (CVE-2014-0224) — HIGH if vulnerable
- robot — HIGH if vulnerable (ROBOT attack)
- session_renegotiation insecure — MODERATE if vulnerable to renegotiation DoS
- tls_compression — MODERATE if CRIME-vulnerable (TLS compression enabled)
- ssl_2_0_cipher_suites accepted — HIGH (deprecated, broken)
- ssl_3_0_cipher_suites accepted — HIGH (POODLE)
- tls_1_0_cipher_suites accepted — LOW (deprecated by PCI-DSS, IETF)
- tls_1_1_cipher_suites accepted — LOW (deprecated by PCI-DSS, IETF)
- tls_1_3 NOT offered (but TLS 1.2 is) — LOW (modernization gap)
- elliptic_curves — INFO if no curves supported

Skipping for now (testssl handles or low signal):
- per-cipher enumeration
- certificate_info detail (cert chain analysis is its own deep problem)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .common import (
    canonical_asset_id,
    is_fqdn_in_scope,
    FindingEvent,
    infer_asset_id,
    relative_to_scan_root,
    stable_finding_id,
    to_utc_iso,
)


def _bool(value) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes", "1"): return True
        if v in ("false", "no", "0"): return False
    return None


def _has_accepted_ciphers(suite_result: Optional[dict]) -> bool:
    if not isinstance(suite_result, dict):
        return False
    accepted = suite_result.get("accepted_cipher_suites") or []
    return bool(accepted)


def _server_location(srv: dict) -> tuple[Optional[str], Optional[str], Optional[int]]:
    """Return (hostname, ip, port) from sslyze server_location."""
    loc = srv.get("server_location") or {}
    hostname = loc.get("hostname") or None
    ip = loc.get("ip_address") or None
    port = loc.get("port")
    try:
        port = int(port) if port is not None else None
    except (TypeError, ValueError):
        port = None
    return (hostname, ip, port)


def _emit(asset_id, scan_id, observed_at, evidence_path, hostname, ip, port,
          test_id, title, severity, category, description, cwe_list, cve_list) -> FindingEvent:
    host = hostname or ip or asset_id
    matched_at = f"https://{host}:{port}" if port else f"https://{host}"
    # Asset = the FQDN tested, not the target-dir apex
    event_asset_id = canonical_asset_id(hostname) if is_fqdn_in_scope(hostname, asset_id) else canonical_asset_id(asset_id)
    return FindingEvent(
        # Same canonical-input rule as testssl.py — see that file's comment
        # block. Raw host varies between scans; event_asset_id + port is
        # the stable identity.
        finding_id=stable_finding_id(event_asset_id, "sslyze", test_id, f"port-{port}"),
        asset_id=event_asset_id,
        scan_id=scan_id,
        source="sslyze",
        title=title,
        severity=severity,
        category=category,
        observed_at=observed_at,
        matched_at=matched_at,
        description=description,
        cve=cve_list,
        cwe=cwe_list,
        references=[],
        raw_excerpt=None,
        evidence_paths=[evidence_path],
        subdomain=hostname,
        host_ip=ip,
        port=port,
        protocol="https" if port in (443, None) else "tcp",
    )


def parse_sslyze_file(
    json_path: Path,
    asset_id: str,
    scan_id: str,
    scan_root: Path,
    fallback_observed_at: Optional[str] = None,
) -> list[FindingEvent]:
    if not json_path.is_file():
        return []
    try:
        data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []

    rel_evidence = relative_to_scan_root(json_path, scan_root)
    observed_at = to_utc_iso(fallback_observed_at) or fallback_observed_at or ""

    servers = data.get("server_scan_results") or []
    events: list[FindingEvent] = []

    for srv in servers:
        sr = srv.get("scan_result") or {}
        if not sr:
            continue
        hostname, ip, port = _server_location(srv)

        # ─── deprecated/broken protocols (SSLv2, SSLv3) ──────────────────
        ssl2 = (sr.get("ssl_2_0_cipher_suites") or {}).get("result")
        if _has_accepted_ciphers(ssl2):
            events.append(_emit(asset_id, scan_id, observed_at, rel_evidence, hostname, ip, port,
                "sslv2_accepted",
                "SSLv2 cipher suites accepted (deprecated, broken)",
                "HIGH", "tls",
                "Server accepts SSLv2 cipher suites. SSLv2 has been deprecated since 2011 (RFC 6176) and is cryptographically broken.",
                [310, 326], []))

        ssl3 = (sr.get("ssl_3_0_cipher_suites") or {}).get("result")
        if _has_accepted_ciphers(ssl3):
            events.append(_emit(asset_id, scan_id, observed_at, rel_evidence, hostname, ip, port,
                "sslv3_accepted",
                "SSLv3 cipher suites accepted (POODLE-vulnerable)",
                "HIGH", "tls",
                "Server accepts SSLv3 cipher suites. SSLv3 is vulnerable to POODLE (CVE-2014-3566) and deprecated by RFC 7568.",
                [310, 326], ["CVE-2014-3566"]))

        # ─── deprecated TLS 1.0 / 1.1 ────────────────────────────────────
        tls10 = (sr.get("tls_1_0_cipher_suites") or {}).get("result")
        if _has_accepted_ciphers(tls10):
            events.append(_emit(asset_id, scan_id, observed_at, rel_evidence, hostname, ip, port,
                "tls10_accepted",
                "TLS 1.0 cipher suites accepted (deprecated)",
                "LOW", "tls",
                "Server accepts TLS 1.0 cipher suites. TLS 1.0 is deprecated by RFC 8996 and PCI-DSS.",
                [326], []))

        tls11 = (sr.get("tls_1_1_cipher_suites") or {}).get("result")
        if _has_accepted_ciphers(tls11):
            events.append(_emit(asset_id, scan_id, observed_at, rel_evidence, hostname, ip, port,
                "tls11_accepted",
                "TLS 1.1 cipher suites accepted (deprecated)",
                "LOW", "tls",
                "Server accepts TLS 1.1 cipher suites. TLS 1.1 is deprecated by RFC 8996 and PCI-DSS.",
                [326], []))

        # TLS 1.2 offered but 1.3 not — modernization gap
        tls12 = (sr.get("tls_1_2_cipher_suites") or {}).get("result")
        tls13 = (sr.get("tls_1_3_cipher_suites") or {}).get("result")
        if _has_accepted_ciphers(tls12) and not _has_accepted_ciphers(tls13):
            events.append(_emit(asset_id, scan_id, observed_at, rel_evidence, hostname, ip, port,
                "tls13_not_offered",
                "TLS 1.3 not offered (server only supports up to TLS 1.2)",
                "LOW", "tls",
                "Server supports TLS 1.2 but does not offer TLS 1.3. TLS 1.3 provides better security and performance.",
                [326], []))

        # ─── vuln checks ─────────────────────────────────────────────────
        heartbleed = (sr.get("heartbleed") or {}).get("result") or {}
        if _bool(heartbleed.get("is_vulnerable_to_heartbleed")) is True:
            events.append(_emit(asset_id, scan_id, observed_at, rel_evidence, hostname, ip, port,
                "heartbleed",
                "Heartbleed (CVE-2014-0160) — server is vulnerable",
                "CRITICAL", "tls",
                "Server is vulnerable to Heartbleed. Memory disclosure vulnerability in OpenSSL <1.0.1g.",
                [125], ["CVE-2014-0160"]))

        ccs = (sr.get("openssl_ccs_injection") or {}).get("result") or {}
        if _bool(ccs.get("is_vulnerable_to_ccs_injection")) is True:
            events.append(_emit(asset_id, scan_id, observed_at, rel_evidence, hostname, ip, port,
                "ccs_injection",
                "OpenSSL CCS Injection (CVE-2014-0224) — server is vulnerable",
                "HIGH", "tls",
                "Server is vulnerable to OpenSSL CCS Injection. Allows MITM to decrypt traffic.",
                [310], ["CVE-2014-0224"]))

        robot = (sr.get("robot") or {}).get("result") or {}
        robot_status = (robot.get("robot_result") or "").upper()
        if "VULNERABLE" in robot_status and "NOT" not in robot_status:
            events.append(_emit(asset_id, scan_id, observed_at, rel_evidence, hostname, ip, port,
                "robot",
                "ROBOT — server is vulnerable to Return of Bleichenbacher's Oracle Threat",
                "HIGH", "tls",
                f"ROBOT vulnerability detected. Status: {robot_status}. Allows decryption of RSA-encrypted traffic.",
                [203], ["CVE-2017-13099"]))

        reneg = (sr.get("session_renegotiation") or {}).get("result") or {}
        if _bool(reneg.get("is_vulnerable_to_client_renegotiation_dos")) is True:
            events.append(_emit(asset_id, scan_id, observed_at, rel_evidence, hostname, ip, port,
                "renegotiation_dos",
                "Insecure client-initiated TLS renegotiation",
                "MODERATE", "tls",
                "Server allows client-initiated renegotiation, enabling DoS amplification (CVE-2011-1473).",
                [400], ["CVE-2011-1473"]))

        compr = (sr.get("tls_compression") or {}).get("result") or {}
        if _bool(compr.get("supports_compression")) is True:
            events.append(_emit(asset_id, scan_id, observed_at, rel_evidence, hostname, ip, port,
                "tls_compression",
                "TLS compression enabled (CRIME-vulnerable)",
                "MODERATE", "tls",
                "Server supports TLS compression. Vulnerable to CRIME attack (CVE-2012-4929).",
                [310], ["CVE-2012-4929"]))

    return events


def parse(target_entry: dict, scan_entry: dict, scan_root: Path) -> list[FindingEvent]:
    target = target_entry["target"]
    asset_id = infer_asset_id(target)

    scan_run_dir = scan_entry["scan_run_dir"]
    if scan_run_dir.startswith("(target-root") or scan_run_dir == "_target_root":
        scan_id = f"{target}__synthetic_root"
    else:
        scan_id = f"{target}__{scan_run_dir}"

    scan_run_abs = Path(scan_entry["absolute_path"])
    fallback_ts = scan_entry.get("inferred_started_at")

    events: list[FindingEvent] = []
    for tool in scan_entry.get("tools_detected", []):
        if tool.get("parser") != "sslyze":
            continue
        for rel_file in tool.get("files", []):
            events.extend(
                parse_sslyze_file(
                    json_path=scan_run_abs / rel_file,
                    asset_id=asset_id,
                    scan_id=scan_id,
                    scan_root=scan_root,
                    fallback_observed_at=fallback_ts,
                )
            )
    return events
