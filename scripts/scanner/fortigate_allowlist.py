#!/usr/bin/env python3
"""
fortigate_allowlist.py — Spec 221 ruling ③: the APPEND-FREE template classifier.

WHY (ruling ③, LOAD-BEARING)
----------------------------
On a ban-on-signature WAF, `nuclei -l urls.txt` is not safe: each template still
appends its OWN path per URL, so a `/.env` template fires `<crawled-url>/.env`
regardless of where the URL came from — re-tripping the exact content signature
crawl-first exists to avoid. `-exclude-tags` is a DENYLIST over an externally-
maintained, inconsistently-tagged set → it fails OPEN (a new/mistagged
signature-path template slips through). The only safe construction is an
ALLOWLIST of reviewed **append-free** templates → it fails CLOSED (only reviewed
templates run; anything unrecognised is excluded until reviewed).

This module is the reviewer, made deterministic. `is_append_free(template)`
decides whether a parsed nuclei template YAML fires ONLY the URL as-given
(headers / TLS / cookies / CORS / tech-detect / DNS — no path append, no attack
payload) or whether it appends a path / carries an injection payload that could
trip the signature.

CONSERVATISM: this fails CLOSED. Anything uncertain — raw requests, non-GET/HEAD
methods, injection-tagged templates, unrecognised protocol blocks — is classified
NOT append-free. Under-including a safe template only costs a little coverage;
over-including a signature-tripping one trips the ban this whole design avoids.

IMPORTANT — this is the CANDIDATE construction, not the final guarantee. Per
ruling ③ / Trap A/D the allowlist must still be VALIDATED empirically against the
FortiGate (fires ZERO enum paths, ZERO blocks) before it drives a real scan. A
per-request 403 is harmless now that rotation is proven (go/no-go 2026-09-04); the
enemy is the VOLUME ban. So this classifier serves both the strict-safe allowlist
AND the ban-rate-reducing exclude-list.

CLI (run in the scanner container where nuclei-templates + PyYAML exist):
    python3 fortigate_allowlist.py <templates_dir>
prints the append-free template IDs + a summary; emit to build the allowlist file.
"""
from __future__ import annotations

import re
import sys

# Injection / attack categories whose PAYLOAD can trip a content signature even
# on the root URL (run #4: `/?q=<script>alert(1)>` was blocked though its path
# was {{BaseURL}}). Append-free path is necessary but NOT sufficient — a template
# that puts an attack payload on the root still trips the signature.
INJECTION_TAGS = frozenset({
    "xss", "sqli", "sql-injection", "ssti", "ssrf", "lfi", "rfi", "rce",
    "crlf", "xxe", "redirect", "open-redirect", "injection", "command-injection",
    "fuzz", "fuzzing", "dast", "intrusive", "traversal", "path-traversal",
})

# Protocol blocks that cannot enumerate an HTTP content path (connect / query
# only) → inherently append-free for a content-path WAF.
SAFE_PROTOCOLS = frozenset({"ssl", "dns", "whois"})

# Protocol blocks we refuse to reason about → fail closed.
UNSAFE_PROTOCOLS = frozenset({
    "tcp", "network", "file", "headless", "javascript", "code", "flow",
})

# A request path that hits ONLY the URL as-given: {{BaseURL}} or {{RootURL}},
# optional trailing slash, optional ?query — but NO /path segment appended.
_BASE_ONLY = re.compile(r"^\{\{(BaseURL|RootURL)\}\}/?(\?.*)?$", re.IGNORECASE)

_SAFE_METHODS = frozenset({"GET", "HEAD", ""})  # "" = default (GET)


def _is_base_only_path(path: str) -> bool:
    return bool(_BASE_ONLY.match((path or "").strip()))


def _http_entries(template: dict) -> list[dict]:
    """nuclei uses `http:` (current) or `requests:` (legacy) for HTTP."""
    for key in ("http", "requests"):
        v = template.get(key)
        if isinstance(v, list):
            return [e for e in v if isinstance(e, dict)]
    return []


def _tags(template: dict) -> set[str]:
    info = template.get("info") or {}
    raw = info.get("tags", "")
    if isinstance(raw, str):
        parts = raw.split(",")
    elif isinstance(raw, list):
        parts = raw
    else:
        parts = []
    return {str(t).strip().lower() for t in parts if str(t).strip()}


def is_append_free(template: dict) -> tuple[bool, str]:
    """Classify a parsed nuclei template. Returns (append_free, reason).

    append_free=True  → fires only the URL as-given; safe against a content-path
                        signature WAF.
    append_free=False → appends a path, carries an attack payload, uses raw
                        requests / a non-GET method, or is an unrecognised shape.
                        Fails closed.
    """
    if not isinstance(template, dict):
        return False, "not_a_template_dict"

    tags = _tags(template)
    if tags & INJECTION_TAGS:
        return False, f"injection_tag:{sorted(tags & INJECTION_TAGS)[0]}"

    # Which protocol block(s) does the template use?
    protocols = [k for k in (
        "http", "requests", "ssl", "dns", "whois", "tcp", "network",
        "file", "headless", "javascript", "code", "flow",
    ) if k in template]

    if not protocols:
        return False, "no_recognised_protocol_block"
    if any(p in UNSAFE_PROTOCOLS for p in protocols):
        return False, f"unsafe_protocol:{next(p for p in protocols if p in UNSAFE_PROTOCOLS)}"

    # Pure connect/query protocols (ssl/dns/whois) with NO http block → safe.
    if all(p in SAFE_PROTOCOLS for p in protocols):
        return True, f"safe_protocol:{'+'.join(protocols)}"

    # HTTP path analysis.
    entries = _http_entries(template)
    if not entries:
        return False, "http_declared_but_no_entries"

    for e in entries:
        if e.get("raw"):
            return False, "raw_request"  # raw can encode any path/payload
        method = str(e.get("method", "")).strip().upper()
        if method not in _SAFE_METHODS:
            return False, f"unsafe_method:{method}"
        paths = e.get("path")
        if not isinstance(paths, list) or not paths:
            return False, "no_path_list"
        for p in paths:
            if not _is_base_only_path(str(p)):
                return False, f"appends_path:{str(p)[:60]}"

    return True, "http_base_only_get"


def classify_dir(templates_dir: str) -> tuple[list[str], dict[str, int]]:
    """Walk a nuclei-templates dir, classify each .yaml, return
    (append_free_ids, reason_counts). PyYAML imported lazily so the pure
    classifier is testable without it."""
    import pathlib
    import yaml  # lazy — only the CLI path needs it

    allow: list[str] = []
    reasons: dict[str, int] = {}
    for path in pathlib.Path(templates_dir).rglob("*.yaml"):
        try:
            doc = yaml.safe_load(path.read_text(errors="ignore"))
        except Exception:
            reasons["unparseable"] = reasons.get("unparseable", 0) + 1
            continue
        if not isinstance(doc, dict):
            continue
        ok, reason = is_append_free(doc)
        key = reason.split(":", 1)[0]
        reasons[key] = reasons.get(key, 0) + 1
        if ok:
            tid = (doc.get("id") or path.stem)
            allow.append(str(tid))
    return sorted(set(allow)), reasons


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: fortigate_allowlist.py <nuclei-templates-dir>", file=sys.stderr)
        return 2
    allow, reasons = classify_dir(argv[1])
    print(f"# append-free allowlist — {len(allow)} templates")
    print(f"# reason histogram: {dict(sorted(reasons.items(), key=lambda kv: -kv[1]))}",
          file=sys.stderr)
    for tid in allow:
        print(tid)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
