#!/usr/bin/env python3
"""
detect_infra_artifacts.py — REPORT-ONLY detector for infrastructure-artifact
findings. 4.7 ruling Q1 (Obsidian 163), 2026-07-25.

    THIS SCRIPT HAS ZERO WRITE AUTHORITY. It issues SELECTs and prints a
    report. It does not UPDATE, INSERT, or DELETE anything, ever. That is
    the ruling, not an implementation gap.

WHY A DETECTOR AND NOT AN AUTOCLOSE RULE
Two artifact classes were root-caused and fixed AT SOURCE on 2026-07-24:
  * cert_trust (CWE-295) emitted because testssl ran against a bare IP
    literal, where no certificate can match the "supplied URI";
  * naabu phantom open-ports, where a cloud edge SYN-ACKs arbitrary ports so
    every heavy scan invented a different random port set.
Both fixes are live and verified. Empirical recurrence is ZERO.

4.7 Q1: an autoclose rule firing against a zero-population problem is by
definition unnecessary automation, and auto-closing HIGH findings carries the
largest blast radius in the system. The infra-artifact class also has genuine
unknown-unknowns — what OTHER tools produce nonsense against cloud edges or
IP-typed assets? The right response to unknown-unknowns is INSTRUMENTATION,
not codified action. So: detect and report; a human dispositions.

SHIP BOUNDARY (Q1, the biggest flagged risk)
Do NOT wire this detector's output to a writer "as phase 2." That path keeps
every risk of standing autoclose while looking conservative. If autoclose is
ever justified, it is justified from scratch against
docs/autoclose_rule_template.md — not as an extension of this script.

REVISIT TRIGGER (Q1)
Steady state is ZERO candidates and NO report. If this reports non-zero for
4 CONSECUTIVE cycles, that is the empirical signal that recurrence is no
longer zero: either a source fix regressed, or a new pattern emerged.
Escalate to a standing-rule design review with the fresh data. The
--state-file tracks the streak so the trigger is measured, not remembered.

USAGE
    detect_infra_artifacts.py --dsn "$SUPABASE_DSN" [--report out.md]
                              [--state-file .detector_state.json]
Exit: 0 always when the query succeeded (candidates are INFORMATION, not
failure). 2 on usage/DB error — a broken detector must be loud, because a
detector that silently reports zero is worse than no detector (Q6).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from gate_retry import (  # noqa: E402
    PROGRESS,
    TransportFailure,
    Verdict,
    run_with_transport_retry,
)

REVISIT_TRIGGER_CYCLES = 4

# ── Signals ───────────────────────────────────────────────────────────────
# Exact-match predicates only (Q4). Every one keys on a STRUCTURED column —
# check_id / source / asset_type / device_class — never on finding text.
# The 18-of-25 over-match that prompted Q4 came from `finding_id ILIKE
# '%cert_trust%'`, which also swept in the unrelated (and accurate)
# cert_trust_wildcard. Note `= 'cert_trust'` below, not LIKE.

CURATED_CLOUD_PORTS = (80, 443, 8080, 8443)

# ── SERVICE-ANSWERED TAGS — the hard exclusion (added 2026-07-26) ─────────
#
# A finding carrying any of these tags means the scanner got a real RESPONSE
# from that port: a protocol banner, a TLS handshake, or an auth prompt.
# Something answered. That is affirmative evidence of a LIVE SERVICE and it
# directly contradicts "phantom", which by definition is a port that answers
# the scanner and nothing else.
#
# WHY THIS EXISTS — it cost us. On 2026-07-26 the first disposition closed 5
# GENUINELY OPEN mail services on email.commandcompanies.com (110 POP3, 143
# IMAP, 587 submission, 993 IMAPS, 995 POP3S — a real Microsoft O365
# endpoint) as naabu phantoms. The rows were tagged smtp / imap / auth / tls /
# banner the whole time. Reverted via the disposition tag handle.
#
# The predicate's flaw was structural, not incidental: "any non-curated port
# on a cloud-classified asset is phantom" holds for a WEB asset behind a CDN.
# It is false for a MAIL host, where non-web ports are the entire point — and
# an O365 endpoint is cloud-classified precisely because it is cloud.
#
# So the fix is not a hostname special-case (the next one won't be mail).
# It is: never call a port phantom when the evidence says a service replied.
# This is a candidate SUPPRESSOR, not a scorer — a single matching tag drops
# the row, and it errs toward under-reporting. That is the correct direction:
# a missed candidate costs a human one extra look; a wrong candidate is how a
# real exposed service gets closed as noise.
SERVICE_ANSWERED_TAGS = ("banner", "auth", "tls")

SIGNALS = {
    # cert_trust on an IP-typed asset: a certificate can never match a bare
    # IP literal, so the check is a category error rather than a finding.
    "cert_trust_on_ip_asset": """
        SELECT f.finding_id, f.asset_id, f.severity, f.current_status, f.title
          FROM public.findings f
          JOIN public.assets  a ON a.asset_id = f.asset_id
         WHERE f.current_status IN ('detected','open','confirmed','regressed')
           AND f.source = 'testssl'
           AND split_part(f.finding_id, ':', 3) = 'cert_trust'
           AND a.type IN ('ip','ip_range')
    """,
    # naabu open-port on a cloud-fronted asset, outside the curated set. The
    # cloud edge answers arbitrary ports; only the curated ones are real.
    "naabu_phantom_cloud_edge": """
        SELECT f.finding_id, f.asset_id, f.severity, f.current_status, f.title
          FROM public.findings f
          JOIN public.assets  a ON a.asset_id = f.asset_id
         WHERE f.current_status IN ('detected','open','confirmed','regressed')
           AND f.finding_id LIKE '%%naabu-open-port-%%'
           AND a.device_class IN ('cloud_endpoint','cdn','waf')
           AND COALESCE(
                 NULLIF(substring(f.finding_id from 'open-port-([0-9]+)-tcp'), '')::int,
                 -1
               ) NOT IN %(curated)s
           -- A service answered on this port => NOT a phantom. See
           -- SERVICE_ANSWERED_TAGS above; this clause is what stops the
           -- 2026-07-26 mail-port mistake recurring.
           AND NOT (COALESCE(f.tags, '{}') && %(answered)s::text[])
    """,
}


def _collect(psycopg, dsn) -> Verdict:
    """One attempt. SELECTs only."""
    try:
        conn = psycopg.connect(dsn, connect_timeout=PROGRESS.connect_timeout_s)
    except Exception as e:  # noqa
        raise TransportFailure(repr(e)) from e
    try:
        out = []
        with conn.cursor() as cur:
            # Bind ONLY the placeholders a given signal actually references.
            # psycopg's tolerance for unused keys in a params dict is not
            # something to rely on unverified — and an unused-param error
            # would surface as a detector that reports zero, which is exactly
            # the silent-success trap (Q6) this script exists to avoid.
            all_params = {
                "curated": CURATED_CLOUD_PORTS,
                "answered": list(SERVICE_ANSWERED_TAGS),
            }
            for name, sql in SIGNALS.items():
                params = {k: v for k, v in all_params.items()
                          if f"%({k})s" in sql}
                cur.execute(sql, params or None)
                for r in cur.fetchall():
                    out.append({
                        "signal": name,
                        "finding_id": r[0], "asset_id": r[1],
                        "severity": r[2], "current_status": r[3], "title": r[4],
                    })
        return Verdict(True, "collected", payload=out)
    except Exception as e:  # noqa
        raise TransportFailure(repr(e)) from e
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _render(cands) -> str:
    by_sig = Counter(c["signal"] for c in cands)
    by_sev = Counter(c["severity"] for c in cands)
    lines = [
        "# Infra-artifact candidates — REVIEW QUEUE (report only)",
        "",
        "These are **candidates**, not conclusions. Nothing has been closed. A human "
        "verifies each one and dispositions it through the normal manual flow.",
        "",
        f"**{len(cands)} candidate(s)** — by signal: "
        + ", ".join(f"`{k}` {v}" for k, v in by_sig.items())
        + " — by severity: "
        + ", ".join(f"{k} {v}" for k, v in by_sev.items()),
        "",
        "| signal | severity | status | asset | finding_id |",
        "|---|---|---|---|---|",
    ]
    for c in sorted(cands, key=lambda x: (x["signal"], x["asset_id"])):
        lines.append(
            f"| {c['signal']} | {c['severity']} | {c['current_status']} "
            f"| {c['asset_id']} | `{c['finding_id']}` |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", default=os.environ.get("SUPABASE_DSN") or os.environ.get("DSN"))
    ap.add_argument("--report", default=None, help="write markdown here when non-empty")
    ap.add_argument("--state-file", default=None, help="tracks the consecutive-cycle streak")
    args = ap.parse_args()
    if not args.dsn:
        print("::error::no DSN (pass --dsn or set SUPABASE_DSN)", file=sys.stderr)
        return 2
    try:
        import psycopg
    except ImportError:
        print("::error::psycopg (psycopg3) required", file=sys.stderr)
        return 2

    v = run_with_transport_retry(
        lambda: _collect(psycopg, args.dsn),
        PROGRESS,
        on_retry=lambda n, e, b: print(
            f"::warning::detector attempt {n}/{PROGRESS.attempts} failed ({e}) — retrying in {b}s",
            file=sys.stderr),
    )
    if v.unreadable:
        # A detector that can't read must NOT report "0 candidates, all clear" —
        # that is the silent-success trap (Q6) in its purest form.
        print(f"::error::detector UNREADABLE after {v.attempts} attempts — "
              f"NOT a clean result. Last error: {v.payload!r}", file=sys.stderr)
        return 2

    cands = v.payload

    streak = 0
    if args.state_file:
        prev = {}
        if os.path.exists(args.state_file):
            try:
                prev = json.load(open(args.state_file))
            except Exception:
                prev = {}
        streak = (prev.get("consecutive_nonzero", 0) + 1) if cands else 0
        try:
            json.dump({"consecutive_nonzero": streak, "last_count": len(cands)},
                      open(args.state_file, "w"))
        except Exception as e:
            print(f"::warning::could not persist detector state: {e!r}", file=sys.stderr)

    if not cands:
        # Expected steady state post-source-fix. No report, no noise.
        print("infra-artifact detector: 0 candidates (expected steady state)")
        return 0

    report = _render(cands)
    print(report)
    if args.report:
        with open(args.report, "w") as fh:
            fh.write(report)

    if streak >= REVISIT_TRIGGER_CYCLES:
        print(f"::warning::REVISIT TRIGGER — {streak} consecutive cycles with candidates. "
              f"Recurrence is no longer zero. Escalate to a standing-rule design review "
              f"per docs/autoclose_rule_template.md.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
