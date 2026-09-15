#!/usr/bin/env python3
"""
synthesize_finding_descriptions.py — Phase F backfill

For each finding with a thin description (citation-only or empty), call
Claude to synthesize three canonical sections:

  description_synth — WHAT IS THIS?  (plain English explanation)
  impact            — WHAT COULD IT DO TO MY SYSTEM?
  remediation       — HOW DO I GET RID OF IT?

Writes results to the new columns (migration 20260522_phase_f_finding_synth_columns.sql)
and stamps description_source = 'ai_synthesized' so the portal knows the
provenance.

Usage:
  # Dry run on a single finding (prints the result, does NOT write)
  python scripts/backfill/synthesize_finding_descriptions.py \\
    --finding-id "commanddigital.com:manual:F-03" --dry-run

  # Real run on all HIGH + MODERATE-HIGH findings with thin descriptions
  python scripts/backfill/synthesize_finding_descriptions.py \\
    --severity HIGH MODERATE-HIGH

  # Real run on a specific finding
  python scripts/backfill/synthesize_finding_descriptions.py \\
    --finding-id "unimacgraphics.com:manual:F-01"

  # Re-synthesize even if already synthesized
  python scripts/backfill/synthesize_finding_descriptions.py \\
    --severity HIGH --force

Environment:
  ANTHROPIC_API_KEY        — required, from ~/.env or shell
  SUPABASE_URL             — required, defaults to the project URL
  SUPABASE_SERVICE_ROLE_KEY — required, from .env

Cost expectations:
  ~1.5-2k input tokens + ~0.5-1k output tokens per finding
  Claude Sonnet 4.5 pricing: $3/MTok in, $15/MTok out
  ~$0.02 per finding
  Initial run on ~40 HIGH/MOD-HIGH findings = ~$0.80
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ─── Lazy imports so --help works without deps installed ────────────────────
def _import_deps():
    global anthropic, create_client
    try:
        import anthropic  # noqa: F401
        from supabase import create_client  # noqa: F401
    except ImportError as e:
        print(f"Missing dependency: {e}", file=sys.stderr)
        print("Install with: pip install anthropic supabase python-dotenv", file=sys.stderr)
        sys.exit(2)


# ─── Config ─────────────────────────────────────────────────────────────────
MODEL_ID = "claude-sonnet-4-6"  # the production model (bumped 2026-05-27)
MAX_TOKENS = 2048
TEMPERATURE = 0.2  # low — we want consistent, factual output

DEFAULT_SUPABASE_URL = "https://hdygktppfvuspnumpfuq.supabase.co"

# Findings whose description is shorter than this AND matches a "citation"
# pattern are considered thin and qualify for synthesis.
THIN_DESCRIPTION_LEN = 200

# ─── Work-queue selection (2026-09-15, relay 139) ────────────────────────────
#
# ⛔ THE DEFECT THIS CLOSES — the worker could not see its own work queue.
#
# fetch_findings used `q.limit(5000)` with NO where-clause and NO order, then
# filtered for thin rows in Python. PostgREST clamps every response to the
# project's Data API `max_rows`, which is 1000. So the worker received an
# UNORDERED 1000-row sample of a 2511-row table and asked "are any of these
# thin?" Whether a thin row landed in the sample was an accident of heap
# order. Measured 2026-09-15 14:05 UTC on hdygktppfvuspnumpfuq:
#
#     findings total                               2511
#     thin (this predicate)                         232
#     rows returned for ?limit=5000    Content-Range 0-999/*   -> 1000
#     thin rows INSIDE that 1000-row response          0
#     thin rows via ordered pagination                232
#     last description_synthesized_at   2026-09-13 22:55:54
#
# That is why 52 consecutive runs were GREEN and each logged "No findings
# match." while the precheck in the SAME run logged "221 thin finding(s) —
# running synthesis." Neither step failed; they simply disagreed, and nothing
# was watching for the disagreement. See the contradiction guard below.
#
# ⚠ The comment removed from fetch_findings claimed the 500->5000 raise on
# 2026-05-28 was needed because "728 enriched out of 1000 total in DB". The
# 1000 was never the table size — it was this same cap. The identical defect
# was found and fixed for the portal's /findings page on 2026-06-04 (vault 63
# §57, 68 §12: "project db-max-rows=1000 overrode .limit(5000). Paginated via
# .range()"). This file had the same line and was not revisited.
#
# THE PREDICATE. Identical string in this constant and in the `QUERY=` line of
# .github/workflows/enrich-finding-descriptions.yml; a test asserts they are
# equal by reading the yml, because the precheck and the worker disagreeing is
# the whole defect.
#
# ⚠ WIDER THAN relay 139's ① SPECIFIED, deliberately — one extra clause,
# `description_source.not.in.(...)`. Without it the server-side predicate is
# not a superset of the Python inclusion test below: a row with all three
# columns NON-NULL but a THIN description and an unattested description_source
# passes `fully_synthesized == False`, is included by Python, and would be
# excluded server-side — i.e. filtering server-side could silently SHRINK the
# work queue. Measured before adding it: that population is 0 today
# (description_source is only ever 'ai_synthesized' 2279 / 'scanner' 232), and
# the widened predicate returns the SAME 232 rows, so it costs nothing now and
# closes the class. Fail-open, which is the discipline the yml's own comment
# at :128-131 states.
_ATTESTED_SOURCES = ("ai_synthesized", "ai_synthesized_reviewed", "manual")
THIN_PREDICATE = (
    "description_synth.is.null,"
    "impact.is.null,"
    "remediation.is.null,"
    f"description_source.not.in.({','.join(_ATTESTED_SOURCES)}),"
    # ⚠ 5th clause, added 2026-09-15 (relay 141). `not.in` is THREE-VALUED:
    # for description_source IS NULL, NOT (NULL IN (...)) evaluates to NULL, so
    # PostgREST EXCLUDES the row — while the Python test (`in {...}` on None ->
    # False -> not fully synthesized) INCLUDES it if the description is thin.
    # The one value the 4th clause cannot see is exactly the population it was
    # added to protect.
    #
    # Verified empirically rather than reasoned about, on a column that
    # actually has NULLs (description_source has none today):
    #     findings total                    2515
    #     impact IS NULL                     232
    #     impact not.in.(bogus)             2283      2283 + 232 == 2515
    # -> not.in excludes NULLs. Confirmed.
    #
    # description_source IS NULL rows today: 0 — same as the 4th clause's
    # population. Zero is a starting point, not a safety margin.
    "description_source.is.null"
)

# The column list, hoisted so the count probe and every page select exactly the
# same shape. Two copies of a column list is two things that can drift.
_SELECT_COLUMNS = (
    "finding_id, title, severity, asset_id, description, cve, cwe, category, source, "
    "tags, cvss_score, affected_component, affected_component_version, "
    "matched_url, frameworks, "
    "description_synth, description_source, description_synth_input_hash, "
    'impact, remediation, "references"'
)

# Page size for every paginated read. Must stay <= the project's max_rows or
# the loop's "a short page means we are done" termination test breaks: a
# clamped page looks short only by luck. 500 is half the 1000 cap, so a cap
# reduction would have to halve before this is wrong.
PAGE_SIZE = 500

# Transport retry (relay 034 ①, finally built). The GOAWAY at run #3421 and
# Prodex #1003's curl exit 35 are real but one-off; they are not the chronic
# defect above. Retry so a blip does not lose a page or a write.
RETRY_ATTEMPTS = 3
RETRY_BACKOFF_S = (2, 4, 8)


def _execute_with_retry(builder, what: str):
    """Run .execute() on a postgrest builder, retrying transport-level faults.

    Only transport errors are retried. A 4xx/5xx from PostgREST is a real
    answer and is allowed to raise — retrying a malformed query just makes the
    same mistake three times more slowly.
    """
    import httpx

    transient = (
        httpx.RemoteProtocolError,
        httpx.ConnectError,
        httpx.ReadTimeout,
        httpx.ReadError,
    )
    last: Exception | None = None
    for attempt in range(RETRY_ATTEMPTS):
        try:
            return builder.execute()
        except transient as e:
            last = e
            if attempt == RETRY_ATTEMPTS - 1:
                break
            delay = RETRY_BACKOFF_S[min(attempt, len(RETRY_BACKOFF_S) - 1)]
            print(
                f"  transport error on {what} "
                f"(attempt {attempt + 1}/{RETRY_ATTEMPTS}): {type(e).__name__}: {e} "
                f"— retrying in {delay}s",
                file=sys.stderr,
            )
            time.sleep(delay)
    raise last  # type: ignore[misc]


# ─── Prompt ─────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an IT security analyst writing internal vulnerability documentation for Command Companies — a multi-org enterprise that includes Command Digital (marketing/print), Command Financial, Command Marketing, Command Missouri, Unimac (Unimac Graphics), and SCI. Your audience is asset owners and their dev leads: technically competent but not security specialists. They need to understand what a finding actually means and what to do about it.

You will receive structured data about one vulnerability finding. Output a single JSON object with TWO halves:
  · prose sections (what is this, what could it do, how do I fix it)
  · structured extractions (cves, cwes, tags, cvss, affected component, suggested category, confidence)

The structured extractions feed the portal's Technical Detail card so chips appear even when the original scanner missed them. ONLY emit values you can defensibly derive from the input — do not invent CVEs or fabricate versions.

WRITING RULES (for the prose):
- Direct, specific, action-oriented. No marketing language, no hedging fluff.
- Plain English where possible. Use technical terms only when they're more precise than the alternative.
- Be concrete about consequences ("an attacker could dump the WordPress user table including hashed passwords") not generic ("could lead to data exposure").
- Name versions, components, and CVE IDs explicitly when they appear in the input.
- Tone: like a senior security analyst writing to a senior engineer they respect. Direct, not patronizing.
- LENGTH guidance: §1 = 2-4 sentences. §2 = 2-4 sentences. §3 = 4-7 numbered steps + an "Estimated remediation time" line + a "Priority" line for HIGH/CRITICAL severities.

CRITICAL — do NOT fabricate stack specifics:
- Use product/framework/daemon names ONLY when they appear in the input (title, description, scan excerpt, source scanner name, category, references). When the input says "manual_named", "info_disclosure", or names no specific software, do not guess at what daemon is running or what config file holds the setting.
- It is BETTER to be slightly vague and correct than confidently wrong. "On the FTP server, locate the TLS configuration — specific file or directive depends on the daemon (e.g., proftpd.conf, IIS FTP site bindings, GlobalScape EFT admin UI)" beats "edit proftpd.conf" when the input doesn't name the daemon.
- For WordPress findings the input is explicit — name WordPress, name the plugin/version, name WP Engine / Pressable when the asset history names them. For findings on internal-stack services where the input doesn't disclose the framework, stay generic.
- Generic phrasing is fine: "in your TLS configuration", "in the application's CSP middleware", "in the web server's TLS settings". Asset owners can translate generic guidance to their actual stack. They cannot reverse-engineer wrong specifics.
- Remediation steps in order: assess → backup → fix → verify → audit. Order matters more than naming.

EXTRACTION RULES (for the structured fields):
- "extracted_cves": every CVE-YYYY-NNNN that appears anywhere in title, description, references, or scan excerpt. Uppercase normalized. Empty array if none.
- "extracted_cwes": every CWE integer mentioned in source data AS WELL AS any CWE you can defensibly infer from the finding's nature. For example: a "password max length" finding maps to CWE-521 (Weak Password Requirements) even if the source data doesn't say so. Auth bypass → CWE-287. Hardcoded credentials → CWE-798. SQL injection → CWE-89. Common inferences are EXPECTED — config findings that have no CVE still have a CWE. Empty array only if you genuinely cannot map this finding to any CWE. Just the integers (e.g. [79, 521]).
- "extracted_tags": short keyword tags (lowercase, hyphenated) describing the finding. Pick 2–6 from this vocabulary or coin similar ones: wordpress, plugin, theme, outdated, vulnerable-component, cve-listed, tls, ssl, cipher, header, csp, hsts, cors, cookie, missing-header, xss, sqli, ssrf, idor, rce, lfi, redirect, auth, mfa, session, csrf, info-disclosure, banner, version-disclosure, directory-listing, debug, dns, dmarc, spf, dkim, takeover, typosquat, sast, sca, secret, deprecation. If the asset is hosted on a known platform (wp-engine, pressable, fortinet, iis, nginx, apache, dotnet, php) include that as a tag too.
- "cvss_score": numeric, 0.0–10.0, ONLY if a CVSS score appears in the input (e.g. "CVSS 6.1"). Null otherwise. Do NOT estimate from the severity bucket.
- "affected_component": the name of the vulnerable software/plugin/library/service (e.g. "Email Encoder Bundle", "Elementor", "nginx", "OpenSSL"). Null if the input doesn't name one.
- "affected_component_version": detected version string (e.g. "2.8.3", "1.24.0"). Null if not in input.
- "suggested_category": ONE of the valid enum values — sast, dast, sca, secret, recon, tls, headers, dns, email, auth, session, csrf, ssrf, xxe, xss, sqli, idor, rce, lfi, redirect, info_disclosure, takeover, typosquat, config, deprecation, supply_chain, other. Pick the BEST fit. An outdated WordPress plugin with known CVEs is "sca". A TLS cipher issue is "tls". A missing security header is "headers". An XSS finding is "xss". When unsure, "other".
- "matched_url": the specific URL / endpoint where the scanner reported this finding (e.g. "/wp-admin/admin-ajax.php", "/account/changepassword", "https://www.example.com/login"). If the source data names a URL, copy it. If it doesn't but the finding clearly targets a known endpoint per the description (e.g. "password change form" → "/account/changepassword"), infer it. Null only if there's no defensible URL.
- "frameworks": compliance framework references that this finding maps to. **YOU MUST emit BOTH explicit source-data mentions AND inferred mappings — not just one.** For Command Companies, the frameworks that always need consideration are: NIST 800-63B (auth/passwords), NIST CSF (any control), ISO 27001 (any control), SOC 2 (any control). HIPAA and PCI DSS only when health data or payment data is involved. **Default expectation: 2–4 framework chips per finding.** Output the framework identifier in the form Command actually uses, with the specific clause/control reference when applicable (e.g. "NIST 800-63B" not just "NIST"; "ISO 27001 A.9.4.3" not "ISO 27001"; "SOC 2 CC6.1" not "SOC 2"; "NIST CSF PR.AC-1" not "NIST CSF"; "HIPAA §164.308(a)(5)(ii)(D)" not "HIPAA"; "PCI DSS 8.3.6" not "PCI DSS"). Reference table for common inferences:
    · Password/credential requirements → ALWAYS: NIST 800-63B, NIST CSF PR.AC-1, ISO 27001 A.9.4.3, SOC 2 CC6.1
    · Access control/auth bypass → NIST CSF PR.AC, ISO 27001 A.9.1, SOC 2 CC6.1, NIST 800-53 AC-2
    · Encryption in transit (TLS) → NIST CSF PR.DS-2, ISO 27001 A.10.1, SOC 2 CC6.7, PCI DSS 4.1
    · Encryption at rest → NIST CSF PR.DS-1, ISO 27001 A.10.1, SOC 2 CC6.1
    · Logging/audit → NIST CSF DE.AE, ISO 27001 A.12.4, SOC 2 CC7.2
    · Vulnerability mgmt / patching → NIST CSF DE.CM-8, ISO 27001 A.12.6.1, SOC 2 CC7.1, PCI DSS 11.3.1
    · Security headers (CSP/HSTS) → NIST CSF PR.PT-3, ISO 27001 A.14.1, SOC 2 CC6.6
    · Input validation (XSS/SQLi/SSRF) → NIST CSF PR.IP-12, ISO 27001 A.14.2.5, OWASP ASVS V5
    · Information disclosure → NIST CSF PR.DS, ISO 27001 A.13.2, SOC 2 CC6.7
    · Insecure deserialization / RCE → NIST CSF PR.IP-12, ISO 27001 A.14.2.5, OWASP ASVS V5
  Empty array ONLY when the finding truly doesn't map to any framework (extremely rare for any real finding).
- "extraction_confidence": "high" if title+description+scan_excerpt all align and the CVE/version/component are explicit. "medium" if you had to infer one field from another. "low" if you guessed.

OUTPUT FORMAT: a single JSON object, no surrounding prose, no markdown fences:

{
  "what_is_this": "Plain-English explanation. 2-4 sentences. Reference asset by name, plugin/component version, and CVE if known.",
  "what_could_it_do": "Concrete impact and business consequence. 2-4 sentences. Specific to this stack, this asset, this finding.",
  "how_do_i_fix_it": "Numbered remediation steps as a single string with embedded newlines (1. ...\\n2. ...\\n3. ...). End with 'Estimated remediation time: X-Y hours' and, for HIGH/CRITICAL severities, 'Priority: P0/P1/etc.'",
  "extracted_cves": ["CVE-2020-13126", "CVE-2021-XXXXX"],
  "extracted_cwes": [79, 89, 521],
  "extracted_tags": ["wordpress", "plugin", "outdated", "vulnerable-component"],
  "cvss_score": 6.1,
  "affected_component": "Email Encoder Bundle",
  "affected_component_version": null,
  "suggested_category": "sca",
  "matched_url": "/wp-admin/admin-ajax.php",
  "frameworks": ["NIST 800-63B", "ISO 27001 A.9.4.3"],
  "extraction_confidence": "medium"
}

No other text. No markdown code fences around the JSON. Just the object."""


USER_PROMPT_TEMPLATE = """Write the three sections for the following finding.

INPUT:
Title: {title}
Severity: {severity}
{cvss_line}Asset: {asset_name} ({organization} — {asset_type})
{cve_line}{cwe_line}Category: {category}
Source scanner: {source}

Existing description: {description}

Best available scan excerpt:
{best_excerpt}

External references:
{references_list}
"""


# ─── Data helpers ───────────────────────────────────────────────────────────
@dataclass
class FindingInput:
    finding_id: str
    title: str
    severity: str
    asset_id: str
    description: str | None
    cve: list[str]
    cwe: list[int]
    category: str | None
    source: str
    references: list[str]

    asset_name: str
    organization: str
    asset_type: str

    best_excerpt: str | None
    cvss: float | None

    # Raw row passed through to write_synthesis so the merge logic can read
    # the current values of cve/cwe/tags/cvss_score/affected_component/etc.
    # without a second DB round-trip.
    existing_row: dict | None = None

    @property
    def is_thin(self) -> bool:
        desc = (self.description or "").strip()
        if len(desc) >= THIN_DESCRIPTION_LEN:
            return False
        # Citation-y pattern: starts with "Source:", "See:", "Ref:" etc, or
        # is just the title + severity restated.
        import re
        if re.match(r"^(source|see|ref(erence)?|cf\.?)\s*:", desc, re.I):
            return True
        if not desc:
            return True
        # Title-like one-liner — no sentence punctuation
        if "." not in desc and "\n" not in desc and len(desc) < THIN_DESCRIPTION_LEN:
            return True
        return False

    def input_hash(self) -> str:
        """Hash the inputs that determine the synthesis output, so we can detect drift."""
        blob = json.dumps({
            "title": self.title,
            "description": self.description,
            "cve": sorted(self.cve),
            "cwe": sorted(self.cwe),
            "category": self.category,
            "source": self.source,
            "best_excerpt": self.best_excerpt,
        }, sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()

    def to_prompt(self) -> str:
        cvss_line = f"CVSS: {self.cvss}\n" if self.cvss else ""
        cve_line = f"CVEs: {', '.join(self.cve)}\n" if self.cve else ""
        cwe_line = f"CWEs: {', '.join(f'CWE-{c}' for c in self.cwe)}\n" if self.cwe else ""
        return USER_PROMPT_TEMPLATE.format(
            title=self.title,
            severity=self.severity,
            cvss_line=cvss_line,
            asset_name=self.asset_name or self.asset_id,
            organization=self.organization or "—",
            asset_type=self.asset_type or "—",
            cve_line=cve_line,
            cwe_line=cwe_line,
            category=self.category or "—",
            source=self.source,
            description=self.description or "(empty)",
            best_excerpt=self.best_excerpt or "(none)",
            references_list="\n".join(f"- {r}" for r in self.references) if self.references else "(none)",
        )


# ─── DB access ──────────────────────────────────────────────────────────────
def fetch_findings(sb, severities: list[str] | None, finding_id: str | None, force: bool):
    """Return list of FindingInput.

    Picks findings that need synth work. A finding qualifies if ANY of:
      - description is thin/citation-only (the original criterion)
      - impact column is NULL (Phase F's "WHAT COULD IT DO?" missing)
      - remediation column is NULL (Phase F's "HOW DO I FIX IT?" missing)

    The impact/remediation case was added 2026-05-24 after the new
    wpvuln_json and probe_results parsers shipped — those write a full
    description directly at parse time, which made the old is_thin filter
    skip them entirely, leaving §2/§3 blank on the portal indefinitely
    unless an operator ran --force manually. The expanded filter lets the
    auto-enrichment chain catch these gaps without intervention.
    """
    q = sb.table("findings").select(_SELECT_COLUMNS)
    def _apply_scope(builder):
        """Every predicate except paging — applied identically to the count
        probe and to each page, so the guard below compares like with like."""
        if finding_id:
            return builder.eq("finding_id", finding_id)
        if severities:
            builder = builder.in_("severity", severities)
        # --force means "re-synthesise everything in scope", so no thin filter.
        if not force:
            builder = builder.or_(THIN_PREDICATE)
        return builder

    # ── The exact denominator, server-side, BEFORE fetching anything ────────
    # head=True sends no rows; count comes back in Content-Range. This is the
    # number the precheck prints, computed the same way, so the run log can
    # state its own denominator instead of implying one.
    count_probe = _apply_scope(
        sb.table("findings").select("finding_id", count="exact", head=True)
    )
    expected = _execute_with_retry(count_probe, "thin-count probe").count or 0

    # ── KEYSET pagination, not OFFSET ──────────────────────────────────────
    #
    # ⚠ THIS CHANGED BECAUSE THE GUARD BELOW NOW TOLERATES GROWTH (relay 141).
    # Offset paging and a growing table do not mix. This workflow is chained to
    # Scanner completion — the one moment thin rows are being inserted — and
    # findings went 2511 -> 2515 during the hour this was written.
    #
    # With OFFSET: page 1 is rows[0:500] ordered by finding_id. If a row is
    # then inserted whose finding_id sorts anywhere BEFORE the cursor, every
    # later row shifts down one, and the read for rows[500:1000] returns what
    # used to be row 501 — row 500 is SKIPPED. Silently.
    #
    # ⛔ 4.7's 141 says "ordering by the PK makes duplicates impossible", which
    # is true and does not cover skips. Duplicates are the harmless direction.
    # A tolerated-growth policy on top of offset paging converts an alarm into
    # a silent omission — the defect this whole change exists to remove.
    #
    # KEYSET carries the cursor in the WHERE clause: `finding_id > :last`.
    # Inserts before the cursor cannot shift the window; inserts after it are
    # picked up naturally on a later page. No skips, no duplicates, and growth
    # becomes genuinely safe to tolerate rather than merely survivable.
    #
    # ⚠ STILL BOUNDED. Found by mutating .range() back to .limit(5000): the
    # read returned a full page forever, `len(page) < PAGE_SIZE` never fired,
    # and the loop spun to the 120-minute workflow timeout. A job that hangs
    # and reports nothing is the same failure class as the 52 green no-ops. The
    # bound survives the switch to keyset because an ignored `.gt()` produces
    # exactly the same non-advancing read.
    max_pages = (expected + PAGE_SIZE) // PAGE_SIZE + 1

    rows: list[dict] = []
    cursor: str | None = None
    pages = 0
    while True:
        page_q = _apply_scope(sb.table("findings").select(_SELECT_COLUMNS))
        if cursor is not None:
            page_q = page_q.gt("finding_id", cursor)
        page = (
            _execute_with_retry(
                page_q.order("finding_id").limit(PAGE_SIZE),
                f"findings page after {cursor!r}",
            ).data
            or []
        )
        rows.extend(page)
        pages += 1
        if len(page) < PAGE_SIZE:
            break
        if pages > max_pages:
            print(
                f"error: pagination did not terminate — {pages} pages read for "
                f"an expected {expected} row(s) at {PAGE_SIZE}/page. The read is "
                f"not advancing (a .limit() reinstated in place of the keyset "
                f"cursor, or an ignored .gt()). Refusing to spin.",
                file=sys.stderr,
            )
            sys.exit(1)
        cursor = page[-1]["finding_id"]

    # ── ⛔ CONTRADICTION GUARD — fail loud, do not proceed on a short read ──
    # This is the assertion that would have turned 52 green no-ops into 52 red
    # runs on day one. If the count and the walk disagree, the worker cannot
    # see its whole queue: a reinstated cap, a page-size >= max_rows, a lost
    # page, or a predicate that drifted between the two. Any of those means the
    # run is about to under-report its own scope, and a green check that did
    # nothing is worse than a red one.
    # ⚠ THE TEST IS `<`, NOT `!=` (relay 141). The two directions mean opposite
    # things and only one of them is a defect:
    #
    #   fetched < expected  the worker cannot see its whole queue — a
    #                       reinstated cap, a page size >= max_rows, a lost
    #                       page, or a predicate that drifted between the count
    #                       and the walk. EXIT 1.
    #
    #   fetched > expected  rows arrived during the walk. This workflow is
    #                       chained to Scanner completion, which is precisely
    #                       when thin rows are inserted — findings went
    #                       2511 -> 2515 during the hour this was written. With
    #                       keyset paging those rows are genuinely ours to
    #                       process. LOG AND PROCEED.
    #
    # `!=` was what shipped first. It would have emailed Howie a red workflow
    # captioned "Refusing to run on a partial queue" for a queue that was not
    # partial — alarming copy for a non-event, built into the fix for the
    # silent-no-op class. That trade is never worth making.
    if len(rows) < expected:
        print(
            f"error: count says {expected} finding(s) in scope, worker fetched "
            f"only {len(rows)} — cap or pagination defect. Refusing to run on a "
            f"partial queue.\n"
            f"       page size {PAGE_SIZE}; if the Data API max_rows was "
            f"lowered below it, the short-page termination test is invalid.",
            file=sys.stderr,
        )
        sys.exit(1)

    grew = len(rows) - expected
    if grew:
        print(f"  queue grew by {grew} during the walk (scan landed mid-run) "
              f"— processing all {len(rows)}")
    print(f"  in scope: {expected} finding(s) (fetched {len(rows)}, "
          f"{PAGE_SIZE}/page)")

    # Pull asset + best history excerpt for each in batches
    asset_ids = list({r["asset_id"] for r in rows})
    assets_by_id: dict[str, Any] = {}
    if asset_ids:
        # ⚠ Same max_rows exposure in principle: this is an unpaginated read
        # clamped at 1000. It is safe only while the DISTINCT asset count stays
        # under the cap — 400 assets total on Command, 232 findings in scope
        # touch far fewer (measured 2026-09-15). A missing asset degrades to
        # asset_name = asset_id rather than to a wrong synthesis, so this is a
        # display gap, not a silent skip like the findings read was. Left
        # unpaginated on purpose so the guarded path stays the one that matters;
        # revisit if the fleet crosses ~1000 assets.
        ar = (
            _execute_with_retry(
                sb.table("assets")
                .select("asset_id, name, organization, type")
                .in_("asset_id", asset_ids),
                "assets batch",
            ).data
            or []
        )
        assets_by_id = {a["asset_id"]: a for a in ar}

    out: list[FindingInput] = []
    for r in rows:
        # Skip only if FULLY synthesized — all three Phase F sections present
        # AND description_source attests to that provenance. Previously this
        # skipped on description_synth alone, which made findings with a
        # parser-written description (wpvuln_json, probe_results) get skipped
        # even though their impact/remediation were still NULL.
        if not force:
            fully_synthesized = (
                r.get("description_synth")
                and r.get("impact")
                and r.get("remediation")
                and r.get("description_source") in {
                    "ai_synthesized", "ai_synthesized_reviewed", "manual"
                }
            )
            if fully_synthesized:
                continue

        # Best history excerpt — pick by score (section markers + length)
        hist = (
            _execute_with_retry(
                sb.table("finding_history")
                .select("scan_id, observed_at, status, severity_at_scan, raw_excerpt")
                .eq("finding_id", r["finding_id"])
                .limit(50),
                f"history for {r['finding_id']}",
            ).data
            or []
        )
        best = _pick_best_excerpt(hist)

        # Try to read CVSS out of description if present
        cvss = _parse_cvss(r.get("description") or "")

        asset = assets_by_id.get(r["asset_id"], {})
        finding = FindingInput(
            finding_id=r["finding_id"],
            title=r["title"],
            severity=r["severity"],
            asset_id=r["asset_id"],
            description=r.get("description"),
            cve=r.get("cve") or [],
            cwe=r.get("cwe") or [],
            category=r.get("category"),
            source=r.get("source") or "unknown",
            references=r.get("references") or [],
            asset_name=asset.get("name") or r["asset_id"],
            organization=asset.get("organization") or "unknown",
            asset_type=asset.get("type") or "unknown",
            best_excerpt=best,
            cvss=cvss,
            existing_row=r,
        )
        # Include if forcing, thin description, OR any Phase F section missing.
        # The impact/remediation check is the key 2026-05-24 addition: it lets
        # findings authored by parsers (wpvuln_json, probe_results) that ship
        # with a complete description but no impact/remediation get picked up
        # by the auto-enrichment chain instead of requiring --force.
        missing_impact_or_remediation = not r.get("impact") or not r.get("remediation")
        if force or finding.is_thin or missing_impact_or_remediation:
            out.append(finding)

    return out


def _pick_best_excerpt(history: list[dict]) -> str | None:
    """Same scoring heuristic as the portal — section markers + length."""
    import re
    marker_re = re.compile(
        r"\*{1,2}(detail|recommendation|impact|risk|mitigation|fix|consequence|status\s+vs|cwe|cve)\s*\*{0,2}\s*:",
        re.I,
    )
    scored = []
    for h in history:
        ex = (h.get("raw_excerpt") or "").strip()
        if len(ex) < 50:
            continue
        markers = len(marker_re.findall(ex))
        scored.append((markers * 100 + len(ex), ex))
    scored.sort(reverse=True)
    return scored[0][1] if scored else None


def _parse_cvss(text: str) -> float | None:
    import re
    m = re.search(r"CVSS\s*[:=]?\s*(\d+\.\d+)", text, re.I)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def write_synthesis(sb, finding_id: str, result: dict, input_hash: str, existing: dict | None = None):
    """
    Write synth output back to the findings row.

    Prose columns are always written. Structured extractions follow a
    *non-destructive merge* policy:
      - cve/cwe arrays: union with whatever is already in the row (don't blow
        away scanner-extracted CVEs with synth-extracted ones, but DO add
        anything the synth found that's missing)
      - tags: union (case-insensitive on the value)
      - cvss_score, affected_component, affected_component_version: only
        overwrite if currently NULL (scanner data is authoritative)
      - suggested_category: always overwrite (it's the AI's suggestion, not
        authoritative — the UI shows a mismatch chip if it disagrees with
        findings.category)
      - extraction_confidence: always overwrite (latest run wins)
    """
    from datetime import datetime, timezone

    payload: dict = {
        "description_synth": result["what_is_this"],
        "impact": result["what_could_it_do"],
        "remediation": result["how_do_i_fix_it"],
        "description_source": "ai_synthesized",
        "description_synthesized_at": datetime.now(timezone.utc).isoformat(),
        "description_synth_model": MODEL_ID,
        "description_synth_input_hash": input_hash,
    }

    existing = existing or {}

    # ── Extracted CVEs — union with existing
    new_cves = [c.upper() for c in (result.get("extracted_cves") or []) if c]
    if new_cves:
        prior = existing.get("cve") or []
        merged = sorted({*prior, *new_cves})
        if merged != prior:
            payload["cve"] = merged

    # ── Extracted CWEs — union with existing (ints)
    new_cwes_raw = result.get("extracted_cwes") or []
    new_cwes: list[int] = []
    for c in new_cwes_raw:
        try:
            new_cwes.append(int(c))
        except (TypeError, ValueError):
            continue
    if new_cwes:
        prior = existing.get("cwe") or []
        merged = sorted({*prior, *new_cwes})
        if merged != prior:
            payload["cwe"] = merged

    # ── Extracted tags — union, case-insensitive de-dupe, keep original casing
    new_tags = [t for t in (result.get("extracted_tags") or []) if t]
    if new_tags:
        prior = existing.get("tags") or []
        seen = {t.lower() for t in prior}
        merged = list(prior)
        for t in new_tags:
            if t.lower() not in seen:
                merged.append(t)
                seen.add(t.lower())
        if merged != prior:
            payload["tags"] = merged

    # ── CVSS score — scanner data wins, only fill if currently empty
    if result.get("cvss_score") is not None and existing.get("cvss_score") is None:
        try:
            payload["cvss_score"] = float(result["cvss_score"])
        except (TypeError, ValueError):
            pass

    # ── Affected component — only fill if empty
    if result.get("affected_component") and not existing.get("affected_component"):
        payload["affected_component"] = str(result["affected_component"]).strip() or None

    if result.get("affected_component_version") and not existing.get("affected_component_version"):
        payload["affected_component_version"] = str(result["affected_component_version"]).strip() or None

    # ── Suggested category — always write (it's an AI hint, not authoritative)
    sc = result.get("suggested_category")
    if sc and sc in VALID_CATEGORIES:
        payload["suggested_category"] = sc

    # ── matched_url — only fill if empty (preserve scanner-extracted URLs)
    if result.get("matched_url") and not existing.get("matched_url"):
        url = str(result["matched_url"]).strip()
        if url:
            payload["matched_url"] = url

    # ── Frameworks — union with existing array
    new_fw = [f.strip() for f in (result.get("frameworks") or []) if f and str(f).strip()]
    if new_fw:
        prior = existing.get("frameworks") or []
        seen = {f.lower() for f in prior}
        merged = list(prior)
        for f in new_fw:
            if f.lower() not in seen:
                merged.append(f)
                seen.add(f.lower())
        if merged != prior:
            payload["frameworks"] = merged

    # ── Extraction confidence — always write
    ec = result.get("extraction_confidence")
    if ec in {"high", "medium", "low"}:
        payload["extraction_confidence"] = ec

    # Retried: a per-finding write that loses a transport blip would silently
    # drop work the model was already paid for.
    _execute_with_retry(
        sb.table("findings").update(payload).eq("finding_id", finding_id),
        f"write synthesis for {finding_id}",
    )


VALID_CATEGORIES = {
    "sast", "dast", "sca", "secret", "recon", "tls", "headers", "dns",
    "email", "auth", "session", "csrf", "ssrf", "xxe", "xss", "sqli",
    "idor", "rce", "lfi", "redirect", "info_disclosure", "takeover",
    "typosquat", "config", "deprecation", "supply_chain", "other",
}


# ─── Claude call ────────────────────────────────────────────────────────────
def _parse_json_lenient(raw: str) -> dict:
    """
    Parse a JSON object string that may have model-induced damage.

    Failure modes we've observed in production:
      1. Literal newlines inside string values (Claude pastes code blocks
         directly into a "how_do_i_fix_it" string without escaping). Standard
         json.loads chokes with "Expecting ',' delimiter".
      2. Unescaped double-quotes inside string values (less common — model
         emits a code excerpt with " not \\").
      3. Trailing commas before } (rare with low temp but happens).

    Strategy:
      - Try strict json.loads first (fast path, no-cost).
      - If that fails, try a "literal newline → \\n" repair pass.
      - If THAT fails, fall back to a per-key regex extractor that captures
        each known top-level key's value as best it can. We may lose strict
        type fidelity (e.g. arrays end up as parsed JSON or fall back to
        empty) but we never lose the whole finding.

    Returns a dict with whichever keys we could recover. Validation of
    required keys still happens in the caller.
    """
    import re as _re

    # Fast path
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Repair pass 1 — escape literal newlines/CRs inside string values.
    # We walk the string, tracking whether we're inside a "...". When inside
    # a string, raw \n or \r becomes \\n / \\r so json.loads accepts it.
    repaired_chars: list[str] = []
    in_string = False
    escape_next = False
    for ch in raw:
        if escape_next:
            repaired_chars.append(ch)
            escape_next = False
            continue
        if ch == "\\":
            repaired_chars.append(ch)
            escape_next = True
            continue
        if ch == '"':
            repaired_chars.append(ch)
            in_string = not in_string
            continue
        if in_string and ch == "\n":
            repaired_chars.append("\\n")
            continue
        if in_string and ch == "\r":
            repaired_chars.append("\\r")
            continue
        if in_string and ch == "\t":
            repaired_chars.append("\\t")
            continue
        repaired_chars.append(ch)
    repaired = "".join(repaired_chars)

    try:
        return json.loads(repaired)
    except json.JSONDecodeError:
        pass

    # Repair pass 2 — strip trailing commas before } or ]
    no_trailing = _re.sub(r",(\s*[}\]])", r"\1", repaired)
    try:
        return json.loads(no_trailing)
    except json.JSONDecodeError:
        pass

    # Fallback — per-key regex extractor. We can't recover everything, but
    # we can usually salvage the three prose strings + the structured fields.
    out: dict = {}
    # String values: "key": "value" where value may span multiple "lines"
    # (because newlines inside string values were repaired above).
    str_keys = [
        "what_is_this", "what_could_it_do", "how_do_i_fix_it",
        "affected_component", "affected_component_version",
        "suggested_category", "extraction_confidence",
    ]
    for key in str_keys:
        m = _re.search(
            rf'"{key}"\s*:\s*"((?:[^"\\]|\\.)*)"',
            no_trailing, _re.DOTALL,
        )
        if m:
            # Unescape the captured string the way json.loads would
            try:
                out[key] = json.loads(f'"{m.group(1)}"')
            except json.JSONDecodeError:
                out[key] = m.group(1)

    # Array values
    arr_keys = ["extracted_cves", "extracted_cwes", "extracted_tags"]
    for key in arr_keys:
        m = _re.search(rf'"{key}"\s*:\s*(\[[^\]]*\])', no_trailing, _re.DOTALL)
        if m:
            try:
                out[key] = json.loads(m.group(1))
            except json.JSONDecodeError:
                pass

    # Numeric value (cvss_score)
    m = _re.search(r'"cvss_score"\s*:\s*(null|[\d.]+)', no_trailing)
    if m:
        v = m.group(1)
        out["cvss_score"] = None if v == "null" else float(v)

    if not out:
        # Truly unparseable — give up and propagate the original error so
        # the caller logs the finding as a failure.
        raise json.JSONDecodeError("Unable to parse JSON after all repair attempts", raw, 0)
    return out


def synthesize_one(client, finding: FindingInput) -> dict:
    resp = client.messages.create(
        model=MODEL_ID,
        max_tokens=MAX_TOKENS,
        temperature=TEMPERATURE,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": finding.to_prompt()}],
    )
    # The model is instructed to output JSON only. Find the first { and last }.
    txt = "".join(b.text for b in resp.content if hasattr(b, "text"))
    start = txt.find("{")
    end = txt.rfind("}")
    if start < 0 or end < 0:
        raise ValueError(f"No JSON object in response: {txt[:500]}")
    raw = txt[start : end + 1]
    payload = _parse_json_lenient(raw)

    # The model occasionally typos JSON keys (observed: "how_do_fix_it"
    # instead of "how_do_i_fix_it"). Normalize known variants before
    # validating so we don't lose otherwise-good output.
    key_aliases = {
        "what_is_this": ["whatIsThis", "what_is", "description"],
        "what_could_it_do": ["whatCouldItDo", "what_could_do", "impact", "what_it_could_do"],
        "how_do_i_fix_it": ["howDoIFixIt", "how_do_fix_it", "how_to_fix", "how_do_i_fix", "remediation", "fix"],
        "extracted_cves": ["cves", "cve_list", "extracted_cve"],
        "extracted_cwes": ["cwes", "cwe_list", "extracted_cwe"],
        "extracted_tags": ["tags", "tag_list"],
        "cvss_score": ["cvss", "cvssScore", "cvss_v3_score"],
        "affected_component": ["component", "affected_software", "vulnerable_component"],
        "affected_component_version": ["component_version", "affected_version", "version"],
        "suggested_category": ["category_suggestion", "category"],
        "matched_url": ["matched_at", "url", "endpoint", "matchedUrl"],
        "frameworks": ["framework_mappings", "compliance_frameworks", "framework_list"],
        "extraction_confidence": ["confidence", "confidence_level"],
    }
    for canonical, aliases in key_aliases.items():
        if canonical not in payload:
            for alias in aliases:
                if alias in payload:
                    payload[canonical] = payload.pop(alias)
                    break

    # Validate keys
    for k in ("what_is_this", "what_could_it_do", "how_do_i_fix_it"):
        if k not in payload or not str(payload[k]).strip():
            raise ValueError(f"Response missing required key {k!r}: keys present = {list(payload.keys())}")
    return payload


# ─── Main ───────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--finding-id", help="Process exactly this finding_id.")
    parser.add_argument("--severity", nargs="+", help="Severity filter (e.g. HIGH MODERATE-HIGH).")
    parser.add_argument("--dry-run", action="store_true", help="Print result, do not write to DB.")
    parser.add_argument("--force", action="store_true", help="Re-synthesize even if already done.")
    parser.add_argument("--limit", type=int, default=300, help="Max findings to process this run. Bumped 100→300 on 2026-05-27 so a single workflow_dispatch can drain the typical backlog (~300 thin findings) in one sitting; cron sweeps the tail.")
    args = parser.parse_args()

    _import_deps()
    import anthropic
    from supabase import create_client

    # Load env from .env in repo root if present
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    sb_url = os.environ.get("SUPABASE_URL", DEFAULT_SUPABASE_URL)
    sb_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not api_key:
        sys.exit("ANTHROPIC_API_KEY not set")
    if not sb_key:
        sys.exit("SUPABASE_SERVICE_ROLE_KEY not set")

    client = anthropic.Anthropic(api_key=api_key)
    sb = create_client(sb_url, sb_key)

    findings = fetch_findings(
        sb,
        severities=args.severity,
        finding_id=args.finding_id,
        force=args.force,
    )
    if not findings:
        print("No findings match.")
        return
    findings = findings[: args.limit]

    print(f"Processing {len(findings)} finding(s) "
          f"({'DRY RUN' if args.dry_run else 'WRITING TO DB'}, model={MODEL_ID})")
    print("-" * 72)

    successes = 0
    failures = []
    for i, f in enumerate(findings, 1):
        print(f"[{i}/{len(findings)}] {f.finding_id} ({f.severity})")
        try:
            t0 = time.monotonic()
            result = synthesize_one(client, f)
            elapsed = time.monotonic() - t0
            print(f"  ✓ synth ok ({elapsed:.1f}s)")
            if args.dry_run:
                print(f"\n  WHAT IS THIS:\n    {result['what_is_this']}")
                print(f"\n  WHAT COULD IT DO:\n    {result['what_could_it_do']}")
                print(f"\n  HOW DO I FIX IT:\n    {result['how_do_i_fix_it']}")
                print("\n  STRUCTURED EXTRACTIONS:")
                print(f"    CVEs:                 {result.get('extracted_cves') or '—'}")
                print(f"    CWEs:                 {result.get('extracted_cwes') or '—'}")
                print(f"    Tags:                 {result.get('extracted_tags') or '—'}")
                print(f"    CVSS:                 {result.get('cvss_score') or '—'}")
                print(f"    Component:            {result.get('affected_component') or '—'}")
                print(f"    Version:              {result.get('affected_component_version') or '—'}")
                print(f"    Suggested category:   {result.get('suggested_category') or '—'}")
                print(f"    Matched URL:          {result.get('matched_url') or '—'}")
                print(f"    Frameworks:           {result.get('frameworks') or '—'}")
                print(f"    Extraction confidence: {result.get('extraction_confidence') or '—'}")
                print()
            else:
                write_synthesis(sb, f.finding_id, result, f.input_hash(), existing=f.existing_row)
                print(f"  ✓ written to DB")
            successes += 1
        except Exception as e:
            print(f"  ✗ failed: {e}")
            failures.append((f.finding_id, str(e)))

    print("-" * 72)
    print(f"Done. {successes} ok, {len(failures)} failed.")
    if failures:
        print("\nFailures:")
        for fid, err in failures:
            print(f"  {fid}: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
