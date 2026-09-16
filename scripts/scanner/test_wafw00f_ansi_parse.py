#!/usr/bin/env python3
"""wafw00f colourises the vendor name — relay 221/222, ruling 9.

⛔ THE DEFECT. `_classify_wafw00f_output`'s Path-1 regex needs `[A-Za-z]`
immediately after "is behind". wafw00f emits:

    is behind \\x1b[1;96mFortiWeb (Fortinet)\\x1b[0m WAF.

`\\s+` stops at the escape, Path 1 never matches, and Path 2 ("seems to be behind"
— present in the SAME output) catches it as `generic`.

MEASURED on Command, 2026-09-16, all 93 raw wafw00f artifacts:

    carrying ANSI escapes                        81  (87%)
    naming a vendor once de-ANSI'd               32  — every one FortiWeb
    matched by the pre-fix regex                  0
    live stack_id_wafw00f rows, by kind          10 generic · 15 null · 0 vendor

So `wafw00f_high_confidence` — the signal that carries `waf/confirmed` from a
NAMED vendor — had never fired in production since E1 landed (2026-07-20). Every
FortiWeb identification was laundered into "generic WAF", which is not "we do not
know": it is a positive claim of a weaker fact, and that is worse than absence.

⭐ WHY THIS FILE EXISTS AT ALL, AND THE RULE IT ENCODES.
`test_wafw00f_persist_fold.py` — written HOURS before this was found, to prove the
persist fold — used a hand-typed fixture with no escapes. It passed. It proved the
artifact was written; it could not notice the artifact's CONTENTS were wrong,
because the bytes it fed in were bytes a human typed, not bytes the tool emits.

    ⇒ A PARSER TESTED ONLY AGAINST TEXT A HUMAN TYPED IS NOT TESTED.

`PRODUCTION_BYTES` below is lifted verbatim from the `wafw00f` artifact of
commandcommcentral.com's 2026-09-03 heavy (scan completed 21:35Z). It is not
retyped, and it must not be "tidied" — its escapes are the test.
"""

from __future__ import annotations

import os
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_medium as m  # noqa: E402

# ── VERBATIM from the DB. Do not retype, do not clean. ──────────────────────
PRODUCTION_BYTES = (
    "[+] The site \x1b[1;94mhttps://commandcommcentral.com/\x1b[0m is behind "
    "\x1b[1;96mFortiWeb (Fortinet)\x1b[0m WAF.\n"
    "[*] The site https://commandcommcentral.com/ seems to be behind a WAF or "
    "some sort of security solution\n"
    "[~] Number of requests: 5\n"
)

# Same verdict, escapes removed — the strip must be idempotent.
DEANSIED = (
    "[+] The site https://commandcommcentral.com/ is behind FortiWeb (Fortinet) WAF.\n"
    "[*] The site https://commandcommcentral.com/ seems to be behind a WAF or "
    "some sort of security solution\n"
)

GENERIC_ONLY = (
    "[*] The site \x1b[1;94mhttps://x/\x1b[0m seems to be behind a WAF or some "
    "sort of security solution\n"
)
NO_WAF = "[-] No WAF detected by the generic detection\n"
DOWN = "[*] The site https://x/ appears to be down.\n"

# ⚠ THE NEAR-MISS. An escape INSIDE the vendor name, not just around it. A strip
# that only removed leading escapes would return "Forti" and look like it worked.
ESCAPE_INSIDE_NAME = "[+] The site https://x/ is behind \x1b[1;96mForti\x1b[0mWeb (Fortinet) WAF.\n"


def _kind(stdout, rc=0):
    ctx = types.SimpleNamespace(waf_detected=False, waf_kind=None, artifacts=[])
    m._classify_wafw00f_output(ctx, stdout, rc)
    return ctx.waf_detected, ctx.waf_kind


# ---------------------------------------------------------------------------
# ⭐ the production-bytes fixture — this is the one that must kill the mutant
# ---------------------------------------------------------------------------

def test_the_real_09_03_artifact_yields_the_vendor_not_generic():
    """commandcommcentral.com, heavy, 2026-09-03 21:35Z, byte for byte.

    PRE-FIX this returns ('generic') — Path 1 misses the escape and Path 2 catches
    the "seems to be behind" line that is sitting in the same output. That is how
    32 FortiWeb identifications became 'generic WAF'."""
    detected, kind = _kind(PRODUCTION_BYTES)
    assert detected is True
    assert kind == "fortiweb", (
        f"got {kind!r} — the vendor is named in these exact bytes; 'generic' here is "
        f"the laundering defect, not a weaker observation")


def test_the_fixture_really_does_contain_escapes():
    """Guards the fixture itself. If someone 'cleans up' PRODUCTION_BYTES, the test
    above still passes and stops testing anything — the vacuous-fixture failure."""
    assert "\x1b" in PRODUCTION_BYTES, "the escapes ARE the test; do not tidy them"
    assert "\x1b[1;96m" in PRODUCTION_BYTES


def test_the_generic_line_is_present_in_the_same_output():
    """Why Path ORDER matters: the real artifact contains BOTH the named verdict and
    the generic one. Named must win. If Path 2 were checked first, the strip would
    fix nothing."""
    assert "seems to be behind" in PRODUCTION_BYTES
    assert _kind(PRODUCTION_BYTES)[1] == "fortiweb"


def test_the_strip_is_idempotent():
    """Already-clean text must parse identically — the 12 artifacts with no escapes
    must not regress."""
    assert _kind(DEANSIED) == (True, "fortiweb")


def test_an_escape_inside_the_vendor_name_still_resolves():
    """The near-miss 4.7 asked for. A strip that only handled escapes AROUND the
    name would yield 'Forti' — a plausible-looking wrong answer."""
    assert _kind(ESCAPE_INSIDE_NAME) == (True, "fortiweb")


# ---------------------------------------------------------------------------
# the other exit paths must be untouched
# ---------------------------------------------------------------------------

def test_generic_only_output_is_still_generic():
    """The strip must not promote a presence-only detection into a vendor."""
    assert _kind(GENERIC_ONLY) == (True, "generic")


def test_no_waf_is_still_no_waf():
    assert _kind(NO_WAF) == (False, None)


def test_a_down_site_is_not_a_waf():
    assert _kind(DOWN) == (False, None)


def test_a_nonzero_rc_still_short_circuits():
    """rc != 0 means the tool failed; the strip must not change that branch."""
    assert _kind(PRODUCTION_BYTES, rc=1) == (False, None)


# ---------------------------------------------------------------------------
# structural
# ---------------------------------------------------------------------------

def test_the_strip_happens_before_any_match():
    """Order is the fix. A strip placed after the Path-1 search would be inert."""
    import ast
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "run_medium.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "_classify_wafw00f_output")
    body = ast.get_source_segment(src, fn)
    # ⚠ COMMENTS STRIPPED FIRST. The first draft of this test searched the raw
    # source for "is behind" and found it in the explanatory COMMENT above the
    # strip — so it compared a comment's position against code and failed on a
    # correct tree. A structural test that can be satisfied (or broken) by prose
    # is not a structural test.
    code = "\n".join(l for l in body.split("\n") if not l.lstrip().startswith("#"))
    i_strip = code.find("_ANSI_ESCAPE.sub")
    i_match = code.find("re.search")
    assert i_strip != -1, "the ANSI strip is gone from _classify_wafw00f_output"
    assert i_match != -1, "no re.search left in the parse — anchor this test again"
    assert i_strip < i_match, "the strip must run BEFORE the first match, or it is inert"


def test_the_raw_artifact_is_stored_unstripped():
    """⚠ Strip what we READ, not what we STORE. The escapes in the stored artifact
    are the provenance that made this reconstructable at all — cleaning them at
    write time would have destroyed the evidence of the bug."""
    import ast
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "run_medium.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "detect_waf")
    body = ast.get_source_segment(src, fn)
    assert 'ctx.artifacts.append(("wafw00f", "text", stdout))' in body, (
        "the raw artifact must be stored as emitted — unstripped")
    assert "_ANSI_ESCAPE" not in body, (
        "the strip belongs in the parse, not on the stored artifact")
