#!/usr/bin/env python3
"""Finding-identity hygiene — relay 155 ⑤⑥, 2026-09-15.

⛔ THE DEFECT. `check_name` drives `finding_id` (`{asset}:medium:{check_name}`) and the nikto
slug is derived from the raw response body. On www.prodexlabs.com nikto's Perl prints an ARRAY
*reference* instead of the OPTIONS method list, so the body carries a heap address that changes
every run:

    …:medium:nikto-999990-options-allowed-http-methods-array-0x561de6ae2e40   first 09-05
    …:medium:nikto-999990-options-allowed-http-methods-array-0x559baf530058   first 09-09
    …:medium:nikto-999990-options-allowed-http-methods-array-0x55df6287a7d0   first 09-15

Every heavy scan mints a brand-new "finding" that is the same non-finding — the "1 new info"
after every scan, forever. ⑤ drops the contentless record; ⑥ stops the NEXT tool with a nonce
or an embedded timestamp from repeating it.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_medium as rm  # noqa: E402


# ⑤ ------------------------------------------------------------------------

def test_array_reference_is_recognised_as_contentless():
    assert rm.is_contentless_array_ref(
        "OPTIONS Allowed HTTP Methods: ARRAY(0x55df6287a7d0)") is True
    assert rm.is_contentless_array_ref("array(0xDEADBEEF)") is True


def test_a_real_method_list_is_NOT_dropped():
    """⛔ The fix must not swallow the useful case. A genuine OPTIONS list is a real
    INFO finding and has to survive."""
    assert rm.is_contentless_array_ref(
        "Allowed HTTP Methods: GET, HEAD, POST, OPTIONS") is False
    assert rm.is_contentless_array_ref("") is False
    assert rm.is_contentless_array_ref(None) is False


# ⑥ ------------------------------------------------------------------------

def test_slug_is_stable_across_runs_that_differ_only_by_heap_address():
    """The three real finding_ids above must collapse to ONE identity."""
    bodies = [
        "OPTIONS Allowed HTTP Methods: ARRAY(0x561de6ae2e40)",
        "OPTIONS Allowed HTTP Methods: ARRAY(0x559baf530058)",
        "OPTIONS Allowed HTTP Methods: ARRAY(0x55df6287a7d0)",
    ]
    slugs = {rm.slug_for_identity(b, "fb") for b in bodies}
    assert len(slugs) == 1, f"volatile address still fragments identity: {slugs}"


def test_timestamps_and_epochs_are_stripped():
    a = rm.slug_for_identity("cert expires 2026-09-15 02:10", "fb")
    b = rm.slug_for_identity("cert expires 2026-09-16 04:30", "fb")
    assert a == b
    assert rm.slug_for_identity("token 1757894400", "fb") == \
           rm.slug_for_identity("token 1757980800", "fb")


def test_nonces_and_session_ids_are_stripped():
    assert rm.slug_for_identity("csp nonce=AbC123xyz", "fb") == \
           rm.slug_for_identity("csp nonce=Zz99qqQQ", "fb")


def test_genuinely_different_findings_stay_different():
    """⛔ THE OVER-COLLAPSE GUARD. Replacing the token with a placeholder (not deleting
    it) keeps 'foo-<token>-bar' distinct from 'foo-bar' — they are not the same finding.
    Deleting would silently merge two real findings into one."""
    assert rm.slug_for_identity("foo 0xAB1234 bar", "fb") != \
           rm.slug_for_identity("foo bar", "fb")
    assert rm.slug_for_identity("missing header x-frame-options", "fb") != \
           rm.slug_for_identity("missing header content-security-policy", "fb")


def test_empty_body_falls_back_rather_than_producing_an_empty_identity():
    assert rm.slug_for_identity("", "finding-7") == "finding-7"
    assert rm.slug_for_identity("!!!???", "finding-7") == "finding-7"


def test_slug_length_is_bounded():
    assert len(rm.slug_for_identity("x" * 500, "fb")) <= 60


def test_the_parser_ACTUALLY_DROPS_the_contentless_record():
    """⛔ ADDED AFTER A SURVIVING MUTATION. The first version of this file tested
    is_contentless_array_ref() in isolation and nothing asserted the PARSER calls it —
    so disabling the drop (`if is_contentless_array_ref(body):` -> `if False:`) passed
    the whole suite. A predicate nothing consumes is the producer-without-consumer
    pattern, which is the defect family this entire lane exists to close.
    """
    src = open(rm.__file__).read()
    src = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    i = src.index("is_contentless_array_ref(body)")
    guard = src[i:i + 400]
    assert "continue" in guard, (
        "the ARRAY(0x…) record must be SKIPPED, not merely detected — "
        "detecting it and emitting it anyway is the bug with extra steps"
    )


def test_the_parser_uses_the_shared_slug_builder_not_a_local_regex():
    """A second inline `re.sub(r"[^a-z0-9]+"…)` would reintroduce the bug on the next
    tool. One builder, one place."""
    src = open(rm.__file__).read()
    src = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    assert "slug_for_identity(body" in src
    assert 'slug = re.sub(r"[^a-z0-9]+", "-", body_lc)' not in src


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))


# ── relay 436: ONE RULE, BOTH nikto PARSERS ─────────────────────────────────
# ⛔ WHY THIS EXISTS. The ⑤/⑥ guard landed here (run_medium) on 2026-09-15 and
# worked — but nikto has TWO parser paths and only this one was fixed.
# cs_parsers/nikto.py::parse_nikto_file (run_normalize + the nikto backfill)
# still emitted the raw ARRAY(0x…). One tool, two parsers, one fixed is the
# shape that produced the shared vendor-digest bug in relay 346/352, so the rule
# moved to cs_parsers/common.py and BOTH import it.

def _ssot():
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "normalize"))
    from cs_parsers import common
    return common


def test_run_medium_uses_the_SSOT_not_a_private_copy():
    """⛔ THE POINT OF THE CONSOLIDATION. If run_medium ever re-grows its own
    copy, the two parsers can drift apart again — which is exactly how this
    defect survived a fix for a week on the path nobody re-read."""
    ssot = _ssot()
    assert rm.is_contentless_array_ref is ssot.is_contentless_array_ref, (
        "run_medium is not using the shared is_contentless_array_ref")
    assert rm.strip_volatile_tokens is ssot.strip_volatile_tokens, (
        "run_medium is not using the shared strip_volatile_tokens")


def test_the_OTHER_parser_drops_the_contentless_arrayref():
    """cs_parsers/nikto.py — the path that was NEVER guarded."""
    import inspect, sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "normalize"))
    from cs_parsers import nikto
    src = inspect.getsource(nikto)
    assert "is_contentless_array_ref(desc)" in src, (
        "cs_parsers/nikto.py does not drop the contentless ARRAYREF — the "
        "duplicate-minting path is still open on run_normalize / the backfill")


def test_an_ARRAYREF_yields_the_SAME_key_across_two_runs():
    """4.7's fixture, exactly: two nikto processes, two heap addresses, ONE key.

    This is the property that makes the row dedup instead of accumulating. It
    must hold even though the record is ALSO dropped — the drop fixes this
    tool, the stable key is what stops the next tool with a nonce or an address
    from doing the same thing.
    """
    run1 = "OPTIONS: Allowed HTTP Methods: ARRAY(0x561de6ae2e40)"
    run2 = "OPTIONS: Allowed HTTP Methods: ARRAY(0x559baf530058)"
    run3 = "OPTIONS: Allowed HTTP Methods: ARRAY(0x55df6287a7d0)"   # the real 09-15 one
    keys = {rm.slug_for_identity(b, "fb") for b in (run1, run2, run3)}
    assert len(keys) == 1, f"three runs produced {len(keys)} identities: {keys}"


def test_a_REAL_options_list_is_parsed_and_kept():
    """A genuine method list has content, so it is NOT dropped — and its
    identity is derived from the METHODS, which are the same every scan."""
    ssot = _ssot()
    assert ssot.parse_options_methods(
        "OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS") == \
        ["GET", "HEAD", "POST", "OPTIONS"]
    # whitespace / ordering noise must not change the answer
    assert ssot.parse_options_methods("Allowed HTTP Methods: GET,  HEAD") == \
           ssot.parse_options_methods("Allowed HTTP Methods: GET, HEAD")
    # and the contentless case is distinguishable from an empty list
    assert ssot.parse_options_methods(
        "OPTIONS: Allowed HTTP Methods: ARRAY(0xdeadbeef)") is None


def test_a_PARTIALLY_corrupt_options_line_is_contentless_not_partially_parsed():
    """⛔ ISOLATE THE ARRAYREF GUARD (the 424 unfalsifiable-gate lesson).

    A pure ARRAY(0x…) line returns None anyway, because nothing in it is
    method-shaped — so it does NOT exercise the guard, and a mutation removing
    the guard survived every other assertion here. The case that distinguishes
    it is a MIXED line: nikto got part of the list out and then printed a
    reference. That output is CORRUPT, not partial. Parsing 'GET' out of it
    would publish a method list we never actually observed, and the heap address
    is still sitting in the text.
    """
    ssot = _ssot()
    assert ssot.parse_options_methods(
        "OPTIONS: Allowed HTTP Methods: GET, ARRAY(0x561de6ae2e40)") is None, (
        "a line containing an ARRAYREF was partially parsed — the guard is gone")


# ── relay 438 fast-follow: the ISO T…Z tail ─────────────────────────────────

def test_ISO_T_Z_timestamps_strip_INCLUDING_the_seconds():
    """⛔ THE EXISTING TEST PASSED WHILE THE BUG WAS LIVE.

    test_timestamps_and_epochs_are_stripped varies date + HH:MM only, so the
    seconds never differed and the defect was invisible. On "…T02:10:07Z" there
    is no word boundary between the final "7" and "Z", so the old
    `(:\\d{2})?\\b` could not match the seconds: the engine backtracked to
    "…T02:10" and left ":07Z" in the key. Two findings a second apart therefore
    produced DIFFERENT identities — mint-every-scan again, in a new costume.
    now_iso() in this package emits exactly T…Z, so this is the shape most
    likely to show up next.

    THIS test varies the SECONDS, which is what makes the gate falsifiable.
    """
    ssot = _ssot()
    s = ssot.strip_volatile_tokens
    # the decisive pair: same minute, different SECOND
    assert s("cert expires 2026-09-15T02:10:07Z") == \
           s("cert expires 2026-09-15T02:10:59Z"), \
        "the T…Z seconds survived the strip — the key still drifts"
    # fractional seconds and offsets are the same class of tail
    assert s("x 2026-09-15T02:10:07.123Z") == s("x 2026-09-16T04:30:59.987Z")
    assert s("x 2026-09-15T02:10:07+02:00") == s("x 2026-09-16T04:30:59-05:00")
    # the space form (which always worked) must not regress
    assert s("c 2026-09-15 02:10:07") == s("c 2026-09-16 04:30:59")
    # and a timestamp-free string is still untouched
    assert s("missing header x-frame-options") == "missing header x-frame-options"


def test_a_timestamped_finding_yields_ONE_identity_across_scans():
    """The property the regex exists for, asserted end-to-end on the slug."""
    a = rm.slug_for_identity("cert expires 2026-09-15T02:10:07Z", "fb")
    b = rm.slug_for_identity("cert expires 2026-09-16T04:30:59Z", "fb")
    assert a == b, f"a timestamped finding minted two identities: {a} vs {b}"


# ── relay 436 T2 / 438 ruling: deterministic non-null keys ──────────────────
# ⛔ THE GATE IS TEST-ONLY, DELIBERATELY. 4.7 ratified the inverted order:
# (1) make the key deterministic + non-null at every producer, (2) MEASURE the
# live null count trending to zero, (3) ONLY THEN flip a runtime gate. With
# 776/1000 Command keys currently NULL, a runtime "null key = fail" would turn
# every Command scan red on day one — the 370 halt. So this asserts that NEW
# findings get a key; it never kills a scan.

def test_deterministic_key_is_never_null():
    ssot = _ssot()
    k = ssot.deterministic_finding_key
    for identity, fb in [("", "id-42"), ("!!!???", "id-42"), (None, "id-7"),
                         ("missing header x-frame-options", "id-1")]:
        got = k("nikto", None, identity, fb)
        assert got, f"null/empty key for identity={identity!r}"
        assert got.startswith("nikto:"), got
        # ⛔ "non-null" IS NOT THE PROPERTY. "nikto:" is truthy and starts with
        # the prefix, yet carries NO discriminator — every such finding would
        # collapse onto one key, which is worse than a null. A mutation that
        # dropped the `or fallback` survived both assertions above. The property
        # is that something DISTINGUISHING follows the source prefix.
        discriminator = got.split(":", 1)[1]
        assert discriminator, (
            f"key {got!r} is a bare source prefix — every finding with an "
            f"unsluggable identity would collapse onto it")
    # and two unsluggable findings with DIFFERENT fallbacks stay distinct
    assert k("nikto", None, "!!!", "id-1") != k("nikto", None, "???", "id-2")


def test_a_CLASS_key_always_wins():
    """⛔ 139's consolidation must not be overridden. When a producer has a
    class key, that key collapses the family into one row — deriving a
    per-finding key instead would refragment exactly what Howie asked to
    consolidate (relay 439)."""
    ssot = _ssot()
    assert ssot.deterministic_finding_key(
        "nikto", "class:tech-header-disclosure", "anything at all", "fb") == \
        "class:tech-header-disclosure"


def test_the_derived_key_is_STABLE_across_runs_and_DISTINCT_across_findings():
    ssot = _ssot()
    k = ssot.deterministic_finding_key
    # volatile tokens stripped -> two runs, one key
    assert k("nikto", None, "OPTIONS: methods ARRAY(0x561de6ae2e40)", "f") == \
           k("nikto", None, "OPTIONS: methods ARRAY(0x559baf530058)", "f")
    assert k("nikto", None, "cert expires 2026-09-15T02:10:07Z", "f") == \
           k("nikto", None, "cert expires 2026-09-16T04:30:59Z", "f")
    # genuinely different findings stay different
    assert k("nikto", None, "missing x-frame-options", "f1") != \
           k("nikto", None, "missing content-security-policy", "f2")
    # and the SOURCE scopes it — cross-source collapse is the curated map's job
    assert k("nikto", None, "same text", "f") != k("nuclei", None, "same text", "f")


def test_BOTH_producers_emit_a_non_null_key():
    """⛔ THE GATE, as a test. Both nikto parsers must now pass their key
    through deterministic_finding_key — a producer that still writes a bare
    None is the defect this turn exists to close."""
    import inspect, sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "normalize"))
    from cs_parsers import nikto
    assert "deterministic_finding_key(" in inspect.getsource(nikto), (
        "cs_parsers/nikto.py still emits a raw normalized_key")
    med = pathlib.Path(__file__).resolve().parent / "run_medium.py"
    assert "deterministic_finding_key(" in med.read_text(), (
        "run_medium.py still emits a raw normalized_key")
    # and neither may pass the bare sentinel through any more
    assert "normalized_key=nkey," not in inspect.getsource(nikto)
    assert "normalized_key=norm_key," not in med.read_text()
