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
