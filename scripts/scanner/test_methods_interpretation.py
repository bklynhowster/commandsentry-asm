"""test_methods_interpretation.py — ㊴ probe 4, the one that cannot migrate.

WHY THIS EXISTS (2026-09-09). httpx cannot SEND an OPTIONS request — its
`-method` flag is display-only — so methods_check stays on curl forever.
4.7 ruling ㊴ therefore applies to its INTERPRETATION: an unmapped curl exit
code must stop being recorded as a reachability verdict about the target.

The defect was measurable, not theoretical. `curl_failed` maps to
CUT_TRANSPORT ("never reached the target") and accounts for 316 of the
~1066 occurrences that make TRANSPORT the dominant cut class on this fleet.
On headers_check, 158 such runs had the Go stack reach the SAME host in the
SAME run 94% of the time. So the label was usually false, and it was
inflating a headline number we then reasoned from.

⚠ The assertion that matters is NOT "curl_failed is gone". It is that an
unmapped exit classifies as UNCLASSIFIED rather than TRANSPORT — i.e. we
admit a gap instead of asserting a wrong population.
"""
import ast
from pathlib import Path

import degradation as D
import run_light
from run_light import methods_check_is_degraded


# ── The mappings that SHOULD still assert transport ───────────────────

def test_documented_transport_codes_still_map_to_transport():
    """⚠ Test the case the mapping should PASS (the ㉟ lesson).

    A fix that made EVERYTHING unclassified would also remove the false
    verdicts — and would be useless. curl 6/7/28 are documented, unambiguous
    transport failures and must still classify as transport.
    """
    for rc, expected in ((6, "network_unreachable"),
                         (7, "network_unreachable"),
                         (28, "network_timeout")):
        degraded, reason = methods_check_is_degraded(rc, "")
        assert degraded, f"rc={rc} should be degraded"
        assert reason == expected, f"rc={rc} -> {reason}, expected {expected}"
        assert D.classify_cut_reason(reason) == D.CUT_TRANSPORT, (
            f"rc={rc} reason {reason!r} must still classify as transport"
        )


# ── 🔴 THE LOAD-BEARING ASSERTION ─────────────────────────────────────

def test_unmapped_exit_is_unclassified_not_transport():
    """An exit code we have not mapped must NOT claim we failed to reach
    the target. This is the whole point of ㊴ probe 4.

    Under the old code every one of these returned `curl_failed`, which
    degradation.py maps to CUT_TRANSPORT.
    """
    # 35 = SSL connect error, 52 = empty reply, 56 = recv failure,
    # 60 = cert problem, 22 = HTTP error returned. None of these mean
    # "unreachable", and several occur on hosts that are plainly up.
    for rc in (22, 35, 52, 56, 60, 92, 246):
        degraded, reason = methods_check_is_degraded(rc, "")
        assert degraded, f"rc={rc} should still be degraded"
        assert reason == f"curl_exit_{rc}_unmapped", (
            f"rc={rc} produced {reason!r}"
        )
        cls = D.classify_cut_reason(reason)
        assert cls == D.CUT_UNCLASSIFIED, (
            f"rc={rc} reason {reason!r} classified as {cls!r}. An unmapped "
            f"curl exit must be an ADMITTED GAP, never a transport verdict — "
            f"that false verdict is 316 rows of the ~1066 that make TRANSPORT "
            f"look dominant on this fleet."
        )


def test_no_curl_failed_catchall_remains():
    """`curl_failed` must no longer be REACHABLE from this function.

    ⚠ Asserts on returned constants via ast, not source text. A grep here
    would match this module's own docstring, which discusses `curl_failed`
    at length — the source-pin-matches-prose mistake this repo has now made
    four times.
    """
    tree = ast.parse(Path(run_light.__file__).read_text())
    fn = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "methods_check_is_degraded"
    )
    returned = {
        c.value
        for node in ast.walk(fn)
        if isinstance(node, ast.Return)
        for c in ast.walk(node.value or ast.Constant(value=None))
        if isinstance(c, ast.Constant) and isinstance(c.value, str)
    }
    assert "curl_failed" not in returned, (
        f"methods_check_is_degraded can still return 'curl_failed'. Returns: {sorted(returned)}"
    )
    # Floor: if the shape changed and we found nothing, this would pass
    # by examining nothing.
    assert len(returned) >= 2, (
        f"only {len(returned)} return-string(s) found — function shape changed "
        f"and this check is now vacuous: {returned}"
    )


def test_curl_failed_stays_mapped_for_historical_rows():
    """We stop EMITTING it; we must not stop UNDERSTANDING it.

    316 historical rows carry `curl_failed`. Removing its mapping would
    silently reclassify all of them as unclassified and change every
    retrospective cut-class count.
    """
    assert D.classify_cut_reason("curl_failed") == D.CUT_TRANSPORT


def test_nobody_added_a_curl_exit_prefix_mapping():
    """⚠ GUARD. The obvious 'cleanup' when `unclassified` appears in a
    group-by is to add a `curl_exit` prefix mapping. Doing that re-asserts
    the exact verdict ㊴ removes, and it would look like tidying.
    """
    offenders = [p for p, _cls in D._CUT_CLASS_PREFIXES if p.startswith("curl_exit")]
    assert offenders == [], (
        f"a curl_exit prefix mapping was added to _CUT_CLASS_PREFIXES: "
        f"{offenders}. An unmapped curl exit is an ADMITTED GAP by design. "
        f"If real evidence now exists for what a specific code means, map "
        f"that ONE code explicitly in methods_check_is_degraded instead."
    )


# ── Non-degraded path ─────────────────────────────────────────────────

def test_rc_zero_is_not_degraded():
    assert methods_check_is_degraded(0, "HTTP/1.1 200 OK\nAllow: GET, POST") == (False, "")


def test_nonzero_rc_with_output_is_not_degraded():
    """curl returned something usable despite a non-zero rc — the probe can
    still be read, so this is not a degradation. Unchanged behaviour,
    pinned so the rewrite did not quietly alter the trigger."""
    degraded, _ = methods_check_is_degraded(52, "HTTP/1.1 200 OK\nAllow: GET")
    assert not degraded
