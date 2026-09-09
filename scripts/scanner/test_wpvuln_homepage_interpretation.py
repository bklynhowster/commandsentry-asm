"""test_wpvuln_homepage_interpretation.py — ㊴ probe 3, interpretation fix.

WHY THIS EXISTS (2026-09-09). probe 3's homepage fetch collapsed
`rc != 0 or not html` into one reason, `homepage_fetch_failed`, which
degradation.py maps to CUT_TRANSPORT — "we never reached the target".

That reason is 265 of the ~1066 occurrences that make TRANSPORT the dominant
cut class on this fleet, second only to `curl_failed`'s 316. Both light-tier,
both over-claiming. Correcting them materially changes a headline number the
coverage specs have been reasoning from.

⚠ probe 3 STAYS ON CURL and that is MEASURED, not lazy. Inventory run #9,
against a real www->apex 301:

    no -fr :  status 301, wp-content occurrences = 0
    -fr    :  status 200, wp-content occurrences = 46

-fr is mandatory (without it every redirecting asset reads "not WordPress"
and mark_tool_ok fires — a healthy-looking total loss of WP CVE coverage).
But under -fr, httpx's `url` still echoes the INPUT, so nothing reports where
we landed and the ratified "never follow a redirect off eTLD+1" guard cannot
be enforced from httpx output. -include-chain reintroduces the control-char
parse error that killed -irr. curl -w %{url_effective} does report it.
"""
import ast
from pathlib import Path

import degradation as D
import run_light
from run_light import wpvuln_homepage_is_degraded


# ── the case it should PASS ───────────────────────────────────────────

def test_successful_fetch_is_not_degraded():
    """⚠ Test the case the check should PASS (the ㉟ lesson). A fix that
    degraded everything would also remove the false verdicts, uselessly."""
    assert wpvuln_homepage_is_degraded(0, "<html>wp-content</html>") == (False, "")


# ── real transport stays transport ────────────────────────────────────

def test_documented_transport_codes_still_classify_as_transport():
    for rc, expected in ((6, "network_unreachable"),
                         (7, "network_unreachable"),
                         (28, "network_timeout")):
        degraded, reason = wpvuln_homepage_is_degraded(rc, "")
        assert degraded and reason == expected
        assert D.classify_cut_reason(reason) == D.CUT_TRANSPORT


# ── 🔴 the two over-claims this removes ───────────────────────────────

def test_reached_but_empty_body_is_not_transport():
    """rc == 0 means curl COMPLETED. The host answered; it just answered with
    nothing. Calling that 'never reached the target' is the same over-claim
    in a different costume."""
    degraded, reason = wpvuln_homepage_is_degraded(0, "")
    assert degraded and reason == "empty_homepage_body"
    assert D.classify_cut_reason(reason) != D.CUT_TRANSPORT, (
        "an empty body from a host that ANSWERED was classified as transport"
    )


def test_unmapped_exit_is_unclassified_not_transport():
    for rc in (22, 35, 52, 56, 60, 92):
        degraded, reason = wpvuln_homepage_is_degraded(rc, "")
        assert degraded and reason == f"curl_exit_{rc}_unmapped"
        assert D.classify_cut_reason(reason) == D.CUT_UNCLASSIFIED, (
            f"rc={rc} still claims a transport verdict"
        )


def test_homepage_fetch_failed_is_no_longer_emitted():
    """⚠ ast on returned constants, not a grep — this module's docstring
    discusses `homepage_fetch_failed` at length and a text pin would match
    prose. Fifth time that trap would have fired in this repo."""
    tree = ast.parse(Path(run_light.__file__).read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "wpvuln_homepage_is_degraded")
    returned = {
        c.value
        for node in ast.walk(fn) if isinstance(node, ast.Return)
        for c in ast.walk(node.value or ast.Constant(value=None))
        if isinstance(c, ast.Constant) and isinstance(c.value, str)
    }
    assert "homepage_fetch_failed" not in returned, (
        f"still returns the blanket transport reason: {sorted(returned)}"
    )
    assert len(returned) >= 3, f"shape changed; check is vacuous: {returned}"


def test_homepage_fetch_failed_stays_mapped_for_history():
    """265 historical rows carry it. We stop emitting it; we must not stop
    understanding it."""
    assert D.classify_cut_reason("homepage_fetch_failed") == D.CUT_TRANSPORT


def test_client_import_failed_path_is_untouched():
    """The OTHER degraded reason wpvulnerability can raise is a genuine env
    bug and must keep behaving exactly as before."""
    from run_light import wpvuln_lookup_is_degraded
    assert wpvuln_lookup_is_degraded("client_import_failed") == (True, "client_import_failed")
    # the two HEALTHY skips must stay healthy
    assert wpvuln_lookup_is_degraded("not_wordpress") == (False, "")
    assert wpvuln_lookup_is_degraded("no_versions_detected") == (False, "")


def test_probe_3_still_follows_redirects():
    """🔴 REGRESSION GUARD, measured in inventory run #9.

    Dropping -L (or porting to httpx without -fr) makes a redirecting asset's
    homepage a 301 stub: wp-content occurrences fall 46 -> 0, the
    `"wp-content" not in html` branch fires, and wpvulnerability calls
    mark_tool_ok. Healthy-looking, and WP CVE coverage silently disappears on
    every www asset with an apex sibling.
    """
    tree = ast.parse(Path(run_light.__file__).read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "check_wpvulnerability")
    argvs = [
        [el.value for el in a.elts if isinstance(el, ast.Constant)]
        for node in ast.walk(fn) if isinstance(node, ast.Call)
        for a in node.args if isinstance(a, ast.List) and a.elts
    ]
    curl_calls = [v for v in argvs if v and v[0] == "curl"]
    assert curl_calls, "no curl call found in check_wpvulnerability — did probe 3 move?"
    homepage = curl_calls[0]
    assert "-L" in homepage, (
        f"probe 3's homepage fetch lost -L: {homepage}. Run #9 measured "
        f"wp-content 46 -> 0 without redirect following."
    )
