"""KB 12 job 4v (2026-11-06) — the script-rule check is LOW.

Howie, 07:38, on the dailies leading with this check day after day: "its too unimportant and
repetitive"; 08:03: "yes" (rate it Low, with the compressed-pages check, one job). Pinned here:
  - every policy that does not limit scripts gives a LOW finding, and so does eval() alone;
  - the several-policies rule still picks the tightest policy: with both findings LOW, the
    ranking must not read the rating (a 'not limited' policy beside an 'eval only' one is still
    the eval-only finding);
  - the finding's words no longer say it is rated like a missing Content-Security-Policy;
  - the quick scan never writes MODERATE for either check.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import csp_policy as cp  # noqa: E402

NOT_LIMITED = (
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",                     # the 22 Prodex app sites
    "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:",        # vpn, vpn2.sciimage.com
    "script-src 'self' *", "script-src https:", "script-src http: 'self'",
    "script-src https://*", "default-src data:",
    "frame-ancestors 'self'; object-src 'none'",                           # no rule for scripts
)
EVAL_ONLY = ("script-src 'self' 'unsafe-eval'", "default-src 'self' 'unsafe-eval'")


def test_every_case_is_low_and_keeps_its_own_check():
    for pol in NOT_LIMITED:
        f = cp.finding_fields("h.example.com", pol)
        assert (f["check_name"], f["severity"]) == (cp.CHECK_NOT_LIMITED, "LOW"), pol
        assert f["title"] == cp.TITLE_NOT_LIMITED
    for pol in EVAL_ONLY:
        f = cp.finding_fields("h.example.com", pol)
        assert (f["check_name"], f["severity"]) == (cp.CHECK_EVAL_ONLY, "LOW"), pol


def test_the_tightest_policy_still_wins_when_both_ratings_are_low():
    for weak in NOT_LIMITED:
        for ev in EVAL_ONLY:
            for header in (f"{weak}, {ev}", f"{ev}, {weak}", [weak, ev]):
                f = cp.finding_fields("h.example.com", header)
                assert f["check_name"] == cp.CHECK_EVAL_ONLY, header
            assert cp.finding_fields("h.example.com", f"{weak}, script-src 'self'") is None


def test_the_words_no_longer_compare_it_to_a_missing_policy():
    d = cp.finding_fields("uat.prodexlabs.com", NOT_LIMITED[0])["description"]
    assert "rated the same as a missing" not in d and "moderate" not in d.lower()
    assert "lets nothing in by itself" in d and "some other flaw" in d
    assert d.endswith("The rule that governs scripts: script-src 'self' 'unsafe-inline' 'unsafe-eval'")


def test_no_case_is_ever_moderate():
    policies = NOT_LIMITED + EVAL_ONLY + ("script-src 'self'", "", None, " , ")
    for a in policies:
        for b in policies:
            header = a if b is None else (f"{a}, {b}" if a is not None else b)
            f = cp.finding_fields("h", header)
            assert f is None or f["severity"] == "LOW", header
    assert not hasattr(cp, "MODERATE"), "no MODERATE left to write"
