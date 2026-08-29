#!/usr/bin/env python3
"""test_gau_harvest.py — gau invocation + yield-floor (fixed 2026-08-28).

WHY THIS FILE EXISTS. gau ran for five weeks reporting `ok: true` while
returning 3-4 URLs on every run across both estates — nearly all of them
http/https variants of the root. Nothing caught it because `ok` means only
"exit code 0 and a non-empty result".

Two defects, both ours:
  1. no `--subs`, so gau queried ONLY the exact hostname; archives index by
     exact hostname string, so records filed under any other host were skipped.
     ⚠ This did NOT explain commandcompanies.com's low yield — verified
     2026-08-28: the apex returns 200 and www 301-redirects TO it, so the apex
     is canonical and we were querying the right host. --subs remains correct
     for genuinely separate hosts (mail/portal/insite).
  2. the success log asserted "archives: wayback,commoncrawl,otx,urlscan" — a
     string WE hardcoded. We had no evidence any provider beyond the first
     responded.

Run: python3 test_gau_harvest.py
"""
from __future__ import annotations

import ast
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from run_heavy import (gau_harvest_shape, gau_yield_verdict,  # noqa: E402
                       gau_provider_failures)

SRC = (pathlib.Path(__file__).parent / "run_heavy.py").read_text()


def _fn_code(name: str) -> str:
    """Function CODE only — no comments, no docstring. A raw-text grep matches
    prose as readily as code; ast.unparse drops comments by construction."""
    tree = ast.parse(SRC)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            body = node.body
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                body = body[1:]
            return "\n".join(ast.unparse(n) for n in body)
    raise AssertionError(f"function {name!r} not found")


# ── gau_harvest_shape — the pure yield describer ───────────────────────────

def test_counts_non_root_paths_only():
    """Root variants tell us nothing DNS didn't already. Only real paths count."""
    urls = ["https://x.com/", "http://x.com/", "https://x.com"]
    assert gau_harvest_shape(urls, "x.com")["distinct_paths"] == 0


def test_trailing_slash_does_not_double_count_a_path():
    urls = ["https://x.com/about", "https://x.com/about/"]
    assert gau_harvest_shape(urls, "x.com")["distinct_paths"] == 1


def test_subdomain_urls_are_counted():
    """Direct evidence that --subs is earning its keep."""
    urls = ["https://x.com/", "https://www.x.com/a", "https://api.x.com/b"]
    s = gau_harvest_shape(urls, "x.com")
    assert s["subdomain_urls"] == 2
    assert s["distinct_hosts"] == 3


def test_apex_itself_is_not_counted_as_a_subdomain():
    assert gau_harvest_shape(["https://x.com/a"], "x.com")["subdomain_urls"] == 0


def test_lookalike_domain_is_not_a_subdomain():
    """notx.com must not match x.com — endswith without the dot would."""
    s = gau_harvest_shape(["https://notx.com/a"], "x.com")
    assert s["subdomain_urls"] == 0


def test_hostname_case_is_normalised():
    s = gau_harvest_shape(["https://WWW.X.COM/a"], "X.com")
    assert s["subdomain_urls"] == 1


def test_malformed_urls_do_not_raise():
    s = gau_harvest_shape(["", "not a url", "https://x.com/a"], "x.com")
    assert s["distinct_paths"] == 1


def test_empty_harvest_is_safe():
    s = gau_harvest_shape([], "x.com")
    assert s["total_urls"] == 0 and s["distinct_paths"] == 0


def test_the_actual_2026_08_28_harvest_would_now_be_flagged():
    """REGRESSION FIXTURE — the real Command harvest that looked healthy.
    3 of its 4 URLs were root variants, scraping by with ONE path. Whether 4 is
    the TRUE archive count for this domain is still unknown; the point is that
    nothing distinguished a thin archive from a broken lookup, which is what
    the yield floor and provider parsing now fix."""
    real = ["http://commandcompanies.com/",
            "https://commandcompanies.com/",
            "https://commandcompanies.com/about/",
            "https://commandcompanies.com/"]
    s = gau_harvest_shape(real, "commandcompanies.com")
    assert s["distinct_paths"] == 1
    assert s["subdomain_urls"] == 0      # apex-only harvest


# ── invocation pins ────────────────────────────────────────────────────────

def test_subs_flag_is_passed():
    """Without --subs gau queries only the exact hostname, so archive records
    filed under any other host are skipped. NOT the cause of the
    commandcompanies.com low yield (apex is canonical there — verified), but
    correct for assets with genuinely separate hosts."""
    # ast.unparse normalises string quotes to single — assert on the
    # VALUE, not the source's quoting style.
    assert "'--subs'" in _fn_code("run_gau_phase")


def test_verbose_flag_is_passed():
    """So gau reports its own provider work instead of us asserting it."""
    assert "'--verbose'" in _fn_code("run_gau_phase")


def test_success_log_no_longer_fabricates_the_provider_list():
    """The old log claimed 'archives: wayback,commoncrawl,otx,urlscan' — our
    string, not gau's report. Evidence now comes from persisted stderr."""
    code = _fn_code("run_gau_phase")
    assert "wayback,commoncrawl,otx,urlscan" not in code


def test_gau_stderr_is_persisted_as_evidence():
    assert "'gau_stderr'" in _fn_code("run_gau_phase")


def test_yield_floor_flags_root_only():
    """Behaviour, not source text."""
    assert gau_yield_verdict({"distinct_paths": 0}) == "root_only_no_surface"


def test_yield_floor_passes_any_real_path():
    assert gau_yield_verdict({"distinct_paths": 1}) is None


def test_yield_floor_is_shape_based_not_count_based():
    """A tiny site with one real path is FINE; a big harvest of nothing but
    roots is NOT. Any URL-count threshold gets this backwards."""
    assert gau_yield_verdict(gau_harvest_shape(["https://x.com/a"], "x.com")) is None
    many_roots = ["https://x.com/", "http://x.com/", "https://www.x.com/",
                  "http://www.x.com/", "https://api.x.com/"]
    assert gau_yield_verdict(gau_harvest_shape(many_roots, "x.com")) == "root_only_no_surface"


def test_yield_floor_is_actually_wired_into_the_phase():
    """The pure function is useless if the phase does not call it."""
    assert "gau_yield_verdict(shape)" in _fn_code("run_gau_phase")


def test_urlparse_is_imported():
    """gau_harvest_shape calls urlparse. A missing import is a RUNTIME
    NameError, not a syntax error — py_compile passes clean and the phase
    explodes in production. That exact omission happened while writing this
    fix: compile was green, the helper would have crashed on first use."""
    imported = set()
    for node in ast.walk(ast.parse(SRC)):
        if isinstance(node, ast.ImportFrom) and node.module == "urllib.parse":
            imported |= {a.name for a in node.names}
    assert "urlparse" in imported, f"urllib.parse imports are {sorted(imported)}"


def test_helper_actually_executes():
    """Belt and braces: import-level pins can drift, calling it cannot."""
    s = gau_harvest_shape(["https://www.x.com/a"], "x.com")
    assert s == {"total_urls": 1, "distinct_hosts": 1, "distinct_paths": 1,
                 "subdomain_urls": 1, "hosts": ["www.x.com"]}


# ── provider failures — gau exits 0 even when every archive is down ────────
# VERBATIM stderr from the 2026-08-28 run on commandcompanies.com. rc was 0
# and the result was empty. Without this parse, an archives outage is
# indistinguishable from "this domain has no history".
REAL_STDERR = (
    'time="2026-08-28T17:55:16Z" level=warning msg="error reading config: '
    'Config file /github/home/.gau.toml not found, using default config"\n'
    'time="2026-08-28T17:56:01Z" level=warning msg="error instantiating '
    'commoncrawl: dial tcp4 54.237.141.66:80: connect: connection refused\\n"\n'
    'time="2026-08-28T17:56:01Z" level=info msg="fetching commandcompanies.com" '
    'page=0 provider=wayback\n'
    'time="2026-08-28T17:56:08Z" level=warning msg="commandcompanies.com - '
    'failed to fetch wayback results page 0: API responded with non-200 '
    'status code" provider=wayback'
)


def test_detects_both_real_provider_failures():
    f = gau_provider_failures(REAL_STDERR)
    assert "commoncrawl" in f, f
    assert "wayback" in f, f


def test_clean_stderr_reports_no_failures():
    clean = ('time="..." level=warning msg="error reading config: Config file '
             'not found, using default config"')
    assert gau_provider_failures(clean) == []


def test_empty_stderr_is_safe():
    assert gau_provider_failures("") == []
    assert gau_provider_failures(None) == []


def test_retries_flag_is_passed():
    """Archives are routinely flaky and rc=0 hides it."""
    assert "'--retries'" in _fn_code("run_gau_phase")


def test_evidence_is_persisted_unconditionally_not_only_on_success():
    """🔴 The artifact append was originally guarded by `if urls:`, so the FIRST
    real failure persisted nothing and had to be diagnosed from the Actions log.
    The append must precede the degradation return."""
    code = _fn_code("run_gau_phase")
    append = code.index("ctx.artifacts.append")
    degrade = code.index("mark_tool_degraded")
    assert append < degrade, "evidence must be written before any early return"


def test_provider_failure_is_a_distinct_reason_from_no_urls():
    """'the archives were down' and 'this domain has no history' are different
    facts and must not collapse into one degradation reason."""
    assert "providers_failed_" in _fn_code("run_gau_phase")


def test_provider_parser_is_actually_called_with_real_stderr():
    """🔴 THIRD TIME THIS PATTERN BIT TODAY. Testing a pure function and
    separately asserting a string exists proves nothing about whether the
    caller wires them together — replacing the call with `failed_providers=[]`
    passed 25/25. Every extracted helper needs a pin that the phase CALLS it,
    with the right argument.

    Prior instances: gau_yield_verdict (mutation to `if False:` passed),
    ThreadPoolExecutor shutdown (presence-of-good rather than absence-of-bad)."""
    code = _fn_code("run_gau_phase")
    assert "gau_provider_failures(stderr)" in code


if __name__ == "__main__":
    tests = [(n, o) for n, o in sorted(globals().items())
             if n.startswith("test_") and callable(o)]
    assert len(tests) >= 25, f"expected >=15 tests, collected {len(tests)}"
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {name}: {e}")
    print(f"\n{len(tests) - failed} / {len(tests)} passed")
    sys.exit(1 if failed else 0)
