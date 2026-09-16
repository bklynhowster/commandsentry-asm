#!/usr/bin/env python3
"""U7 alive clock + U6 resurrection hook — relay 155/158, 2026-09-15.

⛔ THE TWO DEFECTS.

U7 — `assets.last_alive_at` was written in exactly two places, both DISCOVERY: the ASM
importer's UPSERTs, and run_light's promote branch, which is gated
`WHERE discovery_status IN ('ct_ghost','unverified','dns_only')`. Once an asset is
confirmed_live it stops matching, so light stops bumping it; medium and heavy never wrote to
`assets` at all. www.prodexlabs.com had six completed scans and forty liveness verdicts since
2026-09-05 and still read "last observed Sep 5" on its own page — and asm_cron declared the
company website DARK three days after a heavy scan of it.

U6 — UPSERT_ASSET's no-downgrade CASE promotes only from ('ct_ghost','unverified','dns_only').
A dark asset is not in that list, so re-observing it live never brings it back. The importer
had no path to undo a demotion, which is why demotion_writer's --write-enable gate has been
OVERDUE since 2026-07-26: its own docstring names this hook as a required companion.
"""

from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import asset_liveness as al  # noqa: E402


# ---------------------------------------------------------------------------
# U7 — what counts as "this observation got an answer"
# ---------------------------------------------------------------------------

def test_naabu_ports_prove_alive():
    """light + heavy: svc_count is the SAME signal discovery_status_from_service_count
    uses to promote, so the clock and the promote agree by construction."""
    assert al.observation_proves_alive(svc_count=1) is True
    assert al.observation_proves_alive(svc_count=7) is True


def test_zero_ports_do_not_prove_alive():
    """A naabu-firewalled rescan seeing 0 ports must not move the clock. An unbumped
    clock is recoverable; a falsely-bumped one hides a dead host."""
    assert al.observation_proves_alive(svc_count=0) is False


def test_medium_uses_httpx_because_it_has_no_naabu():
    """⛔ Medium runs NO naabu, so relay 155's "svc_count > 0, the same signal the
    promote uses" cannot apply. httpx IS an HTTP prober: a clean httpx run is positive
    evidence the host answered on 80/443."""
    # ⚠ The REAL name medium marks is "httpx[-td]" — not a bare "httpx". The first
    # draft of this test asserted on "httpx", which existed only in the predicate
    # tuple and in this assertion: a name with no producer, agreeing with itself.
    assert al.observation_proves_alive(tool_status={"httpx[-td]": "ok"}) is True
    assert al.observation_proves_alive(tool_status={"httpx_tech": {"status": "ok"}}) is True


def _marks_and_routes(runner_src: str):
    """What a runner MARKS, and what it ROUTES to bump_alive_clock.

    ⚠ VERSION 1 READ ONLY LITERAL ARGUMENTS — `mark_tool_ok(ctx, "naabu")` — so it
    could not see run_heavy, which does `tool_name = "httpx"` and marks through the
    variable. On that blindness I wrote in a comment that a bare "httpx" is produced
    by NOBODY. 4.7 measured and corrected it (relay 166). The conclusion (drop it)
    survived; the stated reason did not.

    ⚠ VERSION 2 RESOLVED VARIABLES WITH A FLAT REGEX DICT AND WAS WORSE. `tool_name`
    is reassigned in every phase function of run_heavy, so one file-wide dict kept
    only the LAST value and confidently reported heavy as marking {gau, fingerprintx,
    naabu}. It failed loudly here, which is the only reason it is a footnote instead
    of another shipped wrong comment.

    THIS VERSION resolves per FUNCTION, via AST. That is deliberately NOT the scope
    analyser 4.7 stopped us writing: no closures, no global/nonlocal, no
    comprehension scopes — one level, literal string assignments inside the function
    that also contains the mark call. An unresolvable name is simply skipped, so the
    failure mode is a FALSE ALARM in the coupling test (a probe name it cannot see
    is a name it will demand be added), which is loud and fixable. It never fails by
    silently approving.
    """
    import ast

    marked = set()
    try:
        tree = ast.parse(runner_src)
    except SyntaxError:
        return marked, False

    def literal_assigns(fn_node):
        out = {}
        for n in ast.walk(fn_node):
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) \
                    and isinstance(n.value.value, str):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        out[t.id] = n.value.value
        return out

    def harvest(scope_node, local_names):
        for n in ast.walk(scope_node):
            if not isinstance(n, ast.Call):
                continue
            fn = n.func
            name = fn.attr if isinstance(fn, ast.Attribute) else \
                   (fn.id if isinstance(fn, ast.Name) else "")
            if name.startswith("mark_tool_") and len(n.args) >= 2:
                a = n.args[1]
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    marked.add(a.value)
                elif isinstance(a, ast.Name) and a.id in local_names:
                    marked.add(local_names[a.id])
            elif name == "append" and isinstance(fn, ast.Attribute) \
                    and getattr(fn.value, "attr", "") == "tools_run" and n.args:
                a = n.args[0]
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    marked.add(a.value)
                elif isinstance(a, ast.Name) and a.id in local_names:
                    marked.add(local_names[a.id])

    module_names = {}
    for n in tree.body:
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) \
                and isinstance(n.value.value, str):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    module_names[t.id] = n.value.value

    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            harvest(n, {**module_names, **literal_assigns(n)})

    routes_tool_status = False
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            fn = n.func
            nm = fn.attr if isinstance(fn, ast.Attribute) else \
                 (fn.id if isinstance(fn, ast.Name) else "")
            if nm == "bump_alive_clock" and any(k.arg == "tool_status" for k in n.keywords):
                routes_tool_status = True
    return marked, routes_tool_status


def _runner_sources() -> dict:
    import glob
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scanner")
    return {os.path.basename(f): open(f).read()
            for f in glob.glob(os.path.join(d, "run_*.py"))}


def test_every_probe_tool_name_has_a_real_producer():
    """The tuple must not contain decoration. Kept, but no longer the WHOLE
    story — being produced is only half of being reachable; see the coupling
    test below, which is the half that actually bites."""
    produced = set()
    for src in _runner_sources().values():
        produced |= _marks_and_routes(src)[0]
    for name in al._HTTP_PROBE_TOOLS:
        assert name in produced, (
            f"{name!r} is in _HTTP_PROBE_TOOLS but no runner marks it — "
            f"drop it or point it at a real producer"
        )


def test_a_runner_that_routes_tool_status_must_have_its_probe_names_here():
    """⛔ THE COUPLING GUARD (4.7, relay 166). A comment guards nothing.

    THE SCENARIO, and it is not hypothetical on the FortiGate fleet: heavy falls
    back to routing `tool_status` when naabu is blocked — a WAF can block naabu
    while the host still answers HTTP. Heavy marks "httpx". This tuple does not
    contain "httpx". observation_proves_alive returns False, the clock is never
    bumped, and the host drifts toward looking DARK while it is plainly alive.

    That failure is SILENT and slow: no exception, no red test, an asset quietly
    fading — the exact class the whole U7/U6 lane exists to close. So the build
    fails on the day the coupling changes, not on the day someone notices an
    asset went dark.

    Scope: httpx-family names only. A runner routing tool_status also marks nikto,
    katana, wafw00f — none are HTTP LIVENESS probes, and demanding they be in the
    tuple would make this fire constantly and get deleted.
    """
    problems = []
    for fname, src in sorted(_runner_sources().items()):
        marked, routes = _marks_and_routes(src)
        if not routes:
            continue
        for name in sorted(n for n in marked if n.split("[")[0].split("_")[0] == "httpx"):
            if name not in al._HTTP_PROBE_TOOLS:
                problems.append(
                    f"{fname} routes tool_status= to bump_alive_clock and marks "
                    f"{name!r}, which is NOT in _HTTP_PROBE_TOOLS — a clean probe "
                    f"there will not bump the alive clock, and the asset will fade"
                )
    assert not problems, "probe-name / routing coupling broken:\n  " + "\n  ".join(problems)


def test_the_reachability_table_in_the_comment_is_still_true():
    """Pins the CORRECTED reason, because the wrong one shipped in a comment and
    only a measurement caught it. Exactly one name is reachable today: medium is
    the only runner routing tool_status. If that changes, this fails and the
    comment gets rewritten deliberately rather than drifting."""
    routing = {f: _marks_and_routes(src)[1] for f, src in _runner_sources().items()}
    routers = sorted(f for f, r in routing.items() if r)
    assert routers == ["run_medium.py"], (
        f"exactly one runner should route tool_status today; found {routers}. "
        f"If this is intentional, update the reachability table in asset_liveness.py "
        f"and the coupling test above will tell you which names must be added."
    )
    # and heavy really does produce the bare name — the fact 4.7 corrected
    heavy = _runner_sources().get("run_heavy.py", "")
    assert "httpx" in _marks_and_routes(heavy)[0], (
        "run_heavy no longer marks a bare 'httpx' — if that is deliberate, the "
        "reachability table in asset_liveness.py needs updating too"
    )


def test_a_degraded_http_probe_does_not_prove_alive():
    assert al.observation_proves_alive(tool_status={"httpx[-td]": "degraded"}) is False
    assert al.observation_proves_alive(tool_status={"httpx[-td]": "skipped"}) is False


def test_no_evidence_means_no_bump():
    """⛔ THE LOAD-BEARING CASE. Bumping because close_out was *reached* would infer
    liveness from the absence of a crash — the exact error class this lane exists to
    kill (the digest's '0 findings', the enrich worker's 'No findings match')."""
    assert al.observation_proves_alive() is False
    assert al.observation_proves_alive(tool_status={}) is False
    assert al.observation_proves_alive(tool_status={"nikto": "ok"}) is False, \
        "a non-probe tool completing says nothing about whether the HOST answered"


def test_garbage_svc_count_does_not_crash_or_bump():
    assert al.observation_proves_alive(svc_count="two") is False
    assert al.observation_proves_alive(svc_count=None) is False


# ---------------------------------------------------------------------------
# U7 — the SQL itself
# ---------------------------------------------------------------------------

def test_alive_clock_sql_never_regresses_the_clock():
    """GREATEST, not assignment: a late-arriving slow scan must not rewind a newer stamp."""
    assert "GREATEST(last_alive_at, now())" in al.ALIVE_CLOCK_SQL


def test_alive_clock_sql_has_NO_discovery_status_filter():
    """⛔ THE WHOLE POINT. The promote-only filter is what stopped light refreshing the
    clock on confirmed_live assets. The clock records an observation, not a transition."""
    assert "discovery_status" not in al.ALIVE_CLOCK_SQL


def test_alive_clock_does_not_touch_last_probe_alive_at():
    """161 Q6 keeps the probe clock separate — it is a RESCUE record (written only when
    the dark gate saves a stale asset), not a freshness record. 155 ②: do not fold them."""
    assert "last_probe_alive_at" not in al.ALIVE_CLOCK_SQL


class _Cur:
    def __init__(self):
        self.calls = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))


def test_bump_runs_the_update_only_when_alive_is_proven():
    c = _Cur()
    assert al.bump_alive_clock(c, "a.example", svc_count=2) is True
    assert len(c.calls) == 1 and c.calls[0][1] == ("a.example",)

    c2 = _Cur()
    assert al.bump_alive_clock(c2, "a.example", svc_count=0) is False
    assert c2.calls == [], "no evidence must mean no statement, not a no-op UPDATE"


# ---------------------------------------------------------------------------
# U6 — resurrection
# ---------------------------------------------------------------------------

def _importer_src() -> str:
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "import_asm_to_surface.py")
    src = open(p).read()
    return "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))


# ⛔ THE AST NAME-RESOLUTION GUARD THAT USED TO LIVE HERE IS GONE — ON PURPOSE.
#
# It was written after `resurrect_if_dark(cur, bucket_id, logfn=log)` shipped into
# a module that has no `log`. Version 1 used a regex and FAILED ON THE FIXED TREE,
# matching `logfn=log` inside the fix's own comment. Version 2 walked the AST and
# killed the mutant correctly.
#
# ⚠ 4.7 (relay 164) stopped version 2 from shipping, and was right. Python scope
# analysis is hard — closures, comprehension scopes, global/nonlocal, star-imports,
# conditional and try/except definitions, del — and a hand-rolled walker fails by
# FALSE NEGATIVE, which in a guard is strictly worse than the false positive that
# had just been caught. `pyflakes` has done this correctly for fifteen years, it
# names file:line:col, and run against the broken tree it found not one undefined
# name but TWO: the shipped `log`, and `utc_now` in the phantom path, latent since
# 2026-06-06 and invisible to 1358 passing tests.
#
# ⇒ The guard is now lane 6 in tests.yml: pyflakes over the whole tree, failing on
#   any `undefined name`, no baseline file. Before building a new instrument,
#   check whether a standard one already exists.

def test_resurrection_handles_BOTH_dark_vocabularies():
    """⛔ CHECK constraint 20260711a:52 admits 'confirmed_dark' AND 'went_dark'.
    demotion_writer writes 'went_dark'; the one dark row on Command today is
    'confirmed_dark'. A hook matching only one strands the other permanently.

    ⚠ READS THE MODULE ATTRIBUTE, NOT THE SOURCE TEXT. The earlier version grepped
    import_asm_to_surface.py, which (a) broke the moment the hook legitimately moved
    to asset_liveness.py, and (b) is the source-grep family that has produced four
    false results in one day. `al._DARK_STATUSES` being a tuple IS the proof that it
    is a named constant rather than something inlined at a call site.
    """
    assert isinstance(al._DARK_STATUSES, tuple)
    assert set(al._DARK_STATUSES) == {"confirmed_dark", "went_dark"}
    assert "%(dark_statuses)s" in al.RESURRECT_ASSET_SQL, \
        "the statement must take the set as a parameter, not inline one status"


def test_resurrection_clears_every_dark_field_in_one_statement():
    """Atomic: a half-resurrected asset (status live, went_dark_at still set) would
    make the demotion writer's own staleness read inconsistent with the row."""
    sql = al.RESURRECT_ASSET_SQL
    for field in ("went_dark_at", "fade_detected_at", "dark_reason"):
        assert re.search(rf"{field}\s*=\s*NULL", sql), f"{field} not cleared"
    assert re.search(r"resurrection_count\s*=\s*COALESCE\(resurrection_count, 0\) \+ 1", sql)
    assert re.search(r"last_transition_at\s*=\s*now\(\)", sql)
    assert sql.count("UPDATE public.assets") == 1, "must be ONE statement"


def test_resurrection_only_matches_dark_assets():
    """It now runs on EVERY proven-alive observation from all four writers, so for
    the overwhelming majority of assets the WHERE must match nothing and the call
    must be a no-op."""
    assert "discovery_status = ANY(" in al.RESURRECT_ASSET_SQL


def test_upsert_still_cannot_resurrect_on_its_own():
    """The no-downgrade CASE must stay as it is — resurrection is an explicit, logged,
    countable transition, not a silent side effect of a routine UPSERT."""
    src = _importer_src()
    i = src.index("UPSERT_ASSET =")
    upsert = src[i:src.index('"""', src.index('"""', i) + 3)]
    assert "'ct_ghost', 'unverified', 'dns_only'" in upsert
    assert "went_dark" not in upsert and "confirmed_dark" not in upsert

# ---------------------------------------------------------------------------
# Q7 — the scanners must resurrect too, not only bump the clock (relay 167/169)
# ---------------------------------------------------------------------------

def test_every_module_that_bumps_the_clock_also_resurrects():
    """⛔ THE STATIC PIN FOR THE Q7 DEFECT (4.7, relay 167).

    resurrect_if_dark lived in import_asm_to_surface.py ONLY. All three scanners
    called bump_alive_clock — which has no discovery_status filter, by design —
    and none of them could resurrect, because they cannot import the importer. A
    dark asset that was scanned and ANSWERED came out `went_dark` with a fresh
    last_alive_at: "dead" and "answered a minute ago" in one row, permanently.

    ⚠ It was reachable by the most human action available. Automatic enqueueing
    filters to confirmed_live (enqueue-fleet.yml:140, seed-device-class.yml:89),
    but that filter is there for AUTHORIZATION SCOPE and protected us by
    coincidence. The per-asset RUN SCAN button has no status filter at all. So:
    someone distrusts a "dark" label, presses Run Scan, the scan succeeds, and
    the card still says dark. Worst for manually-added assets ASM never
    enumerates — for those the resurrection path would never have run at all.

    The two halves are now one import away from each other in asset_liveness.py.
    This fails the build if any future writer takes the clock without the revival.
    """
    import glob
    here = os.path.dirname(os.path.abspath(__file__))
    paths = glob.glob(os.path.join(here, "*.py")) + \
            glob.glob(os.path.join(here, "..", "scanner", "run_*.py"))

    problems = []
    for p in paths:
        if os.path.basename(p).startswith("test_"):
            continue
        src = open(p).read()
        src_code = "\n".join(l for l in src.splitlines()
                             if not l.strip().startswith("#"))
        if "bump_alive_clock(" not in src_code:
            continue
        if "def bump_alive_clock(" in src_code:      # the SSOT itself
            continue
        if "resurrect_if_dark(" not in src_code:
            problems.append(
                f"{os.path.basename(p)} calls bump_alive_clock but never "
                f"resurrect_if_dark — a dark asset observed alive here would stay "
                f"dark forever with a fresh last_alive_at"
            )
    assert not problems, "clock/resurrection asymmetry:\n  " + "\n  ".join(problems)


def test_the_resurrection_hook_lives_in_the_shared_module_not_the_importer():
    """Pins the MOVE, not just the calls. If someone relocates it back into the
    importer, the scanners silently lose it again — the exact regression."""
    assert hasattr(al, "resurrect_if_dark") and hasattr(al, "RESURRECT_ASSET_SQL")
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "import_asm_to_surface.py")).read()
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    assert "def resurrect_if_dark(" not in code, (
        "resurrect_if_dark has been redefined inside the importer — it belongs "
        "beside bump_alive_clock in asset_liveness so all four writers share it"
    )


class _ResCur:
    """Records statements; answers the resurrect RETURNING with a count or None."""
    def __init__(self, resurrect_row=None):
        self.calls = []
        self._last = ""
        self._row = resurrect_row

    def execute(self, sql, params=None):
        self._last = " ".join(str(sql).split())
        self.calls.append((self._last, params))

    def fetchone(self):
        return self._row if "resurrection_count" in self._last else None


def test_clock_then_resurrect_in_that_order_on_proven_evidence():
    """⭐ THE DYNAMIC HALF. Drives the real shared functions in the order the
    runners now call them, so the sequence is executed rather than grepped.
    Order matters: a resurrected asset must already carry a fresh last_alive_at
    when its status flips, or the demotion writer's own staleness read is
    inconsistent with the row it just revived."""
    cur = _ResCur(resurrect_row=(2,))
    assert al.bump_alive_clock(cur, "dark.example", svc_count=3) is True
    n = al.resurrect_if_dark(cur, "dark.example")
    assert n == 2

    stmts = [s for s, _ in cur.calls]
    clock = [i for i, s in enumerate(stmts) if "last_alive_at = GREATEST" in s]
    res = [i for i, s in enumerate(stmts) if "resurrection_count" in s]
    assert clock and res and clock[0] < res[0], \
        "the clock must be stamped BEFORE the status flips"


def test_no_evidence_means_neither_statement_runs():
    """The runners gate the resurrection on bump_alive_clock's return value, so a
    scan that proved nothing must issue NO statements at all — not a clock bump
    without a revival, and not a revival on unproven evidence."""
    cur = _ResCur()
    assert al.bump_alive_clock(cur, "x.example", svc_count=0) is False
    assert cur.calls == []


def test_resurrect_is_a_no_op_for_an_asset_that_was_not_dark():
    cur = _ResCur(resurrect_row=None)
    assert al.resurrect_if_dark(cur, "live.example") is None
    assert len(cur.calls) == 1, "still exactly one statement, matching nothing"

if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
