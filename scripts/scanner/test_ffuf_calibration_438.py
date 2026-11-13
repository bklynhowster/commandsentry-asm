"""438 (2026-11-13): two made-up paths that get DIFFERENT answers are not a host that tells
real paths from fake ones.

Before ffuf runs, detect_ffuf_catchall asks the host for two paths that cannot exist. If both
answers agree, it knows what the host does with a path that is not there. Until 438, answers that
DISAGREED were read as "this host discriminates", and every ffuf result was then written as a
finding.

The live defect (the host name here is made up; the shapes are the ones recorded):
  A site answers every path with the same 3,080-byte page. A long tool run had just finished
  from the same exit, and the site's front door was refusing about half of what that exit sent
  (the health check one second later got a 403; 12 of the first chunk's 25 answers were 403s,
  two or three in every burst of five; none after the exit changed). The two calibration paths
  got two different answers (which two was not logged; the tests use the page and the
  refusal, the two things that exit was being given). Result: 85 "Accessible path" findings for one page, /actuator and
  /swagger among them and rated MODERATE, plus 12 "Forbidden endpoint" findings for refusals
  that had nothing to do with the path. Four days earlier, with both calibration answers the
  same, the same site produced one summary row.

Two made-up paths cannot differ in whether they exist. Different answers mean something between
the scanner and the host is not treating its requests alike, and no per-path result means
anything while that is so. The path check does not run on that scan, and says why.

Run:  pytest scripts/scanner/test_ffuf_calibration_438.py -v
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import degradation as D  # noqa: E402
import run_medium as M  # noqa: E402

PAGE = 3080            # the one page the made-up site serves for every path
REFUSAL = 316          # its front door's refusal page for a 21-character path

ECHO_BASE = "https://sso.example.test/oauth2/start"


def _two_probe(first, second):
    """_probe_calibration_path stub: `first` then `second`, each (status, location, size)."""
    seq = [first, second]
    calls = {"n": 0}

    def _stub(ctx):
        r = seq[calls["n"] % 2]
        calls["n"] += 1
        return r
    _stub.calls = calls
    return _stub


def _detect(monkeypatch, first, second):
    monkeypatch.setattr(M, "_probe_calibration_path", _two_probe(first, second))
    ctx = types.SimpleNamespace(hostname="h.example.test")
    return M.detect_ffuf_catchall(ctx), ctx


# ═══════════════════════════════════════════════════════════════════════
# The decision: detect_ffuf_catchall
# ═══════════════════════════════════════════════════════════════════════

def test_one_made_up_path_served_and_the_other_refused(monkeypatch):
    """THE FIX. 200 for one made-up path and 403 for the other is not a host telling real
    from fake. Calibration is not clean, and nothing is set that could suppress or allow.
    (The recorded scan did not log its two statuses. 200 and 403 are the reproduction: they
    are the two answers that exit was getting from the site at that moment.)"""
    out, _ = _detect(monkeypatch, (200, None, PAGE), (403, None, REFUSAL))
    assert out == (None, None, None, False, None)


@pytest.mark.parametrize("first, second", [
    ((403, None, REFUSAL), (200, None, PAGE)),          # the same thing, other order
    ((200, None, 870), (404, None, 400)),               # the case the old test called "discriminating"
    ((404, None, 400), (200, None, 870)),
    ((200, None, PAGE), (429, None, 120)),              # a rate limit that says so
    ((503, None, 0), (200, None, PAGE)),
    ((401, None, 50), (403, None, 60)),
    ((404, None, 400), (403, None, REFUSAL)),           # a normal host whose front door refused one
    ((302, "https://sso.example.test/login", None), (200, None, PAGE)),
    ((200, None, PAGE), (302, "https://sso.example.test/login", None)),
    ((301, "https://a.example.test/x", None), (302, "https://b.example.test/y", None)),
])
def test_any_two_different_statuses_are_not_a_clean_calibration(monkeypatch, first, second):
    out, _ = _detect(monkeypatch, first, second)
    assert out == (None, None, None, False, None), (first, second, out)


def test_two_not_founds_is_still_a_host_that_discriminates(monkeypatch):
    """The one trustworthy "no catch-all": both made-up paths were not found."""
    out, _ = _detect(monkeypatch, (404, None, 400), (404, None, 400))
    assert out == (None, None, None, True, None)


@pytest.mark.parametrize("first, second, expected", [
    # both the same non-404 status: the status catch-all, with and without a stable size
    ((200, None, PAGE), (200, None, PAGE), (None, 200, PAGE, True, None)),
    ((200, None, 870), (200, None, 915), (None, 200, None, True, None)),
    ((403, None, REFUSAL), (403, None, REFUSAL), (None, 403, REFUSAL, True, None)),
    # both redirected to the same place: the redirect catch-all (the codes may differ)
    ((302, "/login", None), (302, "/login", None), ("/login", None, None, True, None)),
    ((301, "/login", None), (302, "/login", None), ("/login", None, None, True, None)),
    # both redirected with the made-up path echoed back: the pattern
    ((302, f"{ECHO_BASE}?rd=%2Fcs-calib-aaaaaaaaaaaa", None),
     (302, f"{ECHO_BASE}?rd=%2Fcs-calib-bbbbbbbbbbbb", None), (None, None, None, True, (ECHO_BASE, "rd"))),
])
def test_answers_that_agree_decide_exactly_as_before(monkeypatch, first, second, expected):
    out, _ = _detect(monkeypatch, first, second)
    assert out == expected


def test_the_same_redirect_status_to_two_unrelated_places_is_unchanged(monkeypatch):
    """OUT OF SCOPE, PINNED. Same status, different Locations, no echo: per-path emission as
    before. Whether that should collapse belongs to the sign-in wall plan, not to 438."""
    out, _ = _detect(monkeypatch, (302, "https://sso.example.test/a?state=111", None),
                     (302, "https://sso.example.test/b?state=222", None))
    assert out == (None, None, None, True, None)


def test_a_probe_with_no_answer_is_still_not_a_clean_calibration(monkeypatch):
    out, _ = _detect(monkeypatch, (0, None, None), (200, None, PAGE))
    assert out == (None, None, None, False, None)
    out, _ = _detect(monkeypatch, (200, None, PAGE), (0, None, None))
    assert out == (None, None, None, False, None)


def test_the_two_answers_are_kept_for_the_record(monkeypatch):
    _, ctx = _detect(monkeypatch, (200, None, PAGE), (403, None, REFUSAL))
    assert ctx.ffuf_calibration_probes == ((200, None, PAGE), (403, None, REFUSAL))
    _, ctx = _detect(monkeypatch, (404, None, 400), (404, None, 400))
    assert ctx.ffuf_calibration_probes == ((404, None, 400), (404, None, 400))


def test_a_first_probe_with_no_answer_is_kept_alone(monkeypatch):
    stub = _two_probe((0, None, None), (200, None, PAGE))
    monkeypatch.setattr(M, "_probe_calibration_path", stub)
    ctx = types.SimpleNamespace(hostname="h.example.test")
    assert M.detect_ffuf_catchall(ctx) == (None, None, None, False, None)
    assert ctx.ffuf_calibration_probes == ((0, None, None),)
    assert stub.calls["n"] == 1, "no second probe once the first got no answer (unchanged)"


# ═══════════════════════════════════════════════════════════════════════
# The pure pieces
# ═══════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("s1, s2, differ", [
    (200, 403, True), (403, 200, True), (200, 404, True), (301, 302, True),
    (200, 200, False), (404, 404, False), (403, 403, False),
    (0, 200, False), (200, 0, False), (0, 0, False),      # no answer is the other reason, not this one
])
def test_calibration_answers_differ(s1, s2, differ):
    assert M.calibration_answers_differ(s1, s2) is differ


def test_the_skip_reason_follows_what_the_probes_said():
    r = M.ffuf_calibration_skip_reason
    assert r(((200, None, PAGE), (403, None, REFUSAL))) == "catchall_calibration_inconclusive"
    assert r(((0, None, None),)) == "catchall_calibration_failed"
    assert r(((200, None, PAGE), (0, None, None))) == "catchall_calibration_failed"
    assert r(None) == "catchall_calibration_failed", "nothing recorded reads as no answer, never as a disagreement"
    assert r(()) == "catchall_calibration_failed"


def test_the_two_reasons_are_the_two_slugs_the_record_uses():
    assert M.FFUF_CALIB_NO_ANSWER == "catchall_calibration_failed"            # unchanged, in use since July
    assert M.FFUF_CALIB_ANSWERS_DIFFER == "catchall_calibration_inconclusive"


@pytest.mark.parametrize("probes, said", [
    (((200, None, PAGE), (403, None, REFUSAL)), "HTTP 200 (3080 bytes); HTTP 403 (316 bytes)"),
    (((200, None, None), (404, None, 0)), "HTTP 200; HTTP 404 (0 bytes)"),
    (((302, "/login", None), (200, None, PAGE)), "HTTP 302 to /login; HTTP 200 (3080 bytes)"),
    (((0, None, None),), "no answer"),
    (((200, None, PAGE), (0, None, None)), "HTTP 200 (3080 bytes); no answer"),
    (None, "not recorded"),
    ((), "not recorded"),
])
def test_describe_calibration_probes(probes, said):
    assert M.describe_calibration_probes(probes) == said


def test_a_long_location_is_cut_in_the_description():
    said = M.describe_calibration_probes(((302, "https://sso.example.test/" + "a" * 400, None),))
    assert len(said) < 140 and said.endswith("...")
    assert M.location_for_log("https://sso.example.test/" + "a" * 55) == "https://sso.example.test/" + "a" * 55, \
        "80 characters is not cut"


@pytest.mark.parametrize("location, shown", [
    # a Location can carry a signed query, a state value, a token: none of it goes in a log
    ("https://sso.example.test/oauth2/start?client_id=abc&state=SECRET", "https://sso.example.test/oauth2/start"),
    ("https://user:SECRET@sso.example.test:8443/login?next=%2Fx#SECRET", "https://sso.example.test:8443/login"),
    ("/login;jsessionid=SECRET?next=%2Fadmin", "/login"),
    ("/login?token=SECRET", "/login"),
    ("//cdn.example.test/a/b?sig=SECRET", "//cdn.example.test/a/b"),
    ("https://sso.example.test", "https://sso.example.test"),
    ("?only=SECRET", "(no host or path)"),
    ("https://[::1/broken?x=SECRET", "(a location that could not be read)"),
    ("https://sso.example.test:99999999/x?x=SECRET", "(a location that could not be read)"),
    (12345, "12345"),
])
def test_a_location_is_logged_without_its_query_or_credentials(location, shown):
    assert M.location_for_log(location) == shown
    assert "SECRET" not in M.describe_calibration_probes(((302, location, None), (200, None, PAGE)))


def test_no_part_of_a_redirect_query_reaches_the_log(monkeypatch):
    """The wiring: a sign-in redirect with a state value, against a page. The skip line and
    the probes line both name the host and path and neither carries the value."""
    h = _Harness(monkeypatch, (302, "https://sso.example.test/oauth2/start?state=SECRET-STATE-VALUE", None),
                 (200, None, PAGE))
    M.run_ffuf_chunked(_ctx())
    assert "SECRET" not in h.text
    assert h.text.count("HTTP 302 to https://sso.example.test/oauth2/start; HTTP 200 (3080 bytes)") == 2


def test_the_new_reason_classifies_beside_its_sibling():
    assert D.classify_cut_reason("catchall_calibration_inconclusive") == D.CUT_TOOL
    assert D.classify_cut_reason("catchall_calibration_failed") == D.CUT_TOOL
    assert D.classify_cut_reason("catchall_calibration_inconclusive") != D.CUT_UNCLASSIFIED


# ═══════════════════════════════════════════════════════════════════════
# The wiring: run_ffuf_chunked
# ═══════════════════════════════════════════════════════════════════════

def _ctx():
    return M.ScanContext(descriptor={}, hostname="h.example.test", asset_id="h.example.test",
                         scan_run_id="run-438", queue_id="q", intensity="medium")


class _Harness:
    """run_ffuf_chunked with everything that touches the network replaced."""

    def __init__(self, monkeypatch, first, second, answers=None):
        self.chunks_run: list[list[str]] = []
        self.rotations = 0
        self.health_gates = 0
        self.lines: list[str] = []
        self.answers = answers or {}
        monkeypatch.setattr(M, "_probe_calibration_path", _two_probe(first, second))
        monkeypatch.setattr(M, "log", self.lines.append)
        monkeypatch.setattr(M, "rotate_vpn", self._rotate)
        monkeypatch.setattr(M, "ensure_healthy_egress", self._gate)
        monkeypatch.setattr(M, "healthcheck_with_retry", lambda *a, **k: (True, 200, None))
        monkeypatch.setattr(M, "is_tool_output_degraded", lambda **k: None)
        monkeypatch.setattr(M, "run_ffuf_chunk", self._chunk)

    def _rotate(self, ctx):
        self.rotations += 1
        return True

    def _gate(self, ctx, max_rotations=2):
        self.health_gates += 1
        return True, ""

    def _chunk(self, ctx, words, chunk_name):
        """The emit loop's own decisions, on the answers this harness was given."""
        self.chunks_run.append(list(words))
        emitted = 0
        for w in words:
            status, size = self.answers.get(w, (200, PAGE))
            if M.should_suppress_ffuf_status(status, ctx.ffuf_catchall_status, "",
                                             result_size=size, baseline_size=ctx.ffuf_catchall_size):
                ctx.ffuf_catchall_status_count += 1
                continue
            emitted += 1
            kind = "Accessible path" if status == 200 else "Forbidden endpoint"
            ctx.findings.append(M.MediumFinding(
                check_name=f"ffuf-found-{w}", title=f"{kind}: /{w} (HTTP {status})",
                severity=M.classify_ffuf_severity(w, f"https://h.example.test/{w}", status),
                category="info_disclosure", description="d", tags=["ffuf"]))
        return emitted, "{}", {"results": []}, ""

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


# The first chunk exactly as recorded: two or three refusals in every burst of five.
REFUSED_IN_CHUNK_1 = ["api", "v1", "v2", "admin", "console", "manager", "config", "files",
                      "backup", "tmp", "internal", "new"]


def _recorded_answers():
    a = {w: (403, 292 + len(w) + 1) for w in REFUSED_IN_CHUNK_1}
    a["health"] = (200, 8)                 # the site's one real path
    return a


def _chunk_names():
    n = len(M.FFUF_WORDS)
    per = M.FFUF_WORDS_PER_CHUNK
    return [f"ffuf[{len(M.FFUF_WORDS[i:i + per])}w]#{i // per + 1}" for i in range(0, n, per)]


def test_a_scan_that_has_not_calibrated_has_no_answers_recorded():
    ctx = _ctx()
    assert ctx.ffuf_calibration_probes is None
    assert M.describe_calibration_probes(ctx.ffuf_calibration_probes) == "not recorded"
    assert "ffuf_calibration_probes" in {f.name for f in __import__("dataclasses").fields(M.ScanContext)}


def test_the_recorded_scan_now_writes_nothing(monkeypatch):
    """THE ACCEPTANCE, IN THE FORM THE MEASUREMENT TOOK. Calibration answers 200 and 403; the
    first chunk would have come back half refused. Not one per-path finding is written, no
    chunk is sent, and every chunk is on the record as skipped with the reason."""
    h = _Harness(monkeypatch, (200, None, PAGE), (403, None, REFUSAL), answers=_recorded_answers())
    ctx = _ctx()
    M.run_ffuf_chunked(ctx)

    assert ctx.findings == [], [f.title for f in ctx.findings]
    assert h.chunks_run == [], "no ffuf request is sent after a calibration that disagreed"
    assert ctx.tools_run == _chunk_names()
    assert ctx.tool_status == {n: {"skipped": "catchall_calibration_inconclusive"} for n in _chunk_names()}
    assert h.rotations == 0 and h.health_gates == 0
    assert (ctx.ffuf_catchall_redirect, ctx.ffuf_catchall_status,
            ctx.ffuf_catchall_size, ctx.ffuf_catchall_pattern) == (None, None, None, None)


def test_the_deep_scan_takes_the_same_path(monkeypatch):
    """The recorded scan was a deep scan. A deep scan runs this phase against its own context,
    through the recorder that keeps a legacy phase's bookkeeping apart. Same result there: no
    request, no finding, every chunk skipped with the reason, and the two answers kept on the
    real context."""
    import phase_contract as PC
    from run_heavy import HeavyScanContext
    real = HeavyScanContext(descriptor={}, hostname="h.example.test", asset_id="h.example.test",
                            scan_run_id="run-438", queue_id="q", intensity="heavy", dsn="")
    assert real.ffuf_calibration_probes is None
    recorder = PC._LegacyRecorder(real)
    h = _Harness(monkeypatch, (200, None, PAGE), (403, None, REFUSAL), answers=_recorded_answers())
    M.run_ffuf_chunked(recorder)

    assert recorder.findings == [] and h.chunks_run == []
    assert recorder.tools_run == _chunk_names()
    assert recorder.tool_status == {n: {"skipped": "catchall_calibration_inconclusive"} for n in _chunk_names()}
    assert real.ffuf_calibration_probes == ((200, None, PAGE), (403, None, REFUSAL))
    assert real.findings == [] and real.tool_status == {}, "the recorder, not the phase, credits the real scan"


def test_what_the_same_scan_wrote_before_438(monkeypatch):
    """The other half of the acceptance: the same answers with no baseline to compare them to
    (which is what the old reading of that calibration left) are the per-path findings that
    were written, the two MODERATE ones among them. If this stops being true, the test above
    is no longer guarding the recorded failure."""
    h = _Harness(monkeypatch, (404, None, 400), (404, None, 400), answers=_recorded_answers())
    ctx = _ctx()
    M.run_ffuf_chunked(ctx)                       # both 404: a real "no catch-all", per-path emission
    titles = [f.title for f in ctx.findings]
    accessible = [t for t in titles if t.startswith("Accessible path")]
    refused = [t for t in titles if t.startswith("Forbidden endpoint")]
    assert len(refused) == 12
    assert len(accessible) == len(M.FFUF_WORDS) - 12
    by_title = {f.title: f.severity for f in ctx.findings}
    assert by_title["Accessible path: /actuator (HTTP 200)"] == "MODERATE"
    assert by_title["Accessible path: /swagger (HTTP 200)"] == "MODERATE"


def test_the_skip_says_what_the_two_answers_were(monkeypatch):
    h = _Harness(monkeypatch, (200, None, PAGE), (403, None, REFUSAL))
    M.run_ffuf_chunked(_ctx())
    answers = "HTTP 200 (3080 bytes); HTTP 403 (316 bytes)"
    assert f"ffuf catch-all calibration probes: {answers}" in h.lines[1], h.lines
    skip = [ln for ln in h.lines if "skip ffuf" in ln]
    assert len(skip) == 1 and "different answers" in skip[0], h.lines
    assert answers in skip[0], "the skip line itself says what the two answers were"
    assert "failed after retries" not in h.text, "that sentence is for a probe that got no answer"


def test_a_probe_with_no_answer_skips_with_its_own_reason_as_before(monkeypatch):
    h = _Harness(monkeypatch, (0, None, None), (0, None, None))
    ctx = _ctx()
    M.run_ffuf_chunked(ctx)
    assert ctx.findings == [] and h.chunks_run == []
    assert ctx.tool_status == {n: {"skipped": "catchall_calibration_failed"} for n in _chunk_names()}
    skip = [ln for ln in h.lines if "skip ffuf" in ln]
    assert len(skip) == 1 and "failed after retries" in skip[0]
    assert "different answers" not in h.text


def test_the_same_site_with_two_answers_that_agree_is_one_summary_row(monkeypatch):
    """Four days earlier: both made-up paths got the page. One summary, and the one real
    path (a different size) still shows."""
    answers = {"health": (200, 8)}
    h = _Harness(monkeypatch, (200, None, PAGE), (200, None, PAGE), answers=answers)
    ctx = _ctx()
    M.run_ffuf_chunked(ctx)
    assert len(h.chunks_run) == len(_chunk_names())
    titles = sorted(f.title for f in ctx.findings)
    assert titles == ["Accessible path: /health (HTTP 200)",
                      f"Host returns HTTP 200 to {len(M.FFUF_WORDS) - 1} paths uniformly"], titles
    assert all(v == {"ok": True} for v in ctx.tool_status.values())
    assert "calibration probes: HTTP 200 (3080 bytes); HTTP 200 (3080 bytes)" in h.text


def test_a_host_that_discriminates_still_gets_every_chunk(monkeypatch):
    h = _Harness(monkeypatch, (404, None, 400), (404, None, 400),
                 answers={w: (404, 400) for w in M.FFUF_WORDS if w != "admin"})
    ctx = _ctx()
    M.run_ffuf_chunked(ctx)
    assert len(h.chunks_run) == len(_chunk_names())
    assert "no host-wide redirect or status catch-all detected" in h.text
    assert "calibration probes: HTTP 404 (400 bytes); HTTP 404 (400 bytes)" in h.text


def test_an_auth_gated_host_never_reaches_calibration(monkeypatch):
    """Unchanged: the auth-gated skip is decided before any calibration probe is sent."""
    stub = _two_probe((200, None, PAGE), (403, None, REFUSAL))
    h = _Harness(monkeypatch, (200, None, PAGE), (403, None, REFUSAL))
    monkeypatch.setattr(M, "_probe_calibration_path", stub)
    ctx = _ctx()
    ctx.auth_gated = True
    M.run_ffuf_chunked(ctx)
    assert stub.calls["n"] == 0
    assert ctx.tool_status == {n: {"skipped": "auth_gated"} for n in _chunk_names()}
