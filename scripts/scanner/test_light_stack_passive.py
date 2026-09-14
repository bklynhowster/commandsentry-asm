"""(c) light-tier passive posture — the tests 4.7 required (relay 108).

⛔ The one that matters is test_normalise_before_subset_or_the_signal_vanishes:
subset-before-normalise yields a well-formed, non-empty artifact carrying
NOTHING. Every other test here passes under that bug.
"""
import ast
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from stack_passive import (  # noqa: E402
    LIGHT_PASSIVE_TOOL,
    wire_header_key,
    normalise_header_keys,
    vendor_header_subset,
    extract_set_cookie_names,
)

# A REAL httpx -irh map shape, keys as measured on Command 2026-09-14
# (commandmarketinginnovations.com carries x_ac; test.ccc carries set_cookie).
HTTPX_IRH = {
    "server": "nginx",
    "x_ac": "true",
    "x_powered_by": "PHP/8.1",
    "cache_control": "max-age=300",
    "set_cookie": ["cookiesession1=678A3E0D; Path=/", "wordpress_test=1"],
    "content_type": "text/html",
}
# The pre-2026-09-08 curl era shape, same host, wire format.
CURL_WIRE = {"server": "nginx", "x-ac": "true", "set-cookie": "cookiesession1=678A3E0D"}


def test_the_case_the_gate_must_pass_light_map_yields_the_x_ac_tell():
    """⭐ PASS-CASE FIRST. Without it, every deny test below is satisfied by a
    pipeline that produces nothing at all."""
    vh = vendor_header_subset(normalise_header_keys(HTTPX_IRH))
    assert "x-ac" in vh, f"the Automattic tell did not survive: {vh}"
    assert vh["x-ac"] is True


def test_normalise_before_subset_or_the_signal_vanishes():
    """⛔ THE ORDERING BUG, asserted directly. vendor_header_subset matches
    startswith('x-'); httpx keys are x_ac. Subset-first keeps only server —
    non-empty, well-formed, and carrying no tell whatsoever."""
    wrong = vendor_header_subset(HTTPX_IRH)          # subset BEFORE normalise
    right = vendor_header_subset(normalise_header_keys(HTTPX_IRH))
    assert "x-ac" not in wrong and "x_ac" not in wrong
    assert wrong != {}, "the bug is that it is NON-empty — that is what hides it"
    assert set(wrong) == {"server"}, wrong
    assert "x-ac" in right


def test_set_cookie_needs_the_same_normalisation():
    """extract_set_cookie_names matches == 'set-cookie'. Same trap."""
    assert extract_set_cookie_names(HTTPX_IRH) == []          # underscore key missed
    names = extract_set_cookie_names(normalise_header_keys(HTTPX_IRH))
    assert "cookiesession1" in names, names                   # the FortiWeb tell


def test_wire_header_key_is_idempotent_and_key_only():
    assert wire_header_key("x_ac") == "x-ac"
    assert wire_header_key("x-ac") == "x-ac"                  # idempotent
    assert wire_header_key(wire_header_key("x_powered_by")) == "x-powered-by"
    assert wire_header_key("X_AC") == "x-ac"
    assert wire_header_key(None) == ""


def test_values_are_never_touched():
    """Values legitimately contain underscores — cookie names, ETags, tokens."""
    out = normalise_header_keys({"x_thing": "a_b_c", "set_cookie": "my_cookie=v_1"})
    assert out["x-thing"] == "a_b_c"
    assert out["set-cookie"] == "my_cookie=v_1"
    assert extract_set_cookie_names(out) == ["my_cookie"]


def test_curl_era_wire_format_still_works_both_corpora_are_live():
    """The artifact corpus spans the 2026-09-08 migration; both shapes must work."""
    vh = vendor_header_subset(normalise_header_keys(CURL_WIRE))
    assert vh.get("x-ac") is True
    assert extract_set_cookie_names(normalise_header_keys(CURL_WIRE)) == ["cookiesession1"]


def test_empty_map_produces_no_artifact_signals():
    """An empty header map must yield NOTHING, so the emit skips the artifact and
    the per-signal merge falls through to heavy's. Present-but-empty is absence."""
    assert vendor_header_subset(normalise_header_keys({})) == {}
    assert extract_set_cookie_names(normalise_header_keys({})) == []


def test_light_tool_name_is_outside_the_seed_gate_namespace():
    """⛔ seed-device-class.yml gates on `tool_name ilike 'stack_id_passive%'` as a
    proxy for 'this asset has had its post-collector HEAVY'. A light artifact
    matching that prefix would make every light-swept asset look already-seeded."""
    assert not LIGHT_PASSIVE_TOOL.startswith("stack_id_passive")
    assert LIGHT_PASSIVE_TOOL == "light_stack_passive"


def test_the_two_literals_agree_across_the_sys_path_boundary():
    """scripts/db/ cannot import scripts/scanner/, so the tool name is duplicated.
    Pin it (same treatment as DEEP_SWEEP_QUEUE_MARKER) — rename one, this fails."""
    runner = (HERE.parent / "db" / "device_class_runner.py").read_text()
    assert f'"{LIGHT_PASSIVE_TOOL}"' in runner, (
        f"{LIGHT_PASSIVE_TOOL} missing from device_class_runner._PASSIVE_TOOL_NAMES")
    assert '_PASSIVE_TOOL_NAMES = ("stack_id_passive", "light_stack_passive")' in runner


def test_emit_shape_is_json_serialisable_and_omits_cert():
    """⛔ cert is OMITTED, never emitted empty — a present-but-null cert reads as
    evidence of absence. Per-signal merge takes cert from heavy instead."""
    wire = normalise_header_keys(HTTPX_IRH)
    signals = {"schema": 1, "hostname": "h", "headers": vendor_header_subset(wire),
               "set_cookie_names": extract_set_cookie_names(wire)}
    assert "cert" not in signals
    json.loads(json.dumps(signals))


# ── SOURCE PINS — the pure-function tests above CANNOT catch a wiring regression.
# Every test so far passes if run_light calls subset(headers_lc) directly, because
# they exercise stack_passive, not the caller. That is exactly the trap in
# feedback_wiring_untested_by_pure_function_tests. These pin the CALLERS.

def _strip_comments(src: str) -> str:
    """Strip `#` comments and DOCSTRINGS ONLY — never other string literals.

    ⚠ Two lessons are baked in here, both learned on this file:
    1. stripping only `#` lines let a pin fire on the phrase it was checking for,
       sitting inside a docstring that explained why that phrase is NOT used
       (feedback_source_pins_must_strip_comments);
    2. then blanket-stripping every triple-quoted block ALSO removed the SQL the
       pin needs to see, because queries and docstrings share a delimiter.
    ⇒ use the parser, not a regex: only an `Expr` whose value is a bare string
      constant is a docstring. A SQL literal bound to a call argument is not.
    """
    tree = ast.parse(src)
    drop = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        # ⚠ `body` is a LIST on Module/Def/If/For, but a single NODE on IfExp and
        # lambda. Iterating blindly raises TypeError on any ternary in the file.
        if not isinstance(body, list):
            continue
        for child in body:
            if (isinstance(child, ast.Expr)
                    and isinstance(child.value, ast.Constant)
                    and isinstance(child.value.value, str)):
                drop.update(range(child.lineno, (child.end_lineno or child.lineno) + 1))
    lines = [("" if i in drop else l)
             for i, l in enumerate(src.splitlines(), 1)]
    return "\n".join(l for l in lines if not l.strip().startswith("#"))


def test_run_light_normalises_BEFORE_subsetting():
    """⛔ MUTATION TARGET A. If the emit ever calls vendor_header_subset on the
    raw httpx map, the artifact ships non-empty and carries no tell."""
    src = _strip_comments((HERE / "run_light.py").read_text())
    assert "normalise_header_keys(headers_lc)" in src, \
        "run_light no longer normalises the httpx map before subsetting"
    assert "vendor_header_subset(headers_lc)" not in src, \
        "run_light subsets the RAW httpx map — every x_* key is silently dropped"
    assert "extract_set_cookie_names(headers_lc)" not in src, \
        "run_light extracts cookies from the RAW httpx map — set_cookie is missed"
    i_norm = src.index("normalise_header_keys(headers_lc)")
    i_sub = src.index("vendor_header_subset(")
    assert i_norm < i_sub, "normalise must come BEFORE subset"


def test_device_class_runner_merges_per_signal_not_newest_wins():
    """⛔ MUTATION TARGET B. Newest-wins lets light's fresher artifact shadow
    heavy's, silently killing fortiweb_cookiesession1 on the FortiGate estate."""
    src = _strip_comments((HERE.parent / "db" / "device_class_runner.py").read_text())
    assert "_fresh_json_many(_PASSIVE_TOOL_NAMES" in src, \
        "the per-signal merge is gone — passive posture is back to newest-wins"
    assert '_fresh_json("stack_id_passive")' not in src, \
        "a single newest-wins pick of stack_id_passive has returned"
    assert "def _passive_signal(" in src, "the present-and-non-empty selector is gone"


def test_passive_merge_uses_exact_names_never_a_prefix():
    """A prefix predicate is what made seed-device-class.yml fragile."""
    src = _strip_comments((HERE.parent / "db" / "device_class_runner.py").read_text())
    assert "a.tool_name = %s" in src, "the merge query must match tool_name EXACTLY"
    assert "ilike 'stack_id_passive%'" not in src
