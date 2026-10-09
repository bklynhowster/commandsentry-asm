"""D-056 for nikto (2026-10-09): nikto may only LOOK.

Found while extending the detection-only rule: run_nikto ran `-Tuning x6`
(every test category except denial of service) with nikto's default plugins.
That set includes login-bypass, database-injection and command-injection
tests, a plugin that tries default passwords on any login prompt, one that
uploads and deletes a file, and one that sends a 2014 server attack. Prodex's
load-balancer log for the 10-08/09 demo scan shows 61 requests carrying that
attack. Howie's rule (D-056, detection only) covers every tool, not only nuclei.

These tests pin the replacement: nikto runs only plugins that look, only test
categories that look, and every individual test it could send is read first;
anything that is not a plain GET/HEAD of a plain path is skipped by ID.
"""
import os
import re

import pytest

import nikto_look_only as L


# ─── nikto's own CSV reader, ported ─────────────────────────────────────

def test_parse_csv_matches_nikto_on_escaped_quotes_and_empty_fields():
    line = r'"000123","ref","2","/a\"b","GET","200","msg","",""'
    assert L.parse_csv(line) == ["000123", "ref", "2", r'/a\"b', "GET", "200", "msg", "", ""]


def test_parse_csv_bare_commas_are_missing_fields():
    assert L.parse_csv('"1",,"3"') == ["1", None, "3"]
    assert L.parse_csv('"1","2",') == ["1", "2", None]


# ─── which tests may run ────────────────────────────────────────────────

VARS = (
    "@CGIDIRS=/cgi-bin/ /scripts/\n"
    "@ADMIN=/admin/ /adm/\n"
    "@USERS=root guest\n"
    "@BADVAL=/ok/ /x?y=1\n"
    "# comment\n"
)


def _t(tid, tuning="2", uri="/backup.zip", method="GET", data="", headers=""):
    return f'"{tid}","ref","{tuning}","{uri}","{method}","200","msg","{data}","{headers}"'


def _db(*lines):
    return "#header\n" + "\n".join(lines) + "\n"


@pytest.mark.parametrize("line", [
    _t("000001", tuning="1"),
    _t("000002", tuning="2"),
    _t("000003", tuning="3"),
    _t("000004", tuning="b"),
    _t("000005", tuning="e"),
    _t("000006", tuning="123be"),
    _t("000007", method="HEAD"),
    _t("000008", uri="/@ADMINconfig.bak"),
    _t("000009", uri="@CGIDIRStest-cgi"),
])
def test_a_plain_look_test_is_kept(line):
    plan = L.plan(_db(line), VARS)
    assert plan.refusal is None
    assert plan.skip_ids == []
    assert plan.kept == 1


@pytest.mark.parametrize("line,why", [
    (_t("000101", tuning="0"), "file upload"),
    (_t("000102", tuning="4"), "script injection"),
    (_t("000103", tuning="5"), "file retrieval"),
    (_t("000104", tuning="6"), "denial of service"),
    (_t("000105", tuning="7"), "file retrieval, server wide"),
    (_t("000106", tuning="8"), "command execution"),
    (_t("000107", tuning="9"), "database injection"),
    (_t("000108", tuning="a"), "authentication bypass"),
    (_t("000109", tuning="c"), "remote source inclusion"),
    (_t("000110", tuning="d"), "web service"),
    (_t("000111", tuning="f"), "XML injection"),
    (_t("000112", tuning="2a"), "a look category does not excuse an attack category"),
    (_t("000113", tuning="A"), "upper-case category letter"),
    (_t("000114", tuning=""), "no category at all"),
    (_t("000115", method="POST"), "POST"),
    (_t("000116", method="get"), "lower-case method"),
    (_t("000117", method="OPTIONS"), "OPTIONS"),
    (_t("000118", data="x=1"), "request body"),
    (_t("000119", headers="X-A: 1"), "extra header"),
    (_t("000120", uri="/x?y=1"), "query string"),
    (_t("000121", uri="/x%2e"), "encoded character"),
    (_t("000122", uri="/a/../b"), "parent directory"),
    (_t("000123", uri="/~root/"), "home-directory (user) probe"),
    (_t("000124", uri="/x;y"), "semicolon"),
    (_t("000125", uri="/@USERS/"), "user-name list"),
    (_t("000126", uri="/@NOPE/"), "unknown variable"),
    (_t("000127", uri="/@JUNK(5)"), "random-junk macro"),
    (_t("000128", uri="/@BADVAL"), "variable with a non-plain value"),
    (_t("000129", uri="/@CGIDIRSA"), "variable name glued to capitals"),
    (_t("000130", uri="/@IP/"), "@IP is not a path variable"),
    (_t("000131", uri="x"), "not rooted"),
    (_t("000132", uri=""), "empty path"),
    ('"000133","ref","2"', "short row"),
])
def test_anything_else_is_skipped_by_id(line, why):
    plan = L.plan(_db(_t("000900"), line), VARS)    # one good test keeps the plan non-empty
    assert plan.refusal is None, why
    assert plan.kept == 1, why
    assert plan.skip_ids == [re.match(r'"(\d+)"', line).group(1)], why


def test_nothing_left_to_run_is_a_refusal():
    """Every test skipped means the database is not what this screen was
    written for. Say so rather than run nikto on plugins alone."""
    assert L.plan(_db(_t("000001", tuning="9")), VARS).refusal


def test_a_row_with_extra_non_empty_fields_is_skipped():
    """nikto passes fields past the ninth on to the request in some versions.
    A row we do not fully understand is not a plain look."""
    extra = _t("000201") + ',"POST-ish"'
    plan = L.plan(_db(_t("000900"), extra), VARS)
    assert plan.skip_ids == ["000201"]
    trailing_empty = _t("000202") + ',""'
    assert L.plan(_db(_t("000900"), trailing_empty), VARS).skip_ids == []


def test_a_variable_whose_name_starts_with_another_variable_is_skipped():
    """nikto expands variables by SUBSTRING in hash order: in "/@ADMINX" it may
    expand @ADMIN first and leave "X" glued on. We cannot know which, so skip."""
    vars_ = VARS + "@ADMINX=/adminx/\n"
    plan = L.plan(_db(_t("000900"), _t("000203", uri="/@ADMINX")), vars_)
    assert plan.skip_ids == ["000203"]


def test_a_test_that_expands_into_too_many_requests_is_skipped():
    big = "@BIG=" + " ".join(f"/d{i}/" for i in range(200)) + "\n"
    plan = L.plan(_db(_t("000900"), _t("000204", uri="@BIG@BIGx")), VARS + big)
    assert plan.skip_ids == ["000204"]
    assert L.plan(_db(_t("000900"), _t("000205", uri="@BIGx")), VARS + big).skip_ids == []


@pytest.mark.parametrize("data,headers", [(" ", ""), ("\xa0", ""), ("", " "), ("", "\x1f")])
def test_a_whitespace_only_body_or_header_still_counts(data, headers):
    """nikto sends any non-empty field (review 2026-10-09)."""
    plan = L.plan(_db(_t("000900"), _t("000206", data=data, headers=headers)), VARS)
    assert plan.skip_ids == ["000206"]


def test_lfi_variables_are_never_expanded_by_the_screen():
    """nikto handles @LFI* itself (core:38), never as plain values."""
    plan = L.plan(_db(_t("000900"), _t("000207", uri="/@LFIX")), VARS + "@LFIX=/x/\n")
    assert plan.skip_ids == ["000207"]


@pytest.mark.parametrize("word", ["version", "name", "DIV", "configfile"])
def test_a_variable_path_holding_one_of_niktos_own_names_is_skipped(word):
    """Once a path has an @, nikto substitutes every %VARIABLES key it contains,
    its own names included — the path sent would not be the path read."""
    plan = L.plan(_db(_t("000900"), _t("000208", uri=f"/@ADMIN{word}.txt")), VARS)
    assert plan.skip_ids == ["000208"]
    assert L.plan(_db(_t("000900"), _t("000209", uri=f"/{word}.txt")), VARS).skip_ids == []


@pytest.mark.parametrize("bad", ['@lower=/x/', '@Q="/x/"', "@NOEQUALS", "garbage line",
                                 "@ADMIN=/admin/\xa0/x/", "@ADMIN=/admin/\x1c/x/"])
def test_a_variable_line_we_cannot_read_like_nikto_is_a_refusal(bad):
    assert L.plan(_db(_t("000900")), VARS + bad + "\n").refusal


def test_skip_list_is_every_test_that_is_not_plain_look_and_nothing_else():
    db = _db(_t("000001"), _t("000002", tuning="4"), _t("000003", method="POST"), _t("000004", tuning="b"))
    plan = L.plan(db, VARS)
    assert plan.skip_ids == ["000002", "000003"] and plan.kept == 2


def test_comment_and_blank_lines_are_not_tests():
    plan = L.plan("#x\n\n  \n" + _t("000001") + "\n", VARS)
    assert plan.kept == 1 and plan.skip_ids == []


# ─── fail closed ────────────────────────────────────────────────────────

@pytest.mark.parametrize("db", [None, "", "#only comments\n"])
def test_no_readable_tests_is_a_refusal(db):
    plan = L.plan(db, VARS)
    assert plan.refusal


def test_unreadable_variables_is_a_refusal():
    assert L.plan(_db(_t("000001")), None).refusal


def test_a_test_line_without_a_readable_id_is_a_refusal():
    """We skip by ID. A test we cannot name is a test we cannot skip."""
    plan = L.plan(_db(_t("000001"), '"abc","r","4","/x","GET"'), VARS)
    assert plan.refusal


def test_a_duplicate_id_is_a_refusal():
    """Skipping an ID would skip both rows; keeping it would keep both."""
    plan = L.plan(_db(_t("000001"), _t("000001", tuning="4")), VARS)
    assert plan.refusal


def _look(prog, reviewed=None):
    """look_only_args against a test tree, trusting that tree's own files
    unless a test passes a different reviewed set."""
    return L.look_only_args(str(prog), reviewed=L.hashes_of(prog) if reviewed is None else reviewed)


def test_a_changed_nikto_file_is_a_refusal(tmp_path):
    prog = _program(tmp_path)
    reviewed = L.hashes_of(prog)
    (prog / "plugins" / "nikto_tests.plugin").write_text("changed\n")
    args, refusal, _ = _look(prog, reviewed)
    assert args is None and "plugins/nikto_tests.plugin changed" in refusal


def test_an_unreviewed_plugin_file_is_a_refusal(tmp_path):
    """nikto loads every *.plugin in the folder; one we never read is a refusal."""
    prog = _program(tmp_path)
    reviewed = L.hashes_of(prog)
    (prog / "plugins" / "nikto_new.plugin").write_text('my $id = { name => "new" };\n')
    args, refusal, _ = _look(prog, reviewed)
    assert args is None and "nikto_new.plugin not reviewed" in refusal


def test_a_changed_database_is_a_refusal(tmp_path):
    """multiple_index GETs every db_multiple_index entry; databases are pinned."""
    prog = _program(tmp_path)
    (prog / "databases" / "db_multiple_index").write_text("index.html\n")
    reviewed = L.hashes_of(prog)
    (prog / "databases" / "db_multiple_index").write_text("index.html\nother\n")
    args, refusal, _ = _look(prog, reviewed)
    assert args is None and "databases/db_multiple_index changed" in refusal


def test_a_plugin_name_with_a_trailing_newline_is_still_a_plugin():
    """nikto's dirlist uses /\.plugin$/, which also matches before a final newline."""
    assert L._PLUGIN_FILE.search("nikto_x.plugin\n")


def test_a_missing_reviewed_file_is_a_refusal(tmp_path):
    prog = _program(tmp_path)
    reviewed = dict(L.hashes_of(prog), **{"plugins/LW2.pm": "0" * 64})
    args, refusal, _ = _look(prog, reviewed)
    assert args is None and "plugins/LW2.pm missing" in refusal


def test_args_refuse_when_a_user_database_is_present(tmp_path):
    """nikto also loads udb_* files from its database folder, unscreened."""
    prog = _program(tmp_path)
    (prog / "databases" / "udb_tests").write_text(_t("009999", tuning="9") + "\n")
    args, refusal, _ = _look(prog)
    assert args is None and "udb_tests" in refusal


def test_args_refuse_when_the_database_folder_is_missing(tmp_path):
    prog = _program(tmp_path)
    import shutil
    shutil.rmtree(prog / "databases")
    args, refusal, _ = _look(prog)
    assert args is None and refusal


def test_args_refuse_when_an_allowed_plugin_is_not_installed(tmp_path):
    """A renamed plugin would silently drop out; a NEW plugin cannot sneak in
    because every entry is anchored. Refuse on the first, so it gets looked at."""
    prog = _program(tmp_path, drop="sitefiles")
    args, refusal, _ = _look(prog)
    assert args is None and "sitefiles" in refusal


def test_args_refuse_when_the_plugin_folder_is_missing(tmp_path):
    prog = _program(tmp_path)
    import shutil
    shutil.rmtree(prog / "plugins")
    args, refusal, _ = _look(prog)
    assert args is None and refusal


def test_args_refuse_a_nikto_version_that_was_not_reviewed(tmp_path):
    args, refusal, _ = _look(_program(tmp_path, version="2.6.2"))
    assert args is None and "2.6.2" in refusal


def test_args_refuse_when_nikto_pl_is_missing(tmp_path):
    prog = _program(tmp_path)
    (prog / "nikto.pl").unlink()
    args, refusal, _ = _look(prog)
    assert args is None and refusal


@pytest.mark.parametrize("extra,why", [
    ("CLIOPTS=-Tuning 9", "CLIOPTS re-adds arguments after ours"),
    ("PLUGINDIR=/tmp/p", "moves the plugin folder"),
    ("EXECDIR=/tmp", "moves nikto's home"),
    ("DBDIR=/tmp/db", "moves the database folder"),
    ("STATIC-COOKIE=a=b", "adds a header to every request"),
    ("SKIPIDS=", "competes with our skip list"),
    ("PROXYHOST=x", "an unreviewed key"),
    ("CHECKMETHODS=GET POST", "a non-look method"),
])
def test_args_refuse_a_config_that_does_more_than_the_default(tmp_path, extra, why):
    args, refusal, _ = _look(_program(tmp_path, conf=SAFE_CONF + extra + "\n"))
    assert args is None and refusal, why


def test_a_commented_out_key_is_not_a_setting(tmp_path):
    args, refusal, _ = _look(_program(tmp_path, conf=SAFE_CONF + "# CLIOPTS=-Tuning 9\n"))
    assert refusal is None


def test_args_refuse_when_the_config_is_missing(tmp_path):
    args, refusal, _ = _look(_program(tmp_path, conf=None))
    assert args is None and refusal


# ─── the arguments ──────────────────────────────────────────────────────

# The installed nikto 2.6.1 plugin names (the `name =>` of each *_init). The
# file nikto_options.plugin is named "httpoptions" inside.
NIKTO_PLUGINS = ("apacheusers", "auth", "cgi", "content_search", "cookies", "favicon",
                 "fileops", "headers", "ms10_070", "msgs", "multiple_index", "negotiate",
                 "httpoptions", "optionsbleed", "outdated", "paths", "put_del_test",
                 "report_csv", "report_html", "report_json", "report_sqld", "report_sqlg",
                 "report_text", "report_xml", "robots", "shellshock", "siebel", "sitefiles",
                 "springboot", "ssl", "tests")


def _plugindir(base, drop=None):
    d = base / "plugins"
    d.mkdir(exist_ok=True)
    for n in NIKTO_PLUGINS:
        if n != drop:
            (d / f"nikto_{n}.plugin").write_text(
                f"sub nikto_{n}_init {{\n    my $id = {{ name        => \"{n}\",\n }};\n}}\n")
    return str(d)


def _write_dbdir(d):
    (d / "db_tests").write_text(_db(_t("000001"), _t("000002", tuning="9"), _t("000003", uri="/x?y=1")))
    (d / "db_variables").write_text(VARS)


SAFE_CONF = """# nikto.conf.default (2.6.1), comments kept
NIKTODTD=templates/nikto.dtd
DEFAULTHTTPVER=1.1
UPDATES=yes
CIRT=cirt.net
VERSION_API=https://telemetry.hack.llc/products.json
CHECKMETHODS=GET
@@EXTRAS=dictionary;siebel
@@DEFAULT=@@ALL;-@@EXTRAS;tests(report:500)
LW_SSL_ENGINE=auto
FAILURES=20
CHECK6HOST=ipv6.google.com
CHECK6PORT=443
"""


def _program(base, version="2.6.1", conf=SAFE_CONF, drop=None):
    """A nikto program/ tree: nikto.pl, nikto.conf.default, plugins/, databases/."""
    prog = base / "program"
    (prog / "databases").mkdir(parents=True, exist_ok=True)
    _write_dbdir(prog / "databases")
    _plugindir(prog, drop=drop)
    (prog / "nikto.pl").write_text(f'$VARIABLES{{\'name\'}}      = "Nikto";\n$VARIABLES{{\'version\'}}   = "{version}";\n')
    if conf is not None:
        (prog / "nikto.conf.default").write_text(conf)
    return prog


def test_args_name_only_look_plugins_and_skip_every_non_look_test(tmp_path):
    prog = _program(tmp_path)
    args, refusal, plan = _look(prog)
    assert refusal is None
    pairs = list(zip(args[::2], args[1::2]))
    assert len(pairs) * 2 == len(args)
    assert pairs == [
        ("-config", str(prog / "nikto.conf.default")),   # the config we screened, nothing else
        ("-Plugins", ";".join("^" + p + "$" for p in L.ALLOWED_PLUGINS)),
        ("-Tuning", L.TUNING_ARG),
        ("-Option", "SKIPIDS=000002 000003"),
        ("-Option", "DBDIR=" + str(prog / "databases")),   # nikto reads exactly the folder we read
    ]
    assert plan.kept == 1


def test_no_plugin_that_sends_more_than_a_plain_look_is_allowed():
    for p in ("auth", "apacheusers", "put_del_test", "shellshock", "ms10_070",
              "optionsbleed", "headers", "negotiate", "httpoptions", "springboot",
              "dictionary", "siebel", "paths", "robots"):
        assert p not in L.ALLOWED_PLUGINS, p
        assert p in L.REFUSED_PLUGINS, p
    assert not set(L.ALLOWED_PLUGINS) & set(L.REFUSED_PLUGINS)
    assert not any(c in p for p in L.ALLOWED_PLUGINS for c in ";@,-+ ")


def _nikto_runs(plugins_arg, names):
    """nikto's load_plugins matching, ported: each ;-entry is a REGEX tested
    case-insensitively against every plugin's name."""
    entries = [e for e in plugins_arg.split(";") if e]
    return {n for n in names if any(re.search(e, n, re.I) for e in entries)}


def test_nikto_runs_exactly_the_allowed_plugins():
    assert _nikto_runs(L.plugins_arg(), NIKTO_PLUGINS) == set(L.ALLOWED_PLUGINS)


def test_the_anchors_matter():
    """Unanchored, an entry would also run any plugin whose name CONTAINS it."""
    assert _nikto_runs("tests", ("tests", "my_tests_x")) == {"tests", "my_tests_x"}
    assert _nikto_runs(L.plugins_arg(), ("tests", "my_tests_x", "sslx", "xcgi")) == {"tests"}


# nikto's set_scan_items (program/plugins/nikto_core.plugin, 2.6.1), ported
# line for line, INCLUDING its quirk: only the character immediately after an
# `x` is an exclusion. `-Tuning x0456789acdf` would exclude 0 and INCLUDE the
# rest — which is why every attack category carries its own `x`.
def _nikto_selects(cli_tuning, test_tuning):
    includes = excludes = ""
    for tune in cli_tuning:
        if tune == "x":
            continue
        if not re.search(r"(?<![x])" + re.escape(tune), cli_tuning, re.I):
            excludes += tune
        else:
            includes += tune
    add = 0
    if includes:
        for tune in includes:
            if re.search(re.escape(tune), test_tuning, re.I):
                add = 1
                break
    if excludes:
        for tune in excludes:
            if re.search(re.escape(tune), test_tuning, re.I):
                add = 0
                break
            add = 1
    return bool(add)


@pytest.mark.parametrize("test_tuning", ["1", "2", "3", "b", "e", "123be", "23", "1b"])
def test_nikto_tuning_keeps_the_look_categories(test_tuning):
    assert _nikto_selects(L.TUNING_ARG, test_tuning)


@pytest.mark.parametrize("test_tuning", list("0456789acdf") + ["2a", "34", "b8", "1c", "e9"])
def test_nikto_tuning_drops_every_attack_category(test_tuning):
    assert not _nikto_selects(L.TUNING_ARG, test_tuning)


def test_the_quirk_is_real():
    """Guards the guard: the obvious spelling would have let attacks through."""
    assert _nikto_selects("x0456789acdf", "9")


def test_tuning_arg_names_exactly_the_attack_categories():
    assert set(L.TUNING_ARG[1::2]) == set(L.ATTACK_TUNING) == set("0456789acdf")
    assert L.TUNING_ARG[0::2] == "x" * len(L.ATTACK_TUNING)
    assert set(L.ATTACK_TUNING) | set(L.LOOK_TUNING) == set("0123456789abcdef")
    assert not set(L.ATTACK_TUNING) & set(L.LOOK_TUNING)


# ─── against the real database, when it is on this machine ─────────────

NIKTO_PROGRAM = os.environ.get("NIKTO_PROGRAM", "/opt/nikto/program")
NIKTO_DB = os.path.join(NIKTO_PROGRAM, "databases")
NIKTO_PLUGINDIR = os.path.join(NIKTO_PROGRAM, "plugins")


@pytest.mark.skipif(not os.path.isfile(os.path.join(NIKTO_DB, "db_tests")),
                    reason="nikto not installed here")
def test_the_installed_nikto_is_the_reviewed_one():
    """Fails loudly in any environment whose nikto differs from 312645d."""
    assert L.tree_mismatches(NIKTO_PROGRAM, L.REVIEWED_FILES) == []


@pytest.mark.skipif(not os.path.isfile(os.path.join(NIKTO_DB, "db_tests")),
                    reason="nikto not installed here")
def test_real_plugin_names_match_the_ones_these_tests_assume():
    assert L.plugin_names(NIKTO_PLUGINDIR) == set(NIKTO_PLUGINS)


@pytest.mark.skipif(not os.path.isfile(os.path.join(NIKTO_DB, "db_tests")),
                    reason="nikto not installed here")
def test_real_database_screens_cleanly():
    args, refusal, plan = L.look_only_args(NIKTO_PROGRAM)
    assert refusal is None, refusal
    assert plan.kept > 1000
    assert len(" ".join(args)) < 120_000      # one argv string stays under MAX_ARG_STRLEN
