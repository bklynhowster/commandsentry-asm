"""D-056 for nikto — nikto may only LOOK (2026-10-09).

WHY. Howie's ruling the morning of 2026-10-09 (D-056, detection only): the
scanner runs only checks that look and never sends an exploit check. It was
written for nuclei. nikto was still running `-Tuning x6` — every nikto test
category except denial of service — with nikto's default plugins. That set
includes login-bypass, database-injection and command-injection tests, a
plugin that tries default user names and passwords on every login prompt it
meets, one that uploads a file and deletes it, and one that sends the 2014
Shellshock attack. Prodex's load-balancer log for the overnight demo scan shows
61 requests carrying that attack. The rule covers every tool, so nikto is
brought under it here.

WHAT nikto may still do. Three locks, each sufficient for its own layer:

  1. PLUGINS — `-Plugins` names an allow-list. Only plugins that make plain
     GET/HEAD requests (or none at all) are on it. Every plugin left off is
     listed in REFUSED_PLUGINS with the reason. nikto matches each entry as a
     REGEX against plugin names (`$plugin->{name} =~ /$entry/i`), so each entry
     is anchored, ^name$, and every allowed name must exist in the installed
     plugin folder or the answer is a refusal.
  2. CATEGORIES — `-Tuning` drops every category that is not "look"
     (interesting files, misconfiguration, information disclosure, software
     identification, admin consoles). nikto treats only the character right
     after an `x` as an exclusion, so each category carries its own `x`.
  3. EACH TEST — the `tests` plugin reads nikto's test database. Every test in
     it is read here first. A test that is not a plain GET or HEAD of a plain
     path (no body, no extra header, no query string, no encoded or special
     character, no parent-directory step, no user-name probe, only vetted
     path variables) is skipped by ID. nikto is also pointed at the exact
     database folder that was read, so it cannot load a different one.

FAIL CLOSED. If the database cannot be read, a test cannot be named, an ID
appears twice, a user database (udb_*) is present, or nothing would be left
to run, the answer is a refusal: nikto is not run and the scan records it.
"""
from __future__ import annotations

import hashlib
import itertools
import os
import re
from dataclasses import dataclass, field

# nikto 2.6.1 categories (program/plugins/nikto_core.plugin, -Tuning help).
LOOK_TUNING = "123be"        # interesting file, misconfig, info disclosure, software id, admin console
ATTACK_TUNING = "0456789acdf"  # upload, injection, file retrieval x2, DoS, command exec, SQL,
                               # auth bypass, remote inclusion, web service, XML injection
TUNING_ARG = "".join("x" + c for c in ATTACK_TUNING)

ALLOWED_PLUGINS = (
    "tests",           # the test database, screened below
    "cookies",         # reads cookies on responses already fetched
    "content_search",  # reads response bodies already fetched
    "favicon",         # GET favicon
    "msgs",            # compares the server banner with known issues; two plain GETs
    "outdated",        # compares version banners; no request of its own
    "multiple_index",  # GET index files
    "sitefiles",       # GET backup files named after the host
    "ssl",             # reads the certificate
    "cgi",             # GET candidate CGI folders
)

REFUSED_PLUGINS = {
    "auth":         "tries default user names and passwords on any login prompt",
    "apacheusers":  "guesses user names",
    "put_del_test": "uploads a file to the server and deletes it",
    "shellshock":   "sends the 2014 Shellshock attack",
    "ms10_070":     "runs a padding-oracle attack",
    "optionsbleed": "triggers a memory-leak bug to read server memory",
    "headers":      "sends trick headers, one asking the server for page source",
    "negotiate":    "sends a trick Accept header",
    "httpoptions":  "sends methods other than GET/HEAD (file nikto_options.plugin)",
    "springboot":   "downloads Spring Boot heap dumps",
    "dictionary":   "guesses paths from a word list",
    "siebel":       "runs Siebel application checks",
    # Review 2026-10-09: these two copy folder names from the TARGET's own pages
    # (links, robots.txt) into the path variables the kept tests expand, so a
    # kept test would request paths this screen never read.
    "paths":        "copies folder names from the target's pages into test paths",
    "robots":       "requests every path robots.txt lists, unread, and copies folder names into test paths",
}

# The nikto this screen was reviewed against (program/nikto.pl, 2.6.1, commit
# 312645d). Any other version is a refusal until it is re-reviewed.
REVIEWED_VERSION = "2.6.1"

# sha256 of every nikto file that EXECUTES, as reviewed: sullo/nikto 312645d
# (2026-08-15) — upstream HEAD when both scanner images were built on
# 2026-09-07, and still HEAD on 2026-10-09. nikto.pl, its config, LW2.pm and
# every *.plugin (nikto loads them all, then runs the allowed ones). "2.6.1"
# alone is not a pin: that string has stood since April across 71 commits that
# changed nikto.pl or plugins/. Any difference, missing file, or *.plugin not on
# this list is a refusal until the new code is reviewed. The databases are
# pinned too (review: multiple_index GETs every db_multiple_index entry), and
# db_tests / db_variables are ALSO read test by test below.
REVIEWED_FILES = {
    "nikto.pl": "3da3f6a1f5ceb4eb69ff889ed1f2b43a30c6337203cb494ae5a44b441a0e8091",
    "nikto.conf.default": "bd5bcd59e07905e902338a58e2c10e9f0749f690da9360beba02ed23163e554f",
    "plugins/LW2.pm": "075baeb701934a45439f23533ed69f9a088c5a4dc338018b2b13fbde3188e099",
    "plugins/nikto_apacheusers.plugin": "dc19d4b776dd82cb5d5b6a1ae69aab7f92b4d362bf8a2b145d4ed2cae4bc5ed9",
    "plugins/nikto_auth.plugin": "d76dc0e15fc8b07fe0b95c0360682d43d0a772ad1fb885cedf1943c71cde3493",
    "plugins/nikto_cgi.plugin": "4cbc5d45bac4f49d98ca9c61e9d4ab2f6734792b49592c8286622186d0c8da3d",
    "plugins/nikto_content_search.plugin": "d6d1f1191bd0d71bb202749f6c2e86c539ab249b9da573386539f6f0bf76816c",
    "plugins/nikto_cookies.plugin": "a52c56b5ac1040c551f32e812edffa49680c1ef6cbdf9633ba7b78b460e44968",
    "plugins/nikto_core.plugin": "f55da52c2f0c6a16aeaaf9bd13ba0e58ad85628976cf0df61692ec70eb02784f",
    "plugins/nikto_favicon.plugin": "53d30c7202d594b6ded3d4d646f2531d144df236a6a53aa92192d9c69b3018f9",
    "plugins/nikto_fileops.plugin": "692a123e7052001bb132e327c60199d30515dea3e73d86d72bab0b58a9341818",
    "plugins/nikto_headers.plugin": "d0d6d598f888a13f3cb80aa767c57a2982e40eab544f85aa5e76424dbe6dc9f7",
    "plugins/nikto_ms10_070.plugin": "cd8957e4a709ac1a9f90a5921eb73b97d09c5cc79d7e68e8e1e3453ef6641913",
    "plugins/nikto_msgs.plugin": "3d3012bafada123aec59dffdedb02044dc8894d88cbf5e85c8eb075fa8607383",
    "plugins/nikto_multiple_index.plugin": "ca10985707cc77dc2a231e221e82e4b00991f387c469e427e66438bb0d86031c",
    "plugins/nikto_negotiate.plugin": "42872c9d7d2b501246b9a2bb5cdb06dee454660a435d7ec818f9c7f9c1268238",
    "plugins/nikto_options.plugin": "aafed7d51a90cba3e9da450ff7ba9d2d27ee5736a1d348c4e2669ee531539946",
    "plugins/nikto_optionsbleed.plugin": "884cc8961772dc37a1cdb5186a201d2f603c1330246cdcca462c5f9eeb1a37e9",
    "plugins/nikto_outdated.plugin": "128dccd8cbb458628fd1931b26a79cb995f645b0d886bde1cf31f279f571af88",
    "plugins/nikto_paths.plugin": "b9aae3d53bafdfb8c1c30e8b0e7c4bbaf6bb09832c442c4528b5a5d6258e7569",
    "plugins/nikto_put_del_test.plugin": "207f75f9049f03fe80176031760f5f4c3468e2dcc755137370ca73ccca0eff6a",
    "plugins/nikto_report_csv.plugin": "78d8ff539321e493959a15729bb73340e4dfbad43c049064c5155c776254a811",
    "plugins/nikto_report_html.plugin": "6696d771e3216fdc1086d16b622d8e9d44ed6e7321a96d80ecee529ab674f6e1",
    "plugins/nikto_report_json.plugin": "6f978efed2ac39ffc75c2fb07148928fd1050cd8d0ce12d4fac36e12c418417e",
    "plugins/nikto_report_sqld.plugin": "c96e779f7bacd1854f317ff3768579ef8fa43b3723b95a9dd1c759b0d9bad691",
    "plugins/nikto_report_sqlg.plugin": "240ce7fcab2a4e8c0b7436126470a941b8e5414e65b2f0fbb89c8974d87b4b16",
    "plugins/nikto_report_text.plugin": "b9df6348a13527c7e1383a1adebadaad4e0ca02f19bb53a61a09598aa2eb2aa6",
    "plugins/nikto_report_xml.plugin": "64a68ba62392a717a5d4f1e4c79c0e1e01e45687e575cc65caa1c6d7a5166585",
    "plugins/nikto_robots.plugin": "1ef42b88aca1a5bfbe79f97d32fcb40d91031c320ad69b16fa9baba434cb56bd",
    "plugins/nikto_shellshock.plugin": "6da7bbdc3a42a1bf0a827719d8da663b6a1e5b9218b512d3ca521918caedffd4",
    "plugins/nikto_siebel.plugin": "5700d368e14565d3ca8c7d441eecaa5b9b4907d14ac774591bce4cdee2050e74",
    "plugins/nikto_sitefiles.plugin": "00ff41c04d324ab7409571c88067f087f02f286919ef159f08232678908fd2f1",
    "plugins/nikto_springboot.plugin": "1700013ca5f3d3098512538f3f3a64f221855fa7834d3f54e7cbdaffa75e666f",
    "plugins/nikto_ssl.plugin": "5463cfe3ccdde411e9fac629aa45104aa589d7c1ed114dce95ac1fc09fda07b8",
    "databases/db_404_strings": "5b4b5efad49e1471070e1364b6515a2f9b6215c52b081863f73d61f6c5bb1abd",
    "databases/db_content_search": "41b9d0803f6fc1c90d73b995b9c753ec62adc650d805dc07d00c58c11633f401",
    "databases/db_favicon": "1ca725b271b4af5d8b06a0fc6f379a5c1b7f85bc74dba7b022ead7aca2d28202",
    "databases/db_headers_common": "75b3aa6f2d08478e85fe957a537f14fd9768bd4bad504943fc18d1b10d965a75",
    "databases/db_headers_suggested": "8af6ef95718e736acd076695f50ad2bf044f2031529b5330e8cb733ffa75bbd6",
    "databases/db_multiple_index": "cc7fb39fb8a1efea5103baa2f3c59da85a2bf41da99627e4a9a537cc1b59652a",
    "databases/db_options": "4673276fee48046e1c60aa4db9859498b49870b49901a8d133b108af449ddd4c",
    "databases/db_outdated": "0e16e68c84337f2204aa05eda81328f245501bff47bc9d470f96675fb43fdcac",
    "databases/db_realms": "feb3afe98fd7ee3925979f7122b00a030ca9875e88747c00fb171016fe52c19b",
    "databases/db_server_msgs": "9e377c4671ebf155abb1e91df6005bdb4d29aa068e79a502d8d57d6473f6f806",
    "databases/db_tests": "496e2eeb7c6b27c24d813fe32427b7d1529497c406e843e7f07a22623de2f298",
    "databases/db_useragents": "92dec4e9a6a31612b33836e9a7317fff9536d102a30ea41f9e95c2123fbeb360",
    "databases/db_variables": "4755f2ac8087c5c138ce6027933c6ad4c065b8f261ddf2229a1581b654ab20c6",
    "plugins/nikto_tests.plugin": "ddcee473d5a0513b82f80e71db9e09b35bc8ca33b77f310acf9651a82f4d7f6f",
}

# Config keys nikto 2.6.1's own nikto.conf.default sets. The config nikto reads
# is pinned with -config and screened; any other key (CLIOPTS, EXECDIR,
# PLUGINDIR, DBDIR, SKIPIDS, STATIC-COOKIE, PROXY*, ...) is a refusal, because
# several of them can re-add arguments, move the plugin or database folder, or
# add headers after this screen has run.
SAFE_CONFIG_KEYS = frozenset({
    "NIKTODTD", "DEFAULTHTTPVER", "UPDATES", "CIRT", "VERSION_API", "CHECKMETHODS",
    "@@EXTRAS", "@@DEFAULT", "LW_SSL_ENGINE", "FAILURES", "CHECK6HOST", "CHECK6PORT",
})

# nikto's own (non-@) variable names. change_variables substitutes EVERY
# %VARIABLES key it finds in a path once the path has an @ in it, so a path
# with a variable and one of these words would not be the path we read.
_INTERNAL_NAMES = ("deferout", "DIV", "version", "name", "core_version", "defertxt",
                   "ERRSTRINGS", "ERRCODES", "configfile", "TEMPL_HCTR", "MSWIN32", "GMTOFFSET")

LOOK_METHODS = ("GET", "HEAD")
EXPANSION_LIMIT = 10_000          # more expanded URIs than this for one test -> skip it

_PLUGIN_NAME = re.compile(r"""\bname\s*=>\s*['"]([^'"]+)['"]""")
_VAR_TOKEN = re.compile(r"@([A-Z0-9_]+)")
_PLAIN_CHARS = re.compile(r"^[A-Za-z0-9/._-]*$")
_VAR_LINE = re.compile(r"^@([A-Z0-9_]+)=(.*)$")
_ID = re.compile(r"^\d+$")
_PLUGIN_FILE = re.compile(r"\.plugin$")    # nikto's own dirlist pattern ($ also before a final newline)
_PRINTABLE = re.compile(r"^[\x20-\x7e\t]*$")
# Path variables that are not about paths, or are about people.
_REFUSED_VARS = frozenset({"USERS"})
_REFUSED_VAR_PREFIXES = ("LFI",)     # nikto expands these separately (core:38), never as plain values

# nikto's parse_csv (nikto_core.plugin), ported: a quoted field with
# backslash escapes, or an unquoted run, or a bare comma (missing field).
_CSV = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)",?|([^,]+),?|,')


def parse_csv(text: str) -> list:
    if not text:
        return []
    out = []
    for m in _CSV.finditer(text):
        if m.group(1) is not None:
            out.append(m.group(1))
        elif m.group(2) is not None:
            out.append(m.group(2))
        else:
            out.append(None)
    if text.endswith(","):
        out.append(None)
    return out


@dataclass
class Plan:
    kept: int = 0
    skip_ids: list = field(default_factory=list)
    refusal: str | None = None


def _plain_path(uri: str) -> bool:
    if not uri.startswith("/") or not _PLAIN_CHARS.match(uri):
        return False
    return not any(seg in (".", "..") for seg in uri.split("/"))


def _parse_variables(text: str):
    """{name: [values]}, or None when a line nikto would load cannot be read the
    same way here (then the variables cannot be trusted at all)."""
    out = {}
    for raw in text.splitlines():
        if not _PRINTABLE.match(raw):
            return None                               # Python and Perl disagree on odd whitespace
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _VAR_LINE.match(line)
        if not m or '"' in line:
            return None
        out[m.group(1)] = m.group(2).split()
    return out


def _expansions(uri: str, variables: dict):
    """Every URI nikto could build from this one, or None if it must be skipped."""
    names = _VAR_TOKEN.findall(uri)
    if "@" in _VAR_TOKEN.sub("", uri):
        return None                                   # an @ that is not a vetted token
    if names and any(n in uri for n in _INTERNAL_NAMES):
        return None                                   # nikto would substitute that word too
    pieces = _VAR_TOKEN.split(uri)                    # literal, name, literal, name, ...
    choices = []
    for name in names:
        if (name in _REFUSED_VARS or name.startswith(_REFUSED_VAR_PREFIXES)
                or name not in variables or not variables[name]):
            return None
        # A name that another variable's name is a prefix of: nikto expands by
        # substring, in hash order, so the result would not be what we read.
        if any(o != name and name.startswith(o) for o in variables):
            return None
        choices.append(variables[name])
    total = 1
    for c in choices:
        total *= len(c)
        if total > EXPANSION_LIMIT:
            return None
    out = []
    for combo in itertools.product(*choices):
        s = pieces[0]
        for value, lit in zip(combo, pieces[2::2]):
            s += value + lit
        out.append(s)
    return out


def _is_plain_look(row: list, variables: dict) -> bool:
    if len(row) < 9:
        return False
    tuning, uri, method, data, headers = row[2], row[3], row[4], row[7], row[8]
    if not tuning or any(ch not in LOOK_TUNING for ch in tuning):
        return False
    if method not in LOOK_METHODS:
        return False
    if data not in (None, "") or headers not in (None, ""):
        return False                                  # nikto sends any non-empty field
    if any(extra not in (None, "") for extra in row[9:]):
        return False
    expanded = _expansions(uri or "", variables)
    return bool(expanded) and all(_plain_path(u) for u in expanded)


def plan(db_tests_text: str | None, db_variables_text: str | None) -> Plan:
    if db_variables_text is None:
        return Plan(refusal="nikto variable database could not be read")
    if not db_tests_text:
        return Plan(refusal="nikto test database could not be read")
    variables = _parse_variables(db_variables_text)
    if variables is None:
        return Plan(refusal="a nikto variable line could not be read the way nikto reads it")
    seen, skip, kept = set(), [], 0
    for line in db_tests_text.splitlines():
        if not line.startswith('"'):
            continue                                  # nikto: only lines starting " are tests
        row = parse_csv(line)
        tid = row[0] if row else None
        if not tid or not _ID.match(tid):
            return Plan(refusal="a nikto test has no readable ID, so it could not be skipped")
        if tid in seen:
            return Plan(refusal=f"nikto test ID {tid} appears twice")
        seen.add(tid)
        if _is_plain_look(row, variables):
            kept += 1
        else:
            skip.append(tid)
    if not seen:
        return Plan(refusal="nikto test database has no tests")
    if not kept:
        return Plan(refusal="no nikto test passed the look-only screen")
    return Plan(kept=kept, skip_ids=sorted(skip))


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="latin-1") as fh:
            return fh.read()
    except OSError:
        return None


def plugin_names(plugindir: str) -> set | None:
    """Internal names (the `name =>` in each *_init) of installed nikto plugins."""
    try:
        files = [f for f in os.listdir(plugindir) if _PLUGIN_FILE.search(f)]
    except OSError:
        return None
    names = set()
    for f in files:
        m = _PLUGIN_NAME.search(_read(os.path.join(plugindir, f)) or "")
        if m:
            names.add(m.group(1))
    return names


def plugins_arg() -> str:
    return ";".join(f"^{p}$" for p in ALLOWED_PLUGINS)


def screen_config(text: str | None) -> str | None:
    """Refusal reason, or None. Parsed exactly as nikto's load_config does."""
    if text is None:
        return "nikto config could not be read"
    for raw in text.splitlines():
        line = re.sub(r"#.*$", "", raw).strip()
        if not line:
            continue
        key, _, value = line.partition("=")
        if key not in SAFE_CONFIG_KEYS:
            return f"nikto config sets {key!r}, which this screen does not allow"
        if key == "CHECKMETHODS" and not set(value.split()) <= set(LOOK_METHODS):
            return f"nikto config CHECKMETHODS={value!r} is not GET/HEAD only"
    return None


_VERSION = re.compile(r"""\$VARIABLES\{'version'\}\s*=\s*"([^"]+)";""")


def hashes_of(program_dir: str) -> dict:
    """sha256 of nikto.pl, nikto.conf.default and every file in plugins/ and databases/."""
    out = {}
    listed = []
    for sub in ("plugins", "databases"):
        try:
            listed += sorted(f"{sub}/{f}" for f in os.listdir(os.path.join(program_dir, sub)))
        except OSError:
            pass
    for rel in ["nikto.pl", "nikto.conf.default"] + listed:
        try:
            with open(os.path.join(program_dir, rel), "rb") as fh:
                out[rel] = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            pass
    return out


def tree_mismatches(program_dir: str, reviewed: dict) -> list:
    """What differs from the reviewed copy. Empty means identical."""
    have = hashes_of(program_dir)
    bad = [f"{rel} missing" if rel not in have else f"{rel} changed"
           for rel, digest in sorted(reviewed.items()) if have.get(rel) != digest]
    bad += [f"{rel} not reviewed" for rel in sorted(have)
            if rel.startswith("plugins/") and _PLUGIN_FILE.search(rel) and rel not in reviewed]
    return bad


def look_only_args(program_dir: str, reviewed: dict | None = None):
    """(args, refusal, plan). args is None whenever refusal is set.

    program_dir is nikto's program/ folder: nikto.pl, nikto.conf.default,
    plugins/ and databases/ — the exact tree that will run. reviewed defaults
    to REVIEWED_FILES (tests pass their own)."""
    reviewed = REVIEWED_FILES if reviewed is None else reviewed
    dbdir = os.path.join(program_dir, "databases")
    plugindir = os.path.join(program_dir, "plugins")
    conf = os.path.join(program_dir, "nikto.conf.default")
    m = _VERSION.search(_read(os.path.join(program_dir, "nikto.pl")) or "")
    if not m:
        return None, f"nikto.pl not found or unreadable in {program_dir}", None
    if m.group(1) != REVIEWED_VERSION:
        return None, f"nikto {m.group(1)} is not the reviewed {REVIEWED_VERSION}", None
    diff = tree_mismatches(program_dir, reviewed)
    if diff:
        return None, ("nikto files differ from the reviewed copy (312645d): "
                      + "; ".join(diff[:5]) + (" ..." if len(diff) > 5 else "")), None
    why = screen_config(_read(conf))
    if why:
        return None, why, None
    installed = plugin_names(plugindir)
    if installed is None:
        return None, f"nikto plugin folder {plugindir} not found", None
    missing = [p for p in ALLOWED_PLUGINS if p not in installed]
    if missing:
        return None, f"nikto plugin(s) not installed: {', '.join(missing)}", None
    if not os.path.isdir(dbdir):
        return None, f"nikto database folder {dbdir} not found", None
    user_dbs = sorted(f for f in os.listdir(dbdir) if f.startswith("udb_"))
    if user_dbs:
        return None, f"unscreened nikto user database present: {', '.join(user_dbs)}", None
    p = plan(_read(os.path.join(dbdir, "db_tests")), _read(os.path.join(dbdir, "db_variables")))
    if p.refusal:
        return None, p.refusal, p
    args = [
        "-config", conf,
        "-Plugins", plugins_arg(),
        "-Tuning", TUNING_ARG,
        "-Option", "SKIPIDS=" + " ".join(p.skip_ids),
        "-Option", "DBDIR=" + dbdir,
    ]
    return args, None, p
