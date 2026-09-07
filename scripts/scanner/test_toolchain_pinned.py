"""test_toolchain_pinned.py — the scanner toolchain must not float.

WHY THIS EXISTS (2026-09-07). Every scanning tool was installed `@latest`,
the image published as `:latest`, and nuclei templates refreshed at build
time. Three independent floating layers under a security scanner.

The sharpest consequence is not "builds aren't reproducible" — it is that
a finding can DISAPPEAR because a nuclei template was renamed or dropped
upstream, and the finding lifecycle records that as REMEDIATION. That is a
false-remediation path no gate can catch, because the scan itself ran
perfectly and every phase reported ok. It directly undermines spec 227's
premise that a finding's absence means it was fixed.

Secondary, and the reason this surfaced: every coverage number in specs
227-231 assumes stable tool behaviour. `wall_clock_cut_400s at 78%` can
move with a nuclei release while our code is untouched. A baseline built
on a floating toolchain is not a baseline.

This guard is deliberately DUMB — it greps the Dockerfile. It cannot know
whether a pinned version is the RIGHT one; it only refuses the state where
nobody chose. Choosing remains a human act; drifting silently does not.
"""
import re
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[2] / "docker" / "Dockerfile"

# The Go-installed scan toolchain. Every one of these shapes what a scan
# sees, so every one must be a deliberate choice.
PINNED_TOOLS = (
    "subfinder", "dnsx", "httpx", "naabu", "nuclei",
    "katana", "fingerprintx", "ffuf", "gau", "wireguard",
)


def _dockerfile() -> str:
    assert DOCKERFILE.is_file(), f"Dockerfile not found at {DOCKERFILE}"
    src = DOCKERFILE.read_text()
    # Floor: a truncated/renamed Dockerfile must not let every check below
    # pass vacuously — they are all substring searches.
    assert len(src) > 2000 and "go install" in src, (
        f"Dockerfile looks wrong ({len(src)} chars) — every assertion below "
        f"is a substring match and would pass against a stub")
    return src


def test_no_go_tool_is_installed_at_latest():
    """@latest means the scan surface changes with no code change."""
    src = _dockerfile()
    offenders = [
        line.strip()
        for line in src.splitlines()
        if "go install" in line and "@latest" in line
    ]
    assert not offenders, (
        "unpinned Go tools — the scan surface can change without a commit:\n  "
        + "\n  ".join(offenders)
        + "\n\nPin to the versions captured by the `Toolchain inventory` "
          "workflow. Pin to what is INSTALLED, not to newest: every "
          "measurement in specs 227-231 came from the currently-running build, "
          "and pinning forward silently invalidates that baseline."
    )


def test_every_scan_tool_carries_an_explicit_version():
    """Each tool's install line must name a version, not a moving ref."""
    src = _dockerfile()
    missing = []
    for tool in PINNED_TOOLS:
        for line in src.splitlines():
            if "go install" not in line or tool not in line:
                continue
            # accept @vX.Y.Z, @vX.Y.Z-suffix, or a 40-char commit SHA
            if not re.search(r"@(v\d+\.\d+\.\d+[\w.\-]*|[0-9a-f]{40})\b", line):
                missing.append(f"{tool}: {line.strip()}")
            break
        else:
            missing.append(f"{tool}: no `go install` line found")
    assert not missing, "tools without an explicit pinned version:\n  " + "\n  ".join(missing)


def test_nuclei_template_drift_is_addressed_explicitly():
    """Pinning the nuclei BINARY does not pin what it scans FOR.

    `nuclei -update-templates` at build time pulls the latest template set,
    so template drift survives a binary pin. This is the layer that actually
    produces the false-remediation path, so it must be a recorded decision —
    either pinned, or accepted in writing with the trade-off named
    (template freshness is how new CVEs get caught; that is a real cost).
    """
    src = _dockerfile()
    lines = src.splitlines()
    idx = [i for i, l in enumerate(lines) if "-update-templates" in l and not l.strip().startswith("#")]
    if not idx:
        return  # templates not refreshed at build; nothing to decide

    # ⚠ Scope the window to the comment block IMMEDIATELY ABOVE the line,
    # and require an underscored token. The first cut of this test did
    # neither: it swept up every `#` line in the whole Dockerfile and
    # matched /TEMPLATE[ _-]?VERSION/i, so the prose "template version
    # string blank" — describing the PROBLEM — satisfied the assertion for
    # RECORDING THE DECISION. Deleting the actual TEMPLATE_DRIFT marker
    # still passed. Caught by mutation M2, 2026-09-07. A pin that matches
    # incidental prose is not a pin.
    i = idx[0]
    block = []
    j = i - 1
    while j >= 0 and (lines[j].strip().startswith("#") or not lines[j].strip()):
        block.append(lines[j])
        j -= 1
    window = "\n".join(reversed(block))

    assert re.search(r"TEMPLATE_(PIN|DRIFT|VERSION)", window), (
        "`nuclei -update-templates` runs at build time, so the template set "
        "floats even with the binary pinned — and a template renamed or "
        "dropped upstream makes a finding vanish, which the lifecycle records "
        "as REMEDIATION.\n"
        "Record the decision in the comment block IMMEDIATELY ABOVE that "
        "line, containing the literal token TEMPLATE_PIN, TEMPLATE_DRIFT or "
        "TEMPLATE_VERSION (underscored — prose like 'template version' does "
        "not count) — either pin the template set, or accept the drift "
        "explicitly and say why."
    )
