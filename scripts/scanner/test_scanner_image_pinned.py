"""test_scanner_image_pinned.py — the production scan path must not float.

WHY THIS EXISTS (2026-09-07). `scanner.yml` pulled
`commandsentry-scanner:latest` while the comment directly above that line
read "Pin to a date+sha tag in production; bump explicitly when the image
is rebuilt." The intent was written down and never implemented, so every
image rebuild silently swapped the scanning image under production.

The harm is not "builds aren't reproducible." A tool or nuclei template
that changes upstream can make a finding DISAPPEAR, and the finding
lifecycle records that as REMEDIATION — a false-remediation path no gate
catches, because the scan ran perfectly and every phase reported ok.

Pinning docker/Dockerfile (test_toolchain_pinned.py) stops the TOOLS
drifting between builds. Pinning this tag stops the IMAGE changing
without a commit. One without the other leaves the door open.

Deliberately narrow: this does NOT check that the pinned tag is the
NEWEST build. Choosing when to move production is a human act, and the
commit that bumps the tag is the record of when the scanning surface
changed. This only refuses the state where nobody chose.

⚠ Scope: the production scan path ONLY. The 8 diagnostic/canary
workflows (fortigate-*, vpn-egress-*, toolchain-inventory) deliberately
stay on `:latest` so they keep exercising the newest build — that is what
a canary is for.
"""
import re
from pathlib import Path

SCANNER_YML = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "scanner.yml"

# Matches build-scanner-image.yml's Compute tag step: "${DATE}-${SHA7}"
DATED_TAG = re.compile(r"commandsentry-scanner:20\d{6}-[0-9a-f]{7,}\b")
FLOATING_TAG = re.compile(r"commandsentry-scanner:(latest|main|edge)\b")
IMAGE_LINE = re.compile(r"image:\s*ghcr\.io/[^\s]*commandsentry-scanner")


def _code_lines() -> list[str]:
    """scanner.yml with comments stripped.

    ⚠ Strip comments FIRST. A pin that matches the prose describing the
    problem instead of the code is not a pin. This has bitten twice:
    once in feedback_source_pins_must_strip_comments, and again on
    2026-09-07 in test_toolchain_pinned.py (mutation M2 — deleting the
    real marker still passed, because a comment containing the words
    "template version" satisfied the regex).
    """
    assert SCANNER_YML.is_file(), f"scanner.yml not found at {SCANNER_YML}"
    src = SCANNER_YML.read_text()
    # Floor: a truncated or restructured scanner.yml must not let the
    # assertions below pass by matching nothing.
    assert len(src) > 5000 and "container:" in src, (
        f"scanner.yml looks wrong ({len(src)} chars, container: "
        f"{'container:' in src}) — the checks below are regex matches and "
        f"would pass vacuously against a stub")
    return [l for l in src.splitlines() if not l.strip().startswith("#")]


def test_production_scan_path_does_not_pull_a_floating_tag():
    """`:latest` means the scanning image can change with no commit."""
    offenders = [l.strip() for l in _code_lines() if FLOATING_TAG.search(l)]
    assert not offenders, (
        "scanner.yml pulls a FLOATING scanner image tag — the image can "
        "change under production with no commit:\n  "
        + "\n  ".join(offenders)
        + "\n\nUse the YYYYMMDD-<sha7> tag that build-scanner-image.yml "
          "publishes; its run summary prints the exact line to paste."
    )


def test_scanner_image_is_pinned_to_a_dated_build_tag():
    """The image line must exist AND carry a real date+sha build tag."""
    image_lines = [l for l in _code_lines() if IMAGE_LINE.search(l)]

    # ⚠ Not finding the line is a FAILURE, not a pass. Otherwise renaming
    # the image silently disarms this guard.
    assert image_lines, (
        "no `image: ghcr.io/.../commandsentry-scanner...` line found in "
        "scanner.yml. This check must not pass by finding nothing — if the "
        "image reference moved, update this guard to follow it.")

    bad = [l.strip() for l in image_lines if not DATED_TAG.search(l)]
    assert not bad, (
        "scanner image tag is not a date+sha build tag:\n  "
        + "\n  ".join(bad)
        + "\n\nExpected commandsentry-scanner:YYYYMMDD-<sha7>."
    )
