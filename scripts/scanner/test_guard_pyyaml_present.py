"""The D-056 guard must be able to READ templates on Command (2026-10-09).

nuclei_auth_guard.py reads every nuclei template with PyYAML and refuses the
whole chunk when it cannot ("PyYAML is not installed, so no template can be
read"). Prodex's scanner image installs PyYAML; Command's image
(commandsentry-scanner:20260907-14c639a) does not. So on Command's first deep
scan after the guard shipped (run 37976031281, pm.unimacgraphics.com) every
nuclei chunk was refused: nothing unsafe was sent, but nuclei ran nothing.

Until the image carries PyYAML, scanner.yml installs it at run time from
requirements-guard.txt: one exact version (the one Prodex's image carries),
hash-locked, wheel only, before the VPN comes up. A failed install must not
stop the scan — the guard then refuses nuclei on its own, as designed.
"""
import os
import re
import subprocess
import tempfile

import yaml as _yaml_for_ci  # noqa: F401 — CI must have it too, or the guard tests mean nothing

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WF = os.path.join(ROOT, ".github", "workflows", "scanner.yml")
REQ = os.path.join(ROOT, "scripts", "scanner", "requirements-guard.txt")
STEP = "Ensure PyYAML for the D-056 guard"


def _req_lines():
    return [ln.strip() for ln in open(REQ, encoding="utf-8")
            if ln.strip() and not ln.lstrip().startswith("#")]


def _steps():
    text = open(WF, encoding="utf-8").read()
    return [(m.group(1), m.start()) for m in re.finditer(r"^      - name: (.+)$", text, re.M)], text


def test_requirements_pin_one_exact_hash_locked_pyyaml():
    lines = _req_lines()
    assert len(lines) == 1, lines
    assert re.fullmatch(r"pyyaml==6\.0\.3 --hash=sha256:[0-9a-f]{64}", lines[0]), lines[0]
    # the cp312 manylinux x86_64 wheel published on PyPI for 6.0.3 (Ubuntu 24.04 = Python 3.12)
    assert lines[0].endswith("ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc")


def test_the_install_step_exists_once_and_runs_before_any_scan_or_vpn():
    steps, _ = _steps()
    names = [n for n, _ in steps]
    assert names.count(STEP) == 1
    pos = names.index(STEP)
    for later in ("Bring up VPN (WireGuard via wireguard-go userspace)", "Run Light tier",
                  "Run Medium tier", "Run Heavy tier"):
        assert later in names, later
        assert names.index(later) > pos, f"{STEP} must come before {later}"


def _step_body():
    steps, text = _steps()
    for i, (n, start) in enumerate(steps):
        if n == STEP:
            end = steps[i + 1][1] if i + 1 < len(steps) else len(text)
            return text[start:end]
    raise AssertionError("step missing")


def _run_block():
    """The step's `run: |` script, exactly as GitHub will run it."""
    body = _step_body()
    lines = body.split("\n")
    i = next(n for n, ln in enumerate(lines) if ln.strip() == "run: |")
    block = []
    for ln in lines[i + 1:]:
        if ln.strip() and not ln.startswith("          "):
            break
        block.append(ln[10:])
    return "\n".join(block)


def _logical(script):
    return script.replace("\\\n", " ")


def test_the_install_is_hash_locked_wheel_only_from_the_pinned_file():
    script = _logical(_run_block())
    pip = [ln.strip() for ln in script.splitlines() if re.search(r"\bpip3? install\b", ln)]
    assert len(pip) == 1, pip
    cmd = pip[0].split("||")[0].split()
    assert cmd == ["pip3", "install", "--break-system-packages", "--no-cache-dir",
                   "--only-binary=:all:", "--require-hashes", "-r",
                   "scripts/scanner/requirements-guard.txt"], cmd


def _simulate(pip_rc, yaml_after_install):
    """Run the step under GitHub's shell (bash -eo pipefail) with stub python3/pip3."""
    d = tempfile.mkdtemp()
    state = os.path.join(d, "installed")
    with open(os.path.join(d, "python3"), "w") as fh:
        fh.write("#!/bin/bash\n"
                 f"if [ -f {state} ]; then echo 6.0.3; exit 0; fi\n"
                 "exit 1\n")
    with open(os.path.join(d, "pip3"), "w") as fh:
        fh.write("#!/bin/bash\n"
                 f"echo \"$@\" > {d}/pip_args\n"
                 + (f"touch {state}\n" if yaml_after_install else "")
                 + f"exit {pip_rc}\n")
    for f in ("python3", "pip3"):
        os.chmod(os.path.join(d, f), 0o755)
    p = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", _run_block()],
                       env={"PATH": d + ":/usr/bin:/bin"}, cwd=ROOT, capture_output=True, text=True)
    args = open(os.path.join(d, "pip_args")).read().strip() if os.path.exists(os.path.join(d, "pip_args")) else None
    return p, args


def test_a_failed_install_does_not_stop_the_scan():
    """No PyYAML means the guard refuses nuclei (fail-closed). Failing the whole
    job would also stop the light scan and every other tool — worse, not safer."""
    p, args = _simulate(pip_rc=1, yaml_after_install=False)
    assert p.returncode == 0, p.stderr
    assert "::warning::PyYAML install failed" in p.stdout
    assert args == ("install --break-system-packages --no-cache-dir --only-binary=:all: "
                    "--require-hashes -r scripts/scanner/requirements-guard.txt")


def test_a_good_install_reports_the_version():
    p, _ = _simulate(pip_rc=0, yaml_after_install=True)
    assert p.returncode == 0, p.stderr
    assert "::warning::" not in p.stdout
