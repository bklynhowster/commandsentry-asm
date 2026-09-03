#!/usr/bin/env python3
"""FortiGate transport-fingerprint test — the decisive Mullvad-egress run.

WHY
---
2026-09-03, from a clean residential IP, a single-variable test showed FortiWeb
on commandcommcentral.com blocks a non-browser TLS fingerprint (libcurl: 8
blocks, first at request #3) while passing a real-Chrome fingerprint (45/45),
on IDENTICAL benign URLs / same IP / same rate / interleaved. Transport, not
rate, not reputation.

Two gaps remained before the browser-transport port is a known quantity, and
this run closes both:

  1. FAITHFUL scanner arm — the residential run's non-browser arm was libcurl,
     not nuclei's Go stack. Here the scanner arm is `httpx` (ProjectDiscovery,
     Go) — nuclei's SIBLING HTTP stack, same crypto/tls ClientHello class.
  2. THE REAL EGRESS — residential is clean-reputation. The cloud scanner runs
     over a Mullvad DATACENTER range. This must run there: a Chrome fingerprint
     surviving on Mullvad is what proves the port works; a Chrome fingerprint
     ALSO blocked on Mullvad means the port needs residential/rotating egress
     too, not just browser transport.

DESIGN — single variable
-------------------------
Hold constant: egress (the Mullvad tunnel the workflow raised), URL set (benign
same-origin static assets harvested live), rate, and — critically — interleave
the two arms request-by-request so both experience identical cumulative load.
The ONLY thing that differs is the client transport:

  * chrome  arm  → curl_cffi impersonate="chrome"  (the proposed fix)
  * scanner arm  → httpx (PD Go)                    (what bans today)

Interleaving is what separates the hypotheses: if only the scanner arm is
blocked under shared load → transport; if both fail together → reputation.

NO attack payloads. Benign GETs only, so a block is attributable to the client
fingerprint, never to signature-matching on a malicious string.

Output: a markdown verdict to $GITHUB_STEP_SUMMARY (rendered on the run page)
plus a one-line RESULT| to stdout.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time

TARGET = os.environ.get("FGT_TARGET", "commandcommcentral.com")
N = int(os.environ.get("FGT_N", "60"))            # max requests PER ARM
SPACING = float(os.environ.get("FGT_SPACING", "0.5"))  # seconds between requests (~rate 2)
DIVERGE = int(os.environ.get("FGT_DIVERGE", "8"))  # early-stop: one arm blocked N, other 0

BASE = f"https://{TARGET}"
BLOCK_MARKERS = ("fortinet", "fortiweb", "web page blocked", "blocked",
                 "fwbbot", "challenge")


def egress_ip() -> str:
    try:
        from curl_cffi import requests
        return requests.get("https://api.ipify.org", impersonate="chrome",
                            timeout=8, verify=False).text.strip()
    except Exception as e:  # noqa: BLE001
        return f"<unknown:{type(e).__name__}>"


def harvest_urls() -> list[str]:
    """Benign same-origin static assets from the homepage, via the Chrome arm
    (so the harvest itself isn't blocked). Falls back to the bare homepage."""
    from curl_cffi import requests
    try:
        html = requests.get(BASE + "/", impersonate="chrome",
                            timeout=12, verify=False).text
    except Exception:  # noqa: BLE001
        return [BASE + "/"]
    refs = re.findall(r'(?:href|src)="([^"]+)"', html)
    seen, urls = set(), []
    for h in refs:
        p = None
        if h.startswith("/") and not h.startswith("//"):
            p = h.split("#")[0].split("?")[0]
        elif h.startswith(BASE):
            p = h[len(BASE):].split("#")[0].split("?")[0]
        if p and p not in seen:
            seen.add(p)
            urls.append(BASE + p)
    return urls[:12] or [BASE + "/"]


def chrome_probe(url: str) -> str:
    """Real-Chrome transport. Returns 'ok:NNN' / 'BLOCK:NNN' / 'BLOCK:page' / 'ERR:x'."""
    from curl_cffi import requests
    try:
        r = requests.get(url, impersonate="chrome", timeout=12, verify=False,
                         allow_redirects=False)
        body = (r.text[:2000] if hasattr(r, "text") else "").lower()
        if r.status_code in (403, 406, 429):
            return f"BLOCK:{r.status_code}"
        if any(m in body for m in BLOCK_MARKERS):
            return "BLOCK:page"
        return f"ok:{r.status_code}"
    except Exception as e:  # noqa: BLE001
        return f"ERR:{type(e).__name__}"


def scanner_probe(url: str) -> str:
    """PD-Go transport (httpx — nuclei's sibling stack). Same TLS ClientHello class."""
    try:
        out = subprocess.run(
            ["httpx", "-u", url, "-status-code", "-silent", "-no-color",
             "-timeout", "10", "-retries", "0", "-disable-update-check"],
            capture_output=True, text=True, timeout=20,
        )
        txt = (out.stdout or "") + (out.stderr or "")
        m = re.search(r"\[(\d{3})\]", txt)
        if not m:
            # httpx emitted no status => connection refused/reset/hang => a block
            return "BLOCK:noresp"
        sc = int(m.group(1))
        if sc in (403, 406, 429):
            return f"BLOCK:{sc}"
        return f"ok:{sc}"
    except subprocess.TimeoutExpired:
        return "BLOCK:timeout"
    except FileNotFoundError:
        return "ERR:httpx_missing"
    except Exception as e:  # noqa: BLE001
        return f"ERR:{type(e).__name__}"


def classify(v: str) -> str:
    if v.startswith("ok"):
        return "ok"
    if v.startswith("BLOCK"):
        return "block"
    return "err"


# Fail-closed: this diagnostic may ONLY be aimed at Command's own FortiGate
# apexes (the FORTIGATE_APEXES set the scanner hardcodes). It bypasses the
# scanner's normal ROE gate, so it carries its own allowlist.
ALLOWED_APEXES = ("commandcommcentral.com", "sciimage.com")


def target_authorized(host: str) -> bool:
    h = host.lower().strip().rstrip(".")
    return any(h == a or h.endswith("." + a) for a in ALLOWED_APEXES)


def main() -> int:
    import urllib3
    urllib3.disable_warnings()

    if not target_authorized(TARGET):
        print(f"::error::FGT_TARGET '{TARGET}' is not a Command FortiGate apex "
              f"{ALLOWED_APEXES} — refusing (fail-closed).")
        return 2

    eip = egress_ip()
    urls = harvest_urls()
    print(f"egress={eip}  target={TARGET}  urls={len(urls)}  N={N}/arm  spacing={SPACING}s")
    for u in urls:
        print("   ", u)

    arms = ("chrome", "scanner")
    tally = {a: {"ok": 0, "block": 0, "err": 0, "first_block": None} for a in arms}
    probe = {"chrome": chrome_probe, "scanner": scanner_probe}
    stop = None

    for i in range(N):
        url = urls[i % len(urls)]
        for a in arms:
            v = probe[a](url)
            c = classify(v)
            tally[a][c] += 1
            if c == "block" and tally[a]["first_block"] is None:
                tally[a]["first_block"] = tally[a]["ok"] + tally[a]["block"]
            time.sleep(SPACING)
        ch, sc = tally["chrome"], tally["scanner"]
        if (i + 1) % 10 == 0:
            print(f"  after {i+1}/arm: " + " | ".join(
                f"{a}: ok={tally[a]['ok']} block={tally[a]['block']} err={tally[a]['err']}"
                for a in arms))
        if sc["block"] >= DIVERGE and ch["block"] == 0:
            stop = "DIVERGENCE (scanner blocked, chrome clean)"
            break
        if ch["block"] >= DIVERGE and sc["block"] == 0:
            stop = "INVERSE (chrome blocked, scanner clean) — unexpected"
            break
        if ch["block"] >= DIVERGE and sc["block"] >= DIVERGE:
            stop = "BOTH blocking (reputation, not transport)"
            break

    # ── verdict ──
    ch, sc = tally["chrome"], tally["scanner"]
    if sc["block"] > 0 and ch["block"] == 0:
        verdict = ("✅ TRANSPORT CONFIRMED ON MULLVAD — Chrome fingerprint passes, "
                   "PD-Go (nuclei sibling) is blocked, same datacenter egress. "
                   "Browser-transport port is necessary AND sufficient. BUILD IT.")
    elif ch["block"] > 0 and sc["block"] > 0:
        verdict = ("⚠ BOTH BLOCKED ON MULLVAD — reputation is also in play. Browser "
                   "transport alone is not enough from datacenter egress; the port "
                   "must add residential/rotating egress too.")
    elif ch["block"] == 0 and sc["block"] == 0:
        verdict = ("❓ NEITHER BLOCKED — no ban reproduced this run (clean tunnel IP, "
                   "or too few requests). Re-run with higher FGT_N or a warmed egress.")
    else:
        verdict = ("❓ INVERSE/UNEXPECTED — chrome blocked while scanner clean. "
                   "Investigate before drawing conclusions.")

    def row(a):
        t = tally[a]
        tot = t["ok"] + t["block"] + t["err"]
        fb = t["first_block"] if t["first_block"] is not None else "—"
        label = "chrome-impersonate (fix)" if a == "chrome" else "httpx / PD-Go (scanner)"
        return f"| {label} | {t['ok']}/{tot} | {t['block']} | {t['err']} | {fb} |"

    summary = "\n".join([
        "## FortiGate transport-fingerprint test — Mullvad egress",
        "",
        f"**Target:** `{TARGET}`  **Egress:** `{eip}`  "
        f"**Rate:** ~{1/SPACING:.0f}/s  **Interleaved:** yes",
        "",
        "| Arm | passed | blocked | err | first block @ |",
        "|---|---|---|---|---|",
        row("chrome"),
        row("scanner"),
        "",
        f"**Stopped:** {stop or 'completed full N'}",
        "",
        f"### Verdict\n\n{verdict}",
        "",
        "_Single variable: same egress, same benign URLs, same rate, interleaved "
        "request-by-request. Only the client transport differs._",
    ])

    gh = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh:
        with open(gh, "a") as fh:
            fh.write(summary + "\n")
    print("\n" + summary)
    print(f"\nRESULT| chrome_ok={ch['ok']} chrome_block={ch['block']} "
          f"scanner_ok={sc['ok']} scanner_block={sc['block']} "
          f"scanner_first_block={sc['first_block']} egress={eip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
