"""library_flaws.py — published flaws in the JavaScript libraries a site
reports (plan 302 step 2, shipped with step 3; 2026-10-09).

httpx already reports library versions on every scan ("jQuery UI:1.12.1").
For the few libraries in PACKAGES, this asks OSV.dev (Google's open
vulnerability database, npm advisories) whether that exact version is in the
affected range of a published advisory. Each match becomes a finding labelled
version-based: it says "this version is on the list", not "we proved it".

The only request goes to api.osv.dev and carries just a package name and a
version. Nothing is sent to the scanned target (D-056).

Rules (plan 302 step 4, applied from the start):
  * full versions only (x.y.z): "jQuery 3" or "Bootstrap 4.1" says too little,
    and OSV would read it as 3.0.0 / 4.1.0 and match flaws the site may not
    have; no version, no lookup
  * only libraries in PACKAGES, a reviewed list; an unknown name is never guessed
  * withdrawn advisories and anything that is neither a GitHub advisory nor
    carries a CVE number are ignored
"""
from __future__ import annotations

import http.client
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

OSV_QUERY = "https://api.osv.dev/v1/query"
USER_AGENT = "Sentry-ASM library-flaws/1.0 (public advisory lookups)"
ECOSYSTEM = "npm"
TIMEOUT_S = 20
MAX_PAGES = 5

# httpx (Wappalyzer) product name, lower-cased -> npm package. Reviewed by hand:
# each is the browser library itself, published to npm under exactly this name.
PACKAGES = {
    "jquery": "jquery",
    "jquery ui": "jquery-ui",
    "jquery migrate": "jquery-migrate",
    "bootstrap": "bootstrap",
    "lodash": "lodash",
    "moment.js": "moment",
    "angularjs": "angular",
    "handlebars": "handlebars",
    "underscore.js": "underscore",
    "dompurify": "dompurify",
    "vue.js": "vue",
}

SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MODERATE",
            "MEDIUM": "MODERATE", "LOW": "LOW"}
DEFAULT_SEVERITY = "MODERATE"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
FULL_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
# http.client.HTTPException: a reply cut off mid-body (IncompleteRead) or a
# garbled status line; not an OSError, and must not escape as a crash.
NET_ERRORS = (OSError, ValueError, http.client.HTTPException)


class LookupFailed(Exception):
    """OSV could not be asked this time."""


@dataclass(frozen=True)
class Advisory:
    id: str
    cves: tuple
    summary: str
    severity: str           # ours (CRITICAL/HIGH/MODERATE/LOW)
    severity_stated: bool   # False = the advisory gave none; DEFAULT_SEVERITY used
    fixed: str | None
    cwe: tuple
    references: tuple


def lookups(observations) -> list[tuple]:
    """(observation, npm package) for each observed library we know, with a
    full x.y.z version. PURE."""
    out, seen = [], set()
    for o in observations or []:
        pkg = PACKAGES.get(getattr(o, "item_key", ""))
        if pkg and FULL_VERSION_RE.match(str(getattr(o, "version", ""))) and (pkg, o.version) not in seen:
            seen.add((pkg, o.version))
            out.append((o, pkg))
    return out


def _post_json(url, body, timeout=TIMEOUT_S, opener=None):
    opener = opener or urllib.request.urlopen
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"User-Agent": USER_AGENT, "Content-Type": "application/json",
                                          "Accept": "application/json"})
    last = None
    for attempt in (1, 2):
        try:
            with opener(req, timeout=timeout) as resp:
                doc = json.loads(resp.read().decode("utf-8"))
            if not isinstance(doc, dict):
                raise ValueError("answer is not an object")
            return doc
        except urllib.error.HTTPError as e:
            last = e
            if e.code not in (429, 500, 502, 503, 504):
                break
        except NET_ERRORS as e:
            last = e
        if attempt == 1:
            time.sleep(2)
    raise LookupFailed(f"{type(last).__name__}: {str(last)[:200]}")


def query_osv(package, version, post=_post_json) -> list:
    """Every OSV record that lists this npm package version as affected."""
    body = {"package": {"name": package, "ecosystem": ECOSYSTEM}, "version": version}
    vulns = []
    for _ in range(MAX_PAGES):
        doc = post(OSV_QUERY, body)
        page = doc.get("vulns") or []
        if not isinstance(page, list):
            raise LookupFailed("vulns is not a list")
        vulns.extend(page)
        token = doc.get("next_page_token")
        if not token:
            return vulns
        body = {**body, "page_token": token}
    raise LookupFailed(f"more than {MAX_PAGES} pages")


def _vtuple(v):
    m = re.match(r"^(\d+(?:\.\d+)*)", str(v or ""))
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def _dicts(v):
    """The dict items of v if it is a list; [] for anything else."""
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _fixed_after(vuln, package, version):
    """The lowest 'fixed' version for this package above the one seen."""
    seen = _vtuple(version)
    best = None
    for aff in _dicts(vuln.get("affected")):
        pkg = aff.get("package") if isinstance(aff.get("package"), dict) else {}
        if pkg.get("name") != package or pkg.get("ecosystem") != ECOSYSTEM:
            continue
        for rng in _dicts(aff.get("ranges")):
            for ev in _dicts(rng.get("events")):
                fx = ev.get("fixed")
                t = _vtuple(fx)
                if t is not None and seen is not None and t > seen and (best is None or t < best[0]):
                    best = (t, fx)
    return best[1] if best else None


def advisories_from_osv(vulns, package, version) -> list[Advisory]:
    """OSV records -> the advisories we report, one per flaw. PURE."""
    out = {}
    for v in vulns or []:
        if not isinstance(v, dict) or v.get("withdrawn"):
            continue
        vid = str(v.get("id") or "")
        aliases = v.get("aliases") if isinstance(v.get("aliases"), list) else []
        names = [vid] + [a for a in aliases if isinstance(a, str)]
        cves = tuple(sorted({a.upper() for a in names if CVE_RE.match(a.upper())}))
        if not (vid.startswith("GHSA-") or cves):
            continue                                  # e.g. MAL- records: not a flaw advisory
        db = v.get("database_specific") if isinstance(v.get("database_specific"), dict) else {}
        raw_sev = str(db.get("severity") or "").upper()
        cwe = tuple(sorted({int(m.group(1)) for c in (db.get("cwe_ids") if isinstance(db.get("cwe_ids"), list) else [])
                            for m in [re.match(r"^CWE-(\d+)$", str(c))] if m}))
        refs = tuple(r["url"] for r in _dicts(v.get("references")) if isinstance(r.get("url"), str))[:5]
        adv = Advisory(id=vid, cves=cves, summary=str(v.get("summary") or "").strip(),
                       severity=SEVERITY.get(raw_sev, DEFAULT_SEVERITY), severity_stated=raw_sev in SEVERITY,
                       fixed=_fixed_after(v, package, version), cwe=cwe, references=refs)
        key = cves or (vid,)
        if key not in out or (not out[key].id.startswith("GHSA-") and vid.startswith("GHSA-")):
            out[key] = adv                            # one finding per flaw; prefer the GitHub record
    return sorted(out.values(), key=lambda a: (a.cves or (a.id,)))


def finding_fields(obs, package, adv: Advisory, hostname: str) -> dict:
    """LightFinding keyword arguments for one matched advisory. PURE."""
    key = adv.id.lower()            # one advisory, one finding: never two sharing an id
    ids = adv.id + (f" ({', '.join(adv.cves)})" if adv.cves and adv.cves != (adv.id,) else "")
    fixed = f"fixed in {adv.fixed}" if adv.fixed else "no fixed version listed"
    head = adv.summary or f"in the affected range of {adv.id}"
    lines = [
        f"{obs.product} {obs.version} was seen on {hostname} (at {obs.url or 'the site'}). "
        f"That version is in the affected range of {ids}; {fixed}.",
        "Version-based: matched from the version number the site reports, not confirmed by "
        "testing. A site can patch a library without changing its number.",
    ]
    if not adv.severity_stated:
        lines.append(f"The advisory states no severity; {DEFAULT_SEVERITY} is assumed.")
    lines.append(f"Source: OSV.dev, npm package {package}.")
    refs = [f"https://osv.dev/vulnerability/{adv.id}"] + list(adv.references) \
        + [f"https://nvd.nist.gov/vuln/detail/{c}" for c in adv.cves]
    return dict(
        check_name=f"libflaw-{package}-{key}",
        title=f"{obs.product} {obs.version}: {head}"[:200],
        severity=adv.severity,
        category="supply_chain",
        description="\n\n".join(lines),
        tags=["version-cve", "osv", "javascript-library", package],
        cwe=list(adv.cwe) or [1395],     # CWE-1395 Dependency on Vulnerable Third-Party Component
        cve=list(adv.cves),
        references=list(dict.fromkeys(refs)),
        normalized_key_override=f"jslib-{package}",
        raw_excerpt=(f"Library: {obs.product} (npm {package})\nVersion seen: {obs.version}\n"
                     f"Seen at: {obs.url}\nAdvisory: {adv.id}\nCVE: {', '.join(adv.cves) or '(none)'}\n"
                     f"Fixed in: {adv.fixed or '(not listed)'}\n"
                     f"Advisory severity: {adv.severity if adv.severity_stated else '(not stated)'}")[:2000],
    )
