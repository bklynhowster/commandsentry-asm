"""digest_words.py — what a finding means, in plain words (KB 12 job 3l, Howie's review).

Howie, 2026-10-22, on the first test sends: "Too many of the items are complete repeats";
"What the hell does up or down actually mean?"; "doesn't give me the instructions"; "You can
even put a little cynicism or sarcasm or humor here, but you can't have each one be a repeat
of the one before it." And on who reads it (19:34–19:37): "We're aiming this at business
owners ... the Command Unimac IT team"; the WordPress sites are run by an outside company and
nobody inside "has any idea how WordPress works"; "we need to just provide better telemetry,
better intelligence that says where the risk is, not where it might be"; "If there is a
WordPress site where we discover a major vulnerability, we should identify it to the best of
our knowledge, provide what the risk is, and provide what the remediation is."

So every item answers three questions, in words a business owner reads:
    title   what we found
    why     what it means for the business (dry humor allowed here, never in `do`)
    do      the fix
    who     who does the fix: "it" (your IT team) or "wordpress" (the company that runs
            your WordPress sites — the email gives a paragraph to forward to them)
    fixed   how to say it went away ("a web firewall is now in place")

GUESSES ARE NOT FINDINGS. "Runs X, version not shown" is Sentry unable to see something,
not risk; `is_guess` marks it and the emails leave it out entirely — not listed, not
counted, not mentioned, and not used for a site's level (Howie, 10-22: "There are risks and
there are things that are known, that's all"). Job 3r takes it out of the portal's ratings.

WORDPRESS PLUGIN ADVISORIES are read, not echoed: `advisory()` takes the version we saw and
the advisory's own affected range and says whether it applies. On 10-22 four of five Slider
Revolution advisories matched 6.7.58 only because the check read "older than 7.0.11" and not
"from 7.0.0" — the arbitrary-file-upload one among them. An advisory whose range excludes
the version we saw is dropped; one we cannot judge is kept. PURE: no database, no network.
"""
from __future__ import annotations

import re
from html import unescape

PLUGIN_NAMES = {"revslider": "Slider Revolution", "mega_main_menu": "Mega Main Menu"}

# {it}: "this site" / "these sites"; {them}: "it" / "them"; {x}: the regex's first group
FAMILIES = (
    {"key": "waf-absent", "match": r"^No enforcing WAF", "who": "it",
     "title": "No web firewall in front of {it}",
     "why": "Our harmless test attacks walked straight in. Nothing between {it} and the internet "
            "said no, so a real attack would get the same welcome.",
     "do": "Put a web application firewall in front of {it} (Cloudflare, an Azure Application "
           "Gateway WAF, or similar), or take {it} off the public internet if nobody outside needs {them}.",
     "fixed": "a web firewall is now in place",
     "headline": "put a web firewall in front of {where}"},
    {"key": "waf-not-blocking", "match": r"^WAF detected but not blocking", "who": "it",
     "title": "A web firewall is there, but it's only watching",
     "why": "Something sits in front of {it} and let every one of our harmless test attacks through. "
            "A guard who waves everyone in.",
     "do": "Switch the firewall on {it} from detect (monitor) mode to block (prevent) mode. "
           "The next deep scan will check.",
     "fixed": "the web firewall now blocks our test attacks",
     "headline": "switch the web firewall on {where} from watch mode to block mode"},
    {"key": "waf-partial", "match": r"^WAF enforcement is partial: (.+)", "who": "it",
     "title": "The web firewall stops some attacks, not all",
     "why": "{x}. The ones that get through are the ones that matter.",
     "do": "Turn on the firewall's rules for the kind of attack that got through.",
     "fixed": "the web firewall now blocks every kind of test attack",
     "headline": "turn on the missing firewall rules for {where}"},
    {"key": "version-unknown", "match": r"^Runs (.+?), version not shown", "who": "it", "guess": True,
     "title": "Runs {x}; we can't see which version",
     "why": "", "do": "", "fixed": "we can now see it's on a patched version"},
    {"key": "cert-revocation", "match": r"^Certificate revocation checking unavailable", "who": "it",
     "title": "Its certificate can't be checked for revocation",
     "why": "If the certificate were ever stolen, browsers would have no way to learn it had been cancelled.",
     "do": "Replace the certificate on {it} with one from a public certificate authority.",
     "fixed": "its certificate is checkable again",
     "headline": "replace the certificate on {where}"},
    {"key": "cert-lifespan", "match": r"cert_extlifeSpan: (\d+) days", "who": "it",
     "title": "A certificate good for {years} years",
     "why": "It will outlive the hardware it's on. Browsers distrust certificates like this, and nobody issues them on purpose.",
     "do": "Replace the certificate on {it} with a normal one-year certificate.",
     "fixed": "the decades-long certificate is gone",
     "headline": "replace the decades-long certificate on {where}"},
    {"key": "cert-chain", "match": r"Incomplete TLS Certificate Chain", "who": "it",
     "title": "Its certificate is missing a link",
     "why": "Some browsers and apps can't verify it, so they warn or refuse to connect.",
     "do": "Install the intermediate certificate on {it} so the full chain is served.",
     "fixed": "the certificate chain is complete",
     "headline": "install the missing intermediate certificate on {where}"},
    {"key": "cert-expiring", "match": r"^TLS certificate expiring soon .*\((\d+)\)", "who": "it", "minor": True,
     "title": "its certificate expires in about {x} days",
     "why": "", "do": "Renew it before then.", "fixed": "the certificate is renewed"},
    {"key": "ocsp", "match": r"^OCSP stapling not enabled", "who": "it", "minor": True,
     "title": "it doesn't staple its certificate status (a speed nicety, not a hole)",
     "why": "", "do": "", "fixed": "certificate status is stapled"},
    {"key": "caa", "match": r"^No CAA DNS record", "who": "it", "minor": True,
     "title": "its domain doesn't limit which companies may issue it certificates",
     "why": "", "do": "", "fixed": "a CAA record is in place"},
    {"key": "hsts", "match": r"^HSTS not enabled", "who": "it", "minor": True,
     "title": "it doesn't tell browsers to always use a secure connection (HSTS)",
     "why": "", "do": "", "fixed": "HSTS is on"},
    {"key": "auth-bypass", "match": r"Authentication Bypass", "who": "it",
     "title": "{title}",
     "why": "A way past the login, found by hand.",
     "do": "",
     "fixed": "the login bypass is fixed"},
)
FAMILY_BY_KEY = {f["key"]: f for f in FAMILIES}
_COMPILED = [(f, re.compile(f["match"], re.I)) for f in FAMILIES]

# WordPress plugin advisories, in the three spellings the scanners write:
#   "Slider Revolution [revslider] < 7.0.11"            (light, wpvulnerability lookup)
#   "Mega Main Menu [mega_main_menu] <= 2.2.2 (unfixed)"
#   "revslider 6.7.54 — < 7.0.10 (CVE-2026-6728)"        (wpvulnerability import)
#   "F-01: Abandoned Plugin — Mega Main Menu 2.2.1 (CVE-2023-1575)"  (hand assessment)
_PLUGIN_A = re.compile(r"^(?P<name>.+?) \[(?P<slug>[a-z0-9_-]+)\] (?P<op><=?)\s*(?P<ver>\d[\w.]*)(?P<unfixed>.*unfixed)?", re.I)
_PLUGIN_B = re.compile(r"^(?P<slug>[a-z0-9_-]+) (?P<seen>\d[\w.]*) — (?P<op><=?)\s*(?P<ver>\d[\w.]*)", re.I)
_PLUGIN_C = re.compile(r"Abandoned Plugin — (?P<name>.+?) (?P<seen>\d[\w.]*) \(", re.I)


def plugin_of(title: str | None) -> dict | None:
    """{'slug', 'name', 'fixed_in' (None when unfixed or unknown), 'seen' (if in the title)}"""
    t = unescape(title or "").strip()
    m = _PLUGIN_A.search(t)
    if m:
        slug = m["slug"].lower()
        unfixed = bool(m["unfixed"]) or m["op"] == "<="
        return {"slug": slug, "name": PLUGIN_NAMES.get(slug, m["name"].strip()),
                "fixed_in": None if unfixed else m["ver"], "seen": None}
    m = _PLUGIN_B.search(t)
    if m:
        slug = m["slug"].lower()
        return {"slug": slug, "name": PLUGIN_NAMES.get(slug, slug.replace("_", " ").title()),
                "fixed_in": None if m["op"] == "<=" else m["ver"], "seen": m["seen"]}
    m = _PLUGIN_C.search(t)
    if m:
        name = m["name"].strip()
        slug = next((s for s, n in PLUGIN_NAMES.items() if n.lower() == name.lower()),
                    name.lower().replace(" ", "_"))
        return {"slug": slug, "name": name, "fixed_in": None, "seen": m["seen"]}
    return None


def _vt(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


_SEEN = re.compile(r"(?:at version|version \*\*|installed v|version)\s*\**\s*v?(\d+(?:\.\d+)+)", re.I)
_RANGE = (re.compile(r"in versions? (\d[\d.]*) (?:to|-|through) (\d[\d.]*)", re.I),
          re.compile(r"from (\d[\d.]*) through (\d[\d.]*)", re.I),
          re.compile(r"versions (\d[\d.]*)\s*-\s*(\d[\d.]*)", re.I))
_UPTO = re.compile(r"(?:up to,? and including,?|versions up to) (\d[\d.]*)", re.I)
_RISK = re.compile(r"This makes it possible for (.+?)(?:\.\s|\.$)", re.S)
_ONLY = re.compile(r"(This only affects [^.]+\.)")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")


def _actor(phrase: str) -> tuple[str, str]:
    """'unauthenticated attackers to extract …' -> ('Anyone on the internet, without logging in,', 'extract …')"""
    p = phrase.strip()
    m = re.match(r"unauthenticated attackers,? (?:to )?(.+)", p, re.I)
    if m:
        return "Anyone on the internet, without logging in,", m.group(1)
    m = re.match(r"authenticated attackers, with ([\w-]+)-level (?:access|permissions)(?: and above)?,? (?:to )?(.+)", p, re.I)
    if m:
        lvl = m.group(1).lower()
        who = ("Someone who already has administrator access" if lvl in ("administrator", "admin") else
               "Someone with an editor account" if lvl == "editor" else
               "Anyone with even a basic account on the site")
        return who, m.group(2)
    m = re.match(r"(?:authenticated )?attackers,? (?:to )?(.+)", p, re.I)
    if m:
        return "An attacker", m.group(1)
    return "", p


def advisory(title: str | None, description: str | None) -> dict:
    """What one plugin advisory finding says, judged: {'applies': True/False/None, 'seen',
    'risk', 'fixed_in', 'cves'}. applies False only when the advisory's own affected range
    excludes the version we saw; None when we cannot tell."""
    t, d = unescape(title or ""), unescape(description or "")
    p = plugin_of(t) or {}
    m = _SEEN.search(d)
    seen = p.get("seen") or (m.group(1) if m else None)
    lo = hi = None
    for rx in _RANGE:
        r = rx.search(d)
        if r:
            lo, hi = r.group(1), r.group(2)
            break
    if not hi:
        u = _UPTO.search(d)
        if u:
            hi = u.group(1)
    applies = None
    if seen and (lo or hi):
        applies = not ((lo and _vt(seen) < _vt(lo)) or (hi and _vt(seen) > _vt(hi)))
    risk = ""
    r = _RISK.search(d)
    if r:
        who, what = _actor(r.group(1))
        what = re.sub(r",? which makes remote code execution possible", ", and from there take over the site", what)
        risk = (f"{who} can {what}".strip() if who else what[0].upper() + what[1:]).rstrip(".") + "."
        o = _ONLY.search(d)
        if o:
            risk += " " + o.group(1)
    return {"applies": applies, "seen": seen, "risk": risk, "fixed_in": p.get("fixed_in"),
            "cves": sorted(set(_CVE.findall(t + " " + d)))}


def _it(n: int) -> dict:
    return {"it": "this site" if n == 1 else "these sites", "them": "it" if n == 1 else "them"}


def family_of(title: str | None) -> tuple[dict | None, re.Match | None]:
    t = unescape(title or "").strip()
    for f, rx in _COMPILED:
        m = rx.search(t)
        if m:
            return f, m
    return None, None


def is_guess(title: str | None) -> bool:
    f, _m = family_of(title)
    return bool(f and f.get("guess"))


def _fill(text: str, n_sites: int, m: re.Match | None, title: str) -> str:
    vals = dict(_it(n_sites), title=title, x=(m.group(1).strip() if m and m.groups() else ""))
    if m and "years" in text:
        try:
            vals["years"] = str(round(int(m.group(1)) / 365))
        except (ValueError, IndexError):
            vals["years"] = "many"
    out = text
    for k, v in vals.items():
        out = out.replace("{" + k + "}", v)
    return out


def words(title: str | None, n_sites: int = 1) -> dict:
    """{'key', 'title', 'why', 'do', 'who', 'fixed'} for a finding title on n_sites sites. A
    WordPress plugin advisory gets the plugin's words (its risk comes from `advisory`); a
    title with no family keeps its own words: key '', why/do empty, who 'it', fixed 'fixed'."""
    raw = unescape(title or "").strip()
    p = plugin_of(raw)
    if p:
        return {"key": f"plugin:{p['slug']}", "title": f"{p['name']}, a WordPress plugin, has a published security flaw",
                "why": "", "who": "wordpress",
                "do": (f"Update {p['name']} to version {p['fixed_in']} or later." if p["fixed_in"] else
                       f"Remove {p['name']} or replace it with a maintained plugin; there is no fixed version."),
                "fixed": f"{p['name']} is updated",
                "headline": f"ask your WordPress company to {'update' if p['fixed_in'] else 'remove'} {p['name']} on {{where}}"}
    f, m = family_of(raw)
    if not f:
        return {"key": "", "title": raw, "why": "", "do": "", "who": "it", "fixed": "fixed", "headline": ""}
    out = {k: _fill(f[k], n_sites, m, raw) for k in ("key", "title", "why", "do", "fixed")}
    out["who"] = f.get("who", "it")
    out["headline"] = _fill(f.get("headline", ""), n_sites, m, raw)
    return out


def family_key(title: str | None) -> str:
    """What groups 'the same problem': a plugin by its slug, a family by its key (with what it
    names, so WordPress and PHP stay apart), or the lower-cased title for anything else."""
    p = plugin_of(title)
    if p:
        return f"plugin:{p['slug']}"
    f, m = family_of(title)
    if not f:
        return unescape(title or "").strip().lower()
    if f["key"] == "version-unknown" and m and m.groups():
        return f"{f['key']}:{m.group(1).strip().lower()}"
    return f["key"]
