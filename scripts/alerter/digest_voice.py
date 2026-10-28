"""digest_voice.py — the daily in Howie's voice (KB 12 job 3l round 5, 2026-10-27).

Howie, 2026-10-27 08:37, on the first gated daily: "It's not really helpful. I don't know what
it's trying to say. I want this to be far more conversational." / "It's the same verbiage over
and over again. That becomes something that, to a human, just becomes a blur." 08:44: "I want
this to be absolutely coming across as me." 09:53, on how the words get written: "let's write a
model that totally approximates my voice and adds a certain amount of randomness to it."
10:26 (D-d): the model writes every sentence; each sentence is checked against the facts of
the one item it is about.

HOW IT WORKS
  facts()    turns digest_daily's model into a CLOSED facts sheet: every item has an id, its
             hosts, its severity word, what / why / fix, and the dates and numbers it may
             mention. Nothing outside the sheet exists as far as the writer is concerned.
  write()    ONE call to the Anthropic API (MODEL_ID, TEMPERATURE) with the voice rules and
             the sheet; the model answers with strict JSON where every entry names its item.
  check()    refuses the answer if any entry names a host, number, date or severity that is
             not that item's; if a required item has no entry; if a nudge carries a date;
             if a banned word, an em dash or a stray URL appears. Pairs, not a whitelist: a
             real number on the wrong host is caught.
  fallback() the same JSON shape written by code, in the voice, never random: used when the
             API fails, the answer is not JSON, or check() refuses. The reason is logged and
             kept on the pending row, and Howie's copy says so.
  render_*   the email and the text from the (checked) answer.

THE VOICE (from `Prodex Labs/00 - Howie Voice Profile — ProDex (2026-07-29).md` and the
rulings of 2026-10-27): "we" and "Sentry", never blame or ownership ("this is on us",
"nothing for you to do"); never anyone's job; no dates on a nudge; comma-joined, dictated
sentences; no em dashes, no bullet lists in the email; "Short version:", "just FYI", "Heads
up"; each fact said once; the same problem on several hosts is one sentence naming the hosts.

PURE except write(), which is the one network call, and which takes its `post` function as an
argument so tests never touch the network.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime
from html import escape

MODEL_ID = "claude-sonnet-4-6"          # the one place the id lives (plan v2, M8). The id this
                                        # repo already calls with the same key every day
                                        # (synthesize_finding_descriptions.py); the first test
                                        # send (10-27 14:53) got HTTP 400 on "claude-sonnet-5-5".
TEMPERATURE = 0.8                       # Howie, 09:53: "a certain amount of randomness"
MAX_TOKENS = 2500
API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
TIMEOUT_S = 90

STILL_OPEN_MAX = 3                      # the two or three worst open things (Howie, 09:00)
EMAIL_ENTRY_MAX_CHARS = 800                 # a firewall paragraph that says what was sent runs long
SLACK_ENTRY_MAX_CHARS = 600
NUDGE_MAX_CHARS = 240                   # a nudge is ONE line (Howie 16:32: "way too wordy")
LINE_MAX_CHARS = 300
HOSTS_NAMED_MAX = 6                     # more than six hosts: six names, then "and N more" (16:30)

# Never in anything a person reads (Howie 09:38: "I don't want there ever to be anything in
# this that talks about somebody getting fired"; 08:40: no blame, no ownership).
BANNED = ("fired", "firing", "fire ", "let go", "your job", "their job", "his job", "her job",
          "blame", "on us", "nothing for you to do", "discipline", "hr ", "vulnerable",
          "accountable", "fault",
          # Howie 18:22: readers do not know what the scanner sends; no mechanics, no DNS talk
          "test traffic", "test request", "test requests", "attack-shaped", "give-me-a-file",
          "resolve", "resolves", "dns",
          "short version")        # Howie 18:33: "you don't say 'short version'"
OPENER = "Here's your morning briefing."   # Howie 18:33: the email opens with this, every day
SENTENCE_MAX_WORDS = 32      # Howie 18:15: a 36-word sentence "makes your eyes go to the back of your head"; the rules say 30
# Whole words only (Qwen, code review 12:02: "default" tripped 'fault' and "on users" tripped
# 'on us', and one trip sends the whole day to the fallback).
_BANNED_RE = [re.compile(r"(?<![a-z-])" + re.escape(w.strip()) + r"(?![a-z-])") for w in BANNED]
EM_DASH = "—"
SEVERITY_WORDS = {
    "CRITICAL": ("critical",), "HIGH": ("high",), "MODERATE-HIGH": ("moderate-high", "moderate high"),
    "MODERATE": ("moderate", "medium"), "LOW": ("low",), "INFO": ("info", "informational"),
}
# never allowed unless the item's own; the second row are the words that play a thing down
# without being a grade (Qwen, code review: a Moderate-high item called "minor"). "Serious"
# stays allowed: "the most serious thing open" ranks, it does not grade.
ALL_SEVERITY_WORDS = ("critical", "high", "moderate-high", "moderate high", "moderate", "medium", "low",
                      "minor", "trivial", "negligible", "cosmetic")

# The scanner's own titles can carry what the voice may never say (an em dash, "VULNERABLE");
# on Prodex today the oldest developer-side nudge is "BREACH attack vulnerability check —
# potentially VULNERABLE, gzip HTTP compression detected" (Qwen, code review 12:02: on day
# one the model echoes it and the check refuses the day, then the fallback prints it raw).
# So every fact string is cleaned on its way INTO the sheet, and the titles with no plain
# words in digest_words get them here.
# Howie 18:15, on a paragraph that spelled the three requests out: "a run-on sentence that
# makes your eyes go to the back of your head. I want plain, how we talk, simple." 18:22: "people
# don't know what Sentry is. People don't know what the test traffic is"; say "the probes that
# determine whether there is some type of security device that's just in front, like a WAF";
# "generic and simple, so people really understand." So: what we found and what it means, in
# his words; never what the scanner sends or how a check works.
THE_PROBE = ("We send every box a few probes to check whether some kind of security device, like a WAF, "
             "is sitting in front of it.")
PLAIN = (
    (re.compile(r"^Something unrecognized is blocking|^Something is standing guard", re.I),
     None,                                             # keep the title it came with
     "These boxes were already in our fleet; what is new is that they block the probes. " + THE_PROBE
     + " So something is now standing guard in front of them, and we are still working out which product it is. "
     "That is good news.",
     ""),
    (re.compile(r"^A web firewall is there, but it's only watching|^WAF detected but not blocking", re.I),
     None,
     "There is a firewall in front of it. " + THE_PROBE + " Here they go straight through to the site. "
     "So that firewall is watching, not blocking.",
     "Switch that firewall from watching (detect or monitor mode) to blocking (prevent mode). The next deep scan checks."),
    (re.compile(r"^\d+ new hosts? found", re.I),
     None,
     "New boxes that have joined our fleet. They get the same checks as everything else from here on.",
     ""),
    (re.compile(r"^\d+ hosts? (?:is|are) not responding", re.I),
     None,
     "Looks down. Any box that does not come back drops off the portal on its own, and we do not have to talk "
     "about it anymore.",
     ""),
    (re.compile(r"^BREACH attack", re.I),
     "Compressed pages could leak a secret (BREACH)",
     "The site compresses its pages (gzip). Someone who can watch the traffic and make a browser send "
     "requests could use that to read a secret out of a page, a token or a session cookie, a bit at a time.",
     "Turn compression off for pages that carry secrets, or mask the tokens on those pages. A few lines of server config."),
    (re.compile(r"Obsolete 3DES/IDEA", re.I),
     "Old weak ciphers (3DES) still offered",
     "3DES is a 1990s cipher; a long capture of traffic can be broken. Modern browsers never pick it, old tools might.",
     "Drop 3DES and the other legacy ciphers from the TLS settings."),
    (re.compile(r"^TLS · BEAST", re.I),
     "Old CBC ciphers (BEAST) still offered",
     "Browsers have worked around BEAST for years; offering those ciphers at all is a legacy setting.",
     "Prefer the AES-GCM and ChaCha20 cipher suites and drop the CBC ones."),
)


def _clean(text) -> str:
    """A fact string as the voice may see it: no dashes, no 'vulnerable', one space."""
    t = str(text or "")
    t = t.replace("—", ", ").replace("–", ", ").replace(" · ", ", ")
    t = re.sub(r"\bpotentially vulnerable\b", "possibly exposed", t, flags=re.I)
    t = re.sub(r"\bvulnerable\b", "exposed", t, flags=re.I)
    t = re.sub(r"\s*,\s*,", ",", t)
    t = re.sub(r"\s+,", ",", t)
    return re.sub(r"[ \t]+", " ", t).strip()


def _plain(title: str, body: str, fix: str) -> tuple:
    """(what, why, fix) in plain words for a title digest_words has none for, or whose words
    hide what Sentry did (Howie 15:02: "what was Sentry actually trying to do?"); else as given.
    A PLAIN row with `what` None keeps the title; a row's `why` replaces the body outright."""
    for pat, what, why, do in PLAIN:
        if pat.search(title or ""):
            if what is None:                           # a firewall row: its words replace the body
                return title, why, (fix or do)
            return what, (body or why), (fix or do)
    return title, body, fix


_OPPOSITE = ("The same probes that the hosts above now block go straight through here. "
             "This firewall is watching, not blocking.")


def _relate(items: list) -> None:
    """Howie 15:02: two firewall stories in one email read as the same story twice unless the
    email says they are opposites; 15:32: "You are describing the three-pronged attack twice.
    It's not necessary. Do it once and then refer to it later." When a block-page item
    (something blocks) and a watching-only firewall item are both on the sheet, the watching
    one's why becomes ONE sentence that refers back, host-free (the per-item host rule forbids
    naming the other item's hosts). Alone, it keeps the full explanation."""
    guarding = [it for it in items if it["kind"] == "blockpage"]
    if not guarding:
        return
    above = str(len({h for g in guarding for h in g["hosts"]}))   # "the five hosts above" is a true count
    for it in items:
        if it["section"] in ("changed", "still") and (it.get("family") == "waf-not-blocking"
                                                     or it["what"].startswith("A web firewall is there, but it's only watching")):
            it["why"] = _OPPOSITE
            it["numbers"] = sorted(set(it["numbers"]) | {above})
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
WORD_NUMBERS = {"one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6",
                "seven": "7", "eight": "8", "nine": "9", "ten": "10", "eleven": "11", "twelve": "12",
                "thirteen": "13", "fourteen": "14", "fifteen": "15", "sixteen": "16", "seventeen": "17",
                "eighteen": "18", "nineteen": "19", "twenty": "20", "thirty": "30", "forty": "40",
                "fifty": "50", "sixty": "60", "seventy": "70", "eighty": "80", "ninety": "90",
                "a hundred": "100", "hundred": "100", "both": "2", "a couple of": "2", "a couple": "2",
                "a dozen": "12", "none": "0"}

_HOST = re.compile(r"\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\b", re.I)
_DATE = re.compile(r"\b(?:" + "|".join(MONTHS) + r")\.? \d{1,2}\b|\b(?:" + "|".join(WEEKDAYS)
                   + r")\b|\b\d{1,2}/\d{1,2}(?:/\d{2,4})?\b|\b20\d\d-\d\d-\d\d\b")
_NUMBER = re.compile(r"\b\d+(?:[.,]\d+)?\b")
_URL = re.compile(r"https?://\S+", re.I)
_TIME = re.compile(r"\b\d{1,2}:\d\d\b")
# words that say how long, which a nudge may never say (Howie 09:12: no dates on a nudge;
# "don't tell him since July"): since / ago / last week / for weeks / three months / a while
_HOW_LONG = re.compile(r"\b(?:since|ago|yesterday|last (?:week|month|year)|days?|weeks?|months?|years?|a while|ages|"
                       r"a long time|some time)\b", re.I)
_CLAUSE = re.compile(r"[.;,]")


# ── the facts sheet ─────────────────────────────────────────────────────────────────────
def _text_of(item: dict) -> str:
    parts = [item.get("title", ""), item.get("body", ""), item.get("why", ""), item.get("do", ""),
             item.get("tag", ""), item.get("note", ""), item.get("forward", "")]
    parts += list(item.get("lines") or [])
    return " ".join(p for p in parts if p)


def _dates_in(text: str) -> list[str]:
    return sorted({m.group(0).replace(".", "") for m in _DATE.finditer(text or "")})


def _numbers_in(text: str) -> list[str]:
    nums = {m.group(0) for m in _NUMBER.finditer(text or "")}
    return sorted(nums)


def _short(host: str) -> str:
    return (host or "").split(".")[0]


def _item(iid: str, section: str, kind: str, severity: str, hosts: list, what: str, why: str,
          fix: str, text_for_dates: str, *, dates_allowed: bool = True, extra_numbers=(), detail=(),
          family: str = "") -> dict:
    hosts = [h for h in hosts if h]
    what, why, fix = _plain(what or "", why or "", fix or "")
    what, why, fix = _clean(what), _clean(why), _clean(fix)
    detail = [_clean(d) for d in detail if d]
    text_for_dates = " ".join([_clean(text_for_dates), what, why, fix] + detail)
    # the item's own numbers: everything its facts say, how many hosts, how many detail lines,
    # and how many names its title lists after a colon ("Security headers missing: CSP, HSTS" is
    # two headers; test send 2, 10-27 15:25: the writer said "two" and was refused for it)
    nums = set(_numbers_in(_norm_numbers(text_for_dates))) | {str(len(hosts))} | {str(n) for n in extra_numbers}
    nums |= {str(len(detail))} if detail else set()
    if len(hosts) > HOSTS_NAMED_MAX:
        nums.add(str(len(hosts) - HOSTS_NAMED_MAX))     # "and 14 more"
    if ":" in what:
        names = [n for n in re.split(r",|\band\b", what.split(":", 1)[1]) if n.strip()]
        if len(names) >= 2:
            nums.add(str(len(names)))
    return {
        "id": iid, "section": section, "kind": kind, "severity": severity or "",
        "severity_word": _sev_word(severity), "hosts": hosts, "family": family or "",
        "what": what, "why": why, "fix": fix,
        "detail": detail,                            # per-host specifics, in the model's words
        "dates": _dates_in(text_for_dates) if dates_allowed else [],
        "numbers": sorted(nums),
    }


_QUIET_LINE = re.compile(r"^(?P<host>\S+): no answer(?: since (?P<since>[A-Z][a-z]{2} \d{1,2}))?[^.]*\."
                         r"(?:.*?Leaves the portal on (?P<leaves>[A-Z][a-z]{2} \d{1,2})\.)?", re.S)
_PLAIN_QUIET = re.compile(r"^(?P<host>\S+): looks down(?: since (?P<since>[A-Z][a-z]{2} \d{1,2}))?\."
                          r"(?: Drops off the portal on (?P<leaves>[A-Z][a-z]{2} \d{1,2}) if it stays down\.)?")


def _plain_quiet(line: str) -> str:
    """The scanner's 'valorep: no answer since Oct 22, 2:25 PM. Its name no longer exists on
    the internet. Leaves the portal on Nov 2.' as the readers want it (Howie 18:22: "Nobody
    cares if the name doesn't resolve ... It's just a quick thing"): 'valorep: looks down since
    Oct 22. Drops off the portal on Nov 2 if it stays down.' A line in another shape is kept."""
    m = _QUIET_LINE.match(line or "")
    if not m:
        return line
    s = f"{m.group('host')}: looks down" + (f" since {m.group('since')}" if m.group("since") else "") + "."
    if m.group("leaves"):
        s += f" Drops off the portal on {m.group('leaves')} if it stays down."
    return s


_BLOCK_LINE = re.compile(r"^(?P<host>\S+): On (?P<day>[A-Z][a-z]{2} \d{1,2}) ")


def _plain_block(line: str) -> str:
    """The scanner's 'l3h-ss: On Oct 27 it turned away the attack-style test strings with a
    page no vendor the block-page library knows ...' as 'l3h-ss: started blocking the probes
    on Oct 27.' (Howie 18:22: no mechanics). A line in another shape keeps only its host."""
    m = _BLOCK_LINE.match(line or "")
    if m:
        return f"{m.group('host')}: started blocking the probes on {m.group('day')}."
    host = (line or "").split(":", 1)[0].strip()
    return f"{host}: started blocking the probes." if host else line


def _quiet_parts(line: str) -> tuple:
    """(host, since, leaves) from a plain quiet line; ('', '', '') for any other line."""
    m = _PLAIN_QUIET.match(line or "")
    return (m.group("host"), m.group("since") or "", m.group("leaves") or "") if m else ("", "", "")


def _hosts_of_rating_lines(lines) -> list:
    return [ln.split(" is now", 1)[0].strip() for ln in lines or [] if " is now" in ln]


def _merge_blockpages(items: list) -> list:
    """The 3l daily says 'Something unrecognized is blocking in front of X' once per host; the
    voice says it once for all of them (Howie 08:38: the same verbiage over and over becomes
    a blur; 08:40: a block page is good news, Sentry is still working out the security stack)."""
    pages = [i for i in items if i.get("kind") == "blockpage"]
    if len(pages) < 2:
        return items
    hosts = [h for i in pages for h in (i.get("sites") or [])]
    merged = {
        "kind": "blockpage", "severity": "",
        "title": f"Something is standing guard in front of {len(hosts)} of our hosts, and we are still working out what",
        "body": "",                                    # PLAIN gives it the probe, in words
        "sites": hosts, "lines": [f"{i['sites'][0]}: {i.get('body', '')}" for i in pages if i.get("sites")],
        "why": "", "do": "", "tag": "",
    }
    out, placed = [], False
    for i in items:
        if i.get("kind") == "blockpage":
            if not placed:
                out.append(merged)
                placed = True
            continue
        out.append(i)
    return out


def _sev_word(sev: str) -> str:
    return {"CRITICAL": "Critical", "HIGH": "High", "MODERATE-HIGH": "Moderate-high",
            "MODERATE": "Moderate", "LOW": "Low", "INFO": "Info"}.get((sev or "").upper(), "")


def facts(model: dict, *, still_open=None, slack=None, sentry_only=None, company: str = "",
          day: str = "") -> dict:
    """The closed sheet. `model` is digest_daily.build_model's output; `still_open` the picks
    (group_problems items with `since`); `slack` {'changed': [...], 'nudge': [...]} from
    digest_slack.select(); `sentry_only` the coverage items (Howie's copy only, 10-25 ruling)."""
    items = []
    changed = _merge_blockpages([i for i in model.get("do", []) + model.get("ticket", [])
                                 if i.get("kind") != "coverage"])
    for n, it in enumerate(changed):
        kind = it.get("kind", "finding")
        hosts = list(it.get("sites") or [])
        if kind in ("not_responding", "assets", "dark"):
            hosts = [ln.split(":")[0] for ln in it.get("lines", []) if ":" in ln]
        if kind == "rating":
            hosts = _hosts_of_rating_lines(it.get("lines"))
        lines = list(it.get("lines") or [])
        title = it.get("title", "")
        if kind == "not_responding":
            lines = [_plain_quiet(ln) for ln in lines]
        if kind == "blockpage":
            lines = [_plain_block(ln) for ln in lines]
            title = re.sub(r"^Something unrecognized is blocking", "Something is standing guard", title)
        items.append(_item(f"c{n+1}", "changed", kind, it.get("severity", ""), hosts,
                           title, it.get("body", "") or it.get("why", ""), it.get("do", ""),
                           _text_of(it), extra_numbers=[len(lines)], detail=lines,
                           family=it.get("family", "")))
    for n, it in enumerate(model.get("done", [])):
        hosts = [ln.split(":")[0] for ln in it.get("lines", []) if ":" in ln]
        items.append(_item(f"f{n+1}", "fixed", it.get("kind", "fixed"), "", hosts,
                           it.get("title", ""), "", "", _text_of(it), detail=it.get("lines") or []))
    for n, it in enumerate(still_open or []):
        since = it.get("since")
        text = _text_of(it) + (f" {_day(since)}" if since is not None else "")
        d = _item(f"s{n+1}", "still", it.get("told_kind") or "open", it.get("severity", ""),
                  list(it.get("sites") or []), it.get("title", ""), it.get("body", ""), it.get("do", ""),
                  text, dates_allowed=bool(it.get("recent")), family=it.get("family", ""))
        # a still line is ONE line (Howie 16:32); the second real morning (10-28 08:28) fell back
        # because this item alone carried the whole probe story and the writer wrote it all in.
        # Its why is one short sentence; the portal has the rest.
        if THE_PROBE in d["why"]:
            d["why"] = "There is a firewall in front of it, but it is watching, not blocking."
        items.append(d)
    slack = slack or {}
    for n, it in enumerate(slack.get("changed", [])):
        lines = list(it.get("lines") or [])
        if it.get("kind") == "not_responding":
            lines = [_plain_quiet(ln) for ln in lines]
        items.append(_item(f"k{n+1}", "slack_changed", it.get("kind", "finding"), it.get("severity", ""),
                           list(it.get("sites") or it.get("hosts") or []), it.get("title", ""),
                           it.get("body", ""), it.get("do", ""), _text_of(it), detail=lines))
    for n, it in enumerate(slack.get("nudge", [])):
        items.append(_item(f"n{n+1}", "slack_nudge", "nudge", it.get("severity", ""),
                           list(it.get("sites") or []), it.get("title", ""), it.get("body", ""),
                           it.get("do", ""), _text_of(it), dates_allowed=False))
    _relate(items)
    return {
        "company": company, "day": day,
        "small_count": int(model.get("low", 0) or 0) + int(model.get("info", 0) or 0),
        "items": items,
        "sentry_only": [{"title": i.get("title", ""), "lines": list(i.get("lines") or [])}
                        for i in (sentry_only or [])],
        "portal_note": "Where every site stands, and why, comes in the weekly review on Monday.",
    }


def _day(dt) -> str:
    try:
        return f"{MONTHS[dt.month - 1]} {dt.day}"
    except Exception:
        return ""


def required_ids(f: dict) -> dict:
    out = {"email": [], "fixed": [], "still_open": [], "slack_changed": [], "slack_nudge": []}
    for it in f["items"]:
        key = {"changed": "email", "fixed": "fixed", "still": "still_open",
               "slack_changed": "slack_changed", "slack_nudge": "slack_nudge"}[it["section"]]
        out[key].append(it["id"])
    return out


# ── the writer ──────────────────────────────────────────────────────────────────────────
SYSTEM = """You write a short morning security email and a Slack post for a small company, in the voice of Howie, its security lead, to his own colleagues. Everything you write is read by people on the same team, so it is all "we" and "our". Sentry is the company's own scanner: say "we" for what it did, and never explain what it is or how it works.

HOWIE'S VOICE, from his own writing (a profile built from 72 of his emails and his Slack):
- He dictates. It reads spoken, not composed, but one thing per sentence: the way you would say it out loud to a colleague, never a run-on. No sentence over 30 words. No em dashes, no semicolons, no bullet lists, no headings, no bold. Where a dash would go, a comma or a new sentence.
- He opens with the point. This email always opens "Here's your morning briefing." and then the point; never "Short version:". Spoken openers and pivots, used sparingly: "Obviously", "However,", "Look,", "just FYI", "Believe me,".
- He hedges his own framing and holds the line anyway: "I think", "somewhat", "a little bit", "some kind of", "if I had to choose". Softened, not uncertain.
- He does NOT signpost or build an argument ("what really did it for me is", "the rest follows from that", "so we'd be"). He says things in sequence and lets the reader put it together.
- Old-fashioned turns dropped into plain delivery, only his own: "much obliged", "whereby", "the nuts and bolts of that", "make sure everything is kosher", "holding the bag". Do not invent folksy idioms; when unsure, plainer is more him.
- Warm and direct with his own people. Specific data inline, no corporate-speak, no "I hope this finds you well", nothing that reads composed. He often ends by handing off or saying what is next, not with a summary.
- His verbatim rhythm sample: "Obviously Attio is the more mature product, but if I had to choose between Monaco and Day AI, I think Day AI still is somewhat better. Monaco is by far the most immature of the bunch. However, if they have the most incredible features ever, we can set up some kind of guardrails to protect ourselves from them. You guys tell me which direction you want to go."

WHO READS IT. People who are not security people. They do not know what the scanner is, what it sends, or how a check works, and they do not want to. Say what we found and what it means for us, in the fewest plain words, the way he talks. Never describe the scanner's mechanics: no "test traffic", "test requests", "attack-shaped", no naming of attack types, nothing about a name resolving or DNS. "We" did the checking. Short sentences: never more than 30 words in one sentence. A box that stopped answering gets two sentences: it looks down since when, and it drops off the portal on its own if it does not come back; nothing about why.

THE EMAIL HE APPROVED (match its rhythm and register, not its sentences; the facts differ every day):
"Here's your morning briefing. One of our boxes looks down, and two others got some protection in front of them, which is good. valorep.prodexlabs.com looks like it's been down since Oct 22. If it doesn't come back by Nov 2, it drops off the portal on its own and we don't have to talk about it anymore. Since yesterday, l3h-ss and prod have started blocking our probes. We send every box a few probes to check whether there's some kind of security device sitting in front of it, like a WAF. Something is now standing guard in front of those two, and we're still working out which product it is. Still sitting there: the firewall in front of bitec, demo and highcom is only watching, not blocking. 4 small things also turned up, none of them need anybody, they're in the portal if you're curious."

RULES THAT NEVER BEND. Say each fact once. The same problem on several hosts is ONE sentence that names the hosts (short names are fine: "bitec, demo and highcom"). EVERY entry names EVERY host in its item's "hosts" list, however short the entry: never "five of our sites", never a host left out. One sentence can carry six names. Only when an item has MORE than six hosts: name the first six, then "and N more" with N the exact remainder. Never assign blame or ownership: never "this is on us", "on you", "nothing for you to do", "somebody dropped the ball". Never mention anyone's job, being fired, HR or discipline. A box that now blocks the probes is GOOD news: something is standing guard, and we are still working out which product. Such a box is not new, it was in our fleet already; only an item titled "N new hosts found" is about new boxes, and those "joined our fleet". The probes are explained ONCE, the first time it matters (an item's "why" tells you); after that refer back to them ("the same probes"), never explain them again. When two items are about firewalls in opposite states, say so in one breath, so nobody reads them as the same story twice. Never use the word "vulnerable". Never add a date, number, host, product or severity that is not in the facts for that item, and never move one from one item to another. Severity words only as given ("Moderate", "Moderate-high", "High"); you may also just say "the most serious thing open" without a word. For a NUDGE (slack_nudge items) never say how long it has been open and never give a date.

OUTPUT. Strict JSON, no prose around it, this shape:
{"subject": "<5-9 words, no prefix, says the one main thing>",
 "headline": "<one short sentence, the main thing>",
 "opening": "<'Here's your morning briefing.' then one sentence with the point>",
 "email": [{"id": "<item id>", "text": "<one paragraph about that item only>"}],
 "fixed": [{"id": "<item id>", "text": "<one sentence>"}],
 "still_open": [{"id": "<item id>", "text": "<ONE line, under 240 characters: '[Grade] the problem in plain words on host, host and host.' Nothing else; the detail is in the portal. The firewall item may add its one sentence about the hosts above.>"}],
 "small_line": "<one sentence about the small stuff, or empty string if small_count is 0>",
 "slack": {"changed": [{"id": "<item id>", "text": "<one or two sentences; a finding starts with its severity word in brackets, exactly as given, e.g. '[Moderate] ...'>"}],
           "nudge": [{"id": "<item id>", "text": "<ONE line, under 240 characters: '[Grade] the problem in plain words on host, host and host.' Nothing else.>"}],
           "closing": "<one short easy-going sentence, no dates, no job talk, or empty string>"}}
Each item gives "what", "why", "fix", its "hosts", and "detail": per-host specifics in the scanner's own words (when a host stopped answering, why, when it leaves; what a block page looked like), which you may draw on, saying things once. Every item in the facts must get exactly one entry in its own list, in the order given, and no entry may name an item that is not in the facts. The Slack entries are for developers: concrete, host first, what to do; the email entries are for the leadership trio: what happened and what it means. The two are different pieces of writing, not a shortened copy of each other. If "previous_text" is given, do not reuse its sentences or openers."""


def _prompt(f: dict, previous_text: str) -> str:
    req = required_ids(f)
    lists = (f"email: {req['email']}; fixed: {req['fixed']}; still_open: {req['still_open']}; "
             f"slack.changed: {req['slack_changed']}; slack.nudge: {req['slack_nudge']}")
    return (f"Today is {f.get('day') or 'today'}. Company: {f.get('company') or 'Prodex'}.\n\n"
            f"FACTS (the only things you may say):\n{json.dumps(f['items'], indent=1)}\n\n"
            f"WHICH IDS GO IN WHICH LIST (exactly these, in this order; an empty list stays empty):\n{lists}\n\n"
            f"small_count: {f.get('small_count', 0)}\n\n"
            + (f"previous_text (do not reuse these sentences):\n{previous_text[:3000]}\n\n" if previous_text else "")
            + "Write the JSON now.")


def api_post(url: str, body: dict, api_key: str, timeout: int = TIMEOUT_S) -> dict:
    """The one network call. Raises on any failure (urllib errors, bad JSON)."""
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST", headers={
        "content-type": "application/json", "x-api-key": api_key, "anthropic-version": API_VERSION})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def api_error_words(e) -> str:
    """What the API said, for the log and Howie's copy: its error type and message only (the
    API's own words about the request, never the key or the prompt), cut short."""
    try:
        raw = e.read().decode("utf-8", "replace") if hasattr(e, "read") else ""
        err = json.loads(raw).get("error", {}) if raw else {}
        words = f"{err.get('type', '')}: {err.get('message', '')}".strip(": ")
    except Exception:
        words = ""
    return re.sub(r"\s+", " ", words)[:160]


def write(f: dict, *, api_key: str, previous_text: str = "", post=api_post, model_id: str = MODEL_ID,
          temperature: float = TEMPERATURE) -> dict:
    """ONE call; returns the parsed JSON answer. Raises VoiceError with a short reason on any
    failure (never the key, never the request)."""
    if not api_key:
        raise VoiceError("no API key")
    body = {"model": model_id, "max_tokens": MAX_TOKENS, "temperature": temperature, "system": SYSTEM,
            "messages": [{"role": "user", "content": _prompt(f, previous_text)}]}
    try:
        resp = post(API_URL, body, api_key)
    except urllib.error.HTTPError as e:                       # pragma: no cover - live only
        words = api_error_words(e)
        raise VoiceError(f"API HTTP {e.code}" + (f", {words}" if words else "")) from None
    except Exception as e:
        raise VoiceError(f"API call failed: {type(e).__name__}") from None
    try:
        text = "".join(p.get("text", "") for p in resp.get("content", []) if p.get("type") == "text")
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```[a-z]*\s*|\s*```$", "", text, flags=re.S)
        out = json.loads(text)
    except Exception:
        raise VoiceError("answer was not JSON") from None
    if not isinstance(out, dict):
        raise VoiceError("answer was not an object")
    return out


class VoiceError(Exception):
    pass


# ── the check ───────────────────────────────────────────────────────────────────────────
def _norm_numbers(text: str) -> str:
    t = " " + (text or "").lower() + " "
    for w, d in sorted(WORD_NUMBERS.items(), key=lambda kv: -len(kv[0])):
        t = re.sub(r"(?<![a-z-])" + re.escape(w) + r"(?![a-z-])", f" {d} ", t)
    return t


def _entry_problems(entry: dict, item: dict, where: str, portal_host: str) -> list[str]:
    out = []
    text = entry.get("text") if isinstance(entry, dict) else None
    if not isinstance(text, str) or not text.strip():
        return [f"{where} {item['id']}: empty"]
    limit = SLACK_ENTRY_MAX_CHARS if where.startswith("slack") else EMAIL_ENTRY_MAX_CHARS
    if item["section"] in ("still", "slack_nudge"):
        limit = NUDGE_MAX_CHARS + (len(_OPPOSITE) + 1 if item["why"] == _OPPOSITE else 0)
    if len(text) > limit:
        out.append(f"{where} {item['id']}: too long ({len(text)} chars)")
    low = text.lower()
    # hosts: every host named must be this item's (full name or its short name); every item host named
    allowed = {h.lower() for h in item["hosts"]} | {_short(h).lower() for h in item["hosts"]}
    allowed |= {portal_host.lower()} if portal_host else set()
    for m in _HOST.finditer(text):
        h = m.group(0).lower()
        if h in allowed or _short(h) in allowed:
            continue
        if re.fullmatch(r"\d+(\.\d+)+", h):          # a version number, not a host
            continue
        out.append(f"{where} {item['id']}: names a host that is not its own ({h})")
    missing = [h for h in item["hosts"] if h.lower() not in low and _short(h).lower() not in low]
    if len(item["hosts"]) > HOSTS_NAMED_MAX and missing:
        # six names and "and N more" is the form for a long list (Howie 16:30)
        named = len(item["hosts"]) - len(missing)
        if named < HOSTS_NAMED_MAX or f"and {len(missing)} more" not in low:
            out.append(f"{where} {item['id']}: with {len(item['hosts'])} hosts, name {HOSTS_NAMED_MAX} and say 'and {len(item['hosts']) - HOSTS_NAMED_MAX} more'")
    else:
        for h in missing:
            out.append(f"{where} {item['id']}: does not name {h}")
    # dates
    for d in _dates_in(text):
        if d not in item["dates"]:
            out.append(f"{where} {item['id']}: a date that is not its own ({d})")
    if item["section"] == "slack_nudge" and (_HOW_LONG.search(text) or _TIME.search(text)):
        out.append(f"{where} {item['id']}: a nudge says how long")
    # an item with several hosts and a date per host (a quiet host's detail line): a clause
    # that names one of those hosts may carry only that host's dates (Qwen, code review
    # 12:02: "a since Oct 25 and b since Oct 22" with the two swapped passed every rule)
    if len(item["hosts"]) > 1 and item.get("detail"):
        per_host = {}
        for d in item["detail"]:
            if ":" in d:
                h, rest = d.split(":", 1)
                per_host[h.strip().lower()] = set(_dates_in(rest))
        if any(per_host.values()):
            masked, marks = text, {}
            for i, h in enumerate(per_host):            # hosts carry dots: mask them before splitting
                marks[f"hostmark{i}"] = h
                masked = re.sub(re.escape(h), f" hostmark{i} ", masked, flags=re.I)
                if _short(h):
                    masked = re.sub(r"\b" + re.escape(_short(h)) + r"\b", f" hostmark{i} ", masked, flags=re.I)
            for clause in _CLAUSE.split(masked):
                named = sorted(((clause.index(k), marks[k]) for k in marks if k in clause))
                dates = [m.group(0).replace(".", "") for m in _DATE.finditer(clause)]
                dates = [d for d in dates if d in item["dates"]]
                if len(named) == 1:                     # "a went quiet on Oct 22": all its own
                    pairs = [(named[0][1], d) for d in dates]
                elif named and len(named) == len(dates):  # "a and b went quiet on Oct 22 and Oct 25": in order
                    pairs = [(h, d) for (_i, h), d in zip(named, dates)]
                else:
                    continue                            # two hosts, three dates: cannot be told apart
                for h, d in pairs:
                    if d not in per_host[h]:
                        out.append(f"{where} {item['id']}: {d} is not {h}'s date")
    # numbers (digits and spelled-out), ignoring the ones inside hosts, dates and versions
    scrub = _HOST.sub(" ", text)
    scrub = _DATE.sub(" ", scrub)
    scrub = _TIME.sub(" ", scrub)
    for n in _NUMBER.findall(_norm_numbers(scrub)):
        if n not in item["numbers"] and n not in ("1",):
            out.append(f"{where} {item['id']}: a number that is not its own ({n})")
    # severity words: never another item's; on Slack, always its own (Howie 15:38: "you
    # should identify if it's a medium, informational, or a low")
    own = set(SEVERITY_WORDS.get((item.get("severity") or "").upper(), ()))
    if (where.startswith("slack") or item["section"] == "still") and item.get("severity_word") and not re.search(
            r"(?<![a-z-])" + re.escape(item["severity_word"].lower()) + r"(?![a-z-])", low):
        out.append(f"{where} {item['id']}: does not say its severity ({item['severity_word']})")
    for w in ALL_SEVERITY_WORDS:
        if re.search(r"(?<![a-z-])" + re.escape(w) + r"(?![a-z-])", low) and w not in own:
            if w in ("high", "moderate") and any(x.startswith(w) for x in own):
                continue
            out.append(f"{where} {item['id']}: severity word '{w}' is not its own")
    return out


def check(out: dict, f: dict, *, portal_url: str = "") -> list[str]:
    """Every reason to refuse the answer; [] means it may be rendered."""
    problems: list[str] = []
    if not isinstance(out, dict):
        return ["not an object"]
    by_id = {it["id"]: it for it in f["items"]}
    req = required_ids(f)
    portal_host = ""
    m = re.match(r"https?://([^/]+)", portal_url or "")
    if m:
        portal_host = m.group(1)

    def lists(where, entries, wanted):
        if not isinstance(entries, list):
            problems.append(f"{where}: not a list")
            return
        seen = []
        for e in entries:
            iid = e.get("id") if isinstance(e, dict) else None
            if iid not in by_id:
                problems.append(f"{where}: unknown item id {iid!r}")
                continue
            if by_id[iid]["section"] != {"email": "changed", "fixed": "fixed", "still_open": "still",
                                         "slack.changed": "slack_changed", "slack.nudge": "slack_nudge"}[where]:
                problems.append(f"{where}: item {iid} belongs to another list")
                continue
            if iid in seen:
                problems.append(f"{where}: item {iid} twice")
                continue
            seen.append(iid)
            problems.extend(_entry_problems(e, by_id[iid], where, portal_host))
        for iid in wanted:
            if iid not in seen:
                problems.append(f"{where}: item {iid} has no entry")

    lists("email", out.get("email", []), req["email"])
    lists("fixed", out.get("fixed", []), req["fixed"])
    lists("still_open", out.get("still_open", []), req["still_open"])
    slack = out.get("slack") if isinstance(out.get("slack"), dict) else {}
    lists("slack.changed", slack.get("changed", []), req["slack_changed"])
    lists("slack.nudge", slack.get("nudge", []), req["slack_nudge"])

    for key in ("subject", "headline", "opening", "small_line"):
        v = out.get(key, "")
        if not isinstance(v, str):
            problems.append(f"{key}: not text")
        elif key != "small_line" and not v.strip():
            problems.append(f"{key}: empty")
        elif len(v) > LINE_MAX_CHARS:
            problems.append(f"{key}: too long")
    if not isinstance(slack.get("closing", ""), str):
        problems.append("slack.closing: not text")
    if isinstance(out.get("opening"), str) and not out["opening"].strip().startswith(OPENER):
        problems.append(f"opening: does not start with {OPENER!r}")
    if f.get("small_count", 0) == 0 and str(out.get("small_line", "")).strip():
        problems.append("small_line: says something about small items when there are none")

    # the line rules, each attributed to its line (so repair() can replace just that line)
    for label, t in _lines(out):
        low = " " + t.lower() + " "
        for sent in re.split(r"(?<=[.!?])\s+", t):
            n = len(sent.split())
            if n > SENTENCE_MAX_WORDS:
                problems.append(f"{label}: a sentence of {n} words ({sent[:50]}...)")
        for w, rx in zip(BANNED, _BANNED_RE):
            if rx.search(low):
                problems.append(f"{label}: banned word: {w.strip()!r}")
        if EM_DASH in t:
            problems.append(f"{label}: em dash")
        for u in _URL.findall(t):
            if not portal_url or not u.startswith(portal_url.rstrip("/")):
                problems.append(f"{label}: a URL that is not the portal's ({u[:40]})")
    # a host anywhere in the headline/opening/subject/closing must be some item's host; a
    # number there must be one of the day's counts; a date there must be some item's or the
    # day's own (the subject/headline/opening are free text: without this, "Nine small things"
    # or "Six boxes went quiet on Oct 3" would pass, per-item checks never seeing them)
    all_hosts = {h.lower() for it in f["items"] for h in it["hosts"]}
    all_hosts |= {_short(h) for h in all_hosts}
    sections = {}
    for it in f["items"]:
        sections[it["section"]] = sections.get(it["section"], 0) + 1
    day_numbers = {str(n) for n in (f.get("small_count", 0), 0, 1, *sections.values())}
    day_numbers |= set(_numbers_in(str(f.get("day", ""))))
    # the free lines sum up the day: any item's own numbers, and how many boxes the day's
    # changes touch in all (the first real morning, 2026-10-28: "five boxes" was true, one down
    # and four guarding plus one more, and the check knew only the first item's count)
    changed_items = [it for it in f["items"] if it["section"] == "changed"]
    for it in f["items"]:
        day_numbers |= set(it["numbers"])
    day_numbers.add(str(sum(len(it["hosts"]) for it in changed_items)))
    day_numbers.add(str(len({h for it in changed_items for h in it["hosts"]})))
    day_dates = {d for it in f["items"] for d in it["dates"]} | set(_dates_in(str(f.get("day", ""))))
    for key in ("subject", "headline", "opening", "small_line"):
        v = str(out.get(key, ""))
        for m in _HOST.finditer(v):
            h = m.group(0).lower()
            if h not in all_hosts and _short(h) not in all_hosts and not re.fullmatch(r"\d+(\.\d+)+", h):
                problems.append(f"{key}: names a host that is in no item ({h})")
        for d in _dates_in(v):
            if d not in day_dates:
                problems.append(f"{key}: a date that is nobody's ({d})")
        scrub = _TIME.sub(" ", _DATE.sub(" ", _HOST.sub(" ", v)))
        for n in _NUMBER.findall(_norm_numbers(scrub)):
            if n not in day_numbers:
                problems.append(f"{key}: a number that is not one of the day's counts ({n})")
    for m in _HOST.finditer(str(slack.get("closing", ""))):
        h = m.group(0).lower()
        if h not in all_hosts and _short(h) not in all_hosts:
            problems.append(f"slack.closing: names a host ({h})")
    if _DATE.search(str(slack.get("closing", ""))) or _DATE.search(" ".join(
            e.get("text", "") for e in slack.get("nudge", []) if isinstance(e, dict))):
        problems.append("slack: a date in the nudge or the closing")
    return problems


FREE_KEYS = ("subject", "headline", "opening", "small_line")
LISTS = {"email": "email", "fixed": "fixed", "still_open": "still_open", "slack.changed": "changed", "slack.nudge": "nudge"}
_LABEL = re.compile(r"^(subject|headline|opening|small_line|slack\.closing|email|fixed|still_open|slack\.changed|slack\.nudge)(?: (\w+))?: ")
_STRUCTURAL = ("not a list", "unknown item id", "belongs to another list", "twice", "has no entry", "not text")


def _lines(out: dict):
    """(label, text) for every line the writer wrote: the free lines, the closing, each entry."""
    for k in FREE_KEYS:
        yield k, str(out.get(k, "") or "")
    slack = out.get("slack") if isinstance(out.get("slack"), dict) else {}
    yield "slack.closing", str(slack.get("closing", "") or "")
    for where, key in LISTS.items():
        entries = (slack if where.startswith("slack.") else out).get(key, [])
        for e in entries if isinstance(entries, list) else []:
            if isinstance(e, dict):
                yield f"{where} {e.get('id')}", str(e.get("text", "") or "")


def repair(out: dict, f: dict, problems: list, *, portal_url: str = ""):
    """Howie 2026-10-28 08:31, after two mornings went whole to the backup over one line each:
    "One bad line and the entire email goes to the backup, even when the other nine sentences
    were fine." Replace only the lines the check named with the fallback's lines for the same
    place, keep the rest of the writer's prose, and check again. Returns (out2, replaced) with
    `replaced` = [(label, the writer's line, why)], or (None, []) when the problems are
    structural (a missing or unknown entry) or the repaired answer still fails."""
    fb = fallback(f)
    out2 = json.loads(json.dumps(out))
    replaced = []
    for pr in problems:
        m = _LABEL.match(pr)
        if not m or any(w in pr for w in _STRUCTURAL):
            return None, []
        label, iid = m.group(1), m.group(2)
        why = pr[m.end():]
        if any(r[0] == f"{label} {iid}".strip() for r in replaced):
            continue
        if label in FREE_KEYS:
            replaced.append((label, out2.get(label, ""), why))
            out2[label] = fb.get(label, "")
        elif label == "slack.closing":
            replaced.append((label, out2.get("slack", {}).get("closing", ""), why))
            out2.setdefault("slack", {})["closing"] = fb["slack"]["closing"]
        else:
            key = LISTS[label]
            holder = out2["slack"] if label.startswith("slack.") else out2
            fb_holder = fb["slack"] if label.startswith("slack.") else fb
            fb_text = next((e["text"] for e in fb_holder.get(key, []) if e["id"] == iid), None)
            entry = next((e for e in holder.get(key, []) if isinstance(e, dict) and e.get("id") == iid), None)
            if fb_text is None or entry is None:
                return None, []
            replaced.append((f"{label} {iid}", entry.get("text", ""), why))
            entry["text"] = fb_text
    if not replaced or check(out2, f, portal_url=portal_url):
        return None, []
    return out2, replaced


_PLACE = {"subject": "the subject", "headline": "the headline", "opening": "the opening",
          "small_line": "the line about the small things", "slack.closing": "the Slack closing",
          "email": "the paragraph about", "fixed": "the fixed line about", "still_open": "the still-sitting-there line about",
          "slack.changed": "the Slack line about", "slack.nudge": "the Slack nudge about"}


def plain_reasons(replaced: list, f: dict) -> list:
    """The note Howie reads, in plain words (08:29: "frankly, I'm baffled"): which line, what it
    said, and why it was set aside; the check's shorthand stays in the log."""
    by_id = {it["id"]: it for it in f.get("items", [])}
    out = []
    for label, line, why in replaced:
        where, _, iid = label.partition(" ")
        place = _PLACE.get(where, where)
        if iid and iid in by_id:
            it = by_id[iid]
            place += " " + (_hosts_words(it["hosts"]) or it["what"][:40])
        m = re.match(r"too long \((\d+) chars\)", why)
        if m:
            cap = NUDGE_MAX_CHARS if where in ("still_open", "slack.nudge") else (SLACK_ENTRY_MAX_CHARS if where.startswith("slack") else EMAIL_ENTRY_MAX_CHARS)
            reason = f"it ran {m.group(1)} characters; the limit there is {cap}"
        elif re.match(r"a sentence of (\d+) words", why):
            reason = f"one sentence ran {re.match(r'a sentence of (\d+) words', why).group(1)} words; the limit is {SENTENCE_MAX_WORDS}"
        elif "a number that is not" in why:
            reason = f"it uses the number {re.search(r'\((\S+)\)', why).group(1)}, which is not in the facts for that place"
        elif why.startswith("banned word"):
            reason = f"it uses the word {re.search(r"'([^']+)'", why).group(1)!r}, which the rules never allow"
        elif "names a host" in why:
            reason = "it names a box that is not in the facts for that place"
        elif "does not name" in why:
            reason = "it leaves out one of the boxes it should name"
        elif "a date" in why:
            reason = "it carries a date that is not that item's own"
        elif "severity" in why:
            reason = "it gets the grade wrong or leaves it out"
        elif "how long" in why:
            reason = "a nudge may not say how long something has been open"
        elif "does not start with" in why:
            reason = "it does not open with the briefing line"
        elif "em dash" in why:
            reason = "it uses an em dash"
        else:
            reason = why
        said = line.strip()
        if len(said) > 220:
            said = said[:217].rstrip() + "..."
        out.append(f"{place[0].upper() + place[1:]}: {reason}. It said: \"{said}\"")
    return out


def _flatten(out) -> str:
    if isinstance(out, dict):
        return " ".join(_flatten(v) for v in out.values())
    if isinstance(out, list):
        return " ".join(_flatten(v) for v in out)
    return str(out) if out is not None else ""


# ── the fallback ────────────────────────────────────────────────────────────────────────
def _hosts_words(hosts: list) -> str:
    hs = [_short(h) if len(hosts) > 1 else h for h in hosts]
    if not hs:
        return ""
    if len(hs) == 1:
        return hs[0]
    if len(hs) > HOSTS_NAMED_MAX:
        return ", ".join(hs[:HOSTS_NAMED_MAX]) + f" and {len(hs) - HOSTS_NAMED_MAX} more"
    return ", ".join(hs[:-1]) + " and " + hs[-1]


def _para(it: dict) -> str:
    w = _hosts_words(it["hosts"])
    what = it["what"].rstrip(".")
    if it["section"] in ("still", "slack_nudge"):
        # Howie 15:32: "way too long and detailed"; 16:32: "way too wordy". A nudge is ONE
        # line: the grade, the problem in plain words, the hosts. The detail is in the portal.
        # The one thing it may add is the sentence that relates it to an item above.
        s = _sev_prefix(it) + f"{what}" + (f" on {w}" if w and w.lower() not in what.lower() else "") + "."
        if it["why"] == _OPPOSITE:
            s += " " + _OPPOSITE
        return s
    if it["kind"] == "not_responding":
        # Howie 18:22, his own sentences: "valorep.prodexlabs.com looks like it's been down since
        # October 22 ... If it doesn't show up in the next few days, it's dropping off the portal,
        # and we don't have to talk about it anymore."
        parts = {h: (sc, lv) for h, sc, lv in (_quiet_parts(d) for d in it.get("detail") or []) if h}
        if len(it["hosts"]) == 1:
            h = it["hosts"][0]
            since, leaves = parts.get(h, ("", ""))
            when = f" by {leaves}" if leaves else " in the next few days"
            return (f"{h} looks like it's been down{' since ' + since if since else ''}. If it doesn't come back{when}, "
                    f"it drops off the portal on its own and we don't have to talk about it anymore.")
        named = [_short(h) + (f" since {parts[h][0]}" if parts.get(h, ('', ''))[0] else "") for h in it["hosts"]]
        return (", ".join(named[:-1]) + " and " + named[-1] + " look like they're down. Any that don't come back "
                "drop off the portal on their own, and we don't have to talk about them anymore.")
    if it["kind"] == "blockpage":
        # Howie 18:33: "Did these boxes not exist before?" No: the boxes were here; what is new
        # is that they block the probes. Say that, and say "new boxes" only for the item that is.
        one = len(it["hosts"]) == 1
        return (f"Since yesterday, {w} {'has' if one else 'have'} started blocking our probes, which is good news. "
                f"{THE_PROBE} Something is now standing guard in front of {'it' if one else 'them'}, and we're still "
                f"working out which product it is.")
    if it["kind"] == "assets":
        one = len(it["hosts"]) == 1
        return (f"{'A new box has' if one else 'Some new boxes have'} joined our fleet: {w}. "
                f"{'It gets' if one else 'They get'} the same checks as everything else from here on.")
    s = f"{what}" + (f" on {w}" if w and w.lower() not in what.lower() else "") + "."
    if it["why"]:
        s += " " + it["why"].rstrip(".") + "."
    if it["fix"]:
        s += " " + it["fix"].rstrip(".") + "."
    return s


def _closing(n: int) -> str:
    if n == 0:
        return ""
    head = {1: "It isn't urgent.", 2: "Neither one is urgent."}.get(n, "None of these is urgent.")
    return head + " If you own one of those boxes, it's a quick fix when you get a chance."


def _sev_prefix(it: dict) -> str:
    """Slack lines name their grade (Howie 15:38): "[Moderate] ..."; a quiet host has none."""
    return f"[{it['severity_word']}] " if it.get("severity_word") else ""


def fallback(f: dict) -> dict:
    """The same shape, from code, in the voice, never random."""
    changed = [it for it in f["items"] if it["section"] == "changed"]
    fixed = [it for it in f["items"] if it["section"] == "fixed"]
    still = [it for it in f["items"] if it["section"] == "still"]
    kc = [it for it in f["items"] if it["section"] == "slack_changed"]
    kn = [it for it in f["items"] if it["section"] == "slack_nudge"]
    n = len(changed)
    if n == 0:
        headline, subject = "A quiet night.", "quiet night, nothing new"
        opening = f"{OPENER} Nothing new since yesterday."
    elif n == 1:
        headline = changed[0]["what"].rstrip(".") + "."
        subject = changed[0]["what"][:60]
        opening = f"{OPENER} One thing since yesterday: {changed[0]['what'][0].lower()}{changed[0]['what'][1:].rstrip('.')}."
    else:
        headline, subject = f"{n} things since yesterday.", f"{n} things since yesterday"
        opening = f"{OPENER} {n} things since yesterday, the first one matters most."
    small = f.get("small_count", 0)
    return {
        "subject": subject, "headline": headline, "opening": opening,
        "email": [{"id": it["id"], "text": _para(it)} for it in changed],
        "fixed": [{"id": it["id"], "text": it["what"].rstrip(".") + "."} for it in fixed],
        "still_open": [{"id": it["id"], "text": _para(it)} for it in still],
        "small_line": (f"{small} small thing{'s' if small != 1 else ''} also turned up, none of them need anybody, "
                       f"they're in the portal if you're curious." if small else ""),
        "slack": {
            "changed": [{"id": it["id"], "text": _sev_prefix(it) + _para(it)} for it in kc],
            "nudge": [{"id": it["id"], "text": _para(it)} for it in kn],
            "closing": _closing(len(kn)),
        },
    }


# ── rendering ───────────────────────────────────────────────────────────────────────────
FONT = "'Public Sans', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Helvetica, Arial, sans-serif"
INK, MUTED, PAGE = "#0F1B2D", "#4A5668", "#E9EEF5"
PURPLE, PURPLE_TINT = "#6E56A6", "#F3F0FA"
GREEN, GREEN_TINT = "#0B7A55", "#EAF6F1"
HAIRLINE = "#E3E8F0"
# The grade as a pill, not a word in brackets (Howie 17:43: the still lines "blend into
# themselves"; "maybe you want to have the word 'moderate' look a little different"). Ink on a
# tint per grade; the tints sit quietly on white and the ink reads at 12px.
GRADE_COLORS = {
    "Critical": ("#8A1C1C", "#FBE9E9"),
    "High": ("#9A3B0C", "#FCEEE3"),
    "Moderate-high": ("#7A5300", "#FBF1D6"),
    "Moderate": ("#2F4F8F", "#E6EDF9"),
    "Low": ("#4A5668", "#EDF0F4"),
    "Info": ("#4A5668", "#EDF0F4"),
}
_GRADE_LEAD = re.compile(r"^\s*\[(critical|high|moderate-high|moderate high|moderate|low|info)\]\s*", re.I)


def split_grade(text: str) -> tuple[str, str]:
    """'[Moderate] the problem on a and b.' -> ('Moderate', 'the problem on a and b.');
    a line with no leading grade -> ('', the line)."""
    m = _GRADE_LEAD.match(text or "")
    if not m:
        return "", (text or "").strip()
    return _sev_word(m.group(1).replace(" ", "-")), (text or "")[m.end():].strip()


def grade_pill(word: str) -> str:
    if not word:
        return ""
    ink, tint = GRADE_COLORS.get(word, GRADE_COLORS["Low"])
    return (f'<span style="display:inline-block;font-family:{FONT};font-size:12px;line-height:18px;font-weight:700;'
            f'letter-spacing:.02em;color:{ink};background:{tint};border-radius:999px;padding:2px 10px;'
            f'white-space:nowrap;">{escape(word)}</span>')


def host_names(hosts: list) -> list:
    """Every way a host may be written, full and short, longest first so 'prod' never lands
    inside 'prod.prodexlabs.com'."""
    return sorted({h for h in hosts if h} | {_short(h) for h in hosts if h}, key=len, reverse=True)


def _host_re(name: str) -> re.Pattern:
    # a whole name: not inside another word or a longer host, and not followed by more host
    # ('prod' is not 'prod.prodexlabs.com'); a sentence's period after it is fine
    return re.compile(r"(?<![\w.*-])" + re.escape(name) + r"(?![\w-])(?!\.\w)", re.I)


def mark_hosts(escaped: str, hosts: list) -> str:
    """Bold every host name in an already-escaped line (Howie 17:53: "it's a host ... find a
    way to get it in people's eyes"), so the eye lands on which boxes."""
    for n in host_names(hosts):
        escaped = _host_re(escape(n)).sub(lambda m: f'<span style="font-weight:600;">{m.group(0)}</span>', escaped)
    return escaped


def all_hosts(f: dict) -> list:
    """Every host on the sheet, for the lines that are nobody's item (headline, opening)."""
    return sorted({h for it in f.get("items", []) for h in (it.get("hosts") or [])})


def grade_row(word: str, body_html: str, *, first: bool, size: int = 16, color: str = INK,
              pad: int = 14) -> str:
    """One graded line as a table row: the pill in a narrow left cell, the line beside it;
    a hairline above every row but the first. On a phone the pill stacks above the line."""
    top = "" if first else f"border-top:1px solid {HAIRLINE};"
    if not word:                                       # a quiet host has no grade: the line spans both cells
        return (f'<tr><td colspan="2" valign="top" style="{top}padding:{pad}px 0;font-family:{FONT};font-size:{size}px;'
                f'line-height:1.6;color:{color};">{body_html}</td></tr>')
    return (f'<tr><td class="gr" valign="top" style="{top}padding:{pad + 1}px 14px {pad}px 0;width:1%;white-space:nowrap;">'
            f'{grade_pill(word)}</td>'
            f'<td class="gt" valign="top" style="{top}padding:{pad}px 0;font-family:{FONT};font-size:{size}px;'
            f'line-height:1.6;color:{color};">{body_html}</td></tr>')


def _p(text: str, size: int = 16, color: str = INK, extra: str = "", hosts: list = ()) -> str:
    """A paragraph; with `hosts`, every host name in it is bold."""
    body = mark_hosts(escape(text), list(hosts)) if hosts else escape(text)
    return (f'<div style="font-family:{FONT};font-size:{size}px;line-height:1.6;color:{color};{extra}">'
            f'{body}</div>')


def render_html(out: dict, f: dict, *, brand: dict, logo_cid: str, local_end: datetime,
                portal_url: str = "", product_name: str = "", fallback_reason: str = "") -> str:
    b = brand
    portal = (portal_url or "").rstrip("/")
    logo = (f'<img src="cid:{logo_cid}" width="{int(b.get("logo_width") or 160)}" '
            f'alt="{escape(b.get("logo_alt") or b.get("short_name", ""))}" '
            f'style="display:block;border:0;height:auto;max-width:{int(b.get("logo_width") or 160)}px;">'
            if b.get("logo_bytes") else
            f'<span style="font-family:{FONT};font-size:20px;font-weight:800;color:{b.get("band_text", INK)};">'
            f'{escape(product_name or b.get("short_name", "Sentry"))}</span>')
    border = f'border-bottom:1px solid {b["band_border"]};' if b.get("band_border") else ""
    by_id = {it["id"]: it for it in f["items"]}
    hosts = all_hosts(f)                               # a host name is bold wherever it appears
    rows = [
        f'<tr><td bgcolor="{b.get("band_bg", "#FFFFFF")}" style="background:{b.get("band_bg", "#FFFFFF")};{border}'
        f'border-radius:14px 14px 0 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
        f'<tr><td class="px" style="padding:22px 32px 18px;" valign="middle">{logo}</td>'
        f'<td class="px" align="right" valign="middle" style="padding:22px 32px 18px;font-family:{FONT};font-size:13px;'
        f'color:{b.get("band_muted", MUTED)};white-space:nowrap;"><span style="font-weight:700;color:{b.get("band_text", INK)};">'
        f'{escape(product_name or "Sentry")}</span> · {local_end:%A}, {local_end:%B} {local_end.day}</td></tr></table></td></tr>',
        f'<tr><td class="px" style="background:#FFFFFF;padding:26px 32px 8px;">'
        f'<div style="font-family:{FONT};font-size:24px;line-height:1.25;font-weight:800;letter-spacing:-.01em;color:{INK};">'
        f'{mark_hosts(escape(out.get("headline", "")), hosts)}</div>{_p(out.get("opening", ""), extra="margin-top:14px;", hosts=hosts)}</td></tr>',
    ]
    first = True
    for e in out.get("email", []):
        it = by_id.get(e.get("id"), {})
        if first and it.get("kind") in ("not_responding", "finding", "enforcement", "cert"):
            rows.append(f'<tr><td class="px" style="background:#FFFFFF;padding:12px 32px 0;">'
                        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
                        f'<td style="width:5px;background:{PURPLE};border-radius:4px;"></td>'
                        f'<td style="padding:12px 16px 14px;background:{PURPLE_TINT};border-radius:0 10px 10px 0;">'
                        f'{_p(e.get("text", ""), hosts=hosts)}</td></tr></table></td></tr>')
        else:
            rows.append(f'<tr><td class="px" style="background:#FFFFFF;padding:18px 32px 0;">{_p(e.get("text", ""), hosts=hosts)}</td></tr>')
        first = False
    if out.get("fixed"):
        rows.append(f'<tr><td class="px" style="background:#FFFFFF;padding:18px 32px 0;">'
                    f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
                    f'<td style="width:5px;background:{GREEN};border-radius:4px;"></td>'
                    f'<td style="padding:12px 16px 14px;background:{GREEN_TINT};border-radius:0 10px 10px 0;">'
                    + "".join(_p(e.get("text", ""), hosts=hosts) for e in out["fixed"]) + '</td></tr></table></td></tr>')
    if out.get("still_open"):
        # Howie 17:43: a heading that reads as one, then one row per item: the grade as a
        # pill on the left (from the item's own facts, never from the words), the line beside
        # it with its host names in bold, a hairline between rows so nothing blends.
        srows = []
        for n, e in enumerate(out["still_open"]):
            it = by_id.get(e.get("id"), {})
            word, line = split_grade(e.get("text", ""))
            word = it.get("severity_word") or word
            srows.append(grade_row(word, mark_hosts(escape(line), hosts), first=(n == 0)))
        rows.append(f'<tr><td class="px" style="background:#FFFFFF;padding:28px 32px 0;">'
                    f'<div style="font-family:{FONT};font-size:18px;line-height:1.3;font-weight:800;'
                    f'letter-spacing:-.01em;color:{INK};padding-bottom:4px;">Still sitting there</div>'
                    f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
                    + "".join(srows) + '</table></td></tr>')
    if out.get("small_line"):
        rows.append(f'<tr><td class="px" style="background:#FFFFFF;padding:18px 32px 0;">'
                    f'{_p(out["small_line"], 15, MUTED)}</td></tr>')
    if portal:
        rows.append(f'<tr><td class="px" style="background:#FFFFFF;padding:24px 32px 28px;">'
                    f'<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>'
                    f'<td bgcolor="{b.get("button", INK)}" style="background:{b.get("button", INK)};border-radius:8px;">'
                    f'<a href="{escape(portal)}" style="display:inline-block;padding:12px 18px;font-family:{FONT};'
                    f'font-size:15px;font-weight:600;color:#FFFFFF;text-decoration:none;">Open the portal</a>'
                    f'</td></tr></table></td></tr>')
    else:
        rows.append('<tr><td style="background:#FFFFFF;padding:0 0 20px;"></td></tr>')
    rows.append(f'<tr><td bgcolor="#F4F7FB" class="px" style="background:#F4F7FB;border-radius:0 0 14px 14px;padding:14px 32px;'
                f'font-family:{FONT};font-size:12px;line-height:1.5;color:{MUTED};">Sent by {escape(product_name or "Sentry")} '
                f'at {local_end:%-I:%M %p}. {escape(f.get("portal_note", ""))}</td></tr>')
    return (f'<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<meta name="color-scheme" content="light"><title>{escape(out.get("headline", ""))}</title>'
            f'<link href="https://fonts.googleapis.com/css2?family=Public+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">'
            '<style>@media only screen and (max-width: 520px) { .px { padding-left: 18px !important; padding-right: 18px !important; } '
            f'.gr {{ display: block !important; width: auto !important; padding: 14px 0 0 !important; }} '
            '.gt { display: block !important; border-top: 0 !important; padding-top: 6px !important; } }</style>'
            f'</head>\n<body style="margin:0;padding:0;background:{PAGE};">\n'
            f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{PAGE};">'
            '<tr><td align="center" style="padding:24px 12px 40px;">'
            '<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;">'
            + "".join(rows) + '</table></td></tr></table>\n</body></html>\n')


def render_text(out: dict, f: dict, *, brand: dict, local_end: datetime, portal_url: str = "",
                product_name: str = "") -> str:
    lines = [f"{product_name or brand.get('short_name', 'Sentry')}, {local_end:%A} {local_end:%B} {local_end.day}", "",
             out.get("headline", ""), "", out.get("opening", ""), ""]
    for e in out.get("email", []):
        lines += [e.get("text", ""), ""]
    for e in out.get("fixed", []):
        lines += [e.get("text", ""), ""]
    if out.get("still_open"):
        lines += ["Still sitting there:"] + [e.get("text", "").strip() for e in out["still_open"]] + [""]
    if out.get("small_line"):
        lines += [out["small_line"], ""]
    if portal_url:
        lines.append(f"Open the portal: {portal_url.rstrip('/')}")
    lines.append(f"Sent at {local_end:%-I:%M %p}. {f.get('portal_note', '')}")
    return "\n".join(lines)


def subject(out: dict, f: dict, *, product_name: str, local_end: datetime) -> str:
    """'[PRODEXsentry] Tuesday: one box went quiet' — the [name] prefix stays for mail filters."""
    s = (out.get("subject") or out.get("headline") or "").strip().rstrip(".")
    prefix = f"[{product_name}] " if product_name else ""
    return f"{prefix}{local_end:%A}: {s}"
