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
EMAIL_ENTRY_MAX_CHARS = 700
SLACK_ENTRY_MAX_CHARS = 600
LINE_MAX_CHARS = 300

# Never in anything a person reads (Howie 09:38: "I don't want there ever to be anything in
# this that talks about somebody getting fired"; 08:40: no blame, no ownership).
BANNED = ("fired", "firing", "fire ", "let go", "your job", "their job", "his job", "her job",
          "blame", "on us", "nothing for you to do", "discipline", "hr ", "vulnerable",
          "accountable", "fault")
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
PLAIN = (
    (re.compile(r"^BREACH attack", re.I),
     "Compressed pages could let an attacker read a secret out of them (the BREACH trick)",
     "The site compresses its pages (gzip). Someone who can watch the traffic and make a browser send "
     "requests could use that to read a secret out of a page, a token or a session cookie, a bit at a time.",
     "Turn compression off for pages that carry secrets, or mask the tokens on those pages. A few lines of server config."),
    (re.compile(r"Obsolete 3DES/IDEA", re.I),
     "Old weak ciphers (3DES) are still offered",
     "3DES is a 1990s cipher; a long capture of traffic can be broken. Modern browsers never pick it, old tools might.",
     "Drop 3DES and the other legacy ciphers from the TLS settings."),
    (re.compile(r"^TLS · BEAST", re.I),
     "Old CBC ciphers the BEAST trick goes after are still offered",
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
    """(what, why, fix) in plain words for a title digest_words has none for; else as given."""
    for pat, what, why, do in PLAIN:
        if pat.search(title or ""):
            return what, body or why, fix or do
    return title, body, fix
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
          fix: str, text_for_dates: str, *, dates_allowed: bool = True, extra_numbers=(), detail=()) -> dict:
    hosts = [h for h in hosts if h]
    what, why, fix = _plain(what or "", why or "", fix or "")
    what, why, fix = _clean(what), _clean(why), _clean(fix)
    detail = [_clean(d) for d in detail if d]
    text_for_dates = " ".join([_clean(text_for_dates), what, why, fix] + detail)
    nums = set(_numbers_in(text_for_dates)) | {str(len(hosts))} | {str(n) for n in extra_numbers}
    return {
        "id": iid, "section": section, "kind": kind, "severity": severity or "",
        "severity_word": _sev_word(severity), "hosts": hosts,
        "what": what, "why": why, "fix": fix,
        "detail": detail,                            # per-host specifics, in the model's words
        "dates": _dates_in(text_for_dates) if dates_allowed else [],
        "numbers": sorted(nums),
    }


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
        "title": f"Something is standing guard in front of {len(hosts)} of our hosts, and Sentry is still working out what",
        "body": ("Each one turned away Sentry's attack-style test strings with a block page Sentry does not "
                 "recognize yet, which is good news: a firewall or a security device of some kind is in front "
                 "of it. Sentry keeps the pages with the scans and keeps working out which product it is."),
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
        items.append(_item(f"c{n+1}", "changed", kind, it.get("severity", ""), hosts,
                           it.get("title", ""), it.get("body", "") or it.get("why", ""), it.get("do", ""),
                           _text_of(it), extra_numbers=[len(it.get("lines") or [])], detail=it.get("lines") or []))
    for n, it in enumerate(model.get("done", [])):
        hosts = [ln.split(":")[0] for ln in it.get("lines", []) if ":" in ln]
        items.append(_item(f"f{n+1}", "fixed", it.get("kind", "fixed"), "", hosts,
                           it.get("title", ""), "", "", _text_of(it), detail=it.get("lines") or []))
    for n, it in enumerate(still_open or []):
        since = it.get("since")
        text = _text_of(it) + (f" {_day(since)}" if since is not None else "")
        d = _item(f"s{n+1}", "still", it.get("told_kind") or "open", it.get("severity", ""),
                  list(it.get("sites") or []), it.get("title", ""), it.get("body", ""), it.get("do", ""),
                  text, dates_allowed=bool(it.get("recent")))
        items.append(d)
    slack = slack or {}
    for n, it in enumerate(slack.get("changed", [])):
        items.append(_item(f"k{n+1}", "slack_changed", it.get("kind", "finding"), it.get("severity", ""),
                           list(it.get("sites") or it.get("hosts") or []), it.get("title", ""),
                           it.get("body", ""), it.get("do", ""), _text_of(it), detail=it.get("lines") or []))
    for n, it in enumerate(slack.get("nudge", [])):
        items.append(_item(f"n{n+1}", "slack_nudge", "nudge", it.get("severity", ""),
                           list(it.get("sites") or []), it.get("title", ""), it.get("body", ""),
                           it.get("do", ""), _text_of(it), dates_allowed=False))
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
SYSTEM = """You write a short morning security email and a Slack post for a small company, in the voice of Howie, its security lead, to his own colleagues. Everything you write is read by people on the same team, so it is all "we" and "our"; Sentry is the company's own scanner and is referred to as "Sentry".

VOICE. Conversational, dictated, New York plain English. Long comma-joined sentences are fine; no bullet lists in the email; no headings; no em dashes (use commas or a new sentence). Openers and pivots like "Morning.", "Short version:", "Heads up:", "Obviously", "just FYI", "Look," are welcome, used sparingly. Say each fact once. The same problem on several hosts is ONE sentence that names the hosts (short names are fine: "bitec, demo and highcom"). Never assign blame or ownership: never "this is on us", "on you", "nothing for you to do", "somebody dropped the ball". Never mention anyone's job, being fired, HR or discipline. A thing that is turning away our test traffic is GOOD news: something is standing guard and Sentry is still working out which product. Never use the word "vulnerable". Never add a date, number, host, product or severity that is not in the facts for that item, and never move one from one item to another. Severity words only as given ("Moderate", "Moderate-high", "High"); you may also just say "the most serious thing open" without a word. For a NUDGE (slack_nudge items) never say how long it has been open and never give a date.

OUTPUT. Strict JSON, no prose around it, this shape:
{"subject": "<5-9 words, no prefix, says the one main thing>",
 "headline": "<one short sentence, the main thing>",
 "opening": "<one or two sentences, e.g. 'Morning. Short version: ...'>",
 "email": [{"id": "<item id>", "text": "<one paragraph about that item only>"}],
 "fixed": [{"id": "<item id>", "text": "<one sentence>"}],
 "still_open": [{"id": "<item id>", "text": "<one or two sentences about that item only>"}],
 "small_line": "<one sentence about the small stuff, or empty string if small_count is 0>",
 "slack": {"changed": [{"id": "<item id>", "text": "<one or two sentences>"}],
           "nudge": [{"id": "<item id>", "text": "<two or three sentences: what, why it matters in plain words, the fix>"}],
           "closing": "<one short easy-going sentence, no dates, no job talk, or empty string>"}}
Each item gives "what", "why", "fix", its "hosts", and "detail": per-host specifics in the scanner's own words (when a host stopped answering, why, when it leaves; what a block page looked like), which you may draw on, saying things once. Every item in the facts must get exactly one entry in its own list, in the order given, and no entry may name an item that is not in the facts. The Slack entries are for developers: concrete, host first, what to do; the email entries are for the leadership trio: what happened and what it means. The two are different pieces of writing, not a shortened copy of each other. If "previous_text" is given, do not reuse its sentences or openers."""


def _prompt(f: dict, previous_text: str) -> str:
    return (f"Today is {f.get('day') or 'today'}. Company: {f.get('company') or 'Prodex'}.\n\n"
            f"FACTS (the only things you may say):\n{json.dumps(f['items'], indent=1)}\n\n"
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
    for h in item["hosts"]:
        if h.lower() not in low and _short(h).lower() not in low:
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
    # severity words
    own = set(SEVERITY_WORDS.get((item.get("severity") or "").upper(), ()))
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
    if f.get("small_count", 0) == 0 and str(out.get("small_line", "")).strip():
        problems.append("small_line: says something about small items when there are none")

    # whole-output rules
    whole = _flatten(out)
    low = " " + whole.lower() + " "
    for w, rx in zip(BANNED, _BANNED_RE):
        if rx.search(low):
            problems.append(f"banned word: {w.strip()!r}")
    if EM_DASH in whole:
        problems.append("em dash")
    for u in _URL.findall(whole):
        if not portal_url or not u.startswith(portal_url.rstrip("/")):
            problems.append(f"a URL that is not the portal's ({u[:40]})")
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
    first = [it for it in f["items"] if it["section"] == "changed"][:1]
    if first:                                           # the headline is about the main thing
        day_numbers |= set(first[0]["numbers"])
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
    return ", ".join(hs[:-1]) + " and " + hs[-1]


def _para(it: dict) -> str:
    w = _hosts_words(it["hosts"])
    what = it["what"].rstrip(".")
    if it["kind"] == "not_responding":
        one = len(it["hosts"]) == 1
        lines = it.get("detail") or []
        if one:                                        # "valorep: no answer since ..." → the host is already named
            lines = [d.split(":", 1)[1].strip() if ":" in d else d for d in lines]
            lines = [d[0].upper() + d[1:] if d else d for d in lines]
        detail = " ".join(d.rstrip(".") + "." for d in lines)
        return (f"{w} {'has' if one else 'have'} stopped answering Sentry's checks. "
                + (detail + " " if detail else "")
                + (f"If that was on purpose, nothing to do, it leaves the portal on its own. If it should be up, now you know."
                   if one else
                   f"Any that were taken down on purpose leave the portal on their own. If one of them should be up, now you know.")).strip()
    if it["kind"] == "blockpage":
        one = len(it["hosts"]) == 1
        return (f"{w} turned away Sentry's test traffic, which is good news: something is standing guard in front of "
                f"{'it' if one else 'them'}, a firewall or a security device of some kind, and Sentry is still working out which.")
    s = f"{what}" + (f" on {w}" if w and w.lower() not in what.lower() else "") + "."
    if it["why"]:
        s += " " + it["why"].rstrip(".") + "."
    if it["fix"]:
        s += " " + it["fix"].rstrip(".") + "."
    return s


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
        opening = "Morning. Short version: nothing new since yesterday."
    elif n == 1:
        headline = changed[0]["what"].rstrip(".") + "."
        subject = changed[0]["what"][:60]
        opening = f"Morning. Short version: one thing since yesterday, {changed[0]['what'][0].lower()}{changed[0]['what'][1:].rstrip('.')}."
    else:
        headline, subject = f"{n} things since yesterday.", f"{n} things since yesterday"
        opening = f"Morning. Short version: {n} things since yesterday, the first one matters most."
    small = f.get("small_count", 0)
    return {
        "subject": subject, "headline": headline, "opening": opening,
        "email": [{"id": it["id"], "text": _para(it)} for it in changed],
        "fixed": [{"id": it["id"], "text": it["what"].rstrip(".") + "."} for it in fixed],
        "still_open": [{"id": it["id"], "text": _para(it)} for it in still],
        "small_line": (f"{small} small thing{'s' if small != 1 else ''} also turned up, none of them need anybody, "
                       f"they're in the portal if you're curious." if small else ""),
        "slack": {
            "changed": [{"id": it["id"], "text": _para(it)} for it in kc],
            "nudge": [{"id": it["id"], "text": _para(it)} for it in kn],
            "closing": "Neither one is urgent. If you own one of those boxes, it's a quick fix when you get a chance." if kn else "",
        },
    }


# ── rendering ───────────────────────────────────────────────────────────────────────────
FONT = "'Public Sans', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Helvetica, Arial, sans-serif"
INK, MUTED, PAGE = "#0F1B2D", "#4A5668", "#E9EEF5"
PURPLE, PURPLE_TINT = "#6E56A6", "#F3F0FA"
GREEN, GREEN_TINT = "#0B7A55", "#EAF6F1"


def _p(text: str, size: int = 16, color: str = INK, extra: str = "") -> str:
    return (f'<div style="font-family:{FONT};font-size:{size}px;line-height:1.6;color:{color};{extra}">'
            f'{escape(text)}</div>')


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
    rows = [
        f'<tr><td bgcolor="{b.get("band_bg", "#FFFFFF")}" style="background:{b.get("band_bg", "#FFFFFF")};{border}'
        f'border-radius:14px 14px 0 0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">'
        f'<tr><td class="px" style="padding:22px 32px 18px;" valign="middle">{logo}</td>'
        f'<td class="px" align="right" valign="middle" style="padding:22px 32px 18px;font-family:{FONT};font-size:13px;'
        f'color:{b.get("band_muted", MUTED)};white-space:nowrap;"><span style="font-weight:700;color:{b.get("band_text", INK)};">'
        f'{escape(product_name or "Sentry")}</span> · {local_end:%A}, {local_end:%B} {local_end.day}</td></tr></table></td></tr>',
        f'<tr><td class="px" style="background:#FFFFFF;padding:26px 32px 8px;">'
        f'<div style="font-family:{FONT};font-size:24px;line-height:1.25;font-weight:800;letter-spacing:-.01em;color:{INK};">'
        f'{escape(out.get("headline", ""))}</div>{_p(out.get("opening", ""), extra="margin-top:14px;")}</td></tr>',
    ]
    first = True
    for e in out.get("email", []):
        it = by_id.get(e.get("id"), {})
        if first and it.get("kind") in ("not_responding", "finding", "enforcement", "cert"):
            rows.append(f'<tr><td class="px" style="background:#FFFFFF;padding:12px 32px 0;">'
                        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
                        f'<td style="width:5px;background:{PURPLE};border-radius:4px;"></td>'
                        f'<td style="padding:12px 16px 14px;background:{PURPLE_TINT};border-radius:0 10px 10px 0;">'
                        f'{_p(e.get("text", ""))}</td></tr></table></td></tr>')
        else:
            rows.append(f'<tr><td class="px" style="background:#FFFFFF;padding:18px 32px 0;">{_p(e.get("text", ""))}</td></tr>')
        first = False
    if out.get("fixed"):
        rows.append(f'<tr><td class="px" style="background:#FFFFFF;padding:18px 32px 0;">'
                    f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>'
                    f'<td style="width:5px;background:{GREEN};border-radius:4px;"></td>'
                    f'<td style="padding:12px 16px 14px;background:{GREEN_TINT};border-radius:0 10px 10px 0;">'
                    + "".join(_p(e.get("text", "")) for e in out["fixed"]) + '</td></tr></table></td></tr>')
    if out.get("still_open"):
        rows.append(f'<tr><td class="px" style="background:#FFFFFF;padding:22px 32px 0;">'
                    f'<div style="font-family:{FONT};font-size:12px;letter-spacing:.08em;text-transform:uppercase;'
                    f'color:{PURPLE};font-weight:700;">Still sitting there</div>'
                    + _p(" ".join(e.get("text", "").strip() for e in out["still_open"]), extra="margin-top:8px;")
                    + '</td></tr>')
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
            '<style>@media only screen and (max-width: 520px) { .px { padding-left: 18px !important; padding-right: 18px !important; } }</style>'
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
        lines += ["Still sitting there: " + " ".join(e.get("text", "").strip() for e in out["still_open"]), ""]
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
