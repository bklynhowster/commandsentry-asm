#!/usr/bin/env python3
"""
plain_words.py — a plain-English explanation of each finding, written once and saved (KB 12 job 4u).

Howie, 2026-11-04 12:33, on the dashboard's change panel: "This text is barely American English.
It's too dense, and we need to have an AI explanatory area. This is hard for a non-expert to
understand." Ruled "Saved plain-words": the AI writes a plain explanation of each finding once,
it is saved, and the dashboard's "What does this mean?" box shows the saved words (no AI call when
someone looks). 15:35: one explanation per finding. 15:37: "nobody ever uses the approval, or
basically the admin page, to do anything, so I want you to base the application logic on that
assumption." So nothing here waits for a person: an answer that passes the checks below is shown;
one that fails them twice is not.

For every open finding at LOW or above (INFO is never shown on the panel), three short parts:
  plain_what   what it is, for someone who isn't technical       (at most 300 characters)
  plain_worry  whether it matters and how much                   (at most 200)
  plain_todo   what to do and who does it                        (at most 200)
saved with plain_input_hash, plain_model and plain_written_at (migration 20261104c).

⛔ WHAT THIS WORKER MAY WRITE: the six columns in PLAIN_COLUMNS, nothing else. Never D-029's
   description_synth / impact / remediation / description_source / description_synth_*, never
   plain_rejected_at. tests/test_plain_words.py fails if any other key reaches an update.

⛔ THE OFF SWITCH IS STICKY, ON EVERY PATH (D-029's relay-154 discipline, plan v2 must-fix 2).
   plain_rejected_at is set by a script Howie runs when an explanation reads wrong. A switched-off
   finding is never written again: (1) the server-side scope filters it first, before
   --finding-id, --force or --limit are looked at; (2) the loop checks it again on every row;
   (3) every update is conditional on it still being NULL, so a switch set mid-run wins;
   (4) the database refuses words on a switched-off row (CHECK findings_plain_words_off_means_empty).
   --force re-runs the MACHINE; it does not overrule the human.

WHEN IT WRITES: when plain_input_hash differs from the hash of what the words would be written
from (prompt version, title, severity, scanner description, and D-029's three sections). New
finding: no hash yet. Changed finding, or a new rating (job 4v): a different hash. Changed prompt:
PROMPT_VERSION is in the hash. The scan excerpt is sent to the model but kept out of the hash on
purpose: each scan writes a new history row, and a hash over raw tool output would rewrite (and
pay for) the same explanation again and again.

AN ANSWER THAT FAILS THE CHECKS is retried once, told what it broke. If it fails again the words
are cleared (an old explanation of something the finding no longer says is worse than none) and
the hash is recorded with plain_model = "failed-check:<model>", so the same inputs are not paid
for again on every run. A changed finding, or a new PROMPT_VERSION, tries again. A transport or
API error writes nothing; the row is tried on the next run.

Runs as a step of .github/workflows/enrich-finding-descriptions.yml, after D-029's worker, at most
PER_RUN_LIMIT findings a run (the run log says when it hit the limit). By hand:
  python scripts/backfill/plain_words.py --dry-run --limit 5     # print five, write nothing
  python scripts/backfill/plain_words.py --finding-id "<id>"      # one finding
  python scripts/backfill/plain_words.py --limit 0                # everything pending

Environment: SUPABASE_URL (the workflow sets this repo's), SUPABASE_SERVICE_ROLE_KEY,
ANTHROPIC_API_KEY. Cost: about 2,000 tokens in and 250 out per finding, $0.01-0.02 each with
Claude Sonnet 4.6 ($3 / $15 per million). Byte-identical in both scanner repos.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

# ─── Config ─────────────────────────────────────────────────────────────────
MODEL_ID = "claude-sonnet-4-6"       # the D-029 worker's model
TEMPERATURE = 0.2
MAX_TOKENS = 700
PROMPT_VERSION = "4u-1"              # in the hash: change it and every explanation is rewritten
PER_RUN_LIMIT = 100                  # the scheduled step's ceiling (pinned in a test)
PAGE_SIZE = 500                      # under PostgREST's 1000-row cap (relay 139)
RETRY_ATTEMPTS = 3
RETRY_BACKOFF_S = (2, 4, 8)

SEVERITIES = ("LOW", "MODERATE", "MODERATE-HIGH", "HIGH", "CRITICAL")   # never INFO
OPEN_STATUSES = ("detected", "confirmed", "open", "regressed")
SWITCH = "plain_rejected_at"
PLAIN_COLUMNS = ("plain_what", "plain_worry", "plain_todo",
                 "plain_input_hash", "plain_model", "plain_written_at")
FAILED_PREFIX = "failed-check:"
CAPS = {"what": 300, "worry": 200, "todo": 200}
EXCERPT_CHARS = 1500

SELECT_COLUMNS = ("finding_id, asset_id, title, severity, category, current_status, description, "
                  "description_synth, impact, remediation, plain_what, plain_input_hash, plain_model, "
                  "plain_rejected_at")

SEVERITY_WORDS = {"LOW": "Low (minor)", "MODERATE": "Moderate", "MODERATE-HIGH": "Moderate-high",
                  "HIGH": "High", "CRITICAL": "Critical"}

# ─── The prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You explain website security findings to people who are not technical: the owners and managers of the company whose websites these are. A security scanner found something on one of the company's sites. Explain it in plain, everyday American English, the way you would to a smart friend who has never worked in IT.

Write three short parts:
- "what": what it is. One or two short sentences, under 300 characters.
- "worry": whether it matters, and how much. One sentence, under 200 characters. Be honest: never alarming, never dismissive.
- "todo": what to do and who does it ("your IT team", "your web developer", or "nobody, for now"). One sentence, under 200 characters. For a small item, "Nothing now" and when it could be done is fine.

Rules:
1. Say only what the finding shows. If the scan only saw a setting (for example: pages are compressed, or an old method is still allowed), say what was seen and what else would have to be true for it to matter. Never describe an attack, or what someone could take, as if it happened.
2. When the scanner says "potentially" or "possible", say it might matter in a narrow case. Do not say the site is open to attack.
3. No site names, web addresses, IP addresses or port numbers. Say "this site", "its sign-in page" or "its email" instead.
4. No CVE, CWE, RFC, ISO, NIST, CVSS, OWASP, PCI or SOC 2 numbers or names. No file names, setting names, commands or code.
5. No attack nicknames (BREACH, CRIME, POODLE, BEAST, DROWN, FREAK, LOGJAM, ROBOT, LUCKY13, SWEET32, Heartbleed), and never the word "breach" in any form: those sound like "you were broken into", and that is almost never what a finding means.
6. Avoid technical terms. If one cannot be avoided, put it in parentheses after the plain words, like "an email-protection setting (DMARC)". Any abbreviation in capital letters goes in parentheses that way, except IT and AI.
7. Short sentences. No lists, no headings, no line breaks, no markdown.

Answer with JSON only, exactly this shape: {"what": "...", "worry": "...", "todo": "..."}"""

USER_PROMPT = """Finding: {title}
Rated: {severity}
Kind: {category}
What the scanner reported: {description}

The detailed explanation Sentry already has (written for IT people; use it for the facts, not the wording):
- What it is: {synth}
- What it could do: {impact}
- How to fix it: {remediation}

From the scan itself (raw tool output, may be cut short): {excerpt}

Write the three parts."""

RETRY_PROMPT = ("Your answer broke these rules: {problems}. Write the three parts again, following "
                "every rule. JSON only.")

# ─── An out-of-date finding says only what was seen (rule 3r; D-077 step 2) ──
# "Runs X 1.2.3: out of date" means a version number was SEEN and its maker's later release
# fixes published flaws. Nothing was tried against the site, so the explanation may not say,
# or deny, that this site can be attacked, crashed, taken offline or taken over (Howie,
# 2026-10-22: never "vulnerable"; 2026-11-12: the finding's own lead says "shows", "its maker
# says", "are described as", and the plain words may not say more than it does). The line
# below is added to the request for these findings only; the shared prompt and PROMPT_VERSION
# are untouched, so no other finding's explanation is rewritten. An answer that breaks it is
# retried once and then left empty, like any other failed check.
OUT_OF_DATE_TITLE = re.compile(r"^Runs .+: out of date\b")
OUT_OF_DATE_NOTE = ("\n\nThis is an out-of-date finding: a version number was seen, and its maker's newer "
                    "release fixes published flaws. Say what was seen, what its maker says, and that updating "
                    "is the fix. You may repeat how the flaws are described (for example \"described as crash "
                    "or overload flaws\"). Do not say or deny that this site can be attacked, crashed, "
                    "overloaded, taken offline or taken over, or that it is or is not affected. Do not use "
                    "these words: vulnerable, vulnerability, attack, attacker, hacker, stranger, remote, remotely, offline, "
                    "exploit, compromised, affected, unaffected, take over, at risk.")
# "can", "could", "might" and their negatives ("won't", "cannot"): the start of a prediction.
_MODAL = (r"(?:can(?:not)?|can[’']t|could(?:n[’']t)?|may|might(?:n[’']t)?|will|won[’']t|would(?:n[’']t)?"
          r"|should(?:n[’']t)?)")
# Words that say (or deny) what could happen to this site. Any form: "attacked" as much as
# "attacker", "unaffected" as much as "affected" (outside review, 17:50).
_OUT_OF_DATE_WORDS = (r"\bvulnerab\w*|\battack\w*|\bhack\w*|\bstrangers?\b|\bremote(?:ly)?\b"
                      r"|\boff-?line\b|\bcompromis\w*|\b(?:un)?affect\w*"
                      r"|\bt(?:ake|akes|aken|aking|ook)[ -]?over\b|\bat risk\b"
                      # "could crash", "can be overloaded", "might knock it out": a prediction about
                      # the site, anywhere later in the same sentence. "described as crash or overload
                      # flaws" has no such verb before it.
                      r"|\b" + _MODAL + r"\b[^.!?]*?"
                      r"\b(?:crash\w*|overload\w*|knock\w*|(?:take|taken|bring|brought|shut|go|goes)\s+down)\b")
_OUT_OF_DATE_RULE = re.compile(_OUT_OF_DATE_WORDS + r"|\bexploit\w*", re.I)
# A title that itself says a flaw is on CISA's exploited list may be explained in those words,
# but only as that list's statement: the sentence must name the list, and "exploitable" or
# "can be exploited" is a claim about this site in any sentence.
_OUT_OF_DATE_RULE_LISTED = re.compile(_OUT_OF_DATE_WORDS + r"|\bexploitab\w*"
                                      r"|\b" + _MODAL + r"\b[^.!?]*?\bexploit\w*", re.I)
_EXPLOIT = re.compile(r"\bexploit\w*", re.I)
_NAMES_A_LIST = re.compile(r"\blist(?:ed|s)?\b", re.I)
OUT_OF_DATE_WHY = "says more than an out-of-date finding shows (it may only say what was seen and what its maker says)"


class _ListedRule:
    """For a title that names CISA's exploited list: the words above, plus any "exploit..."
    in a sentence that does not name a list."""
    def search(self, text):
        if _OUT_OF_DATE_RULE_LISTED.search(text):
            return True
        return any(_EXPLOIT.search(sent) and not _NAMES_A_LIST.search(sent)
                   for sent in re.split(r"(?<=[.!?])\s+", text))


def is_out_of_date(title) -> bool:
    return isinstance(title, str) and bool(OUT_OF_DATE_TITLE.match(title))

# ─── The answer checker ─────────────────────────────────────────────────────
# Every part of every answer passes all of these, or the answer is not saved. Plan v2 §1; the
# re-check's note (Grok, handoff 004): "breach" in any case is its own rule; the code review (Kimi,
# handoff 006): nicknames in any capitalization, bare file names, hyphenated setting names,
# hostnames on any ending, and a time of day is not a port; its re-check (handoff 008): every
# capitalization. A nickname is refused in any case EXCEPT the five that are also ordinary words
# (crime, beast, drown, freak, robot) written all in lower case, so ordinary prose still passes;
# file names, header names and hostnames are refused in any case; its final re-check (handoff 010,
# Howie: "Another Kimi round"): the cross-origin headers, and any "x-" name with two hyphens.
# A word list can never name every setting; the 10-example read-back and the off switch are the
# guards behind it.
_NICKNAME = re.compile(r"\b(breach|crime|poodle|beast|drown|freak|logjam|robot|lucky ?13|sweet ?32)\b", re.I)
_ORDINARY_WORDS = {"crime", "beast", "drown", "freak", "robot"}


class _NicknameRule:
    """A nickname, unless it is one of the ordinary words written as an ordinary word."""
    def search(self, text):
        return any(m.group(0).lower() not in _ORDINARY_WORDS or m.group(0) != m.group(0).lower()
                   for m in _NICKNAME.finditer(text))


_RULES = [
    ("names a CVE, CWE or standard",
     re.compile(r"\bCVE-\d{4}-\d{4,}|\bCWE-?\d+|\bRFC ?\d+|\bISO(/IEC)? ?\d{4,5}|\bNIST\b|\bCVSS\b"
                r"|\bOWASP\b|\bPCI\b|\bSOC ?2\b", re.I)),
    ("names an address, port or hostname",
     re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b|\bport \d+|(?<!\d):\d{2,5}\b|https?://|\bwww\."
                r"|\b[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,24}\b", re.I)),
    ("names a file, setting or command",
     re.compile(r"/[\w.-]+\.(conf|php|ini|xml|json|ya?ml|htaccess|config|js|txt)\b|\.htaccess\b"
                r"|\b[\w-]+\.(conf|php|ini|xml|json|ya?ml|config|cfg|env|txt|js|py|sh|log)\b"
                r"|\b(content-security-policy|x-frame-options|strict-transport-security|x-content-type-options"
                r"|referrer-policy|permissions-policy|feature-policy|x-xss-protection|expect-ct|x-powered-by"
                r"|cross-origin-(opener|embedder|resource)-policy|access-control-allow-[a-z]+)\b"
                r"|\bx-[a-z0-9]+(-[a-z0-9]+)+\b", re.I)),
    ("names a file, setting or command",
     re.compile(r"\b[A-Za-z0-9]+_[A-Za-z0-9_]+\b|`"
                r"|\b(?!Wi-Fi\b)[A-Z][A-Za-z0-9]*(-[A-Z][A-Za-z0-9]*)+\b")),
    ("uses an attack nickname", _NicknameRule()),
    ("uses the word breach or Heartbleed",
     re.compile(r"breach|heartbleed", re.I)),
    ("has a line break, list or markdown",
     re.compile(r"[\r\n]|\*\*|^#|^\s*[-*•] ", re.M)),
]
_ACRONYM = re.compile(r"\b[A-Z][A-Z0-9]{1,5}\b")
_ACRONYM_OK = {"IT", "AI", "OK", "US"}
_PARENS = re.compile(r"\([^()]*\)")
_PLAIN_WORD = re.compile(r"[A-Za-z][A-Za-z'-]*")


def _acronyms(text: str) -> list:
    return [t for t in _ACRONYM.findall(text) if t not in _ACRONYM_OK and sum(c.isupper() for c in t) >= 2]


def check_answer(parts, title=None) -> list:
    """The reasons an answer may not be saved; [] means it may. `title` is the finding's
    title: an out-of-date finding carries one more rule (OUT_OF_DATE_TITLE above)."""
    problems = []
    if not isinstance(parts, dict):
        return ["is not a JSON object with what, worry and todo"]
    rules = list(_RULES)
    if is_out_of_date(title):
        rules.append((OUT_OF_DATE_WHY, _ListedRule() if "exploited list" in title else _OUT_OF_DATE_RULE))
    for key, cap in CAPS.items():
        text = parts.get(key)
        if not isinstance(text, str) or not text.strip():
            problems.append(f'"{key}" is empty')
            continue
        if len(text) > cap:
            problems.append(f'"{key}" is longer than {cap} characters')
        for why, rx in rules:
            msg = f'"{key}" {why}'
            if rx.search(text) and msg not in problems:
                problems.append(msg)
        # An abbreviation is allowed only inside parentheses AND after plain words: at least two
        # lower-case words among the last six before the "(", in the same sentence (Kimi, minor 3).
        bare = _acronyms(_PARENS.sub(" ", text))
        for m in _PARENS.finditer(text):
            inside = _acronyms(m.group(0))
            if not inside:
                continue
            before = re.split(r"[.!?;:]\s", text[:m.start()])[-1]
            plain = [w for w in _PLAIN_WORD.findall(before)[-6:] if w.islower() and len(w) > 1]
            if len(plain) < 2:
                bare += inside
        if bare:
            problems.append(f'"{key}" uses an abbreviation without plain words first: {", ".join(sorted(set(bare)))}')
    return problems


# ─── What the words are written from ────────────────────────────────────────
def input_hash(row: dict) -> str:
    blob = json.dumps({
        "prompt_version": PROMPT_VERSION,
        "title": row.get("title"),
        "severity": row.get("severity"),
        "description": row.get("description"),
        "description_synth": row.get("description_synth"),
        "impact": row.get("impact"),
        "remediation": row.get("remediation"),
    }, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def is_switched_off(row: dict) -> bool:
    return bool(row.get(SWITCH))


def needs_words(row: dict, force: bool) -> bool:
    if is_switched_off(row):          # ⛔ second gate: the loop, on every path
        return False
    return force or row.get("plain_input_hash") != input_hash(row)


def best_excerpt(history: list) -> str | None:
    """The longest scan excerpt of 50 characters or more, cut to EXCERPT_CHARS."""
    texts = [(h.get("raw_excerpt") or "").strip() for h in history or []]
    texts = [t for t in texts if len(t) >= 50]
    if not texts:
        return None
    best = max(texts, key=len)
    return best[:EXCERPT_CHARS]


def build_prompt(row: dict, excerpt: str | None) -> str:
    def v(x):
        return (x or "").strip() or "(none)"
    return USER_PROMPT.format(
        title=v(row.get("title")),
        severity=SEVERITY_WORDS.get(row.get("severity"), v(row.get("severity"))),
        category=v(row.get("category")),
        description=v(row.get("description")),
        synth=v(row.get("description_synth")),
        impact=v(row.get("impact")),
        remediation=v(row.get("remediation")),
        excerpt=v(excerpt),
    ) + (OUT_OF_DATE_NOTE if is_out_of_date(row.get("title")) else "")


# ─── The database ───────────────────────────────────────────────────────────
def _execute_with_retry(builder, what: str):
    """Retry transport faults only; a 4xx/5xx from PostgREST is an answer and raises."""
    import httpx
    transient = (httpx.RemoteProtocolError, httpx.ConnectError, httpx.ReadTimeout, httpx.ReadError)
    last = None
    for attempt in range(RETRY_ATTEMPTS):
        try:
            return builder.execute()
        except transient as e:
            last = e
            if attempt == RETRY_ATTEMPTS - 1:
                break
            delay = RETRY_BACKOFF_S[min(attempt, len(RETRY_BACKOFF_S) - 1)]
            print(f"  transport error on {what} (attempt {attempt + 1}/{RETRY_ATTEMPTS}): "
                  f"{type(e).__name__}: {e}; retrying in {delay}s", file=sys.stderr)
            time.sleep(delay)
    raise last


def _scope(builder, finding_id: str | None = None):
    """Every predicate except paging, the same for the count probe and every page.
    ⛔ First gate: the off switch is filtered here, before anything else is applied."""
    builder = builder.is_(SWITCH, "null")
    builder = builder.in_("severity", list(SEVERITIES)).in_("current_status", list(OPEN_STATUSES))
    if finding_id:
        builder = builder.eq("finding_id", finding_id)
    return builder


def fetch_scope(sb, finding_id: str | None = None) -> list:
    """Every open finding at LOW or above that is not switched off (keyset paging, count-checked)."""
    if finding_id:
        probe = _execute_with_retry(
            sb.table("findings").select(f"finding_id, severity, current_status, {SWITCH}")
            .eq("finding_id", finding_id), "targeted probe")
        row = (probe.data or [None])[0]
        if row is None:
            print(f"  {finding_id}: no such finding")
            return []
        if is_switched_off(row):
            print(f"  {finding_id}: switched off at {row.get(SWITCH)}; its plain words are never "
                  f"written again (clear {SWITCH} to allow it)")
            return []
        if row.get("severity") not in SEVERITIES or row.get("current_status") not in OPEN_STATUSES:
            print(f"  {finding_id}: {row.get('severity')}, {row.get('current_status')}: not shown "
                  f"on the panel, so no plain words")
            return []
    expected = _execute_with_retry(
        _scope(sb.table("findings").select("finding_id", count="exact", head=True), finding_id),
        "count probe").count or 0
    rows, cursor, pages = [], None, 0
    max_pages = (expected + PAGE_SIZE) // PAGE_SIZE + 1
    while True:
        q = _scope(sb.table("findings").select(SELECT_COLUMNS), finding_id)
        if cursor is not None:
            q = q.gt("finding_id", cursor)
        page = _execute_with_retry(q.order("finding_id").limit(PAGE_SIZE),
                                   f"findings page after {cursor!r}").data or []
        rows.extend(page)
        pages += 1
        if len(page) < PAGE_SIZE:
            break
        if pages > max_pages:
            sys.exit(f"error: the findings read is not advancing ({pages} pages for {expected} rows); "
                     f"refusing to spin")
        cursor = page[-1]["finding_id"]
    if len(rows) < expected:
        sys.exit(f"error: counted {expected} findings in scope but read {len(rows)}; the worker "
                 f"cannot see its whole queue, so it writes nothing")
    return rows


def fetch_excerpt(sb, finding_id: str) -> str | None:
    hist = _execute_with_retry(
        sb.table("finding_history").select("raw_excerpt").eq("finding_id", finding_id)
        .order("observed_at", desc=True).limit(20), f"history for {finding_id}").data or []
    return best_excerpt(hist)


def write_row(sb, finding_id: str, payload: dict) -> bool:
    """Write the plain columns only, and only while the switch is still off. True if a row took it."""
    bad = set(payload) - set(PLAIN_COLUMNS)
    if bad:                                       # a programming error, never a data condition
        raise RuntimeError(f"plain_words may only write {PLAIN_COLUMNS}; got {sorted(bad)}")
    res = _execute_with_retry(
        sb.table("findings").update(payload).eq("finding_id", finding_id).is_(SWITCH, "null"),
        f"write {finding_id}")
    return bool(res.data)                        # ⛔ third gate: switched off mid-run = nothing written


def words_payload(parts: dict, h: str, now: str) -> dict:
    return {"plain_what": parts["what"].strip(), "plain_worry": parts["worry"].strip(),
            "plain_todo": parts["todo"].strip(), "plain_input_hash": h, "plain_model": MODEL_ID,
            "plain_written_at": now}


def cleared_payload(h: str, now: str) -> dict:
    return {"plain_what": None, "plain_worry": None, "plain_todo": None, "plain_input_hash": h,
            "plain_model": FAILED_PREFIX + MODEL_ID, "plain_written_at": now}


# ─── The AI ─────────────────────────────────────────────────────────────────
def parse_answer(text: str):
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        obj = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def ask(client, messages: list) -> str:
    resp = client.messages.create(model=MODEL_ID, max_tokens=MAX_TOKENS, temperature=TEMPERATURE,
                                  system=SYSTEM_PROMPT, messages=messages)
    return "".join(getattr(b, "text", "") for b in resp.content)


def write_one(client, row: dict, excerpt: str | None):
    """(parts, problems): parts that passed the checks, or None and the last problems seen.
    One retry, told what the first answer broke. API errors raise."""
    messages = [{"role": "user", "content": build_prompt(row, excerpt)}]
    problems = []
    for attempt in (1, 2):
        text = ask(client, messages)
        parts = parse_answer(text)
        problems = (check_answer(parts, row.get("title")) if parts is not None
                    else ["is not a JSON object with what, worry and todo"])
        if not problems:
            return parts, []
        if attempt == 1:
            messages += [{"role": "assistant", "content": text},
                         {"role": "user", "content": RETRY_PROMPT.format(problems="; ".join(problems))}]
    return None, problems


# ─── The run ────────────────────────────────────────────────────────────────
def run(sb, client, finding_id=None, force=False, dry_run=False, limit=PER_RUN_LIMIT, now=None) -> dict:
    rows = fetch_scope(sb, finding_id)
    pending = [r for r in rows if needs_words(r, force)]
    todo = pending if not limit else pending[:limit]
    stats = {"in_scope": len(rows), "current": len(rows) - len(pending), "pending": len(pending),
             "wrote": 0, "cleared": 0, "switched_off_mid_run": 0, "errors": 0,
             "left_for_next_run": len(pending) - len(todo), "by_severity": {}}
    print(f"In scope: {len(rows)} open finding(s) at LOW or above, not switched off. "
          f"Current: {stats['current']}. Pending: {len(pending)}. This run: {len(todo)}"
          f"{' (DRY RUN, nothing written)' if dry_run else ''}.")
    for i, row in enumerate(todo, 1):
        fid, sev = row["finding_id"], row.get("severity")
        if is_switched_off(row):                 # ⛔ second gate, again, right before the work
            continue
        h = input_hash(row)
        try:
            parts, problems = write_one(client, row, fetch_excerpt(sb, fid))
        except Exception as e:                   # transport or API: nothing written, next run retries
            stats["errors"] += 1
            print(f"[{i}/{len(todo)}] {fid}: error, nothing written: {type(e).__name__}: {e}")
            continue
        stamp = now or datetime.now(timezone.utc).isoformat()
        if parts is not None:
            payload, outcome = words_payload(parts, h, stamp), "wrote"
        else:
            payload, outcome = cleared_payload(h, stamp), "cleared"
        if dry_run:
            print(f"[{i}/{len(todo)}] {fid} ({sev}): {outcome}")
            if parts:
                print(f"    what:  {parts['what']}\n    worry: {parts['worry']}\n    todo:  {parts['todo']}")
            else:
                print(f"    failed the checks twice: {'; '.join(problems)}")
            stats[outcome] += 1
            continue
        if not write_row(sb, fid, payload):
            stats["switched_off_mid_run"] += 1
            print(f"[{i}/{len(todo)}] {fid}: switched off during the run; nothing written")
            continue
        stats[outcome] += 1
        if outcome == "wrote":
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
            print(f"[{i}/{len(todo)}] {fid} ({sev}): written")
        else:
            print(f"[{i}/{len(todo)}] {fid} ({sev}): left empty, the answer failed the checks twice: "
                  f"{'; '.join(problems)}")
    by_sev = ", ".join(f"{k} {v}" for k, v in sorted(stats["by_severity"].items())) or "none"
    print(f"Done. Wrote {stats['wrote']} ({by_sev}); left empty {stats['cleared']}; switched off "
          f"during the run {stats['switched_off_mid_run']}; errors {stats['errors']}; still pending "
          f"{stats['left_for_next_run']}"
          f"{f' (the limit of {limit} was reached; the next run continues)' if stats['left_for_next_run'] else ''}.")
    return stats


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--finding-id", help="Only this finding.")
    p.add_argument("--force", action="store_true",
                   help="Rewrite even when nothing changed. Never a switched-off finding.")
    p.add_argument("--dry-run", action="store_true", help="Print, write nothing.")
    p.add_argument("--limit", type=int, default=PER_RUN_LIMIT,
                   help=f"Most findings to write this run (default {PER_RUN_LIMIT}; 0 = all pending).")
    a = p.parse_args(argv)
    url, key, api = (os.environ.get("SUPABASE_URL"), os.environ.get("SUPABASE_SERVICE_ROLE_KEY"),
                     os.environ.get("ANTHROPIC_API_KEY"))
    missing = [n for n, v in (("SUPABASE_URL", url), ("SUPABASE_SERVICE_ROLE_KEY", key),
                              ("ANTHROPIC_API_KEY", api)) if not v]
    if missing:
        sys.exit(f"not set: {', '.join(missing)}")
    import anthropic
    from supabase import create_client
    stats = run(create_client(url, key), anthropic.Anthropic(api_key=api), finding_id=a.finding_id,
                force=a.force, dry_run=a.dry_run, limit=a.limit)
    sys.exit(1 if stats["errors"] else 0)


if __name__ == "__main__":
    main()
