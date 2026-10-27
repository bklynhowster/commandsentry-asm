"""digest_slack.py — the daily's Slack post to #on-call (KB 12 job 3l round 5, 2026-10-27).

Howie, 2026-10-27 08:44: "Channel number two is Slack ... the on-call Slack channel ... They're
developers. What do developers need to know? They need to know if there's something new that's
happening: a site went down, a site came up, or a new vulnerability was found. Because ...
there might be a problem with their code or the security settings that they're going to try to
remediate." 08:46: Moderate and up only; a post only when there is news. 08:47: "when I
approve for Slack, it needs to be different. It's a stripped-down, different form of
communication for a different audience." 09:01: sections — (1) what changed in the last day;
(2) a gentle nudge about something not yet addressed; (3) reserved. 09:12: no dates on a
nudge. 09:38: never anything about anyone's job. 09:53 (who gets which nudge): developer-
fixable things (headers, ciphers, outdated components) go to Slack; infrastructure and policy
(firewalls, DNS, certificates, hosts going dark) stay in the email.

THE UNIT is a title-group with its hosts named (the email's unit, and the shape Howie approved
at 09:46), never one line per host. THE NUDGE is an allow-list: everything not on it, key ""
included, is the email's. PURE: no database, no network. run_alerter.py reads, stores and posts.
"""
from __future__ import annotations

import re
from datetime import timedelta

SEV_RANK = {"CRITICAL": 1, "HIGH": 2, "MODERATE-HIGH": 3, "MODERATE": 4, "LOW": 5, "INFO": 6}
MODERATE_PLUS = ("CRITICAL", "HIGH", "MODERATE-HIGH", "MODERATE")
# Howie 2026-10-27 16:33, on a nudge about missing security headers: "These missing security
# headers are nonsense ... if there's something that's important that's been ignored for a
# while, we can bring it up." A nudge is Moderate-high and up; news (section 1) stays Moderate+.
NUDGE_FLOOR = ("CRITICAL", "HIGH", "MODERATE-HIGH")
NUDGE_DAYS = 30                 # the email's timer (3s), same here so the two never disagree
NUDGE_MIN_AGE_DAYS = 30         # a nudge is for something that has sat; younger is news
NUDGE_MAX = 3                   # the two or three worst, worst first (the email's rule)

# The developer side (plan v2 D2, after the review's M1): family keys, then title patterns for
# the light- and heavy-tier titles that have no family. Everything else is the email's.
DEVELOPER_FAMILIES = ("out-of-date", "hsts", "auth-bypass")
DEVELOPER_TITLES = (
    re.compile(r"^Missing security header", re.I),
    re.compile(r"^Security headers missing", re.I),
    re.compile(r"Obsolete 3DES/IDEA", re.I),
    re.compile(r"^BREACH attack", re.I),
    re.compile(r"^TLS · BEAST_CBC", re.I),
    re.compile(r"^TLS · BEAST", re.I),
    re.compile(r"(admin|debug|phpinfo|\.git|\.env)\b.*(exposed|reachable|accessible|public)", re.I),
    re.compile(r"(exposed|reachable|accessible|public)\b.*(admin|debug|phpinfo|\.git|\.env)", re.I),
    re.compile(r"^Runs .+: out of date", re.I),
)
# Same-condition pairs that must read as one line (the review's M2: 5 hosts carry both)
MERGE_GROUPS = (
    ("security headers", (re.compile(r"^Missing security header", re.I), re.compile(r"^Security headers missing", re.I))),
    ("weak ciphers", (re.compile(r"Obsolete 3DES/IDEA", re.I), re.compile(r"^TLS · BEAST", re.I))),
)

RED, YELLOW, GREEN = "#C43B3B", "#D9A400", "#2E8B57"


def is_developer(title: str | None, family: str | None) -> bool:
    """On the allow-list: a developer fixes it in code or server config."""
    if (family or "") in DEVELOPER_FAMILIES:
        return True
    t = title or ""
    return any(p.search(t) for p in DEVELOPER_TITLES)


def merge_key(title: str | None, family: str | None) -> str:
    """Two titles that are one condition to a developer collapse under one key."""
    t = title or ""
    for key, pats in MERGE_GROUPS:
        if any(p.search(t) for p in pats):
            return key
    return family or t.strip().lower()


QUIET_AFTER = timedelta(hours=24)   # v_asset_reachability: not_responding once 24 h without an answer


def quiet_news(not_responding_rows, window_start, window_end) -> set:
    """The hosts whose not-responding notice BEGAN inside the window — the day it is news.
    Rows are SQL_NOT_RESPONDING's (asset_id, last_answer_at, reason, notice_since, leaves_on).
    A host crosses the line 24 h after its last answer (the view's rule); one that never
    answered crosses it when the notice was stamped. The email says the roster every day
    until the host leaves (3t D5); #on-call hears it once."""
    out = set()
    for r in not_responding_rows or []:
        aid, last_answer, _reason, notice = r[0], r[1], r[2], r[3]
        became = (last_answer + QUIET_AFTER) if last_answer is not None else notice
        if became is not None and window_start < became <= window_end:
            out.add(aid)
    return out


def changed_items(model: dict, *, quiet_news=None) -> list[dict]:
    """Section 1 — what changed since yesterday, for developers: every new Moderate+ problem
    (any family), a host that stopped answering (the day it did: `quiet_news`, from
    quiet_news(); None = say the whole roster), a web firewall that stopped blocking, a
    certificate about to lapse; then what got fixed or came back (section 1b, green)."""
    out = []
    for it in model.get("do", []) + model.get("ticket", []):
        kind = it.get("kind")                          # "coverage" (Sentry's own problems) and
        if kind == "not_responding":                   # "blockpage" are not developer news
            lines = [ln for ln in it.get("lines", []) if ":" in ln
                     and (quiet_news is None or ln.split(":")[0] in quiet_news)]
            if not lines:
                continue                               # on the roster since before yesterday: told already
            hosts = [ln.split(":")[0] for ln in lines]
            n = len(hosts)
            out.append(dict(it, lines=lines, sites=hosts, slack_color=RED,
                            title=f"{n} host{' is' if n == 1 else 's are'} not responding"))
            continue
        if kind in ("finding", "enforcement", "cert") and (it.get("severity") or "").upper() in MODERATE_PLUS:
            out.append(dict(it, slack_color=RED))
    for it in model.get("done", []):
        if it.get("kind") in ("fixed", "back", "blocking"):
            hosts = [ln.split(":")[0] for ln in it.get("lines", []) if ":" in ln]
            out.append(dict(it, sites=hosts or list(it.get("sites") or []), slack_color=GREEN))
    return out


def nudge_items(open_items: list[dict], slack_told: dict | None, now, *, exclude_ids=frozenset(),
                exclude_families=frozenset()) -> list[dict]:
    """Section 2 — the nudge. `open_items` are group_problems items over every open Moderate+
    row, each with `since` (earliest first sighting) and `finding_ids`. Eligible: on the
    developer allow-list, open ≥ NUDGE_MIN_AGE_DAYS, every member untold to Slack or told ≥
    NUDGE_DAYS ago, not in this post's section 1. Merged by condition, capped, worst then
    oldest. `slack_told` None = no record yet = everything eligible."""
    told = slack_told or {}
    cands = []
    for it in open_items:
        if (it.get("severity") or "").upper() not in NUDGE_FLOOR:
            continue
        if not is_developer(it.get("title"), it.get("family")):
            continue
        ids = list(it.get("finding_ids") or [])
        if not ids or any(f in exclude_ids for f in ids):
            continue
        if it.get("family") and it["family"] in exclude_families:
            continue
        since = it.get("since")
        if since is None or now - since < timedelta(days=NUDGE_MIN_AGE_DAYS):
            continue
        lasts = [told[f]["last_full_at"] for f in ids if told.get(f) and told[f].get("last_full_at") is not None]
        if lasts and now - max(lasts) < timedelta(days=NUDGE_DAYS):
            continue
        cands.append(it)
    items = merge_items(cands)
    # worst first, then the one on the most hosts, then the oldest, then the title
    items.sort(key=lambda g: (SEV_RANK.get((g.get("severity") or "").upper(), 9), -len(g.get("sites") or []),
                              g.get("since") or now, g.get("title", "")))
    return items[:NUDGE_MAX]


def merge_items(items: list[dict]) -> list[dict]:
    """Same-condition groups (MERGE_GROUPS) become one item with the hosts' union, the worst
    severity and the earliest since; used by the nudge and by the email's still-open picks
    (Howie 16:32: the two header items in one breath, as one line)."""
    merged: dict = {}
    for it in items:
        k = merge_key(it.get("title"), it.get("family"))
        g = merged.get(k)
        if g is None:
            merged[k] = dict(it, sites=sorted(set(it.get("sites") or [])), finding_ids=list(it.get("finding_ids") or []),
                             titles=[it.get("title", "")], merge_key=k)
            continue
        g["sites"] = sorted(set(g["sites"]) | set(it.get("sites") or []))
        g["finding_ids"] = list(g["finding_ids"]) + list(it.get("finding_ids") or [])
        g["titles"].append(it.get("title", ""))
        if SEV_RANK.get((it.get("severity") or "").upper(), 9) < SEV_RANK.get((g.get("severity") or "").upper(), 9):
            g["severity"] = it["severity"]
        if it.get("since") is not None and (g.get("since") is None or it["since"] < g["since"]):
            g["since"] = it["since"]
    out = list(merged.values())
    for g in out:
        if len(g.get("titles", [])) > 1:
            g["title"] = _merged_title(g["merge_key"], g["titles"])
    return out


HEADER_SHORT = {"Content-Security-Policy": "CSP", "Strict-Transport-Security": "HSTS", "X-Frame-Options": "X-Frame-Options",
                "X-Content-Type-Options": "X-Content-Type-Options", "Referrer-Policy": "Referrer-Policy",
                "Permissions-Policy": "Permissions-Policy"}


def _merged_title(key: str, titles: list) -> str:
    if key == "security headers":
        names = sorted({HEADER_SHORT.get(t.split(":", 1)[1].strip(), t.split(":", 1)[1].strip()) for t in titles if ":" in t})
        return ("Security headers missing: " + ", ".join(names)) if names else "Security headers missing"
    if key == "weak ciphers":
        return "Old weak ciphers (3DES, BEAST) still offered"
    return titles[0]


def select(model: dict, open_items: list[dict], slack_told: dict | None, now, *, quiet_news=None) -> dict:
    """{'changed': [...], 'nudge': [...]} — the post's two sections; both empty = no post."""
    changed = changed_items(model, quiet_news=quiet_news)
    ex_ids = {f for it in changed for f in (it.get("finding_ids") or [])}
    ex_fam = {it.get("family") for it in changed if it.get("family")}
    return {"changed": changed,
            "nudge": nudge_items(open_items, slack_told, now, exclude_ids=ex_ids, exclude_families=ex_fam)}


def records(selection: dict, member_sev: dict | None = None) -> list[tuple]:
    """(finding_id, severity) for every member of every nudge in the post — what slack_told
    records after a post that worked. Section 1 is news, not a telling: it is not recorded,
    so a new finding can still be nudged 30 days on."""
    out, seen = [], set()
    member_sev = member_sev or {}
    for it in selection.get("nudge", []):
        for f in it.get("finding_ids", []):
            if f not in seen:
                seen.add(f)
                out.append((f, (member_sev.get(f) or it.get("severity") or "").upper()))
    return out


# ── the post ────────────────────────────────────────────────────────────────────────────
def _mrkdwn(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def payload(out: dict, selection: dict, *, product_name: str, day_label: str) -> dict | None:
    """The webhook body (Block Kit): a header, a red attachment for what changed, a green one
    for what got fixed, a yellow one for the nudge, a context closing. None when there is
    nothing to post. `out` is the writer's (checked) JSON; `selection` is select()'s."""
    changed_txt = [e.get("text", "") for e in (out.get("slack") or {}).get("changed", [])]
    nudge_txt = [e.get("text", "") for e in (out.get("slack") or {}).get("nudge", [])]
    if not changed_txt and not nudge_txt:
        return None
    changed_items_ = selection.get("changed", [])
    red, green = [], []
    for it, txt in zip(changed_items_, changed_txt):
        (green if it.get("slack_color") == GREEN else red).append(txt)
    attachments = []
    if red:
        attachments.append({"color": RED, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text":
            "*What changed since yesterday*\n" + "\n".join("• " + _mrkdwn(t) for t in red)}}]})
    if green:
        attachments.append({"color": GREEN, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text":
            "*Fixed, or back*\n" + "\n".join("• " + _mrkdwn(t) for t in green)}}]})
    if nudge_txt:
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text":
                   "*Still sitting there, just FYI*\n" + "\n".join("• " + _mrkdwn(t) for t in nudge_txt)}}]
        closing = ((out.get("slack") or {}).get("closing") or "").strip()
        if closing:
            blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": _mrkdwn(closing)}]})
        attachments.append({"color": YELLOW, "blocks": blocks})
    summary = " ".join(red + green + nudge_txt)[:280]
    return {
        "text": f"{product_name}, {day_label}: {summary}",
        "blocks": [{"type": "header", "text": {"type": "plain_text", "text": f"{product_name}  ·  {day_label}", "emoji": True}}],
        "attachments": attachments,
    }


def preview_text(p: dict | None) -> str:
    """What Howie's copy shows under the Post to Slack button: the post as plain lines."""
    if not p:
        return ""
    lines = []
    for a in p.get("attachments", []):
        for b in a.get("blocks", []):
            if b.get("type") == "section":
                lines.append(b["text"]["text"])
            elif b.get("type") == "context":
                lines.append("\n".join(e.get("text", "") for e in b.get("elements", [])))
    return "\n\n".join(lines)
