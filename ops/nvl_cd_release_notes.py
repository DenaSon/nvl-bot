"""Bounded, best-effort release notes tied to the exact deployed commit range."""
import re
import unicodedata

if __package__:
    from . import nvl_cd_planner as p
else:
    import nvl_cd_planner as p

MAX_COMMITS = 3
HEADINGS = {
    "release summary": "summary",
    "changes": "changes",
    "acceptance tests": "tests",
}
BASE_URL = "https://github.com/" + p.REPO


def clean(value, limit):
    if not isinstance(value, str):
        return ""
    # Plain text, no Markdown/HTML parse mode. Strip controls and bidi
    # overrides while keeping Persian ZWNJ and ordinary whitespace.
    value = "".join(c for c in value if c in "\n\t\u200c" or
                    unicodedata.category(c) not in ("Cc", "Cf", "Cs"))
    value = re.sub(r"https?://[^\s<>]+", "[لینک حذف شد]", value, flags=re.I)
    value = re.sub(r"\b[0-9]{5,20}:[A-Za-z0-9_-]{20,100}\b",
                   "[حذف شد]", value)
    value = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
                   "[حذف شد]", value)
    value = re.sub(r"<!--.*?(?:-->|$)", "", value, flags=re.S)
    value = re.sub(r"<[^>\n]*>", "", value)
    value = " ".join(value.split())
    return value if len(value) <= limit else value[:limit - 1].rstrip() + "…"


def sections(body):
    if not isinstance(body, str):
        return {}
    body = re.sub(r"<!--.*?(?:-->|$)", "", body[:30000], flags=re.S)
    result, section, fenced = {}, None, False
    for line in body.splitlines():
        if re.match(r"^\s*(?:\x60{3,}|~{3,})", line):
            fenced = not fenced
            continue
        if fenced:
            continue
        heading = re.match(r"^\s*#{1,6}\s+(.+?)\s*#*\s*$", line)
        if heading:
            section = HEADINGS.get(heading.group(1).strip().lower())
            continue
        if section:
            line = re.sub(r"^\s*(?:[-*+]|\d+[.)])\s+", "", line)
            value = clean(line, 150)
            if value:
                result.setdefault(section, []).append(value)
    return {k: v[:(1 if k == "summary" else 2)] for k, v in result.items()}


def exact_pr(rows, sha):
    if not isinstance(rows, list):
        return None
    found = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        base = row.get("base") or {}
        repo = base.get("repo") or {}
        number = row.get("number")
        if (row.get("merge_commit_sha") == sha and row.get("merged_at")
                and base.get("ref") == "master"
                and repo.get("full_name", "").lower() == p.REPO.lower()
                and type(number) is int and number > 0):
            found.append(row)
    if len(found) != 1:
        return None
    row = found[0]
    return {"number": row["number"], "title": clean(row.get("title"), 100),
            **sections(row.get("body"))}


def collect(repo, baseline, candidate, fetch=None):
    """No authority to deploy; return fallback on missing data or API failure."""
    if fetch is None:
        fetch = lambda path: p.api_json(path, timeout=5)
    notes = {"entries": [], "complete": False}
    try:
        p.exact_sha(baseline)
        p.exact_sha(candidate)
        chain = p.git(repo, "rev-list", "--first-parent",
                      "--max-count=" + str(MAX_COMMITS + 1), candidate).decode("ascii").splitlines()
        if not chain or chain[0] != candidate or baseline not in chain:
            return notes
        commits = chain[:chain.index(baseline)]
        for sha in reversed(commits):
            p.exact_sha(sha)
            try:
                item = exact_pr(fetch("/commits/" + sha + "/pulls?per_page=100"), sha)
            except Exception:
                item = None
            if item:
                notes["entries"].append(item)
        notes["complete"] = (len(notes["entries"]) == len(commits)
                             and all(item.get("summary") and item.get("changes") and item.get("tests")
                                     for item in notes["entries"]))
    except Exception:
        pass
    return notes


def render(state):
    """Plain-text presentation. Never claim that manager acceptance tests passed."""
    sha = state.get("candidate")
    if state.get("phase") != "COMMITTED" or not isinstance(sha, str) or not p.SHA.fullmatch(sha):
        return ""
    lines = []
    notes = state.get("release_notes")
    if not isinstance(notes, dict):
        notes = {}
    entries = notes.get("entries")
    if not isinstance(entries, list):
        entries = []
    for item in entries[:MAX_COMMITS]:
        if not isinstance(item, dict) or type(item.get("number")) is not int or item["number"] <= 0:
            continue
        number = item["number"]
        title = clean(item.get("title"), 100)
        lines.append("\n📌 " + (title or "Pull Request") + " (#" + str(number) + ")")
        for key, label in (("summary", "خلاصه توسعه"), ("changes", "✨ تغییرات"),
                           ("tests", "🧪 تست عملیاتی پیشنهادی")):
            values = item.get(key)
            if not isinstance(values, list):
                continue
            values = [clean(value, 150) for value in values[:(1 if key == "summary" else 2)]]
            values = [value for value in values if value]
            if values:
                lines.append(label + ":")
                lines.extend("• " + value for value in values)
        lines.append(BASE_URL + "/pull/" + str(number))
    if not lines or notes.get("complete") is not True:
        lines.append("\nℹ️ توضیحات همه تغییرات یا مسیر تست کامل در دسترس نیست؛ جزئیات GitHub را بررسی کنید.")
    baseline = state.get("previous_deployed")
    if isinstance(baseline, str) and p.SHA.fullmatch(baseline):
        lines.append("جزئیات نسخه: " + BASE_URL + "/compare/" + baseline + "..." + sha)
    else:
        lines.append("جزئیات نسخه: " + BASE_URL + "/commit/" + sha)
    return "\n".join(lines)
