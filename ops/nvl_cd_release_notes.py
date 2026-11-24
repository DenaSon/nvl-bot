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


def redact_links(value):
    """No repository address, including bare host or SSH forms, in notices."""
    value = re.sub(r"https?://[^\s<>]+", "[لینک حذف شد]", value, flags=re.I)
    value = re.sub(r"(?<![\w])(?:git@|ssh://)?(?:[\w.-]+\.)?(?:github\.com|githubusercontent\.com)(?:[:/][^\s<>]*)?", "[لینک حذف شد]", value, flags=re.I)
    return re.sub(re.escape(p.REPO), "[حذف شد]", value, flags=re.I)


def clean(value, limit):
    if not isinstance(value, str):
        return ""
    # Plain text, no Markdown/HTML parse mode. Strip controls and bidi
    # overrides while keeping Persian ZWNJ and ordinary whitespace.
    value = "".join(c for c in value if c in "\n\t\u200c" or
                    unicodedata.category(c) not in ("Cc", "Cf", "Cs"))
    value = redact_links(value)
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
        # Local Git is authoritative for the actual commit message, even
        # when the PR API is unavailable or the release range is too long.
        try:
            raw = p.git(repo, "show", "-s", "--format=%s%n%b", candidate)
            subject, _, body = raw.decode("utf-8", errors="replace").partition("\n")
            notes["commit_message"] = clean(subject, 150)
            notes["commit_changes"] = [
                value for line in body.splitlines()
                if (value := clean(line, 150))
            ][:3]
        except Exception:
            pass
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
                             and all(item.get("summary") and item.get("changes")
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
    subject = clean(notes.get("commit_message"), 150)
    if subject:
        lines.append("📝 پیام کامیت: " + subject)
    entries = notes.get("entries")
    if not isinstance(entries, list):
        entries = []
    changes = []
    structured = False
    for item in entries[:MAX_COMMITS]:
        if not isinstance(item, dict) or type(item.get("number")) is not int or item["number"] <= 0:
            continue
        title = clean(item.get("title"), 100)
        if title and title != subject:
            changes.append("• " + title)
        for key, limit in (("summary", 1), ("changes", 2)):
            values = item.get(key)
            if isinstance(values, list):
                cleaned = [value for raw in values[:limit]
                           if (value := clean(raw, 150))]
                structured = structured or bool(cleaned)
                changes.extend("• " + value for value in cleaned)
    if not structured:
        fallback = notes.get("commit_changes")
        if isinstance(fallback, list):
            changes.extend("• " + value for raw in fallback[:3]
                           if (value := clean(raw, 150)))
    if changes:
        lines.extend(["", "✨ تغییرات (Changelog):", *changes])
    if not changes or notes.get("complete") is not True:
        lines.append("ℹ️ جزئیات کامل تغییرات در دسترس نیست.")
    return "\n".join(lines)


def sanitize_notice(message):
    """Also protect already-queued notices created by older observers."""
    lines = []
    for line in message.splitlines():
        if line.startswith("جزئیات نسخه: ") or re.match(
                r"^\s*https?://(?:www\.)?github\.com/", line, flags=re.I):
            continue
        if "جزئیات GitHub را بررسی کنید" in line:
            line = "ℹ️ جزئیات کامل تغییرات در دسترس نیست."
        lines.append(redact_links(line))
    return "\n".join(lines)
