"""Choose which nuclei templates may run.

nuclei's own tag filters are not enough. Templates tagged as plain detection
can still send attack-shaped requests: the stock WAF detection template posts
a script payload. So every template is read and admitted only if each request
it makes is a plain GET or HEAD with nothing attached.

The rules are fixed in code. No flag or setting widens them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Only these parts of the template collection are considered at all.
ALLOWED_DIRS = (
    "http/exposures",
    "http/misconfiguration",
    "http/takeovers",
    "http/technologies",
    "ssl",
    "dns",
)
ALLOWED_TAGS = frozenset({"exposure", "misconfig", "takeover", "tech", "ssl", "dns"})
BLOCKED_TAGS = frozenset(
    {
        "dos", "fuzz", "fuzzing", "intrusive", "bruteforce", "brute-force", "default-login",
        "rce", "sqli", "xss", "lfi", "rfi", "ssrf", "ssti", "xxe", "oast", "oob", "injection",
        "cve", "kev", "exploit", "auth-bypass", "upload", "fileupload", "traversal", "redirect",
        "crlf", "cmdi", "deserialization", "smuggling", "headless", "code",
    }
)  # fmt: skip
SAFE_METHODS = frozenset({"GET", "HEAD"})
# Request fields that attach a payload or drive many requests.
BLOCKED_REQUEST_KEYS = frozenset(
    {"raw", "body", "payloads", "fuzzing", "attack", "race", "race_count", "pipeline",
     "unsafe", "threads", "self-contained", "analyzer", "pre-condition"}
)  # fmt: skip
# Template sections other than plain http, ssl and dns.
BLOCKED_SECTIONS = frozenset(
    {"tcp", "network", "headless", "code", "javascript", "file", "workflows", "workflow",
     "websocket", "whois", "flow", "variables"}
)  # fmt: skip
MAX_PATHS = 6
MAX_TEMPLATE_BYTES = 200_000


@dataclass
class Selection:
    admitted: list[Path] = field(default_factory=list)
    ids: set[str] = field(default_factory=set)
    rejected: dict[str, int] = field(default_factory=dict)

    def reject(self, reason: str) -> None:
        self.rejected[reason] = self.rejected.get(reason, 0) + 1


def _tags(info: dict[str, Any]) -> set[str]:
    raw = info.get("tags", "")
    items = raw if isinstance(raw, list) else str(raw).split(",")
    return {str(t).strip().lower() for t in items if str(t).strip()}


def _request_problem(request: Any) -> str | None:
    if not isinstance(request, dict):
        return "malformed request"
    blocked = BLOCKED_REQUEST_KEYS & set(request)
    if blocked:
        return f"request uses {sorted(blocked)[0]}"
    if str(request.get("method", "GET")).upper() not in SAFE_METHODS:
        return "request method is not GET or HEAD"
    paths = request.get("path", [])
    if not isinstance(paths, list) or not paths:
        return "malformed request"
    if len(paths) > MAX_PATHS:
        return "too many requests per host"
    for path in paths:
        text = str(path)
        if not text.startswith(("{{BaseURL}}", "{{RootURL}}")):
            return "request leaves the scanned host"
        if any(mark in text for mark in ("{{interactsh", "<script", "../", "%2e%2e", "${")):
            return "request carries a payload"
    return None


def problem(template: Any) -> str | None:
    """Why a template is refused, or None if it may run."""
    if not isinstance(template, dict):
        return "malformed template"
    info = template.get("info")
    if not isinstance(info, dict) or not template.get("id"):
        return "malformed template"
    tags = _tags(info)
    if tags & BLOCKED_TAGS:
        return "blocked tag"
    if not tags & ALLOWED_TAGS:
        return "no allowed tag"
    sections = BLOCKED_SECTIONS & set(template)
    if sections:
        return f"uses {sorted(sections)[0]}"
    if template.get("self-contained"):
        return "self-contained"
    requests = [*(template.get("http") or []), *(template.get("requests") or [])]
    if not requests and not template.get("ssl") and not template.get("dns"):
        return "no supported request"
    for request in requests:
        issue = _request_problem(request)
        if issue:
            return issue
    return None


def select_templates(templates_dir: Path) -> Selection:
    selection = Selection()
    root = templates_dir.resolve()
    for sub in ALLOWED_DIRS:
        base = root / sub
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.yaml")):
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                selection.reject("outside the template directory")
                continue
            if path.stat().st_size > MAX_TEMPLATE_BYTES:
                selection.reject("template too large")
                continue
            try:
                template = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
            except yaml.YAMLError:
                selection.reject("unreadable template")
                continue
            issue = problem(template)
            if issue:
                selection.reject(issue)
            else:
                selection.admitted.append(path)
                selection.ids.add(str(template["id"]))
    return selection
