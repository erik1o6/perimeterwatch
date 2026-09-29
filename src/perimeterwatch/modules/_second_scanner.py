"""Betterleaks, a second secret scanner run beside trufflehog.

The two scanners use different rules, so a credential one misses the other may
catch. The rules of github_secrets hold here too:
- A credential is never stored or shown. The raw value is dropped in
  `parse_finding`, and nothing else in the report is kept that could hold it.
- A credential is never tested. Betterleaks tests nothing unless asked to with
  `--validation`. It is switched off explicitly all the same, so that a later
  change of default cannot switch it on.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from perimeterwatch.core.redact import secret_hash_prefix, secret_prefix

NAME = "betterleaks"
MAX_ROWS = 20_000
# Exit code 1 means the scan met errors part of the way. The report is still written.
OK_RETURNCODES = (0, 1)

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
_GITHUB = "https://github.com/"


def command(org: str) -> list[str]:
    """Arguments for one scan of an organisation. The token is never among them."""
    return [
        "github",
        f"{_GITHUB}{org}",
        "--validation=false",
        "--report-format=json",
        "--report-path=-",
        # Finding a credential is not a failure of the tool.
        "--exit-code=0",
        # A repository must not be able to hide a credential with a comment.
        "--ignore-gitleaks-allow",
        "--max-target-megabytes=10",
        "--no-banner",
        "--no-color",
        "--log-level=warn",
    ]


def environment(token: str, scratch: Path) -> dict[str, str]:
    """The token goes in the environment. Clones go under the scan's own directory."""
    return {"GITHUB_TOKEN": token, "TMPDIR": str(scratch), "GIT_TERMINAL_PROMPT": "0"}


def parse_report(text: str, limit: int = MAX_ROWS) -> Iterator[dict[str, Any]]:
    """The objects of a JSON list, read one at a time.

    Output that was cut short, or that has noise around it, gives the objects
    that came before the damage instead of nothing at all.
    """
    decoder = json.JSONDecoder()
    position = text.find("[")
    if position < 0:
        return
    position += 1
    for _ in range(limit):
        while position < len(text) and text[position] in " \t\r\n,":
            position += 1
        if position >= len(text) or text[position] != "{":
            return
        try:
            row, position = decoder.raw_decode(text, position)
        except (ValueError, RecursionError):
            return
        if isinstance(row, dict):
            yield row


def _text(value: Any, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _repo(attributes: dict[str, Any], row: dict[str, Any]) -> str:
    for candidate in (
        attributes.get("github.repo_url"),
        attributes.get("git.remote_url"),
        row.get("Link"),
    ):
        if not isinstance(candidate, str) or not candidate.startswith(_GITHUB):
            continue
        parts = candidate[:500].removeprefix(_GITHUB).split("/")
        if len(parts) < 2:
            continue
        name = f"{parts[0]}/{parts[1].removesuffix('.git')}"
        if _REPO_RE.match(name):
            return name
    return ""


def parse_finding(row: dict[str, Any]) -> dict[str, str] | None:
    """Reduce one Betterleaks finding to what may be kept. The raw value is dropped here."""
    raw = row.get("Secret")
    rule = row.get("RuleID")
    if not isinstance(raw, str) or not raw.strip() or not isinstance(rule, str) or not rule:
        return None
    if raw == "REDACTED":
        return None  # the tool was asked to hide the value, so there is nothing to compare
    found = row.get("Attributes")
    attributes: dict[str, Any] = found if isinstance(found, dict) else {}
    repo = _repo(attributes, row)
    if not repo:
        return None  # a result that cannot be located is of no use to anyone
    commit = (_text(attributes.get("git.sha"), 40) or _text(row.get("Commit"), 40)).lower()
    line = row.get("StartLine")
    return {
        "detector": rule[:80],
        "repo": repo,
        "file": _text(attributes.get("path"), 300) or _text(row.get("File"), 300),
        "commit": commit if _COMMIT_RE.match(commit) else "",
        "line": str(line) if isinstance(line, int) and not isinstance(line, bool) else "",
        "committed": (_text(attributes.get("git.date"), 10) or _text(row.get("Date"), 10)),
        "starts_with": secret_prefix(raw),
        "hash": secret_hash_prefix(raw),
        # Deliberately not kept: the raw value, the match and the lines around
        # it (both contain the value), capture groups, the commit message, and
        # the author's name and email.
    }
