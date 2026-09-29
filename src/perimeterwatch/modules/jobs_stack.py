"""Which technologies the organisation's own job postings name.

Reads the public job board the organisation itself publishes. No other site is
consulted, and nothing about applicants or staff is collected.
"""

from __future__ import annotations

import html
import json
import re
from functools import lru_cache
from importlib import resources
from typing import Any

import httpx

from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.models import (
    AssetType,
    Category,
    Confidence,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Target,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register
from perimeterwatch.safety.domains import validate_slug

BOARDS = {
    "greenhouse": ("boards-api.greenhouse.io", "/v1/boards/{slug}/jobs", {"content": "true"}),
    "lever": ("api.lever.co", "/v0/postings/{slug}", {"mode": "json"}),
}
MAX_BYTES = 8_000_000
MAX_POSTINGS = 300
_TAG_RE = re.compile(r"<[^>]+>")


@lru_cache(maxsize=1)
def keywords() -> list[tuple[str, str, re.Pattern[str]]]:
    raw = resources.files("perimeterwatch.data").joinpath("tech_keywords.json").read_text()
    data = json.loads(raw)
    exact = set(data.get("exact", []))
    out = []
    for group, names in data["groups"].items():
        for name in names:
            flags = 0 if name in exact else re.IGNORECASE
            pattern = re.compile(rf"(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])", flags)
            out.append((group, name, pattern))
    return out


def plain_text(value: Any) -> str:
    text = html.unescape(html.unescape(str(value or "")))
    return " ".join(_TAG_RE.sub(" ", text).split())


def postings(kind: str, payload: Any) -> list[tuple[str, str]]:
    """(title, text) for each posting."""
    if kind == "greenhouse":
        rows = payload.get("jobs", []) if isinstance(payload, dict) else []
        return [
            (plain_text(r.get("title")), plain_text(r.get("content")))
            for r in rows
            if isinstance(r, dict)
        ]
    rows = payload if isinstance(payload, list) else []
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        parts = [row.get("descriptionPlain") or row.get("description"), row.get("additionalPlain")]
        for section in row.get("lists") or []:
            if isinstance(section, dict):
                parts.extend([section.get("text"), section.get("content")])
        out.append((plain_text(row.get("text")), " ".join(plain_text(p) for p in parts if p)))
    return out


def find_technologies(texts: list[tuple[str, str]]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for title, text in texts:
        for group, name, pattern in keywords():
            if pattern.search(text) or pattern.search(title):
                entry = found.setdefault(name, {"group": group, "postings": 0})
                entry["postings"] += 1
    return found


@register
class JobsStack(ScanModule):
    spec = ModuleSpec(
        name="jobs_stack",
        title="Technology named in job postings",
        category=Category.WEB3,
        mode=ScanMode.PASSIVE,
        description="Systems and tools your own job postings reveal.",
        requires_target=("job_board",),
        contacts=("your public job board (Greenhouse or Lever)",),
        default_timeout_s=120,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        board = target.job_board
        assert board is not None
        if board.kind not in BOARDS:
            return self.result(
                ModuleStatus.FAILED, skip_reason=f"job board type '{board.kind}' is not supported"
            )
        slug = validate_slug(board.value, "job board name")
        host, path, params = BOARDS[board.kind]
        await ctx.limiter.acquire(host)
        try:
            response = await ctx.http.get(f"https://{host}{path.format(slug=slug)}", params=params)
        except httpx.TransportError as exc:
            return self.result(
                ModuleStatus.FAILED,
                skip_reason=f"the job board could not be reached ({type(exc).__name__})",
            )
        if response.status_code == 404:
            return self.result(
                ModuleStatus.FAILED, skip_reason=f"no {board.kind} job board is named {slug}"
            )
        if response.status_code != 200 or len(response.content) > MAX_BYTES:
            return self.result(
                ModuleStatus.FAILED,
                skip_reason=f"the job board answered HTTP {response.status_code}",
            )
        try:
            texts = postings(board.kind, response.json())[:MAX_POSTINGS]
        except ValueError:
            return self.result(
                ModuleStatus.FAILED, skip_reason="the job board did not answer with JSON"
            )

        found = find_technologies(texts)
        if not found:
            return self.result(stats={"postings": len(texts), "technologies": 0})

        by_group: dict[str, list[str]] = {}
        for name, info in sorted(found.items()):
            by_group.setdefault(info["group"], []).append(name)
        sensitive = [
            g
            for g in ("key_management", "secrets_and_identity", "security_tooling")
            if g in by_group
        ]
        finding = self.finding(
            "jobs.tech_disclosed",
            AssetType.DOMAIN,
            target.root_domain,
            f"Job postings name {len(found)} technologies in use",
            state={"technologies": sorted(found)},
            evidence={
                **{g.replace("_", " "): names for g, names in sorted(by_group.items())},
                "postings_read": len(texts),
                "source": f"{board.kind} job board '{slug}'",
            },
            confidence=Confidence.CONFIRMED,
            severity_steps=1 if sensitive else 0,
            severity_note="Postings name key-management, identity or security tooling."
            if sensitive
            else None,
        )
        return self.result(
            findings=[finding], stats={"postings": len(texts), "technologies": len(found)}
        )
