"""Which supply-chain safeguards the organisation's public repositories lack, as assessed
by OpenSSF Scorecard. Reads Scorecard's published results. The repositories themselves
are not contacted.

Only the checks that fail are reported. Scorecard's overall score is never shown: this
project gives no scores or grades.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

from parapet.clients import github
from parapet.core.context import ScanContext
from parapet.core.models import (
    Asset,
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Target,
)
from parapet.core.module import ModuleSpec, ScanModule, register, skipped

API_HOST = "api.securityscorecards.dev"
MAX_REPOS = 20
MAX_BYTES = 2_000_000
MAX_REASON_CHARS = 300
REQUEST_TIMEOUT_S = 30.0
PASS_MARK = 5

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,38})$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._\-]{1,100}$")
_DOCS_PREFIX = "https://github.com/ossf/scorecard/"

CHECKS = {
    "Branch-Protection": "Whether the main branches are protected against direct or "
    "forced changes.",
    "Code-Review": "Whether changes are reviewed by a second person before they are merged.",
    "Dangerous-Workflow": "Whether automated workflows can be made to run code from an "
    "outsider's pull request with access to secrets.",
    "Pinned-Dependencies": "Whether build steps name the exact versions of what they download.",
    "Token-Permissions": "Whether automated workflows run with no more access than they need.",
}


class ScorecardError(Exception):
    """Scorecard could not be read. The message is plain language."""


def repo_parts(full_name: object) -> tuple[str, str] | None:
    if not isinstance(full_name, str) or full_name.count("/") != 1:
        return None
    owner, repo = full_name.split("/")
    if not _OWNER_RE.match(owner) or not _REPO_RE.match(repo) or set(repo) == {"."}:
        return None
    return owner, repo


def bucket(score: object) -> str | None:
    """The band a failing score falls in. None when the check passes or was not assessed."""
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    if score < 0 or score >= PASS_MARK or score != score:
        return None
    return "0-2" if score < 3 else "3-4"


def plain(value: object, length: int) -> str:
    text = " ".join(str(value or "").split())
    return "".join(ch for ch in text if ch.isprintable())[:length].replace("--", ":")


def failing_checks(document: object) -> tuple[dict[str, str], dict[str, Any], list[str]]:
    """(state, evidence, checks that could not be assessed) from a Scorecard result."""
    if not isinstance(document, dict) or not isinstance(document.get("checks"), list):
        raise ScorecardError("Scorecard answered with something other than a result")
    state: dict[str, str] = {}
    evidence: dict[str, Any] = {}
    unassessed: list[str] = []
    for check in document["checks"][:100]:
        if not isinstance(check, dict):
            continue
        name = check.get("name")
        if not isinstance(name, str) or name not in CHECKS or name in state:
            continue
        score = check.get("score")
        band = bucket(score)
        if band is None:
            if isinstance(score, (int, float)) and not isinstance(score, bool) and score < 0:
                unassessed.append(name)
            continue
        state[name] = band
        docs = check.get("documentation")
        link = docs.get("url") if isinstance(docs, dict) else None
        evidence[name] = {
            "what_it_checks": CHECKS[name],
            "result": f"{band} out of 10",
            "reason": plain(check.get("reason"), MAX_REASON_CHARS),
            "more": link[:300] if isinstance(link, str) and link.startswith(_DOCS_PREFIX) else "",
        }
    return dict(sorted(state.items())), evidence, sorted(set(unassessed))


async def scorecard(ctx: ScanContext, owner: str, repo: str) -> dict[str, Any] | None:
    """The published result, or None when Scorecard holds none for this repository."""
    url = httpx.URL(f"https://{API_HOST}/projects/github.com/{owner}/{repo}")
    if url.host != API_HOST or ".." in url.path.split("/"):
        raise ScorecardError("the repository name was not safe to look up")
    await ctx.limiter.acquire(API_HOST)
    body = bytearray()
    try:
        async with asyncio.timeout(REQUEST_TIMEOUT_S):
            async with ctx.http.stream(
                "GET", url, headers={"Accept": "application/json"}
            ) as response:
                status = response.status_code
                if status == 200:
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_BYTES:
                            raise ScorecardError("Scorecard sent an unusually large answer")
    except TimeoutError as exc:
        raise ScorecardError("Scorecard took too long to answer") from exc
    except httpx.HTTPError as exc:
        raise ScorecardError(f"Scorecard could not be reached ({type(exc).__name__})") from exc
    if status == 404:
        return None
    if status == 429:
        raise ScorecardError("Scorecard's request limit was reached")
    if status != 200:
        raise ScorecardError(f"Scorecard answered HTTP {status}")
    try:
        document = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise ScorecardError("Scorecard did not answer with valid JSON") from exc
    if not isinstance(document, dict):
        raise ScorecardError("Scorecard answered with something other than a result")
    return document


@register
class RepoScorecard(ScanModule):
    spec = ModuleSpec(
        name="repo_scorecard",
        title="Repository safeguards",
        category=Category.SUPPLY_CHAIN,
        mode=ScanMode.PASSIVE,
        description="Which of your public repositories lack branch protection, code review "
        "or safe automation settings, according to OpenSSF Scorecard.",
        requires_target=("github_org",),
        optional_keys=("GITHUB_TOKEN",),
        depends_on=("github_org",),
        contacts=("OpenSSF Scorecard API", "GitHub API"),
        default_timeout_s=300,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        org = target.github_org
        assert org is not None
        listing = ctx.assets.get("github_org")
        if listing is None or not ctx.assets.completed("github_org"):
            return skipped(
                self.spec,
                "the check that lists your repositories did not complete",
                "run the scan with the github_org module enabled",
            )
        notes: list[str] = []
        repos: list[Asset] = []
        for asset in listing.assets:
            parts = repo_parts(asset.key) if asset.type is AssetType.REPOSITORY else None
            if parts is not None and parts[0].lower() == org.lower():
                repos.append(asset)
        repos.sort(key=lambda a: a.key)
        repos.sort(key=lambda a: str(a.attributes.get("last_push") or ""), reverse=True)
        if not repos:
            return self.result(notes=["The organisation has no public repositories to assess."])
        truncated = len(repos) > MAX_REPOS
        if truncated:
            notes.append(f"Only the {MAX_REPOS} most recently updated repositories were read.")
        repos = repos[:MAX_REPOS]

        spelling = await self._spelling(ctx, org, repos, notes)
        findings: list[Finding] = []
        no_data: list[str] = []
        failures: list[str] = []
        assessed = 0
        for asset in repos:
            name = spelling.get(asset.key, asset.key)
            parts = repo_parts(name)
            if parts is None:
                continue
            try:
                document = await scorecard(ctx, *parts)
                if document is None:
                    no_data.append(name)
                    continue
                state, evidence, unassessed = failing_checks(document)
            except ScorecardError as exc:
                failures.append(f"{name}: {exc}")
                if "limit" in str(exc):
                    break
                continue
            assessed += 1
            if not state:
                continue
            dangerous = "Dangerous-Workflow" in state
            date = document.get("date")
            findings.append(
                self.finding(
                    "github.repo.scorecard",
                    AssetType.REPOSITORY,
                    asset.key,
                    f"Repository {name} fails {len(state)} of {len(CHECKS)} supply-chain checks",
                    state=state,
                    evidence={
                        "failing_checks": evidence,
                        "could_not_be_assessed": unassessed,
                        "assessed_on": plain(date, 10) if isinstance(date, str) else "",
                        "source": "OpenSSF Scorecard",
                    },
                    confidence=Confidence.LIKELY,
                    severity_steps=1 if dangerous else 0,
                    severity_note="An automated workflow can be made to run an outsider's "
                    "code with access to the repository's secrets."
                    if dangerous
                    else None,
                )
            )
        if no_data:
            notes.append(
                "Scorecard holds no result for: " + ", ".join(no_data) + ". It assesses "
                "well-known repositories by itself. Others appear once they run the "
                "Scorecard workflow."
            )
        if failures:
            notes.append(f"{len(failures)} repositories were not read (first: {failures[0]}).")
        stats = {
            "repositories": len(repos),
            "assessed": assessed,
            "no_data": len(no_data),
            "failing": len(findings),
        }
        if failures and not assessed and not no_data:
            return self.result(
                ModuleStatus.FAILED,
                skip_reason=failures[0].split(": ", 1)[-1],
                notes=notes,
                stats=stats,
            )
        return self.result(
            ModuleStatus.PARTIAL if failures or truncated else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats=stats,
        )

    async def _spelling(
        self, ctx: ScanContext, org: str, repos: list[Asset], notes: list[str]
    ) -> dict[str, str]:
        """Repository names with their capital letters, which Scorecard insists on.

        Asset keys are stored in lower case. One request to GitHub recovers the
        original spelling for every repository at once.
        """
        known: dict[str, str] = {}
        for asset in repos:
            name = asset.attributes.get("full_name")
            if isinstance(name, str) and name.lower() == asset.key and repo_parts(name):
                known[asset.key] = name
        if len(known) == len(repos) or not _OWNER_RE.match(org):
            return known
        try:
            rows = await github.get(
                ctx,
                f"/orgs/{org}/repos",
                {"type": "public", "sort": "pushed", "per_page": "100"},
            )
        except github.GitHubError as exc:
            notes.append(
                "The exact spelling of repository names could not be read from GitHub "
                f"({exc}) Repositories with capital letters in their names may be "
                "reported as having no Scorecard result."
            )
            return known
        except ValueError:
            return known
        wanted = {asset.key for asset in repos}
        for row in rows[:100] if isinstance(rows, list) else []:
            name = row.get("full_name") if isinstance(row, dict) else None
            if isinstance(name, str) and name.lower() in wanted and repo_parts(name):
                known.setdefault(name.lower(), name)
        return known
