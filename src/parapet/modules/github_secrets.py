"""Credentials committed to the organisation's public repositories.

Two rules hold throughout:
- A credential is never stored or shown. Only its type, location, first four
  characters and a short hash are kept.
- A credential is never tested. trufflehog can try to log in with what it finds
  in order to confirm it is live; that is switched off.

trufflehog is required. Betterleaks runs beside it when installed, and what the
two find is merged.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from parapet.core.context import ScanContext
from parapet.core.models import (
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Sensitivity,
    Target,
)
from parapet.core.module import ModuleSpec, ScanModule, register
from parapet.core.redact import secret_hash_prefix, secret_prefix
from parapet.modules import _second_scanner
from parapet.safety.domains import validate_github_org
from parapet.safety.subprocess import run_tool

MAX_FINDINGS = 500


def repo_name(link: str, repository: str) -> str:
    source = repository or link
    source = source.removeprefix("https://github.com/").removesuffix(".git")
    parts = source.split("/")
    return "/".join(parts[:2])[:200] if len(parts) >= 2 else source[:200]


def parse_result(row: dict[str, Any]) -> dict[str, str] | None:
    """Reduce one trufflehog result to what may be kept. The raw value is dropped here."""
    raw = row.get("Raw")
    detector = row.get("DetectorName")
    if not isinstance(raw, str) or not raw or not isinstance(detector, str):
        return None
    meta: Any = row
    for key in ("SourceMetadata", "Data", "Github"):
        meta = meta.get(key) if isinstance(meta, dict) else None
    if not isinstance(meta, dict):
        return None
    repo = repo_name(str(meta.get("link") or ""), str(meta.get("repository") or ""))
    if not repo:
        return None  # a result that cannot be located is of no use to anyone
    return {
        "detector": detector[:80],
        "repo": repo,
        "file": str(meta.get("file") or "")[:300],
        "commit": str(meta.get("commit") or "")[:40],
        "line": str(meta.get("line") or ""),
        "committed": str(meta.get("timestamp") or "")[:10],
        "starts_with": secret_prefix(raw),
        "hash": secret_hash_prefix(raw),
        # Deliberately not kept: the raw value, the redacted form trufflehog
        # offers (it can show more than four characters), and the committer's email.
    }


@register
class GitHubSecrets(ScanModule):
    spec = ModuleSpec(
        name="github_secrets",
        title="Secrets in public code",
        category=Category.SECRETS,
        mode=ScanMode.PASSIVE,
        description="Credentials committed to the organisation's public repositories.",
        requires_binaries=("trufflehog",),
        optional_binaries=(_second_scanner.NAME,),
        requires_keys=("GITHUB_TOKEN",),
        requires_target=("github_org",),
        contacts=("GitHub (public repositories are downloaded and read)",),
        default_timeout_s=3600,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        org = validate_github_org(target.github_org or "")
        token = ctx.secret("GITHUB_TOKEN") or ""
        clone_dir = ctx.workdir / "trufflehog-clones"
        clone_dir.mkdir(mode=0o700, exist_ok=True)

        second: asyncio.Task[tuple[list[dict[str, str]], bool, str | None]] | None = None
        if ctx.tools.available(_second_scanner.NAME):
            second = asyncio.create_task(self._betterleaks(org, token, ctx))
        try:
            output = await run_tool(
                ctx,
                "trufflehog",
                [
                    "github",
                    f"--org={org}",
                    "--json",
                    "--no-verification",
                    "--no-update",
                    "--concurrency=4",
                    f"--clone-path={clone_dir}",
                ],
                # The token goes in the environment: arguments are visible to other users.
                env={"GITHUB_TOKEN": token},
                timeout_s=3500,
                ok_returncodes=(0, 183),
            )
        except BaseException:
            if second is not None:
                second.cancel()
                with contextlib.suppress(BaseException):
                    await second
            raise

        # Keyed on where the credential is and what it is, not on which rule
        # matched: the two scanners name their rules differently.
        seen: dict[tuple[str, str, str], dict[str, str]] = {}
        found_by: dict[tuple[str, str, str], set[str]] = {}
        counts = {"trufflehog": 0}

        def merge(item: dict[str, str], scanner: str) -> None:
            key = (item["repo"].lower(), item["file"], item["hash"])
            seen.setdefault(key, item)
            if scanner not in found_by.setdefault(key, set()):
                found_by[key].add(scanner)
                counts[scanner] = counts.get(scanner, 0) + 1

        for row in output.json_lines():
            item = parse_result(row)
            if item is not None:
                merge(item, "trufflehog")

        notes = []
        incomplete = False
        if second is None:
            notes.append(
                "Betterleaks is not installed, so one scanner was used instead of two. "
                "Run 'parapet tools install betterleaks' for wider coverage."
            )
        else:
            items, incomplete, problem = await second
            counts[_second_scanner.NAME] = 0
            for item in items:
                merge(item, _second_scanner.NAME)
            if problem:
                notes.append(problem)

        findings: list[Finding] = []
        for key, item in list(seen.items())[:MAX_FINDINGS]:
            findings.append(
                self.finding(
                    "secrets.exposed",
                    AssetType.REPOSITORY,
                    item["repo"],
                    f"{item['detector']} credential in {item['repo']}",
                    identity={
                        "detector": item["detector"],
                        "file": item["file"],
                        "commit": item["commit"],
                        "hash": item["hash"],
                    },
                    evidence={
                        "type": item["detector"],
                        "file": item["file"],
                        "line": item["line"],
                        "commit": item["commit"][:12],
                        "committed": item["committed"],
                        "starts_with": item["starts_with"],
                        "tested": "no",
                        "found_by": sorted(found_by[key]),
                    },
                    confidence=Confidence.LIKELY,
                    sensitivity=Sensitivity.SECRET,
                )
            )
        truncated = output.truncated or len(seen) > MAX_FINDINGS
        if truncated:
            notes.append(f"More than {MAX_FINDINGS} results were found. The list is cut short.")
        notes.append(
            "Found credentials were not tested, so some may already be revoked or be examples."
        )
        return self.result(
            ModuleStatus.PARTIAL if truncated or incomplete else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats={"credentials": len(seen), **{f"from_{k}": v for k, v in counts.items()}},
        )

    async def _betterleaks(
        self, org: str, token: str, ctx: ScanContext
    ) -> tuple[list[dict[str, str]], bool, str | None]:
        """What Betterleaks found, whether it fell short, and a note if it did.

        It is optional, so its failure is reported and never stops the module.
        """
        scratch = ctx.workdir / "betterleaks-tmp"
        try:
            scratch.mkdir(mode=0o700, exist_ok=True)
            output = await run_tool(
                ctx,
                _second_scanner.NAME,
                _second_scanner.command(org),
                env=_second_scanner.environment(token, scratch),
                timeout_s=3500,
                ok_returncodes=_second_scanner.OK_RETURNCODES,
            )
        except Exception as exc:
            return [], True, f"Betterleaks failed ({type(exc).__name__}). trufflehog ran alone."
        items = []
        rows = 0
        for row in _second_scanner.parse_report(output.stdout):
            rows += 1
            item = _second_scanner.parse_finding(row)
            if item is not None:
                items.append(item)
        if output.returncode != 0 or output.truncated or rows >= _second_scanner.MAX_ROWS:
            return items, True, "Betterleaks did not finish, so its results may be incomplete."
        return items, False, None
