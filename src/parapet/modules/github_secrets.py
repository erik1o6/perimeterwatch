"""Credentials committed to the organisation's public repositories.

Two rules hold throughout:
- A credential is never stored or shown. Only its type, location, first four
  characters and a short hash are kept.
- A credential is never tested. trufflehog can try to log in with what it finds
  in order to confirm it is live; that is switched off.
"""

from __future__ import annotations

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

        seen: dict[tuple[str, ...], dict[str, str]] = {}
        for row in output.json_lines():
            item = parse_result(row)
            if item is None:
                continue
            seen.setdefault((item["detector"], item["repo"], item["file"], item["hash"]), item)

        findings: list[Finding] = []
        for item in list(seen.values())[:MAX_FINDINGS]:
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
                    },
                    confidence=Confidence.LIKELY,
                    sensitivity=Sensitivity.SECRET,
                )
            )
        notes = []
        truncated = output.truncated or len(seen) > MAX_FINDINGS
        if truncated:
            notes.append(f"More than {MAX_FINDINGS} results were found. The list is cut short.")
        notes.append(
            "Found credentials were not tested, so some may already be revoked or be examples."
        )
        return self.result(
            ModuleStatus.PARTIAL if truncated else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats={"credentials": len(seen)},
        )
