"""What the organisation's public GitHub presence reveals. Public API data only."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from perimeterwatch.clients import github
from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.models import (
    Asset,
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Target,
    utcnow,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register

STALE_AFTER = timedelta(days=730)
MAX_STALE_FINDINGS = 25


@register
class GitHubOrg(ScanModule):
    spec = ModuleSpec(
        name="github_org",
        title="GitHub organisation",
        category=Category.WEB3,
        mode=ScanMode.PASSIVE,
        description="Public repositories and organisation settings visible on GitHub.",
        requires_target=("github_org",),
        optional_keys=("GITHUB_TOKEN",),
        contacts=("GitHub API",),
        default_timeout_s=180,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        org = target.github_org
        assert org is not None
        try:
            profile = await github.get(ctx, f"/orgs/{org}")
            repos, more = await github.get_pages(
                ctx, f"/orgs/{org}/repos", {"type": "public", "sort": "pushed"}
            )
        except github.GitHubNotFound:
            return self.result(
                ModuleStatus.FAILED, skip_reason=f"GitHub has no organisation named {org}"
            )
        except github.GitHubError as exc:
            return self.result(ModuleStatus.FAILED, skip_reason=str(exc))

        notes = ["Only the 500 most recently updated repositories were read."] if more else []
        findings: list[Finding] = []
        assets: list[Asset] = [
            self.asset(
                AssetType.GITHUB_ORG,
                org,
                attributes={
                    "public_repos": profile.get("public_repos"),
                    "verified": bool(profile.get("is_verified")),
                    "website": str(profile.get("blog") or "")[:200],
                },
                state={"verified": bool(profile.get("is_verified"))},
            )
        ]

        # Only present when the token belongs to an owner of the organisation.
        two_factor = profile.get("two_factor_requirement_enabled")
        if two_factor is False:
            findings.append(
                self.finding(
                    "github.org.two_factor_not_required",
                    AssetType.GITHUB_ORG,
                    org,
                    f"GitHub organisation {org} does not require two-factor sign-in",
                    confidence=Confidence.CONFIRMED,
                )
            )
        elif two_factor is None:
            notes.append(
                "Whether two-factor sign-in is required could not be read. GitHub shows this "
                "only to a token belonging to an owner of the organisation."
            )

        now = utcnow()
        stale = [r for r in repos if self._is_stale(r, now)]
        for repo in stale[:MAX_STALE_FINDINGS]:
            name = str(repo.get("full_name", ""))[:200]
            findings.append(
                self.finding(
                    "github.repo.stale_public",
                    AssetType.REPOSITORY,
                    name,
                    f"Public repository {name} has not been updated in over two years",
                    evidence={"last_push": str(repo.get("pushed_at", ""))[:10]},
                    confidence=Confidence.CONFIRMED,
                )
            )
        for repo in repos:
            if not repo.get("archived") and not repo.get("fork"):
                assets.append(
                    self.asset(
                        AssetType.REPOSITORY,
                        str(repo.get("full_name", ""))[:200],
                        attributes={
                            # Asset keys are lower-cased. Some services need the real spelling.
                            "full_name": str(repo.get("full_name", ""))[:200],
                            "last_push": str(repo.get("pushed_at", ""))[:10],
                            "language": str(repo.get("language") or ""),
                        },
                    )
                )
        return self.result(
            ModuleStatus.PARTIAL if more else ModuleStatus.OK,
            assets=assets,
            findings=findings,
            notes=notes,
            stats={"public_repos": len(repos), "stale": len(stale)},
        )

    @staticmethod
    def _is_stale(repo: dict[str, Any], now: datetime) -> bool:
        if repo.get("archived") or repo.get("fork"):
            return False
        try:
            pushed = datetime.fromisoformat(str(repo.get("pushed_at")).replace("Z", "+00:00"))
        except ValueError:
            return False
        return now - pushed > STALE_AFTER
