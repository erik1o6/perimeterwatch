"""Find the organisation's hostnames from public records. Sends nothing to the target."""

from __future__ import annotations

from perimeterwatch.clients import crtsh
from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.errors import ValidationError
from perimeterwatch.core.models import (
    AssetType,
    Category,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Target,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register
from perimeterwatch.safety.domains import validate_hostname

MAX_NAMES = 5000


def clean_names(raw: list[str], ctx: ScanContext) -> tuple[set[str], int]:
    """In-scope, valid hostnames. Returns the names and how many were wildcards."""
    names: set[str] = set()
    wildcards = 0
    for value in raw:
        name = value.strip().lower().rstrip(".")
        if name.startswith("*."):
            wildcards += 1
            name = name[2:]
        if "@" in name or not ctx.in_scope(name):
            continue
        try:
            names.add(validate_hostname(name, allow_reserved=True))
        except ValidationError:
            continue
    return names, wildcards


@register
class Subdomains(ScanModule):
    spec = ModuleSpec(
        name="subdomains",
        title="Subdomain discovery",
        category=Category.SURFACE,
        mode=ScanMode.PASSIVE,
        description="Hostnames seen in certificate transparency logs and passive DNS sources.",
        optional_binaries=("subfinder",),
        optional_keys=(
            "VIRUSTOTAL_API_KEY",
            "SECURITYTRAILS_API_KEY",
            "CERTSPOTTER_API_KEY",
            "CHAOS_API_KEY",
            "GITHUB_TOKEN",
        ),
        contacts=("crt.sh (certificate transparency)", "subfinder passive sources"),
        default_timeout_s=420,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        root = target.root_domain
        sources: dict[str, set[str]] = {}
        notes: list[str] = []
        failed = 0

        try:
            entries = await crtsh.search(ctx, f"%.{root}", namespace="subdomains")
        except crtsh.CrtShUnavailable as exc:
            failed += 1
            notes.append(f"crt.sh was unavailable ({exc}). Results may be incomplete.")
        else:
            names, wildcards = clean_names([n for e in entries for n in e.names], ctx)
            sources["crt.sh"] = names
            if wildcards:
                notes.append(f"{wildcards} wildcard certificate names were seen.")

        if ctx.tools.available("subfinder"):
            from perimeterwatch.modules._subfinder import held_back, run_subfinder

            for source in held_back(ctx):
                notes.append(
                    f"The key for {source} was not used. Its free plan does not allow use in "
                    "a service for other organisations. If your plan does, name it in "
                    "PW_LICENSED_SOURCES."
                )

            try:
                found = await run_subfinder(root, ctx)
            except Exception as exc:
                failed += 1
                notes.append(f"subfinder failed ({type(exc).__name__}).")
            else:
                sources["subfinder"], _ = clean_names(found, ctx)
        else:
            notes.append(
                "subfinder is not installed, so only certificate transparency was searched. "
                "Run 'pwatch tools install subfinder' for wider coverage."
            )

        if not sources:
            return self.result(
                ModuleStatus.FAILED, skip_reason="no discovery source answered", notes=notes
            )

        by_name: dict[str, list[str]] = {}
        for source, names in sources.items():
            for name in names:
                by_name.setdefault(name, []).append(source)
        by_name.setdefault(root, [])

        truncated = len(by_name) > MAX_NAMES
        selected = sorted(by_name, key=lambda n: (n.count("."), n))[:MAX_NAMES]
        if truncated:
            notes.append(
                f"{len(by_name)} names were found. Only the first {MAX_NAMES} are analysed."
            )

        assets = [
            self.asset(
                AssetType.DOMAIN if name == root else AssetType.SUBDOMAIN,
                name,
                attributes={"sources": sorted(by_name[name])},
            )
            for name in selected
        ]
        status = ModuleStatus.PARTIAL if failed or truncated else ModuleStatus.OK
        return self.result(
            status,
            assets=assets,
            notes=notes,
            stats={"names": len(assets), **{f"from_{k}": len(v) for k, v in sources.items()}},
        )
