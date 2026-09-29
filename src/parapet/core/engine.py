"""Run the selected modules against one target and record what they found."""

from __future__ import annotations

import asyncio
import shutil
import tempfile
import traceback
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

from parapet.clients.dns import DnsClient
from parapet.clients.http import make_client
from parapet.config import Settings
from parapet.core.context import ScanContext
from parapet.core.diff import ScanDiff, compute_diff
from parapet.core.errors import AuthorisationError, ValidationError
from parapet.core.fingerprint import (
    asset_fingerprint,
    asset_state_hash,
    finding_fingerprint,
    finding_state_hash,
)
from parapet.core.models import (
    AuthLevel,
    Authorisation,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    ScanSnapshot,
    Target,
    utcnow,
)
from parapet.core.module import ModuleSpec, ScanModule, all_modules, ordered, skipped
from parapet.logging import get_logger, scrub
from parapet.safety.ratelimit import RateLimiter
from parapet.storage.db import Database
from parapet.storage.repo import Cache, TenantRepo
from parapet.tools.locate import ToolLocator

ProgressFn = Callable[[str, ModuleResult | None], None]

_MODE_FLAG = {ScanMode.PROBE: "--probe", ScanMode.ACTIVE: "--active"}


class DbCache:
    """Cache backend that uses a short session per call."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def get(self, namespace: str, key: str) -> str | None:
        with self.database.session() as session:
            return Cache(session).get(namespace, key)

    def set(self, namespace: str, key: str, value: str, ttl: timedelta) -> None:
        with self.database.session() as session:
            Cache(session).set(namespace, key, value, ttl)


def check_mode_allowed(mode: ScanMode, authorisation: Authorisation, domain: str) -> None:
    """Refuse an active scan without authorisation. There is no override."""
    if mode is ScanMode.ACTIVE and authorisation.level.rank < AuthLevel.ACKNOWLEDGED.rank:
        raise AuthorisationError(
            f"Active scanning of {domain} needs authorisation, and none is on record.\n"
            f"  Prove control of the domain:  parapet verify init {domain}\n"
            f"  Or record an authorisation:   parapet authorise {domain}"
        )


def preflight(spec: ModuleSpec, target: Target, ctx: ScanContext) -> ModuleResult | None:
    """Return a skipped result when the module cannot or must not run."""
    if spec.mode.rank > ctx.mode_ceiling.rank:
        flag = _MODE_FLAG[spec.mode]
        return skipped(spec, f"{spec.mode.value} module, not requested", f"add {flag} to the scan")
    if spec.mode is ScanMode.ACTIVE and ctx.authorisation.level.rank < AuthLevel.ACKNOWLEDGED.rank:
        return skipped(spec, "requires authorisation", f"parapet verify init {ctx.root_domain}")
    if spec.requires_verification and not ctx.verified:
        return skipped(spec, "requires a verified domain", f"parapet verify init {ctx.root_domain}")
    for attr in spec.requires_target:
        if not getattr(target, attr, None):
            return skipped(
                spec,
                f"no {attr.replace('_', ' ')} configured for this target",
                f"parapet target add {ctx.root_domain} --help",
            )
    for binary in spec.requires_binaries:
        if not ctx.tools.available(binary):
            return skipped(spec, f"missing binary: {binary}", f"parapet tools install {binary}")
    if spec.any_of_binaries and not any(ctx.tools.available(b) for b in spec.any_of_binaries):
        names = " or ".join(spec.any_of_binaries)
        return skipped(
            spec, f"missing binary: {names}", f"parapet tools install {spec.any_of_binaries[0]}"
        )
    for key in spec.requires_keys:
        if not ctx.secret(key):
            return skipped(spec, f"missing key: {key}", f"set {key} in the environment or .env")
    return None


def select_modules(only: set[str] | None, skip: set[str] | None) -> list[type[ScanModule]]:
    registry = all_modules()
    unknown = ((only or set()) | (skip or set())) - set(registry)
    if unknown:
        raise ValidationError(
            f"Unknown module: {', '.join(sorted(unknown))}. See 'parapet modules list'."
        )
    modules = ordered(only)
    if skip:
        modules = [m for m in modules if m.spec.name not in skip]
    return modules


def _stamp(result: ModuleResult, root_domain: str, blind_key: bytes) -> None:
    for asset in result.assets:
        asset.source_module = asset.source_module or result.module
        asset.fingerprint = asset_fingerprint(root_domain, asset)
        asset.state_hash = asset_state_hash(asset)
        asset.facets = {result.module: asset.state_hash}
    for finding in result.findings:
        finding.module = finding.module or result.module
        finding.fingerprint = finding_fingerprint(root_domain, finding, blind_key)
        finding.state_hash = finding_state_hash(finding)


async def _run_module(
    module_cls: type[ScanModule], target: Target, ctx: ScanContext
) -> ModuleResult:
    spec = module_cls.spec
    blocked = preflight(spec, target, ctx)
    if blocked is not None:
        return blocked
    started = utcnow()
    log = ctx.log.bind(module=spec.name)
    try:
        result = await asyncio.wait_for(module_cls().run(target, ctx), spec.default_timeout_s)
    except TimeoutError:
        result = ModuleResult(
            module=spec.name,
            status=ModuleStatus.FAILED,
            skip_reason=f"timed out after {spec.default_timeout_s}s",
        )
    except Exception as exc:
        log.error("module failed", error=scrub(f"{type(exc).__name__}: {exc}"))
        log.debug("traceback", traceback=scrub(traceback.format_exc()))
        result = ModuleResult(
            module=spec.name,
            status=ModuleStatus.FAILED,
            skip_reason=scrub(f"{type(exc).__name__}: {exc}")[:300],
        )
    result.started_at = started
    result.finished_at = utcnow()
    return result


async def execute(
    target: Target,
    ctx: ScanContext,
    modules: list[type[ScanModule]],
    progress: ProgressFn | None = None,
) -> list[ModuleResult]:
    """Run modules concurrently, each waiting for the modules it depends on."""
    selected = {m.spec.name for m in modules}
    done = {name: asyncio.Event() for name in selected}
    limit = asyncio.Semaphore(max(1, ctx.settings.concurrency))
    results: dict[str, ModuleResult] = {}

    async def run_one(module_cls: type[ScanModule]) -> None:
        spec = module_cls.spec
        try:
            for dep in spec.depends_on:
                if dep in done:
                    await done[dep].wait()
            async with limit:
                if progress:
                    progress(spec.name, None)
                result = await _run_module(module_cls, target, ctx)
            _stamp(result, target.root_domain, ctx.blind_key)
            ctx.assets.add(result)
            results[spec.name] = result
            if progress:
                progress(spec.name, result)
        finally:
            done[spec.name].set()

    await asyncio.gather(*(run_one(m) for m in modules))
    return [results[m.spec.name] for m in modules if m.spec.name in results]


async def run_scan(
    target: Target,
    *,
    settings: Settings,
    database: Database,
    tenant_id: UUID,
    mode: ScanMode,
    authorisation: Authorisation,
    only: set[str] | None = None,
    skip: set[str] | None = None,
    requested_by: str = "cli",
    scan_id: UUID | None = None,
    progress: ProgressFn | None = None,
) -> tuple[ScanSnapshot, ScanDiff]:
    check_mode_allowed(mode, authorisation, target.root_domain)
    modules = select_modules(only, skip)
    scan_id = scan_id or uuid4()
    started = utcnow()

    with database.session() as session:
        repo = TenantRepo(session, tenant_id)
        target_row = repo.get_target(target.root_domain) or repo.upsert_target(target)
        target_id = target_row.id
        existing = repo.get_scan(scan_id)
        if existing is not None:
            # A queued scan: authorisation is recorded as it stands now, at the start.
            existing.auth_level = authorisation.level.value
            existing.auth_basis = authorisation.basis
        else:
            repo.create_scan(
                target_id,
                mode=mode,
                authorisation=authorisation,
                requested_by=requested_by,
                scan_id=scan_id,
                only=only,
                skip=skip,
            )

    workdir = Path(tempfile.mkdtemp(prefix="parapet-"))  # created with mode 0700
    tools = ToolLocator(settings.resolved_tools_dir, allow_path=settings.allow_path_tools)
    limiter = RateLimiter(settings.per_host_rps)
    limiter.set_limit("crt.sh", rps=1 / 15, burst=1)

    try:
        async with make_client(settings) as http:
            ctx = ScanContext(
                settings=settings,
                scan_id=scan_id,
                tenant_id=tenant_id,
                root_domain=target.root_domain,
                mode_ceiling=mode,
                authorisation=authorisation,
                http=http,
                dns=DnsClient(timeout_s=settings.dns_timeout_s),
                tools=tools,
                limiter=limiter,
                workdir=workdir,
                blind_key=database.keys.blind_key,
                log=get_logger("scan").bind(scan=str(scan_id)[:8], domain=target.root_domain),
                cache=DbCache(database),
            )
            results = await execute(target, ctx, modules, progress)
    except BaseException as exc:
        with database.session() as session:
            repo = TenantRepo(session, tenant_id)
            scan = repo.get_scan(scan_id)
            if scan is not None:
                repo.fail_scan(scan, scrub(f"{type(exc).__name__}: {exc}"))
        raise
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    used = {
        b
        for m in modules
        for b in (*m.spec.requires_binaries, *m.spec.any_of_binaries, *m.spec.optional_binaries)
    }
    snapshot = ScanSnapshot(
        scan_id=scan_id,
        # Staff addresses are input, not output. They stay out of snapshots and reports.
        target=target.model_copy(update={"staff_emails": []}),
        mode=mode,
        authorisation=authorisation,
        started_at=started,
        finished_at=utcnow(),
        modules=results,
        tool_versions={b: v for b in sorted(used) if (v := tools.version(b))},
    )

    with database.session() as session:
        repo = TenantRepo(session, tenant_id)
        scan = repo.get_scan(scan_id)
        if scan is None:
            raise RuntimeError("Scan record disappeared while the scan was running.")
        previous = repo.previous_scan(scan)
        previous_snapshot = repo.load_snapshot(previous) if previous else None
        diff = compute_diff(previous_snapshot, snapshot)
        repo.save_results(scan, snapshot)
        repo.apply_diff(scan, snapshot, diff)
        repo.audit(
            "scan.completed",
            actor=requested_by,
            object_type="scan",
            object_id=str(scan_id),
            meta={"mode": mode.value, "auth_level": authorisation.level.value},
        )
    return snapshot, diff
