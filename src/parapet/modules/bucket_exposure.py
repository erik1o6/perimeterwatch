"""Storage buckets your own DNS points at. Active: needs authorisation.

Bucket names are taken only from DNS records the organisation itself
published. Names are never guessed: a guessed name may belong to someone else.
Each bucket is asked what an anonymous visitor may do. Its contents are never
listed, and nothing is ever written.
"""

from __future__ import annotations

import re
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
    Target,
)
from parapet.core.module import ModuleSpec, ScanModule, register
from parapet.safety.subprocess import run_tool

ALLOWED = 1  # the tool's value for "permission granted"
MAX_BUCKETS = 50
# Options that would list contents or send results elsewhere. Never passed.
FORBIDDEN = ("-enumerate", "-db", "-mq")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_AWS = re.compile(r"^(?P<bucket>.+?)\.s3(?:-website)?(?:[.-][a-z0-9-]+)?\.amazonaws\.com$")
_SPACES = re.compile(r"^(?P<bucket>.+?)\.[a-z0-9]+\.(?:cdn\.)?digitaloceanspaces\.com$")
GCS_TARGETS = ("c.storage.googleapis.com",)


def valid_bucket(name: str) -> bool:
    return bool(_BUCKET.match(name)) and ".." not in name and not name.startswith("xn--")


def bucket_from(host: str, cname: str) -> tuple[str, str] | None:
    """(provider, bucket) if this alias points at a storage bucket."""
    target = cname.lower().rstrip(".")
    found: tuple[str, str] | None = None
    if match := _AWS.match(target):
        found = ("aws", match.group("bucket"))
    elif match := _SPACES.match(target):
        found = ("digitalocean", match.group("bucket"))
    elif target in GCS_TARGETS:
        # Google serves the bucket named after the host that points at it.
        found = ("gcp", host.lower())
    elif target.endswith(".storage.googleapis.com"):
        found = ("gcp", target.removesuffix(".storage.googleapis.com"))
    return found if found and valid_bucket(found[1]) else None


@register
class BucketExposure(ScanModule):
    spec = ModuleSpec(
        name="bucket_exposure",
        title="Public storage buckets",
        category=Category.VULN,
        mode=ScanMode.ACTIVE,
        description="Storage buckets your DNS points at that anyone can list or write to.",
        requires_binaries=("s3scanner",),
        depends_on=("dns_resolve",),
        contacts=("the storage provider, asking what an anonymous visitor may do",),
        default_timeout_s=600,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        resolved = ctx.assets.get("dns_resolve")
        if resolved is None or not ctx.assets.completed("dns_resolve"):
            return self.result(ModuleStatus.FAILED, skip_reason="DNS resolution did not complete")

        buckets: dict[tuple[str, str], list[str]] = {}
        for asset in resolved.assets:
            cname = asset.state.get("cname")
            if not cname or not ctx.in_scope(asset.key):
                continue
            found = bucket_from(asset.key, str(cname))
            if found:
                buckets.setdefault(found, []).append(asset.key)
        if not buckets:
            return self.result(notes=["None of your DNS names points at a storage bucket."])

        truncated = len(buckets) > MAX_BUCKETS
        findings: list[Finding] = []
        checked = 0
        for provider in sorted({p for p, _ in buckets}):
            names = sorted(b for p, b in buckets if p == provider)[:MAX_BUCKETS]
            listing = ctx.workdir / f"buckets-{provider}.txt"
            listing.write_text("\n".join(names) + "\n")
            output = await run_tool(
                ctx,
                "s3scanner",
                ["-bucket-file", str(listing), "-provider", provider, "-json", "-threads", "2"],
                timeout_s=280,
            )
            for row in output.json_lines():
                bucket = row.get("bucket")
                if not isinstance(bucket, dict) or bucket.get("name") not in names:
                    continue
                checked += 1
                hosts = sorted(buckets[(provider, str(bucket["name"]))])[:10]
                findings.extend(self._assess(provider, bucket, hosts))
        return self.result(
            ModuleStatus.PARTIAL if truncated else ModuleStatus.OK,
            findings=findings,
            notes=[f"Only the first {MAX_BUCKETS} buckets were checked."] if truncated else [],
            stats={"buckets_found": len(buckets), "buckets_checked": checked},
        )

    def _assess(self, provider: str, bucket: dict[str, Any], hosts: list[str]) -> list[Finding]:
        name = str(bucket["name"])
        if bucket.get("exists") != 1:
            return []  # a missing bucket is reported by the dangling DNS check

        def allowed(*fields: str) -> list[str]:
            return [f for f in fields if bucket.get(f) == ALLOWED]

        findings = []
        for kind, fields, what in (
            ("cloud.bucket.public_write", ("perm_all_users_write", "perm_all_users_full_control"),
             "lets anyone write to it"),
            ("cloud.bucket.public_read", ("perm_all_users_read",), "lets anyone list its contents"),
            ("cloud.bucket.public_acl", ("perm_all_users_read_acl", "perm_all_users_write_acl"),
             "lets anyone read or change its access settings"),
        ):  # fmt: skip
            granted = allowed(*fields)
            if granted:
                findings.append(
                    self.finding(
                        kind,
                        AssetType.SERVICE,
                        f"{provider}:{name}",
                        f"Storage bucket {name} {what}",
                        state={"permissions": granted},
                        evidence={
                            "bucket": name,
                            "provider": provider,
                            "pointed_at_by": hosts,
                            "open_to_anyone": [g.removeprefix("perm_all_users_") for g in granted],
                            "contents_listed": "no",
                        },
                        confidence=Confidence.CONFIRMED,
                    )
                )
        return findings
