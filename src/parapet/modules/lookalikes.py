"""Domains that imitate the organisation's name.

Only DNS and certificate transparency are consulted. Lookalike domains are
never contacted: no web requests, no mail server connections.
"""

from __future__ import annotations

import asyncio
from typing import Any

import dnstwist

from parapet.clients import crtsh
from parapet.clients.dns import DnsStatus
from parapet.core.context import ScanContext
from parapet.core.errors import ValidationError
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
from parapet.core.module import ModuleSpec, ScanModule, register
from parapet.safety.domains import registrable_domain, validate_hostname

MIN_BRAND_LENGTH_FOR_CT = 6
MAX_CT_FINDINGS = 50

_PRIORITY = {
    name: rank
    for rank, name in enumerate(
        (
            "homoglyph",
            "omission",
            "transposition",
            "repetition",
            "replacement",
            "hyphenation",
            "addition",
            "insertion",
            "vowel-swap",
            "plural",
            "tld-swap",
            "dictionary",
            "bitsquatting",
            "cyrillic",
            "various",
        )
    )
}


def permutations(domain: str, limit: int) -> tuple[list[dict[str, str]], int]:
    """Candidate lookalike names. Returns the capped list and the uncapped count."""
    fuzzer = dnstwist.Fuzzer(domain)
    fuzzer.generate()
    seen: dict[str, str] = {}
    for entry in fuzzer.domains:
        name = str(entry.get("domain", "")).lower()
        kind = str(entry.get("fuzzer", ""))
        if not name or name == domain or kind.startswith("*"):
            continue
        try:
            name = validate_hostname(name, allow_reserved=True)
            # Keep only names someone could register. A variation such as
            # "my.project.xyz" is a subdomain of an unrelated domain.
            if registrable_domain(name) != name:
                continue
        except ValidationError:
            continue
        seen.setdefault(name, kind)
    # Fixed order, so that a capped list holds the same names on every scan.
    # The techniques most used in real phishing come first.
    items = sorted(
        ({"domain": d, "fuzzer": f} for d, f in seen.items()),
        key=lambda i: (_PRIORITY.get(i["fuzzer"], len(_PRIORITY)), i["domain"]),
    )
    return items[:limit], len(items)


def display_name(domain: str) -> str:
    """Unicode form of an internationalised name, for showing next to the encoded form."""
    try:
        return domain.encode("ascii").decode("idna")
    except UnicodeError:
        return domain


@register
class Lookalikes(ScanModule):
    spec = ModuleSpec(
        name="lookalikes",
        title="Lookalike domains",
        category=Category.LOOKALIKE,
        mode=ScanMode.PASSIVE,
        description="Registered domains that resemble yours, and certificates using your name.",
        contacts=("public DNS resolvers", "crt.sh (certificate transparency)"),
        default_timeout_s=900,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        domain = registrable_domain(target.root_domain)
        candidates, total = permutations(domain, ctx.settings.lookalike_max_permutations)
        notes: list[str] = []
        if total > len(candidates):
            notes.append(f"{total} variations exist. The first {len(candidates)} were checked.")

        checked = await asyncio.gather(*(self._check(c, ctx) for c in candidates))
        errors = sum(1 for c in checked if c is not None and c.get("error"))
        registered = [c for c in checked if c is not None and not c.get("error")]

        assets: list[Asset] = []
        findings: list[Finding] = []
        for item in registered:
            name = item["domain"]
            mail = bool(item["mx"])
            assets.append(
                self.asset(
                    AssetType.LOOKALIKE_DOMAIN,
                    name,
                    attributes={
                        "display": display_name(name),
                        "technique": item["fuzzer"],
                        "ips": item["ips"][:4],
                        "mx": item["mx"][:4],
                    },
                    state={"mail_capable": mail, "has_address": bool(item["ips"])},
                )
            )
            findings.append(
                self.finding(
                    "lookalike.mail_capable" if mail else "lookalike.registered",
                    AssetType.LOOKALIKE_DOMAIN,
                    name,
                    f"{display_name(name)} is registered"
                    + (" and can receive mail" if mail else ""),
                    state={"has_address": bool(item["ips"])},
                    evidence={
                        "domain": name,
                        "shown_as": display_name(name),
                        "technique": item["fuzzer"],
                        "has_web_address": bool(item["ips"]),
                        "mail_servers": item["mx"][:4],
                    },
                    confidence=Confidence.LIKELY,
                )
            )

        ct_findings, ct_note = await self._certificates(domain, ctx, {a.key for a in assets})
        findings.extend(ct_findings)
        if ct_note:
            notes.append(ct_note)

        status = ModuleStatus.OK
        if errors > max(5, len(candidates) // 10):
            status = ModuleStatus.PARTIAL
            notes.append(f"{errors} variations could not be checked because of DNS errors.")
        return self.result(
            status,
            assets=assets,
            findings=findings,
            notes=notes,
            stats={
                "variations_checked": len(candidates),
                "registered": len(registered),
                "mail_capable": sum(1 for r in registered if r["mx"]),
                "certificate_matches": len(ct_findings),
            },
        )

    async def _check(self, candidate: dict[str, str], ctx: ScanContext) -> dict[str, Any] | None:
        name = candidate["domain"]
        # NS is the best sign of registration: parked names often have no address.
        ns = await ctx.dns.query(name, "NS", retries=0)
        if ns.status is DnsStatus.NXDOMAIN:
            return None
        if ns.status is DnsStatus.ERROR:
            return {**candidate, "error": True}
        ips, _ = await ctx.dns.addresses(name)
        mx = await ctx.dns.query(name, "MX", retries=0)
        mail_hosts = [
            host
            for host in (r.split()[-1].rstrip(".").lower() for r in mx.records)
            if host  # "0 ." is a null MX: the domain declares it takes no mail
        ]
        if not ns.ok and not ips and not mail_hosts:
            return None
        return {**candidate, "ips": ips, "mx": mail_hosts}

    async def _certificates(
        self, domain: str, ctx: ScanContext, known: set[str]
    ) -> tuple[list[Finding], str | None]:
        brand = domain.split(".")[0]
        if len(brand) < MIN_BRAND_LENGTH_FOR_CT:
            return [], (
                f"Certificate search for the name '{brand}' was skipped: it is too short to "
                "search for without a flood of unrelated matches."
            )
        try:
            entries = await crtsh.search(ctx, f"%{brand}%", namespace="brand", exclude_expired=True)
        except crtsh.CrtShUnavailable:
            return [], "Certificate search for your name was unavailable this time."

        matches: dict[str, dict[str, Any]] = {}
        for entry in entries:
            for raw in entry.names:
                name = raw.removeprefix("*.")
                if ctx.in_scope(name) or name.endswith("." + domain) or name == domain:
                    continue
                try:
                    name = validate_hostname(name, allow_reserved=True)
                    owner = registrable_domain(name)
                except ValidationError:
                    continue
                # Only names where the brand is part of what was registered or
                # a label of its own, not an accidental substring of a long word.
                labels = name.split(".")
                if brand not in owner.split(".")[0] and brand not in labels:
                    continue
                matches.setdefault(
                    owner,
                    {"names": set(), "issuer": entry.issuer, "not_before": entry.not_before},
                )["names"].add(name)

        findings = []
        for owner, info in sorted(matches.items())[:MAX_CT_FINDINGS]:
            names = sorted(info["names"])
            findings.append(
                self.finding(
                    "lookalike.certificate_issued",
                    AssetType.LOOKALIKE_DOMAIN,
                    owner,
                    f"A certificate using your name was issued for {display_name(owner)}",
                    evidence={
                        "names": names[:10],
                        "issued": info["not_before"],
                        "also_a_registered_variation": owner in known,
                    },
                    confidence=Confidence.CANDIDATE,
                    severity_steps=-1 if owner not in known else 0,
                    severity_note=None
                    if owner in known
                    else "Name match only. Many such domains are unrelated businesses.",
                )
            )
        note = None
        if len(matches) > MAX_CT_FINDINGS:
            note = f"{len(matches)} domains hold certificates with your name. {MAX_CT_FINDINGS} are listed."
        return findings, note
