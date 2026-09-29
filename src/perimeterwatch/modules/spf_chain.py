"""Domains your SPF record trusts that no longer exist.

An SPF record names other domains whose servers may send mail for you. If one
of those domains has lapsed, whoever registers it next can send mail as you
and pass the check. This module follows the record the way a receiving mail
server does, through DNS alone, and reports every named domain that is gone.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from perimeterwatch.clients.dns import DnsStatus
from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.errors import ValidationError
from perimeterwatch.core.models import (
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Target,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register
from perimeterwatch.safety.domains import registrable_domain, validate_hostname

# RFC 7208 section 4.6.4: a receiver gives up after ten terms that need a lookup.
MAX_LOOKUPS = 10
MAX_RECORD_LENGTH = 4096
MAX_TERMS = 100
MAX_NOTES = 20

# Mechanisms that make a receiver look something up, and the record type asked for.
_LOOKUP_TYPES = {"include": "TXT", "redirect": "TXT", "a": "A", "mx": "MX", "exists": "A"}
_RECURSIVE = ("include", "redirect")


@dataclass(frozen=True)
class Term:
    mechanism: str  # include, redirect, a, mx, exists or ptr
    domain: str | None  # None when the term refers to the domain holding the record
    macro: bool = False
    invalid: bool = False


@dataclass
class Walk:
    """What has been seen so far while following one SPF record."""

    lookups: int = 0
    over_limit: bool = False
    dns_errors: int = 0
    visited: set[str] = field(default_factory=set)
    checked: set[str] = field(default_factory=set)
    findings: dict[str, Finding] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def note(self, text: str) -> None:
        if text not in self.notes and len(self.notes) < MAX_NOTES:
            self.notes.append(text)


def spf_records(txt_records: tuple[str, ...]) -> list[str]:
    out = []
    for record in txt_records:
        text = record.strip().strip('"')
        lowered = text.lower()
        if lowered == "v=spf1" or lowered.startswith("v=spf1 "):
            out.append(text[:MAX_RECORD_LENGTH])
    return out


def parse_terms(record: str) -> list[Term]:
    """The terms of an SPF record that make a receiver look something up."""
    terms: list[Term] = []
    for raw in record.split()[1 : MAX_TERMS + 1]:
        word = raw.lstrip("+-~?")
        lowered = word.lower()
        if lowered.startswith("redirect="):
            mechanism, value = "redirect", word[len("redirect=") :]
        else:
            name, sep, rest = word.partition(":")
            if not sep:
                # "a", "mx/24" and "ptr" refer to the domain holding the record.
                name = name.partition("/")[0]
            mechanism = name.lower()
            value = rest
        if mechanism not in _LOOKUP_TYPES and mechanism != "ptr":
            continue
        if not value:
            terms.append(Term(mechanism, None))
            continue
        if "%" in value:
            terms.append(Term(mechanism, None, macro=True))
            continue
        try:
            domain = validate_hostname(value.partition("/")[0], allow_reserved=True)
        except ValidationError:
            terms.append(Term(mechanism, None, invalid=True))
            continue
        terms.append(Term(mechanism, domain))
    return terms


@register
class SpfChain(ScanModule):
    spec = ModuleSpec(
        name="spf_chain",
        title="Domains trusted by your SPF record",
        category=Category.EMAIL,
        mode=ScanMode.PASSIVE,
        description="Domains your SPF record allows to send mail for you that no longer exist.",
        contacts=("public DNS resolvers",),
        default_timeout_s=180,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        domain = target.root_domain
        answer = await ctx.dns.query(domain, "TXT")
        if answer.status is DnsStatus.ERROR:
            return self.result(
                ModuleStatus.FAILED,
                skip_reason="the SPF record could not be looked up because of a DNS error",
            )
        records = spf_records(answer.records)
        if not records:
            return self.result(
                notes=[f"{domain} has no SPF record, so there is nothing to follow."],
                stats={"domains_checked": 0, "lookups": 0, "missing": 0},
            )
        if len(records) > 1:
            return self.result(
                notes=[
                    f"{domain} has {len(records)} SPF records. Mail servers reject that "
                    "outright, so none of them was followed."
                ],
                stats={"domains_checked": 0, "lookups": 0, "missing": 0},
            )

        walk = Walk(visited={domain})
        await self._follow(records[0], domain, (domain,), walk, ctx)

        incomplete = walk.over_limit or walk.dns_errors > 0
        if walk.over_limit:
            walk.note(
                f"The record needs more than {MAX_LOOKUPS} lookups, the most a mail server "
                "will make. The parts beyond that limit were not checked."
            )
        if walk.dns_errors:
            walk.note(
                f"{walk.dns_errors} lookups failed because of DNS errors, so some domains "
                "could not be checked. A failed lookup is never counted as a missing domain."
            )
        return self.result(
            ModuleStatus.PARTIAL if incomplete else ModuleStatus.OK,
            findings=[walk.findings[name] for name in sorted(walk.findings)],
            notes=walk.notes,
            stats={
                "domains_checked": len(walk.checked),
                "lookups": walk.lookups,
                "missing": len(walk.findings),
            },
        )

    async def _follow(
        self, record: str, holder: str, chain: tuple[str, ...], walk: Walk, ctx: ScanContext
    ) -> None:
        for term in parse_terms(record):
            if walk.lookups >= MAX_LOOKUPS:
                walk.over_limit = True
                return
            walk.lookups += 1
            if term.macro:
                walk.note(
                    f"The record of {holder} has a '{term.mechanism}' term built from a macro, "
                    "which is filled in per message. It cannot be checked from outside and "
                    "was skipped."
                )
                continue
            if term.invalid:
                walk.note(
                    f"The record of {holder} has a '{term.mechanism}' term that does not name "
                    "a valid domain. It was skipped."
                )
                continue
            if term.domain is None or term.domain == holder or term.mechanism == "ptr":
                continue

            name = term.domain
            first_visit = name not in walk.checked
            walk.checked.add(name)
            answer = await ctx.dns.query(name, _LOOKUP_TYPES[term.mechanism])
            if answer.status is DnsStatus.ERROR:
                walk.dns_errors += 1
                continue
            if answer.status is DnsStatus.NXDOMAIN:
                if first_visit and name not in walk.findings:
                    finding = await self._missing(term, holder, chain, walk, ctx)
                    if finding is not None:
                        walk.findings[name] = finding
                continue
            if term.mechanism not in _RECURSIVE or name in walk.visited:
                continue
            walk.visited.add(name)
            nested = spf_records(answer.records)
            if len(nested) == 1:
                await self._follow(nested[0], name, (*chain, name), walk, ctx)
                if walk.over_limit:
                    return

    async def _missing(
        self, term: Term, holder: str, chain: tuple[str, ...], walk: Walk, ctx: ScanContext
    ) -> Finding | None:
        name = term.domain
        assert name is not None
        root = chain[0]
        try:
            owner = registrable_domain(name)
        except ValidationError:
            walk.note(
                f"The record of {holder} names {name}, which is not under a recognised "
                "public ending. It was skipped."
            )
            return None
        parent = await ctx.dns.query(owner, "NS")
        if parent.status is DnsStatus.ERROR:
            walk.dns_errors += 1
            return None
        unregistered = parent.status is DnsStatus.NXDOMAIN
        if not unregistered and owner == name:
            walk.note(
                f"Lookups for {name} gave conflicting answers, so it was not reported as missing."
            )
            return None

        shown = f"{term.mechanism}{'=' if term.mechanism == 'redirect' else ':'}{name}"
        evidence = {
            "term": shown,
            "found_in_record_of": holder,
            "reached_through": list(chain),
            "missing_domain": name,
            "registrable_domain": owner,
            "registrable_domain_unregistered": unregistered,
            "who_could_claim_it": "anyone, by registering the domain"
            if unregistered
            else f"only whoever controls {owner}",
        }
        if unregistered:
            return self.finding(
                "email.spf.dangling_include",
                AssetType.DOMAIN,
                root,
                f"Your SPF record trusts {name}, and {owner} is not registered",
                identity={"domain": name},
                state={"registrable_domain_unregistered": True},
                evidence=evidence,
                confidence=Confidence.LIKELY,
                severity_steps=1,
                severity_note=f"{owner} appears unregistered, so anyone could register it "
                "and send mail as you.",
            )
        return self.finding(
            "email.spf.dangling_include",
            AssetType.DOMAIN,
            root,
            f"Your SPF record trusts {name}, which does not exist",
            identity={"domain": name},
            state={"registrable_domain_unregistered": False},
            evidence=evidence,
            confidence=Confidence.CANDIDATE,
        )
