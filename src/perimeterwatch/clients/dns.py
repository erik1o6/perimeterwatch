"""Async DNS lookups with bounded concurrency and explicit outcomes."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import StrEnum

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

PUBLIC_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")


class DnsStatus(StrEnum):
    OK = "ok"
    NXDOMAIN = "nxdomain"
    NODATA = "nodata"
    ERROR = "error"


@dataclass(frozen=True)
class DnsAnswer:
    name: str
    rdtype: str
    status: DnsStatus
    records: tuple[str, ...] = field(default_factory=tuple)
    # Canonical name the answer came from, when an alias was followed.
    canonical: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is DnsStatus.OK and bool(self.records)


def _text(rdata: object) -> str:
    strings = getattr(rdata, "strings", None)
    if strings is not None:
        return "".join(part.decode("utf-8", "replace") for part in strings)
    return str(rdata).rstrip(".")


class DnsClient:
    def __init__(
        self,
        *,
        nameservers: tuple[str, ...] = PUBLIC_RESOLVERS,
        timeout_s: float = 4.0,
        concurrency: int = 40,
    ) -> None:
        self._resolver = dns.asyncresolver.Resolver(configure=False)
        self._resolver.nameservers = list(nameservers)
        self._resolver.timeout = timeout_s
        self._resolver.lifetime = timeout_s * 2
        self._sem = asyncio.Semaphore(concurrency)
        self.queries = 0

    async def query(self, name: str, rdtype: str, *, retries: int = 1) -> DnsAnswer:
        name = name.rstrip(".")
        last_error = "unknown error"
        for attempt in range(retries + 1):
            async with self._sem:
                self.queries += 1
                try:
                    answer = await self._resolver.resolve(
                        name, rdtype, raise_on_no_answer=True, search=False
                    )
                except dns.resolver.NXDOMAIN:
                    return DnsAnswer(name, rdtype, DnsStatus.NXDOMAIN)
                except dns.resolver.NoAnswer:
                    return DnsAnswer(name, rdtype, DnsStatus.NODATA)
                except (dns.exception.DNSException, OSError) as exc:
                    last_error = type(exc).__name__
                else:
                    canonical = str(answer.canonical_name).rstrip(".").lower()
                    return DnsAnswer(
                        name,
                        rdtype,
                        DnsStatus.OK,
                        tuple(sorted(_text(r) for r in answer)),
                        canonical if canonical != name.lower() else None,
                    )
            if attempt < retries:
                await asyncio.sleep(0.3 * (attempt + 1))
        return DnsAnswer(name, rdtype, DnsStatus.ERROR, error=last_error)

    async def addresses(self, name: str) -> tuple[list[str], DnsStatus]:
        """A and AAAA records. Status is the most informative of the two lookups."""
        a, aaaa = await asyncio.gather(self.query(name, "A"), self.query(name, "AAAA"))
        ips = sorted(set(a.records) | set(aaaa.records))
        if ips:
            return ips, DnsStatus.OK
        for status in (DnsStatus.NXDOMAIN, DnsStatus.ERROR):
            if status in (a.status, aaaa.status):
                return [], status
        return [], DnsStatus.NODATA

    async def exists(self, name: str) -> bool:
        """True unless the name is NXDOMAIN. A name with no A record still exists."""
        answer = await self.query(name, "A")
        return answer.status is not DnsStatus.NXDOMAIN
