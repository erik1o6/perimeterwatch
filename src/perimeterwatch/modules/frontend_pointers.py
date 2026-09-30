"""Where the organisation's website content is said to live, when it is served from IPFS.

Two records can name that content: the contenthash of an ENS name, and a
DNSLink TXT record. Whoever changes either one replaces the website. This
module records what each points to, so that a change is noticed.

Only the pointers are read. The content itself is never fetched, from a
gateway or from anywhere else. The ENS part makes read-only calls to the RPC
endpoint; the DNSLink part makes DNS lookups and needs no key.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass
from typing import Any

from perimeterwatch.clients import contenthash, ethrpc
from perimeterwatch.clients.contenthash import ContentPointer
from perimeterwatch.clients.dns import DnsStatus
from perimeterwatch.clients.ethrpc import MalformedAnswer, NoAnswer, RpcError
from perimeterwatch.core.context import ScanContext
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
from perimeterwatch.core.module import ModuleSpec, ScanModule, register, skipped
from perimeterwatch.modules.ens_names import ENS_REGISTRY, NameRefused, namehash, validate_name

RPC_SECRET = "PW_RPC_ETH_MAINNET"  # noqa: S105 - the name of a setting, not a credential

# Source: https://eips.ethereum.org/EIPS/eip-137
#   function resolver(bytes32 node) constant returns (address);
SIG_RESOLVER = "resolver(bytes32)"
# Source: https://docs.ens.domains/ensip/7
#   function contenthash(bytes32 node) external view returns (bytes memory)
# ENSIP-7 gives its interface number as 0xbc1c58d1, which is this selector.
SIG_CONTENTHASH = "contenthash(bytes32)"

NONE = "none"
UNRECOGNISED = "unrecognised"

# DNSLink: a TXT record at _dnslink.<host> holding dnslink=/<namespace>/<target>.
# Source: https://dnslink.dev
DNSLINK_LABEL = "_dnslink"
DNSLINK_PREFIX = "dnslink="
MAX_HOSTS = 500
MAX_RECORDS_PER_HOST = 20
MAX_CID_LENGTH = 128
MAX_DOMAIN_LENGTH = 253
# A CID as text uses letters and digits only, whichever base it is written in.
_CID = re.compile(rf"[A-Za-z0-9]{{16,{MAX_CID_LENGTH}}}")
_NAME = r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"(?=.{{4,{MAX_DOMAIN_LENGTH}}}\Z){_NAME}")
_HOST = re.compile(rf"(?=.{{4,{MAX_DOMAIN_LENGTH - len(DNSLINK_LABEL) - 1}}}\Z){_NAME}")

IPNS_NOTE = (
    "This points to an IPNS name, not to the content itself. Whoever holds the key for "
    "that name can change the content behind it without changing this record, and such "
    "a change cannot be seen this way."
)
DNSLINK_DOMAIN_NOTE = (
    "This points to another domain name, not to the content itself. The content is "
    "whatever that name's own DNSLink record says, and a change there cannot be seen "
    "in this record."
)


class PointerError(Exception):
    """The pointer could not be read. The message is safe to show."""

    def __init__(self, message: str, *, endpoint: bool = False) -> None:
        super().__init__(message)
        self.endpoint = endpoint


@dataclass(frozen=True)
class DnsLink:
    protocol: str  # "ipfs", "ipns" or "unrecognised"
    # The CID or name. For an unrecognised value, a digest of it: the value
    # itself is never kept, because it can hold anything at all.
    target: str


def decode_bytes(data: str) -> bytes:
    """Decode one ABI-encoded `bytes` return value."""
    if not isinstance(data, str) or not re.fullmatch(r"0x[0-9a-fA-F]*", data):
        raise MalformedAnswer("the answer is not hexadecimal")
    body = data[2:]
    if len(body) < 128 or len(body) % 64:
        raise MalformedAnswer("unexpected response length")
    if len(body) > 128 + 2 * (contenthash.MAX_CONTENTHASH_BYTES + 32):
        raise MalformedAnswer("the answer is too long")
    if int(body[:64], 16) != 32:
        raise MalformedAnswer("unexpected offset")
    length = int(body[64:128], 16)
    if length > contenthash.MAX_CONTENTHASH_BYTES:
        raise MalformedAnswer("the value is too long")
    padded = (length + 31) // 32 * 32
    if len(body) != 128 + 2 * padded:
        raise MalformedAnswer("the value is not as long as it says it is")
    return bytes.fromhex(body[128 : 128 + 2 * length])


def parse_dnslink(value: str) -> DnsLink | None:
    """Read one TXT value. None means it is not a DNSLink record at all."""
    if not isinstance(value, str) or not value.startswith(DNSLINK_PREFIX):
        return None
    path = value[len(DNSLINK_PREFIX) :]
    if path.startswith("/ipfs/"):
        target = path[len("/ipfs/") :]
        if _CID.fullmatch(target):
            return DnsLink("ipfs", target)
    elif path.startswith("/ipns/"):
        target = path[len("/ipns/") :]
        if _CID.fullmatch(target) or _DOMAIN.fullmatch(target):
            return DnsLink("ipns", target)
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()
    return DnsLink(UNRECOGNISED, f"sha256:{digest}")


@register
class FrontendPointers(ScanModule):
    spec = ModuleSpec(
        name="frontend_pointers",
        title="Pointers to your website content",
        category=Category.SUPPLY_CHAIN,
        mode=ScanMode.PASSIVE,
        description=(
            "What the contenthash of your ENS names and the DNSLink records of your "
            "hostnames point to, so that a replaced website is noticed. The content itself "
            "is never fetched."
        ),
        # The ENS part needs the key and the DNSLink part does not, so the key
        # is optional and the ENS part is left out, with a note, without it.
        optional_keys=("PW_RPC_ETH_MAINNET",),
        depends_on=("subdomains",),
        contacts=("your Ethereum RPC endpoint", "public DNS"),
        default_timeout_s=600,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        rpc_url = ctx.secret(RPC_SECRET)
        hosts, too_many = self._hosts(ctx)
        ens_applies = bool(target.ens_names) and bool(rpc_url)
        if not hosts and not ens_applies:
            if target.ens_names:
                return skipped(
                    self.spec,
                    "No RPC endpoint is configured for Ethereum mainnet, and there is no "
                    "hostname to look up.",
                    "Set PW_RPC_ETH_MAINNET to check the contenthash of your ENS names.",
                )
            return skipped(
                self.spec,
                "There is no ENS name and no hostname to check.",
                "Add your ENS names to the target to have their contenthash checked.",
            )

        findings: list[Finding] = []
        notes: list[str] = []
        failed = 0
        checked = 0
        endpoint_failed = 0

        if target.ens_names and not rpc_url:
            failed += 1
            notes.append(
                "The contenthash of your ENS names was not checked: no RPC endpoint is "
                "configured for Ethereum mainnet. Set PW_RPC_ETH_MAINNET to check it."
            )
        elif rpc_url:
            seen: set[str] = set()
            for raw in target.ens_names:
                try:
                    name = validate_name(raw)
                except NameRefused as exc:
                    failed += 1
                    notes.append(f"{str(raw)[:80]!r} was not checked: {exc}.")
                    continue
                if name in seen:
                    continue
                seen.add(name)
                try:
                    findings.append(await self._contenthash(ctx, rpc_url, name))
                except PointerError as exc:
                    failed += 1
                    endpoint_failed += exc.endpoint
                    notes.append(
                        f"The contenthash of {name} could not be read: {exc}. Nothing is "
                        "reported for it this time, and nothing about it counts as changed."
                    )
                    continue
                checked += 1

        if too_many:
            failed += 1
            notes.append(f"Only the first {MAX_HOSTS} hostnames were checked for a DNSLink record.")
        answers = await asyncio.gather(
            *(ctx.dns.query(f"{DNSLINK_LABEL}.{host}", "TXT") for host in hosts)
        )
        dns_errors = 0
        for host, answer in zip(hosts, answers, strict=True):
            if answer.status is DnsStatus.ERROR:
                dns_errors += 1
                continue
            checked += 1
            if answer.status is not DnsStatus.OK:
                continue
            finding = self._dnslink(ctx, host, list(answer.records))
            if finding is not None:
                findings.append(finding)
        if dns_errors:
            failed += 1
            endpoint_failed += 1
            notes.append(
                f"The DNSLink record of {dns_errors} of {len(hosts)} hostnames could not be "
                "looked up. Nothing is reported for them this time, and nothing about them "
                "counts as changed."
            )

        if failed and not checked and endpoint_failed:
            return self.result(ModuleStatus.FAILED, skip_reason=notes[0], notes=notes)
        kinds = [f.kind for f in findings]
        return self.result(
            ModuleStatus.PARTIAL if failed else ModuleStatus.OK,
            findings=findings,
            notes=notes,
            stats={
                "ens_contenthashes": kinds.count("web3.ens.contenthash"),
                "dnslink_records": kinds.count("dns.dnslink"),
                "hostnames_checked": len(hosts) - dns_errors,
            },
        )

    # -- ENS contenthash ------------------------------------------------------

    async def _contenthash(self, ctx: ScanContext, rpc_url: str, name: str) -> Finding:
        try:
            resolver, pointer, reason = await self._read_contenthash(ctx, rpc_url, name)
        except (NoAnswer, MalformedAnswer) as exc:
            raise PointerError(f"an answer was not in the expected form ({exc})") from None
        except RpcError as exc:
            # Messages from the client never hold the endpoint's address.
            raise PointerError(str(exc), endpoint=True) from None
        evidence: dict[str, Any] = {"resolver": resolver}
        if pointer is None:
            evidence["note"] = reason
            return self.finding(
                "web3.ens.contenthash",
                AssetType.ENS_NAME,
                name,
                f"{name} does not point to any website content",
                state={"protocol": NONE, "hash": None},
                evidence=evidence,
                confidence=Confidence.CONFIRMED,
            )
        state: dict[str, Any] = {"protocol": pointer.protocol, "hash": pointer.hash}
        evidence["length_in_bytes"] = pointer.raw_length
        if not pointer.known:
            # Only part of a long value is shown, so its digest is kept as well.
            state["sha256"] = pointer.sha256
            evidence["note"] = (
                "The contenthash names a protocol that is not decoded here, or is not in "
                "the form its protocol requires. Its bytes are shown in hexadecimal, cut "
                f"to {contenthash.MAX_RAW_HEX} characters."
            )
            title = f"{name} points to content in a form that is not recognised"
        else:
            evidence["uri"] = pointer.uri
            if pointer.also_written:
                evidence["also_written"] = pointer.also_written
            title = f"{name} points to {pointer.protocol.upper()} content {pointer.hash[:16]}…"
            if pointer.protocol == "swarm":
                title = f"{name} points to Swarm content {pointer.hash[:16]}…"
            if pointer.protocol == "ipns":
                evidence["note"] = IPNS_NOTE
                title = f"{name} points to the IPNS name {pointer.hash[:24]}"
                if len(pointer.hash) > 24:
                    title += "…"
        return self.finding(
            "web3.ens.contenthash",
            AssetType.ENS_NAME,
            name,
            title,
            # A change of protocol or of content shows up as a changed finding.
            state=state,
            evidence=evidence,
            confidence=Confidence.CONFIRMED,
        )

    async def _read_contenthash(
        self, ctx: ScanContext, rpc_url: str, name: str
    ) -> tuple[str | None, ContentPointer | None, str]:
        node = namehash(name)
        answer = await ethrpc.eth_call(
            ctx, rpc_url, ENS_REGISTRY, ethrpc.encode_call(SIG_RESOLVER, node)
        )
        resolver = ethrpc.decode_address(answer)
        if ethrpc.is_zero_address(resolver):
            return None, None, "This name has no resolver, so it cannot hold a contenthash."
        try:
            answer = await ethrpc.eth_call(
                ctx, rpc_url, resolver, ethrpc.encode_call(SIG_CONTENTHASH, node)
            )
        except NoAnswer:
            # A resolver is whatever contract the owner chose. It may not hold one.
            return resolver, None, "The resolver of this name does not hold a contenthash."
        pointer = contenthash.decode(decode_bytes(answer))
        return resolver, pointer, "The contenthash of this name is empty."

    # -- DNSLink --------------------------------------------------------------

    def _hosts(self, ctx: ScanContext) -> tuple[list[str], bool]:
        """The root domain first, then every in-scope hostname found so far."""
        hosts: list[str] = []
        for raw in [ctx.root_domain, *ctx.assets.hostnames()]:
            if not isinstance(raw, str):
                continue
            host = raw.strip().rstrip(".").lower()
            if host in hosts or not _HOST.fullmatch(host) or not ctx.in_scope(host):
                continue
            hosts.append(host)
        return hosts[:MAX_HOSTS], len(hosts) > MAX_HOSTS

    def _dnslink(self, ctx: ScanContext, host: str, records: list[str]) -> Finding | None:
        links: list[DnsLink] = []
        for value in sorted(records)[:MAX_RECORDS_PER_HOST]:
            link = parse_dnslink(value)
            if link is not None and link not in links:
                links.append(link)
        if not links:
            return None
        # Records that were understood come first, so that one of them is the
        # one shown whenever there is one.
        links.sort(key=lambda link: (link.protocol == UNRECOGNISED, link.protocol, link.target))
        first = links[0]
        state: dict[str, Any] = {"protocol": first.protocol, "target": first.target}
        evidence: dict[str, Any] = {"record": f"{DNSLINK_LABEL}.{host}"}
        if len(links) > 1:
            others = [f"{link.protocol}:{link.target}" for link in links[1:]]
            state["other_records"] = others
            evidence["note_on_number"] = (
                f"There are {len(links)} different DNSLink records for this name. Only one "
                "is expected, and which one is used is up to the software reading them."
            )
        if first.protocol == UNRECOGNISED:
            title = f"{host} has a DNSLink record that is not in a recognised form"
            evidence["note"] = (
                "The record is not shown because it is not in the form a DNSLink record "
                "should have. A digest of it is kept, so that a change is still noticed."
            )
        elif first.protocol == "ipns":
            title = f"{host} points to the IPNS name {first.target[:24]}"
            if len(first.target) > 24:
                title += "…"
            evidence["points_to"] = f"/ipns/{first.target}"
            evidence["note"] = DNSLINK_DOMAIN_NOTE if "." in first.target else IPNS_NOTE
        else:
            title = f"{host} points to IPFS content {first.target[:16]}…"
            evidence["points_to"] = f"/ipfs/{first.target}"
        return self.finding(
            "dns.dnslink",
            AssetType.DOMAIN if host == ctx.root_domain.lower() else AssetType.SUBDOMAIN,
            host,
            title,
            # A change of protocol or of target shows up as a changed finding.
            state=state,
            evidence=evidence,
            confidence=Confidence.CONFIRMED,
        )
