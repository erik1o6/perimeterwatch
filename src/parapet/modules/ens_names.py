"""Who holds the organisation's ENS names, where they point and when they lapse.

Everything is read from the ENS contracts on Ethereum mainnet with read-only
calls. No third-party API is used and no transaction is ever sent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from eth_utils.crypto import keccak

from parapet.clients import ethrpc
from parapet.clients.ethrpc import MalformedAnswer, NoAnswer, RpcError
from parapet.core.context import ScanContext
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
    utcnow,
)
from parapet.core.module import ModuleSpec, ScanModule, register

RPC_SECRET = "PARAPET_RPC_ETH_MAINNET"  # noqa: S105 - the name of a setting, not a credential

# ENS contracts on Ethereum mainnet.
# Source: https://docs.ens.domains/learn/deployments (read 2026-09-29), and each
# was then called on mainnet to confirm it answers as expected.
ENS_REGISTRY = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"
BASE_REGISTRAR = "0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85"
NAME_WRAPPER = "0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401"

# Registry and resolver functions.
# Source: https://eips.ethereum.org/EIPS/eip-137
#   function owner(bytes32 node) constant returns (address);
#   function resolver(bytes32 node) constant returns (address);
#   function addr(bytes32 node) constant returns (address);
SIG_OWNER = "owner(bytes32)"
SIG_RESOLVER = "resolver(bytes32)"
SIG_ADDR = "addr(bytes32)"
# BaseRegistrar functions. The number passed is keccak256 of the label, so
# keccak256("foo") for foo.eth.
# Source: https://docs.ens.domains/registry/eth
#   BaseRegistrar.nameExpires(uint256 label) view returns (uint)
#   BaseRegistrar.ownerOf(uint256 tokenId) view returns (address)
SIG_NAME_EXPIRES = "nameExpires(uint256)"
SIG_OWNER_OF = "ownerOf(uint256)"
# NameWrapper.ownerOf(uint256 id), where id is the namehash of the full name.
# Source: contracts/wrapper/NameWrapper.sol in https://github.com/ensdomains/ens-contracts
# It is the same signature as the registrar's, with a different number. It was
# called on mainnet for a wrapped name to confirm it returns the holder.

# After expiry the owner has 90 days in which only they can renew.
# Source: "uint256 public constant GRACE_PERIOD = 90 days;" in
# contracts/ethregistrar/BaseRegistrarImplementation.sol of ens-contracts, and
# GRACE_PERIOD() on the BaseRegistrar returned 7776000 seconds on mainnet.
GRACE_PERIOD = timedelta(days=90)

# Narrowest first, so a name lands in the smallest bucket that holds it.
BUCKETS = ((7, "7d"), (14, "14d"), (30, "30d"), (90, "90d"))
URGENT = frozenset({"expired", "7d", "14d"})

MAX_NAME_LENGTH = 255
_LABEL = re.compile(r"[a-z0-9-]+")
# No real expiry is later than this (the year 9999), so a larger number is not one.
MAX_TIMESTAMP = 253_402_300_799


class NameRefused(Exception):
    """The name will not be checked. The message is safe to show."""


class EnsError(Exception):
    """The name could not be read. The message is safe to show."""

    def __init__(self, message: str, *, endpoint: bool = False) -> None:
        super().__init__(message)
        self.endpoint = endpoint


def validate_name(raw: str) -> str:
    """Accept only names that need no normalisation at all.

    Full ENS normalisation (ENSIP-15) is complex, and getting it wrong would
    check a different name from the one meant. So anything outside a-z, 0-9
    and the hyphen is refused rather than guessed at.
    """
    if not isinstance(raw, str) or not raw:
        raise NameRefused("it is empty")
    if len(raw) > MAX_NAME_LENGTH:
        raise NameRefused("it is too long")
    if raw != raw.strip():
        raise NameRefused("it has spaces around it")
    labels = raw.split(".")
    if len(labels) < 2 or labels[-1] != "eth":
        raise NameRefused("only names ending in .eth are supported")
    for label in labels:
        if not label:
            raise NameRefused("it has an empty part between two dots")
        if not _LABEL.fullmatch(label):
            if _LABEL.fullmatch(label.lower()):
                raise NameRefused("it must be written in lower case")
            raise NameRefused(
                "names with characters other than a-z, 0-9 and the hyphen are not supported "
                "yet, because they could be mistaken for a different name"
            )
        if label[2:4] == "--":
            # ENSIP-15 forbids a hyphen in both the third and fourth place.
            raise NameRefused("a part of it has hyphens in the third and fourth place")
    return raw


def labelhash(label: str) -> bytes:
    return keccak(text=label)


def namehash(name: str) -> bytes:
    """The ENS namehash of an already normalised name (EIP-137)."""
    node = b"\x00" * 32
    if name:
        for label in reversed(name.split(".")):
            node = keccak(node + labelhash(label))
    return node


def expiry_bucket(expires: datetime, now: datetime) -> str | None:
    """Which bucket an expiry falls in, or None if it is more than 90 days away."""
    if expires <= now:
        return "expired"
    remaining = expires - now
    for days, bucket in BUCKETS:
        if remaining <= timedelta(days=days):
            return bucket
    return None


@dataclass
class NameDetails:
    name: str
    owner: str | None = None
    resolver: str | None = None
    address: str | None = None
    wrapped: bool = False
    wrapped_owner: str | None = None
    # The second-level name that carries the registration, e.g. foo.eth for app.foo.eth.
    registered_name: str = ""
    registrant: str | None = None
    expires: datetime | None = None


class _Reader:
    def __init__(self, ctx: ScanContext, rpc_url: str) -> None:
        self.ctx = ctx
        self.rpc_url = rpc_url

    async def address(self, contract: str, data: str, *, optional: bool = False) -> str | None:
        try:
            answer = await ethrpc.eth_call(self.ctx, self.rpc_url, contract, data)
        except NoAnswer:
            if optional:
                return None
            raise
        found = ethrpc.decode_address(answer)
        return None if ethrpc.is_zero_address(found) else found

    async def read(self, name: str) -> NameDetails:
        node = namehash(name)
        details = NameDetails(name=name)
        details.owner = await self.address(ENS_REGISTRY, ethrpc.encode_call(SIG_OWNER, node))
        details.resolver = await self.address(ENS_REGISTRY, ethrpc.encode_call(SIG_RESOLVER, node))
        if details.resolver is not None:
            # A resolver is whatever contract the owner chose. It may not hold an address.
            details.address = await self.address(
                details.resolver, ethrpc.encode_call(SIG_ADDR, node), optional=True
            )
        if details.owner == NAME_WRAPPER:
            details.wrapped = True
            details.wrapped_owner = await self.address(
                NAME_WRAPPER, ethrpc.encode_call(SIG_OWNER_OF, node), optional=True
            )

        labels = name.split(".")
        details.registered_name = ".".join(labels[-2:])
        token = labelhash(labels[-2])
        answer = await ethrpc.eth_call(
            self.ctx, self.rpc_url, BASE_REGISTRAR, ethrpc.encode_call(SIG_NAME_EXPIRES, token)
        )
        timestamp = ethrpc.decode_uint256(answer)
        if timestamp > MAX_TIMESTAMP:
            raise MalformedAnswer("the expiry time is not a real date")
        if timestamp:
            details.expires = datetime.fromtimestamp(timestamp, UTC)
            # The registrar stops answering this once the name has expired.
            details.registrant = await self.address(
                BASE_REGISTRAR, ethrpc.encode_call(SIG_OWNER_OF, token), optional=True
            )
        return details


@register
class EnsNames(ScanModule):
    spec = ModuleSpec(
        name="ens_names",
        title="ENS names",
        category=Category.WEB3,
        mode=ScanMode.PASSIVE,
        description=(
            "Who holds each of your ENS names, which address it points to and when it "
            "expires, read from the chain."
        ),
        requires_target=("ens_names",),
        requires_keys=("PARAPET_RPC_ETH_MAINNET",),
        contacts=("your Ethereum RPC endpoint",),
        default_timeout_s=300,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        assets: list[Asset] = []
        findings: list[Finding] = []
        notes: list[str] = []
        failed = 0
        endpoint_failed = 0
        seen: set[str] = set()
        now = utcnow()
        rpc_url = ctx.secret(RPC_SECRET)
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
            if not rpc_url:
                failed += 1
                endpoint_failed += 1
                notes.append("No RPC endpoint is configured for Ethereum mainnet.")
                break
            try:
                details = await self._read(_Reader(ctx, rpc_url), name)
            except EnsError as exc:
                failed += 1
                endpoint_failed += exc.endpoint
                notes.append(f"{name} could not be read: {exc}.")
                continue
            if details.owner is None and details.expires is None:
                notes.append(f"{name} is not registered. Check the spelling.")
            findings.extend(self._assess(details, now))
            assets.append(
                self.asset(
                    AssetType.ENS_NAME,
                    name,
                    attributes={
                        "expires": details.expires.isoformat() if details.expires else None
                    },
                    state={"registered": details.owner is not None},
                )
            )
        if failed and not assets and endpoint_failed:
            return self.result(ModuleStatus.FAILED, skip_reason=notes[0], notes=notes)
        return self.result(
            ModuleStatus.PARTIAL if failed else ModuleStatus.OK,
            assets=assets,
            findings=findings,
            notes=notes,
            stats={"ens_names": len(assets)},
        )

    async def _read(self, reader: _Reader, name: str) -> NameDetails:
        try:
            return await reader.read(name)
        except NoAnswer:
            raise EnsError("the ENS contracts did not answer") from None
        except MalformedAnswer as exc:
            raise EnsError(f"an answer was not in the expected form ({exc})") from None
        except RpcError as exc:
            # Messages from the client never hold the endpoint's address.
            raise EnsError(str(exc), endpoint=True) from None

    def _assess(self, details: NameDetails, now: datetime) -> list[Finding]:
        name = details.name
        evidence: dict[str, Any] = {
            "owner": details.owner,
            "resolver": details.resolver,
            "points_to": details.address,
            "registered_name": details.registered_name,
            "registrant": details.registrant,
            "expires": details.expires.isoformat() if details.expires else None,
            "held_in_name_wrapper": details.wrapped,
        }
        if details.wrapped:
            evidence["note"] = (
                "This name is held in the ENS Name Wrapper, so the registry lists the "
                "wrapper contract as its owner. The owner inside the wrapper is shown "
                "as wrapped_owner."
            )
            evidence["wrapped_owner"] = details.wrapped_owner
        if details.owner is None:
            title = f"{name} has no owner in the ENS registry"
        elif details.address is None:
            title = f"{name} does not point to an address"
        else:
            title = f"{name} points to {details.address[:10]}…"
        findings = [
            self.finding(
                "web3.ens.details",
                AssetType.ENS_NAME,
                name,
                title,
                # A change of owner, resolver or address shows up as a changed finding.
                state={
                    "owner": details.owner,
                    "wrapped_owner": details.wrapped_owner,
                    "registrant": details.registrant,
                    "resolver": details.resolver,
                    "address": details.address,
                },
                evidence=evidence,
                confidence=Confidence.CONFIRMED,
            )
        ]
        if details.expires is None:
            return findings
        bucket = expiry_bucket(details.expires, now)
        if bucket is None:
            return findings
        subject = name
        if details.registered_name != name:
            subject = f"{details.registered_name}, which {name} depends on,"
        state: dict[str, Any] = {"expires_within": bucket}
        expiry_evidence = dict(evidence)
        day = details.expires.date().isoformat()
        if bucket == "expired":
            grace_ends = details.expires + GRACE_PERIOD
            in_grace = now < grace_ends
            state["in_grace_period"] = in_grace
            expiry_evidence["grace_period_ends"] = grace_ends.isoformat()
            if in_grace:
                title = (
                    f"{subject} expired on {day} and can still be renewed until "
                    f"{grace_ends.date().isoformat()}"
                )
            else:
                title = f"{subject} expired on {day} and can now be registered by anyone"
        else:
            title = f"{subject} expires within {bucket.removesuffix('d')} days, on {day}"
        urgent = bucket in URGENT
        findings.append(
            self.finding(
                "web3.ens.expiring",
                AssetType.ENS_NAME,
                name,
                title,
                state=state,
                evidence=expiry_evidence,
                confidence=Confidence.CONFIRMED,
                severity_steps=1 if urgent else 0,
                severity_note="Raised one step: the name has expired or has two weeks or less left."
                if urgent
                else None,
            )
        )
        return findings
