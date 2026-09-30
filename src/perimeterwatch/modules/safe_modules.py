"""What else can act for the organisation's Safe, read straight from the chain.

The owners are not the only way to move funds out of a Safe. A module can do
so without any owner signing, a guard can block what the owners sign, and the
code the Safe runs can be swapped. This records each of them so that a change
is noticed. Every call only reads. No third-party API is used and no
transaction is ever sent.

A Safe that could not be read in full produces no findings at all, so that a
failing endpoint can never look like a module or guard being removed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from perimeterwatch.clients import ethrpc
from perimeterwatch.clients.ethrpc import MalformedAnswer, NoAnswer, RpcError
from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.errors import ValidationError
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
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register
from perimeterwatch.modules.contract_control import is_delegation
from perimeterwatch.safety.domains import validate_eth_address

RPC_SECRET = {"eth": "PW_RPC_ETH_MAINNET"}

# Storage slots that Safe defines, each the keccak256 of a label.
# Source, read 2026-09-29:
# https://github.com/safe-global/safe-smart-account/blob/main/contracts/libraries/SafeStorage.sol
#   FALLBACK_HANDLER_STORAGE_SLOT  keccak256("fallback_manager.handler.address")
#   GUARD_STORAGE_SLOT             keccak256("guard_manager.guard.address")
#   MODULE_GUARD_STORAGE_SLOT      keccak256("module_manager.module_guard.address")
# The same values are in contracts/base/GuardManager.sol and FallbackManager.sol
# at the tags v1.3.0, v1.4.1 and v1.5.0, and in ModuleManager.sol at v1.5.0,
# which is where the module guard first appears. Each was recomputed with
# eth_utils.keccak when this module was written, and
# tests/modules/test_safe_modules_and_pointers.py computes them again on every run.
SLOT_GUARD = "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8"
SLOT_FALLBACK_HANDLER = "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5"
SLOT_MODULE_GUARD = "0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947"
# "address internal singleton" is the first variable of both the proxy and the
# Safe itself, so it is storage slot 0, and the proxy reads it with sload(0).
# Source: contracts/proxies/SafeProxy.sol and contracts/libraries/SafeStorage.sol
# in the same repository.
SLOT_SINGLETON = "0x" + "0" * 64

# The list of modules starts and ends at this address.
# Source: "address internal constant SENTINEL_MODULES = address(0x1);" in
# contracts/base/ModuleManager.sol of the same repository.
SENTINEL = "0x0000000000000000000000000000000000000001"

SIG_MODULES_PAGINATED = "getModulesPaginated(address,uint256)"
GET_THRESHOLD = ethrpc.encode_call("getThreshold()")
GET_OWNERS = ethrpc.encode_call("getOwners()")
# Safe 1.0.0 has no paginated function. Its getModules() returns every module.
GET_MODULES = ethrpc.encode_call("getModules()")

_STORAGE_WORD = re.compile(r"0x[0-9a-fA-F]{1,64}")

PAGE_SIZE = 50
MAX_PAGES = 10
NONE = "none"


class SafeError(Exception):
    """This Safe could not be read. The message is safe to show."""

    def __init__(self, message: str, *, endpoint: bool = False) -> None:
        super().__init__(message)
        # True when the fault lies with the RPC endpoint, not the contract.
        self.endpoint = endpoint


class NotASafe(Exception):
    """The address does not answer as a Safe does."""


@dataclass
class SafeSetup:
    modules: list[str] = field(default_factory=list)
    # Module address to whether it holds contract code.
    module_has_code: dict[str, bool] = field(default_factory=dict)
    guard: str | None = None
    module_guard: str | None = None
    fallback_handler: str | None = None
    singleton: str | None = None


def short(address: str) -> str:
    return f"{address[:10]}…"


def decode_modules_page(data: str) -> tuple[list[str], str]:
    """Decode the (address[] array, address next) that getModulesPaginated returns."""
    if not isinstance(data, str) or not data.startswith("0x"):
        raise MalformedAnswer("the answer is not hexadecimal")
    body = data[2:]
    # Two head words, the array length, and at most one page of addresses.
    if len(body) < 3 * 64 or len(body) % 64 or len(body) > (3 + PAGE_SIZE) * 64:
        raise MalformedAnswer("unexpected response length")
    try:
        offset = int(body[:64], 16)
    except ValueError:
        raise MalformedAnswer("the answer is not hexadecimal") from None
    if offset != 64:
        raise MalformedAnswer("unexpected array offset")
    following = ethrpc.decode_address("0x" + body[64:128])
    # decode_addresses wants the offset word first, then the array itself.
    modules = ethrpc.decode_addresses("0x" + f"{32:064x}" + body[128:])
    if len(modules) > PAGE_SIZE:
        raise MalformedAnswer("unexpected array length")
    return modules, following


def _is_list_end(address: str) -> bool:
    return int(address, 16) == int(SENTINEL, 16)


class _Reader:
    def __init__(self, ctx: ScanContext, rpc_url: str) -> None:
        self.ctx = ctx
        self.rpc_url = rpc_url

    async def check_is_safe(self, safe: str) -> None:
        """Raise NotASafe unless the threshold and owners answer sensibly."""
        try:
            threshold_raw = await ethrpc.eth_call(self.ctx, self.rpc_url, safe, GET_THRESHOLD)
            owners_raw = await ethrpc.eth_call(self.ctx, self.rpc_url, safe, GET_OWNERS)
        except NoAnswer:
            raise NotASafe from None
        try:
            threshold = ethrpc.decode_uint256(threshold_raw)
            owners = ethrpc.decode_addresses(owners_raw)
        except MalformedAnswer:
            raise NotASafe from None
        if not owners or not 1 <= threshold <= len(owners):
            raise NotASafe

    async def slot_address(self, safe: str, slot: str) -> str | None:
        # The shared client is asked for the answer as it came, because an
        # answer with nothing in it must not be read as a slot holding zero:
        # that would say a guard had been removed. A node that leaves out
        # leading zeros still sends at least one digit.
        raw = await ethrpc.call(self.ctx, self.rpc_url, "eth_getStorageAt", [safe, slot, "latest"])
        if not isinstance(raw, str) or not _STORAGE_WORD.fullmatch(raw):
            raise MalformedAnswer("a storage value is not in the expected form")
        address = ethrpc.decode_address("0x" + raw[2:].rjust(64, "0"))
        return None if ethrpc.is_zero_address(address) else address

    async def modules(self, safe: str) -> list[str]:
        """Every enabled module. Raises rather than return a list that may be short."""
        found: list[str] = []
        start = SENTINEL
        asked: set[str] = set()
        for _ in range(MAX_PAGES):
            asked.add(start.lower())
            data = ethrpc.encode_call(SIG_MODULES_PAGINATED, int(start, 16), PAGE_SIZE)
            try:
                answer = await ethrpc.eth_call(self.ctx, self.rpc_url, safe, data)
            except NoAnswer:
                if start != SENTINEL:
                    raise SafeError("the list of modules stopped part of the way") from None
                return await self._modules_unpaginated(safe)
            page, following = decode_modules_page(answer)
            for module in page:
                self._add(found, module)
            if _is_list_end(following):
                return found
            if ethrpc.is_zero_address(following) or not page:
                raise MalformedAnswer("the list of modules does not end where it should")
            if following != page[-1]:
                # Safe up to 1.3.0 names the first module after this page, and
                # the page that starts there leaves it out. From 1.4.0 the last
                # module of this page is named instead.
                self._add(found, following)
            if following.lower() in asked:
                raise MalformedAnswer("the list of modules goes round in a circle")
            start = following
        raise SafeError(
            f"it has more than {MAX_PAGES * PAGE_SIZE} modules, which is more than is read"
        )

    async def _modules_unpaginated(self, safe: str) -> list[str]:
        try:
            answer = await ethrpc.eth_call(self.ctx, self.rpc_url, safe, GET_MODULES)
        except NoAnswer:
            raise SafeError("it does not say which modules it has") from None
        found: list[str] = []
        for module in ethrpc.decode_addresses(answer):
            self._add(found, module)
        return found

    @staticmethod
    def _add(found: list[str], module: str) -> None:
        if ethrpc.is_zero_address(module) or _is_list_end(module):
            raise MalformedAnswer("a module address is not a real address")
        if module in found:
            raise MalformedAnswer("the same module is listed twice")
        found.append(module)

    async def read(self, safe: str) -> SafeSetup:
        await self.check_is_safe(safe)
        setup = SafeSetup()
        setup.modules = sorted(await self.modules(safe), key=str.lower)
        setup.singleton = await self.slot_address(safe, SLOT_SINGLETON)
        setup.guard = await self.slot_address(safe, SLOT_GUARD)
        setup.fallback_handler = await self.slot_address(safe, SLOT_FALLBACK_HANDLER)
        setup.module_guard = await self.slot_address(safe, SLOT_MODULE_GUARD)
        for module in setup.modules:
            code = await ethrpc.get_code(self.ctx, self.rpc_url, module)
            setup.module_has_code[module] = code != "0x" and not is_delegation(code)
        return setup


@register
class SafeModules(ScanModule):
    spec = ModuleSpec(
        name="safe_modules",
        title="Safe modules, guard and code",
        category=Category.WEB3,
        mode=ScanMode.PASSIVE,
        description=(
            "The modules, guard, fallback handler and underlying code of your Safe, read "
            "from the chain, so that a change to any of them is noticed."
        ),
        requires_target=("safes",),
        requires_keys=("PW_RPC_ETH_MAINNET",),
        contacts=("your Ethereum RPC endpoint",),
        default_timeout_s=300,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        assets: list[Asset] = []
        findings: list[Finding] = []
        notes: list[str] = []
        failed = 0
        endpoint_failed = 0
        readers: dict[str, _Reader] = {}
        seen: set[str] = set()
        for safe in target.safes:
            if safe.chain != "eth":
                failed += 1
                notes.append(
                    f"{str(safe.address)[:42]} was not checked: chain '{str(safe.chain)[:20]}' "
                    "is not supported yet. Only Ethereum mainnet ('eth') is."
                )
                continue
            try:
                address = validate_eth_address(safe.address)
            except ValidationError:
                failed += 1
                notes.append("A Safe was not checked: its address is not valid.")
                continue
            if address in seen:
                continue
            seen.add(address)
            rpc_url = ctx.secret(RPC_SECRET[safe.chain])
            if not rpc_url:
                failed += 1
                endpoint_failed += 1
                notes.append(f"No RPC endpoint is configured for chain '{safe.chain}'.")
                continue
            reader = readers.setdefault(safe.chain, _Reader(ctx, rpc_url))
            try:
                setup = await self._read(reader, address)
            except NotASafe:
                failed += 1
                notes.append(f"{address} does not look like a Safe, so it was not checked.")
                continue
            except SafeError as exc:
                failed += 1
                endpoint_failed += exc.endpoint
                notes.append(
                    f"{address} could not be read: {exc}. Nothing is reported for it this "
                    "time, and nothing about it counts as changed."
                )
                continue
            key = f"{safe.chain}:{address}"
            findings.extend(self._assess(key, address, setup))
            assets.append(
                self.asset(AssetType.SAFE, key, attributes={"modules": list(setup.modules)})
            )
        if failed and not assets and endpoint_failed:
            return self.result(ModuleStatus.FAILED, skip_reason=notes[0], notes=notes)
        return self.result(
            ModuleStatus.PARTIAL if failed else ModuleStatus.OK,
            assets=assets,
            findings=findings,
            notes=notes,
            stats={
                "safes": len(assets),
                "modules": sum(len(a.attributes["modules"]) for a in assets),
            },
        )

    async def _read(self, reader: _Reader, address: str) -> SafeSetup:
        try:
            return await reader.read(address)
        except (NoAnswer, MalformedAnswer) as exc:
            raise SafeError(f"an answer was not in the expected form ({exc})") from None
        except RpcError as exc:
            # Messages from the client never hold the endpoint's address.
            raise SafeError(str(exc), endpoint=True) from None

    def _assess(self, key: str, address: str, setup: SafeSetup) -> list[Finding]:
        name = f"Safe {short(address)}"
        count = len(setup.modules)
        if count == 0:
            title = f"{name} has no modules enabled"
        elif count == 1:
            title = f"{name} has 1 module enabled"
        else:
            title = f"{name} has {count} modules enabled"
        findings = [
            self.finding(
                "web3.safe.modules",
                AssetType.SAFE,
                key,
                title,
                # A module added or removed shows up as a changed finding.
                state={"modules": list(setup.modules)},
                evidence={
                    "modules": [
                        {"address": module, "holds_contract_code": setup.module_has_code[module]}
                        for module in setup.modules
                    ]
                },
                confidence=Confidence.CONFIRMED,
            )
        ]
        for module in setup.modules:
            has_code = setup.module_has_code[module]
            evidence: dict[str, Any] = {"module": module, "holds_contract_code": has_code}
            title = f"{name} lets the module {short(module)} move funds without the owners"
            if not has_code:
                title = (
                    f"{name} lets {short(module)}, which holds no contract code, move funds "
                    "without the owners"
                )
                evidence["note"] = (
                    "No contract code is stored at this address. It is either an ordinary "
                    "account, run by whoever holds its key, or a contract that does not "
                    "exist yet or no longer exists."
                )
            findings.append(
                self.finding(
                    "web3.safe.module_enabled",
                    AssetType.SAFE,
                    key,
                    title,
                    identity={"module": module},
                    evidence=evidence,
                    confidence=Confidence.CONFIRMED,
                )
            )

        if setup.guard and setup.module_guard:
            title = f"{name} has a guard and a module guard set"
        elif setup.guard:
            title = f"{name} has the guard {short(setup.guard)} set"
        elif setup.module_guard:
            title = f"{name} has the module guard {short(setup.module_guard)} set"
        else:
            title = f"{name} has no guard set"
        findings.append(
            self.finding(
                "web3.safe.guard",
                AssetType.SAFE,
                key,
                title,
                state={
                    "guard": setup.guard or NONE,
                    "module_guard": setup.module_guard or NONE,
                },
                evidence={
                    "guard": setup.guard or NONE,
                    "module_guard": setup.module_guard or NONE,
                    "note": (
                        "The guard checks what the owners sign. The module guard checks "
                        "what modules do, and exists from Safe version 1.5.0."
                    ),
                },
                confidence=Confidence.CONFIRMED,
            )
        )
        handler = setup.fallback_handler
        findings.append(
            self.finding(
                "web3.safe.fallback_handler",
                AssetType.SAFE,
                key,
                f"{name} uses the fallback handler {short(handler)}"
                if handler
                else f"{name} has no fallback handler set",
                state={"fallback_handler": handler or NONE},
                evidence={"fallback_handler": handler or NONE},
                confidence=Confidence.CONFIRMED,
            )
        )
        singleton = setup.singleton
        singleton_evidence: dict[str, Any] = {"singleton": singleton or NONE}
        if singleton is None:
            singleton_evidence["note"] = (
                "A Safe is normally a small proxy that names the code it runs. This one "
                "names none, so it may have been set up in another way."
            )
        findings.append(
            self.finding(
                "web3.safe.singleton",
                AssetType.SAFE,
                key,
                f"{name} runs the code at {short(singleton)}"
                if singleton
                else f"{name} does not say which code it runs",
                state={"singleton": singleton or NONE},
                evidence=singleton_evidence,
                confidence=Confidence.CONFIRMED,
            )
        )
        return findings
