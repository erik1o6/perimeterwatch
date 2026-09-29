"""Who can change the organisation's contracts, read straight from the chain.

For each contract this reads the standard upgrade slots and the usual owner
functions, then looks at whoever holds control: an ordinary account, a Safe
multisig, a timelock or some other contract. Every call only reads. No
third-party API is used and no transaction is ever sent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from eth_utils.crypto import keccak

from perimeterwatch.clients import ethrpc
from perimeterwatch.clients.ethrpc import MalformedAnswer, NoAnswer, RpcError
from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.errors import ValidationError
from perimeterwatch.core.models import (
    Asset,
    AssetType,
    Category,
    Confidence,
    ContractRef,
    Finding,
    ModuleResult,
    ModuleStatus,
    ScanMode,
    Target,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register
from perimeterwatch.safety.domains import validate_eth_address

RPC_SECRET = {"eth": "PW_RPC_ETH_MAINNET"}

# EIP-1967 storage slots: keccak256 of the label, minus one.
# Source: https://eips.ethereum.org/EIPS/eip-1967
# Each was recomputed with eth_utils.keccak when this module was written, and
# tests/modules/test_onchain.py computes them again on every run.
SLOT_IMPLEMENTATION = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SLOT_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

# Proxies older than EIP-1967, such as the one in front of USDC, keep the same
# two values in slots named by the plain hash of these labels. They are hashed
# when the module loads, and were checked against USDC on mainnet.
# Source: UpgradeabilityProxy.sol and AdminUpgradeabilityProxy.sol in
# https://github.com/zeppelinos/zos (now OpenZeppelin SDK)
LEGACY_SLOT_IMPLEMENTATION = "0x" + keccak(text="org.zeppelinos.proxy.implementation").hex()
LEGACY_SLOT_ADMIN = "0x" + keccak(text="org.zeppelinos.proxy.admin").hex()

# Call data, worked out from the function signatures rather than typed in.
OWNER = ethrpc.encode_call("owner()")
PENDING_OWNER = ethrpc.encode_call("pendingOwner()")
GET_OWNER = ethrpc.encode_call("getOwner()")
IMPLEMENTATION = ethrpc.encode_call("implementation()")  # on an EIP-1967 beacon
GET_THRESHOLD = ethrpc.encode_call("getThreshold()")  # Safe
GET_OWNERS = ethrpc.encode_call("getOwners()")  # Safe
GET_MIN_DELAY = ethrpc.encode_call("getMinDelay()")  # OpenZeppelin TimelockController

# An account that has handed its behaviour to a contract (EIP-7702) has this
# marker followed by an address as its code. It is still run by one key.
# Source: https://eips.ethereum.org/EIPS/eip-7702
DELEGATION_PREFIX = "0xef0100"
DELEGATION_LENGTH = len("0x") + 2 * 23

KIND_ACCOUNT = "account"
KIND_TIMELOCK = "timelock"
KIND_CONTRACT = "contract"
KIND_NOBODY = "nobody"

ROLE_NAMES = {
    "owner": "owner",
    "proxy_admin": "upgrade admin",
    "proxy_admin_owner": "owner of the upgrade admin",
    "beacon_owner": "owner of the upgrade beacon",
}


class ControlError(Exception):
    """This contract could not be read. The message is safe to show."""

    def __init__(self, message: str, *, endpoint: bool = False) -> None:
        super().__init__(message)
        # True when the fault lies with the RPC endpoint, not the contract.
        self.endpoint = endpoint


@dataclass
class Controller:
    address: str
    kind: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Control:
    owner: str | None = None
    pending_owner: str | None = None
    proxy_admin: str | None = None
    proxy_admin_owner: str | None = None
    implementation: str | None = None
    beacon: str | None = None
    beacon_owner: str | None = None
    # Role name to whoever holds that role.
    controllers: dict[str, Controller] = field(default_factory=dict)

    @property
    def upgradeable(self) -> bool:
        return self.implementation is not None or self.beacon is not None

    @property
    def readable(self) -> bool:
        return any(
            value is not None
            for value in (self.owner, self.proxy_admin, self.implementation, self.beacon)
        )

    def final_roles(self) -> list[str]:
        """The roles that have the last word, leaving out any that only pass control on."""
        roles: list[str] = [r for r in ("owner", "beacon_owner") if r in self.controllers]
        if "proxy_admin_owner" in self.controllers:
            roles.append("proxy_admin_owner")
        elif "proxy_admin" in self.controllers:
            roles.append("proxy_admin")
        return roles


def short(address: str) -> str:
    return f"{address[:10]}…"


def is_delegation(code: str) -> bool:
    return code.startswith(DELEGATION_PREFIX) and len(code) == DELEGATION_LENGTH


class _Reader:
    """Reads one chain through one endpoint, remembering what it has classified."""

    def __init__(self, ctx: ScanContext, rpc_url: str) -> None:
        self.ctx = ctx
        self.rpc_url = rpc_url
        self.kinds: dict[str, Controller] = {}

    async def slot_address(self, contract: str, slot: str) -> str | None:
        word = await ethrpc.get_storage_at(self.ctx, self.rpc_url, contract, slot)
        address = ethrpc.decode_address(word)
        return None if ethrpc.is_zero_address(address) else address

    async def address_from(self, contract: str, data: str) -> str | None:
        """The address a function returns, or None if there is no such function."""
        try:
            answer = await ethrpc.eth_call(self.ctx, self.rpc_url, contract, data)
        except NoAnswer:
            return None
        return ethrpc.decode_address(answer)

    async def probe(self, contract: str, data: str) -> str | None:
        try:
            return await ethrpc.eth_call(self.ctx, self.rpc_url, contract, data)
        except NoAnswer:
            return None

    async def is_contract(self, address: str) -> bool:
        code = await ethrpc.get_code(self.ctx, self.rpc_url, address)
        return code != "0x" and not is_delegation(code)

    async def classify(self, address: str) -> Controller:
        if address not in self.kinds:
            self.kinds[address] = await self._classify(address)
        return self.kinds[address]

    async def _classify(self, address: str) -> Controller:
        if ethrpc.is_zero_address(address):
            return Controller(address, KIND_NOBODY)
        code = await ethrpc.get_code(self.ctx, self.rpc_url, address)
        if code == "0x":
            return Controller(address, KIND_ACCOUNT)
        if is_delegation(code):
            return Controller(address, KIND_ACCOUNT, {"delegates_to_contract": True})
        safe = await self._as_safe(address)
        if safe is not None:
            return safe
        delay = await self.probe(address, GET_MIN_DELAY)
        if delay is not None:
            try:
                seconds = ethrpc.decode_uint256(delay)
            except RpcError:
                seconds = None
            if seconds is not None:
                return Controller(address, KIND_TIMELOCK, {"delay_seconds": seconds})
        return Controller(address, KIND_CONTRACT)

    async def _as_safe(self, address: str) -> Controller | None:
        threshold_raw = await self.probe(address, GET_THRESHOLD)
        if threshold_raw is None:
            return None
        owners_raw = await self.probe(address, GET_OWNERS)
        if owners_raw is None:
            return None
        # The controller is whatever contract the owner chose, so an answer in
        # the wrong shape means "not a Safe", not that anything went wrong.
        try:
            threshold = ethrpc.decode_uint256(threshold_raw)
            owners = ethrpc.decode_addresses(owners_raw)
        except RpcError:
            return None
        if not owners or not 1 <= threshold <= len(owners):
            return None
        return Controller(
            address,
            f"safe {threshold} of {len(owners)}",
            {"signatures_needed": f"{threshold} of {len(owners)}", "signers": sorted(owners)},
        )

    async def read(self, contract: str) -> Control:
        if not await self.is_contract(contract):
            raise ControlError("there is no contract at that address")
        control = Control()
        control.implementation = await self.slot_address(contract, SLOT_IMPLEMENTATION)
        control.proxy_admin = await self.slot_address(contract, SLOT_ADMIN)
        if control.implementation is None:
            control.implementation = await self.slot_address(contract, LEGACY_SLOT_IMPLEMENTATION)
            if control.implementation is not None and control.proxy_admin is None:
                control.proxy_admin = await self.slot_address(contract, LEGACY_SLOT_ADMIN)
        control.beacon = await self.slot_address(contract, SLOT_BEACON)
        if control.beacon is not None:
            if control.implementation is None:
                control.implementation = await self.address_from(control.beacon, IMPLEMENTATION)
            control.beacon_owner = await self.address_from(control.beacon, OWNER)
        control.owner = await self.address_from(contract, OWNER)
        if control.owner is None:
            control.owner = await self.address_from(contract, GET_OWNER)
        pending = await self.address_from(contract, PENDING_OWNER)
        control.pending_owner = None if ethrpc.is_zero_address(pending) else pending

        if control.owner is not None:
            control.controllers["owner"] = await self.classify(control.owner)
        if control.beacon_owner is not None:
            control.controllers["beacon_owner"] = await self.classify(control.beacon_owner)
        if control.proxy_admin is not None:
            admin = await self.classify(control.proxy_admin)
            control.controllers["proxy_admin"] = admin
            if admin.kind == KIND_CONTRACT:
                # OpenZeppelin's ProxyAdmin is a small contract with an owner.
                control.proxy_admin_owner = await self.address_from(control.proxy_admin, OWNER)
                if control.proxy_admin_owner is not None:
                    control.controllers["proxy_admin_owner"] = await self.classify(
                        control.proxy_admin_owner
                    )
        return control


@register
class ContractControl(ScanModule):
    spec = ModuleSpec(
        name="contract_control",
        title="Who controls your contracts",
        category=Category.WEB3,
        mode=ScanMode.PASSIVE,
        description=(
            "The owner, upgrade admin and current implementation of each of your contracts, "
            "and whether control sits with a single key, read from the chain."
        ),
        requires_target=("contracts",),
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
        for contract in target.contracts:
            if contract.chain != "eth":
                failed += 1
                notes.append(
                    f"{contract.address} was not checked: chain '{contract.chain}' is not "
                    "supported yet. Only Ethereum mainnet ('eth') is."
                )
                continue
            try:
                address = validate_eth_address(contract.address)
            except ValidationError:
                failed += 1
                notes.append("A contract was not checked: its address is not valid.")
                continue
            if address in seen:
                continue
            seen.add(address)
            rpc_url = ctx.secret(RPC_SECRET[contract.chain])
            if not rpc_url:
                failed += 1
                endpoint_failed += 1
                notes.append(f"No RPC endpoint is configured for chain '{contract.chain}'.")
                continue
            reader = readers.setdefault(contract.chain, _Reader(ctx, rpc_url))
            try:
                control = await self._read(reader, address)
            except ControlError as exc:
                failed += 1
                endpoint_failed += exc.endpoint
                notes.append(f"{address} could not be read: {exc}.")
                continue
            if not control.readable:
                failed += 1
                notes.append(
                    f"No owner, upgrade admin or implementation could be read from {address}. "
                    "It may use a different kind of access control, which is not checked yet."
                )
                continue
            ref = ContractRef(chain=contract.chain, address=address, label=contract.label)
            findings.extend(self._assess(ref, control))
            assets.append(
                self.asset(
                    AssetType.CONTRACT,
                    f"{ref.chain}:{ref.address}",
                    attributes={"label": ref.label},
                    state={"upgradeable": control.upgradeable},
                )
            )
        stats = {"contracts": len(assets)}
        if failed and not assets and endpoint_failed:
            return self.result(ModuleStatus.FAILED, skip_reason=notes[0], notes=notes)
        return self.result(
            ModuleStatus.PARTIAL if failed else ModuleStatus.OK,
            assets=assets,
            findings=findings,
            notes=notes,
            stats=stats,
        )

    async def _read(self, reader: _Reader, address: str) -> Control:
        try:
            return await reader.read(address)
        except (NoAnswer, MalformedAnswer) as exc:
            raise ControlError(f"an answer was not in the expected form ({exc})") from None
        except RpcError as exc:
            # Messages from the client never hold the endpoint's address.
            raise ControlError(str(exc), endpoint=True) from None

    def _assess(self, ref: ContractRef, control: Control) -> list[Finding]:
        key = f"{ref.chain}:{ref.address}"
        name = f"Contract {short(ref.address)}"
        if ref.label:
            name += f" ({ref.label})"

        def kind(role: str) -> str | None:
            holder = control.controllers.get(role)
            return holder.kind if holder else None

        state: dict[str, Any] = {
            "owner": control.owner,
            "owner_kind": kind("owner"),
            "pending_owner": control.pending_owner,
            "proxy_admin": control.proxy_admin,
            "proxy_admin_kind": kind("proxy_admin"),
            "proxy_admin_owner": control.proxy_admin_owner,
            "proxy_admin_owner_kind": kind("proxy_admin_owner"),
            "implementation": control.implementation,
            "beacon": control.beacon,
            "beacon_owner": control.beacon_owner,
            "beacon_owner_kind": kind("beacon_owner"),
        }
        evidence: dict[str, Any] = {
            "label": ref.label,
            "upgradeable": control.upgradeable,
            "controllers": [
                {
                    "role": ROLE_NAMES[role],
                    "address": holder.address,
                    "kind": holder.kind,
                    **holder.details,
                }
                for role, holder in control.controllers.items()
            ],
        }
        final = control.final_roles()
        if final:
            summary = " and ".join(
                f"{self._describe(control.controllers[role])} ({ROLE_NAMES[role]})"
                for role in final
            )
            title = f"{name} is controlled by {summary}"
        else:
            title = f"{name} can be upgraded, but who can upgrade it could not be read"
        findings = [
            self.finding(
                "web3.contract.control",
                AssetType.CONTRACT,
                key,
                title,
                # Any change of owner, admin or implementation shows up as a changed finding.
                state=state,
                evidence=evidence,
                confidence=Confidence.CONFIRMED,
            )
        ]
        single = {
            ROLE_NAMES[role]: control.controllers[role].address
            for role in final
            if control.controllers[role].kind == KIND_ACCOUNT
        }
        if single:
            if control.upgradeable:
                title = f"{name} can be replaced by whoever holds a single key"
                note = "Raised one step: the contract is upgradeable, so its code can be swapped."
            else:
                title = f"{name} is controlled by a single key"
                note = None
            findings.append(
                self.finding(
                    "web3.contract.single_key_control",
                    AssetType.CONTRACT,
                    key,
                    title,
                    state={"single_key_controllers": single, "upgradeable": control.upgradeable},
                    evidence=evidence,
                    confidence=Confidence.CONFIRMED,
                    severity_steps=1 if control.upgradeable else 0,
                    severity_note=note,
                )
            )
        return findings

    @staticmethod
    def _describe(holder: Controller) -> str:
        if holder.kind == KIND_ACCOUNT:
            return f"an ordinary account {short(holder.address)}"
        if holder.kind == KIND_TIMELOCK:
            return f"a timelock {short(holder.address)}"
        if holder.kind == KIND_NOBODY:
            return "nobody, because ownership was given up"
        if holder.kind.startswith("safe "):
            policy = holder.kind.removeprefix("safe ")
            return f"a Safe multisig {short(holder.address)} needing {policy} signatures"
        return f"another contract {short(holder.address)}"
