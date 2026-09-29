"""Modules that read contracts and ENS names from the chain.

A local stand-in plays the RPC endpoint. It answers by method, contract
address and call data, and records every request. Nothing touches the network.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Any

import httpx
import pytest
from eth_utils.crypto import keccak

from parapet.clients import ethrpc
from parapet.core.models import ContractRef, ModuleStatus, ScanMode, Severity, Target
from parapet.core.severity import kind_info
from parapet.modules import contract_control
from parapet.modules.contract_control import ContractControl
from parapet.modules.ens_names import (
    BASE_REGISTRAR,
    ENS_REGISTRY,
    NAME_WRAPPER,
    EnsNames,
    NameRefused,
    expiry_bucket,
    labelhash,
    namehash,
    validate_name,
)
from tests.conftest import ROOT

RPC_KEY = "SECRET-RPC-KEY"
RPC = f"https://rpc.example.org/v2/{RPC_KEY}"
READ_ONLY = {"eth_call", "eth_getStorageAt", "eth_getCode"}

CONTRACT = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
OTHER_CONTRACT = "0x52908400098527886E0F7030069857D2E4169EE7"
ALICE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
BOB = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
CAROL = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
SAFE = "0x8617E340B3D01FA5F11F306F4090FD50E238070D"
TIMELOCK = "0xde709f2102306220921060314715629080e2fb77"
PROXY_ADMIN = "0x27b1fdb04752bbc536007a920d24acb045561c26"
BEACON = "0x5AAEB6053f3e94c9B9a09F33669435e7EF1bEaEE"
IMPL_V1 = "0x1111111111111111111111111111111111111111"
IMPL_V2 = "0x2222222222222222222222222222222222222222"
RESOLVER = "0x3333333333333333333333333333333333333333"
ZERO = "0x" + "0" * 40
CODE = "0x6080604052"


def word(value: int) -> str:
    return f"{value:064x}"


def address_word(address: str) -> str:
    return "0x" + address[2:].lower().rjust(64, "0")


def encode_addresses(addresses: list[str]) -> str:
    body = word(32) + word(len(addresses))
    body += "".join(a[2:].lower().rjust(64, "0") for a in addresses)
    return "0x" + body


def sel(signature: str) -> str:
    return "0x" + keccak(text=signature)[:4].hex()


class FakeChain:
    """A stand-in RPC endpoint. Unknown calls revert; unknown storage and code are empty."""

    def __init__(self) -> None:
        self.code: dict[str, str] = {}
        self.storage: dict[tuple[str, str], str] = {}
        self.calls: dict[tuple[str, str], str] = {}
        self.requests: list[dict[str, Any]] = []
        self.urls: list[str] = []

    # -- setting up ---------------------------------------------------------

    def contract(self, address: str, **functions: str) -> None:
        """Put code at an address. Keyword names are call data, values are answers."""
        self.code[address.lower()] = CODE
        for data, answer in functions.items():
            self.calls[(address.lower(), data)] = answer

    def answer(self, address: str, data: str, result: str) -> None:
        self.code.setdefault(address.lower(), CODE)
        self.calls[(address.lower(), data)] = result

    def returns_address(self, address: str, signature: str, value: str) -> None:
        self.answer(address, sel(signature), address_word(value))

    def slot(self, address: str, slot: str, value: str) -> None:
        self.storage[(address.lower(), slot)] = address_word(value)

    def safe(self, address: str, owners: list[str], threshold: int) -> None:
        self.answer(address, sel("getThreshold()"), "0x" + word(threshold))
        self.answer(address, sel("getOwners()"), encode_addresses(owners))

    def timelock(self, address: str, delay: int = 172_800) -> None:
        self.answer(address, sel("getMinDelay()"), "0x" + word(delay))

    # -- answering ----------------------------------------------------------

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.urls.append(str(request.url))
        call = json.loads(request.content)
        self.requests.append(call)
        method, params = call["method"], call["params"]
        if method == "eth_getCode":
            result: str | None = self.code.get(params[0].lower(), "0x")
        elif method == "eth_getStorageAt":
            result = self.storage.get((params[0].lower(), params[1]), "0x" + word(0))
        elif method == "eth_call":
            result = self.calls.get((params[0]["to"].lower(), params[0]["data"]))
        else:
            raise AssertionError(f"{method} must never be sent")
        if result is None:
            error = {"code": 3, "message": "execution reverted", "data": "0x"}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": error})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

    @property
    def methods(self) -> set[str]:
        return {r["method"] for r in self.requests}


@pytest.fixture
def chain() -> FakeChain:
    return FakeChain()


@pytest.fixture(autouse=True)
def rpc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PARAPET_RPC_ETH_MAINNET", RPC)


def by_kind(result: Any) -> dict[str, Any]:
    return {f.kind: f for f in result.findings}


# --- the shared client -------------------------------------------------------------


class TestEthRpc:
    def test_constants_match_their_definitions(self) -> None:
        def slot(label: str) -> str:
            return f"0x{int.from_bytes(keccak(text=label), 'big') - 1:064x}"

        assert slot("eip1967.proxy.implementation") == contract_control.SLOT_IMPLEMENTATION
        assert slot("eip1967.proxy.admin") == contract_control.SLOT_ADMIN
        assert slot("eip1967.proxy.beacon") == contract_control.SLOT_BEACON
        # Well-known selectors, as published with the contracts themselves.
        assert ethrpc.selector("owner()") == "0x8da5cb5b"
        assert ethrpc.selector("getOwners()") == "0xa0e67e2b"
        assert ethrpc.selector("getThreshold()") == "0xe75235b8"
        assert ethrpc.selector("addr(bytes32)") == "0x3b3b57de"

    def test_decoding(self) -> None:
        assert ethrpc.decode_address(address_word(ALICE)) == ALICE
        assert ethrpc.decode_uint256("0x" + word(3)) == 3
        assert ethrpc.decode_bytes32("0x" + "ab" * 32) == b"\xab" * 32
        assert ethrpc.decode_addresses(encode_addresses([ALICE, BOB])) == [ALICE, BOB]
        assert ethrpc.decode_addresses(encode_addresses([])) == []

    def test_encoding(self) -> None:
        data = ethrpc.encode_call("nameExpires(uint256)", 5)
        assert data == sel("nameExpires(uint256)") + word(5)
        assert ethrpc.encode_call("owner(bytes32)", b"\x01" * 32).endswith("01" * 32)
        with pytest.raises(ValueError):
            ethrpc.encode_call("owner(bytes32)", b"\x01" * 31)
        with pytest.raises(ValueError):
            ethrpc.encode_call("nameExpires(uint256)", 2**256)

    @pytest.mark.parametrize(
        "data",
        ["0x", "0x1234", "12" * 32, "0x" + "zz" * 32, "0x" + "f" * 64, "0x" + word(1) * 2],
    )
    def test_malformed_addresses_are_refused(self, data: str) -> None:
        with pytest.raises(ethrpc.MalformedAnswer):
            ethrpc.decode_address(data)

    @pytest.mark.parametrize(
        "data",
        [
            "0x",
            "0x1234",
            "0x" + word(32),
            "0x" + word(32) + word(5) + word(1),  # claims 5 addresses, holds 1
            "0x" + word(32) + word(10**6),  # absurd length
            "0x" + word(64) + word(1),  # offset beyond the data
            "0x" + word(32) + word(1) + "f" * 64,  # not an address
            "0x" + word(32) + word(201) + word(1) * 201,  # more than is believable
        ],
    )
    def test_malformed_arrays_are_refused(self, data: str) -> None:
        with pytest.raises(ethrpc.MalformedAnswer):
            ethrpc.decode_addresses(data)

    @pytest.mark.parametrize(
        "method",
        ["eth_sendRawTransaction", "eth_sendTransaction", "eth_sign", "personal_sign", "eth_Call"],
    )
    async def test_only_read_only_methods_are_sent(
        self, make_ctx: Any, chain: FakeChain, method: str
    ) -> None:
        with pytest.raises(ethrpc.RpcError, match="read-only"):
            await ethrpc.call(make_ctx(handler=chain), RPC, method, [])
        assert chain.requests == []

    async def test_reverts_and_empty_answers_mean_no_such_function(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        ctx = make_ctx(handler=chain)
        with pytest.raises(ethrpc.NoAnswer):
            await ethrpc.eth_call(ctx, RPC, CONTRACT, sel("owner()"))
        chain.answer(CONTRACT, sel("owner()"), "0x")
        with pytest.raises(ethrpc.NoAnswer):
            await ethrpc.eth_call(ctx, RPC, CONTRACT, sel("owner()"))

    async def test_an_endpoint_error_is_not_mistaken_for_a_revert(self, make_ctx: Any) -> None:
        def limited(request: httpx.Request) -> httpx.Response:
            error = {"code": -32005, "message": f"rate limit exceeded for {RPC}"}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": error})

        with pytest.raises(ethrpc.RpcError) as caught:
            await ethrpc.eth_call(make_ctx(handler=limited), RPC, CONTRACT, sel("owner()"))
        assert not isinstance(caught.value, ethrpc.NoAnswer)
        assert RPC_KEY not in str(caught.value)

    @pytest.mark.parametrize(
        "answer",
        [
            httpx.Response(500, text=f"boom at {RPC}"),
            httpx.Response(200, text="<html>not json</html>"),
            httpx.Response(200, json=["a", "list"]),
            httpx.Response(200, json={"jsonrpc": "2.0", "id": 1}),
            httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": 12}),
            httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"a": 1}}),
            httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0xnothex"}),
            httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x" + "00" * 300_000}),
        ],
    )
    async def test_bad_answers_raise_without_the_address(
        self, make_ctx: Any, answer: httpx.Response
    ) -> None:
        ctx = make_ctx(handler=lambda request: answer)
        for attempt in (
            ethrpc.eth_call(ctx, RPC, CONTRACT, sel("owner()")),
            ethrpc.get_code(ctx, RPC, CONTRACT),
            ethrpc.get_storage_at(ctx, RPC, CONTRACT, contract_control.SLOT_ADMIN),
        ):
            with pytest.raises(ethrpc.RpcError) as caught:
                await attempt
            assert RPC_KEY not in str(caught.value)
            assert "rpc.example.org" not in str(caught.value)
            assert caught.value.__cause__ is None

    async def test_an_unreachable_endpoint_raises_without_the_address(self, make_ctx: Any) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"cannot connect to {request.url}", request=request)

        with pytest.raises(ethrpc.RpcError) as caught:
            await ethrpc.get_code(make_ctx(handler=down), RPC, CONTRACT)
        assert RPC_KEY not in str(caught.value)
        assert caught.value.__cause__ is None, "the original error names the address"

    async def test_short_storage_answers_are_padded(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.storage[(CONTRACT.lower(), contract_control.SLOT_ADMIN)] = "0x0"
        ctx = make_ctx(handler=chain)
        value = await ethrpc.get_storage_at(ctx, RPC, CONTRACT, contract_control.SLOT_ADMIN)
        assert value == "0x" + word(0)


# --- contract_control --------------------------------------------------------------


class TestContractControl:
    def test_spec(self) -> None:
        spec = ContractControl.spec
        assert spec.mode is ScanMode.PASSIVE
        assert spec.requires_keys == ("PARAPET_RPC_ETH_MAINNET",)
        assert spec.requires_target == ("contracts",)
        assert kind_info("web3.contract.control").severity is Severity.INFO
        assert kind_info("web3.contract.single_key_control").severity is Severity.MEDIUM

    async def scan(
        self, make_ctx: Any, chain: FakeChain, *contracts: ContractRef, label: str = "Vault"
    ) -> Any:
        refs = list(contracts) or [ContractRef(chain="eth", address=CONTRACT, label=label)]
        target = Target(root_domain=ROOT, contracts=refs)
        result = await ContractControl().run(target, make_ctx(handler=chain))
        assert chain.methods <= READ_ONLY, "only read-only calls are ever made"
        assert set(chain.urls) <= {RPC}
        assert RPC_KEY not in result.model_dump_json()
        return result

    async def test_owned_by_an_ordinary_account(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.returns_address(CONTRACT, "owner()", ALICE)
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.OK
        found = by_kind(result)
        control = found["web3.contract.control"]
        assert control.severity is Severity.INFO
        assert control.state["owner"] == ALICE
        assert control.state["owner_kind"] == "account"
        assert control.state["implementation"] is None
        assert control.identity == {}
        assert control.asset_key == f"eth:{CONTRACT}"
        assert "Vault" in control.title
        single = found["web3.contract.single_key_control"]
        assert single.severity is Severity.MEDIUM
        assert single.state["single_key_controllers"] == {"owner": ALICE}
        [asset] = result.assets
        assert asset.key == f"eth:{CONTRACT}".lower()
        assert asset.state == {"upgradeable": False}

    async def test_upgradeable_and_single_key_is_one_step_up(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.returns_address(CONTRACT, "owner()", ALICE)
        chain.slot(CONTRACT, contract_control.SLOT_IMPLEMENTATION, IMPL_V1)
        found = by_kind(await self.scan(make_ctx, chain))
        assert found["web3.contract.control"].state["implementation"] == IMPL_V1
        assert found["web3.contract.single_key_control"].severity is Severity.HIGH
        assert found["web3.contract.single_key_control"].severity_note

    async def test_owned_by_a_safe(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.returns_address(CONTRACT, "owner()", SAFE)
        chain.safe(SAFE, [ALICE, BOB, CAROL], 2)
        result = await self.scan(make_ctx, chain)
        [finding] = result.findings
        assert finding.kind == "web3.contract.control"
        assert finding.state["owner_kind"] == "safe 2 of 3"
        [holder] = finding.evidence["controllers"]
        assert holder["signers"] == sorted([ALICE, BOB, CAROL])
        assert "2 of 3" in finding.title

    async def test_owned_by_a_timelock(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.returns_address(CONTRACT, "owner()", TIMELOCK)
        chain.timelock(TIMELOCK)
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state["owner_kind"] == "timelock"
        assert finding.evidence["controllers"][0]["delay_seconds"] == 172_800

    async def test_owned_by_some_other_contract(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.returns_address(CONTRACT, "owner()", OTHER_CONTRACT)
        chain.contract(OTHER_CONTRACT)
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state["owner_kind"] == "contract"

    async def test_a_contract_that_only_looks_like_a_safe(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.returns_address(CONTRACT, "owner()", OTHER_CONTRACT)
        chain.safe(OTHER_CONTRACT, [ALICE], 5)  # needs more signatures than it has signers
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state["owner_kind"] == "contract"
        chain.answer(OTHER_CONTRACT, sel("getOwners()"), "0x1234")
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state["owner_kind"] == "contract"

    async def test_an_account_that_delegates_is_still_one_key(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.returns_address(CONTRACT, "owner()", ALICE)
        chain.code[ALICE.lower()] = "0xef0100" + "5a" * 20
        found = by_kind(await self.scan(make_ctx, chain))
        assert found["web3.contract.control"].state["owner_kind"] == "account"
        assert "web3.contract.single_key_control" in found

    async def test_ownership_given_up(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.returns_address(CONTRACT, "owner()", ZERO)
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state["owner_kind"] == "nobody"

    async def test_get_owner_is_used_when_owner_is_missing(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.returns_address(CONTRACT, "getOwner()", ALICE)
        found = by_kind(await self.scan(make_ctx, chain))
        assert found["web3.contract.control"].state["owner"] == ALICE

    async def test_pending_owner(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.returns_address(CONTRACT, "owner()", SAFE)
        chain.safe(SAFE, [ALICE, BOB, CAROL], 2)
        before = (await self.scan(make_ctx, chain)).findings[0]
        assert before.state["pending_owner"] is None
        chain.returns_address(CONTRACT, "pendingOwner()", BOB)
        after = (await self.scan(make_ctx, chain)).findings[0]
        assert after.state["pending_owner"] == BOB
        assert before.state != after.state

    async def test_proxy_admin_contract_owned_by_a_safe(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.contract(CONTRACT)
        chain.slot(CONTRACT, contract_control.SLOT_IMPLEMENTATION, IMPL_V1)
        chain.slot(CONTRACT, contract_control.SLOT_ADMIN, PROXY_ADMIN)
        chain.returns_address(PROXY_ADMIN, "owner()", SAFE)
        chain.safe(SAFE, [ALICE, BOB, CAROL], 3)
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state["proxy_admin"].lower() == PROXY_ADMIN
        assert finding.state["proxy_admin_kind"] == "contract"
        assert finding.state["proxy_admin_owner"] == SAFE
        assert finding.state["proxy_admin_owner_kind"] == "safe 3 of 3"
        assert finding.state["owner"] is None

    async def test_proxy_admin_contract_owned_by_an_account(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.contract(CONTRACT)
        chain.slot(CONTRACT, contract_control.SLOT_IMPLEMENTATION, IMPL_V1)
        chain.slot(CONTRACT, contract_control.SLOT_ADMIN, PROXY_ADMIN)
        chain.returns_address(PROXY_ADMIN, "owner()", ALICE)
        single = by_kind(await self.scan(make_ctx, chain))["web3.contract.single_key_control"]
        assert single.severity is Severity.HIGH
        assert single.state["single_key_controllers"] == {"owner of the upgrade admin": ALICE}

    async def test_safe_owner_does_not_hide_a_single_key_admin(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.returns_address(CONTRACT, "owner()", SAFE)
        chain.safe(SAFE, [ALICE, BOB, CAROL], 2)
        chain.slot(CONTRACT, contract_control.SLOT_IMPLEMENTATION, IMPL_V1)
        chain.slot(CONTRACT, contract_control.SLOT_ADMIN, BOB)
        found = by_kind(await self.scan(make_ctx, chain))
        assert found["web3.contract.control"].state["proxy_admin_kind"] == "account"
        single = found["web3.contract.single_key_control"]
        assert single.state["single_key_controllers"] == {"upgrade admin": BOB}

    async def test_beacon_proxy(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.contract(CONTRACT)
        chain.slot(CONTRACT, contract_control.SLOT_BEACON, BEACON)
        chain.returns_address(BEACON, "implementation()", IMPL_V1)
        chain.returns_address(BEACON, "owner()", ALICE)
        found = by_kind(await self.scan(make_ctx, chain))
        state = found["web3.contract.control"].state
        assert state["beacon"].lower() == BEACON.lower()
        assert state["implementation"] == IMPL_V1
        assert state["beacon_owner_kind"] == "account"
        assert found["web3.contract.single_key_control"].severity is Severity.HIGH

    async def test_proxy_older_than_the_standard(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.contract(CONTRACT)
        chain.slot(CONTRACT, contract_control.LEGACY_SLOT_IMPLEMENTATION, IMPL_V1)
        chain.slot(CONTRACT, contract_control.LEGACY_SLOT_ADMIN, SAFE)
        chain.safe(SAFE, [ALICE, BOB, CAROL], 2)
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state["implementation"] == IMPL_V1
        assert finding.state["proxy_admin_kind"] == "safe 2 of 3"

    async def test_each_change_alters_the_state(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.returns_address(CONTRACT, "owner()", ALICE)
        chain.slot(CONTRACT, contract_control.SLOT_IMPLEMENTATION, IMPL_V1)
        chain.slot(CONTRACT, contract_control.SLOT_ADMIN, BOB)
        seen = [(await self.scan(make_ctx, chain)).findings[0]]

        chain.returns_address(CONTRACT, "owner()", CAROL)
        seen.append((await self.scan(make_ctx, chain)).findings[0])
        assert seen[-1].state["owner"] == CAROL

        chain.slot(CONTRACT, contract_control.SLOT_ADMIN, CAROL)
        seen.append((await self.scan(make_ctx, chain)).findings[0])
        assert seen[-1].state["proxy_admin"] == CAROL

        chain.slot(CONTRACT, contract_control.SLOT_IMPLEMENTATION, IMPL_V2)
        seen.append((await self.scan(make_ctx, chain)).findings[0])
        assert seen[-1].state["implementation"] == IMPL_V2

        for before, after in pairwise(seen):
            assert before.kind == after.kind == "web3.contract.control"
            assert (before.asset_key, before.identity) == (after.asset_key, after.identity)
            assert before.state != after.state

    async def test_the_kind_of_controller_is_part_of_the_state(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.returns_address(CONTRACT, "owner()", SAFE)
        chain.safe(SAFE, [ALICE, BOB, CAROL], 2)
        before = (await self.scan(make_ctx, chain)).findings[0]
        chain.safe(SAFE, [ALICE, BOB, CAROL], 1)
        after = (await self.scan(make_ctx, chain)).findings[0]
        assert before.state["owner"] == after.state["owner"]
        assert before.state != after.state

    async def test_the_same_scan_twice_gives_the_same_state(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.returns_address(CONTRACT, "owner()", ALICE)
        first = await self.scan(make_ctx, chain)
        second = await self.scan(make_ctx, chain)
        assert [f.state for f in first.findings] == [f.state for f in second.findings]

    async def test_nothing_to_read_is_a_note(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.contract(CONTRACT)  # every call reverts
        chain.returns_address(OTHER_CONTRACT, "owner()", SAFE)
        chain.safe(SAFE, [ALICE, BOB, CAROL], 2)
        result = await self.scan(
            make_ctx, chain, ContractRef(address=CONTRACT), ContractRef(address=OTHER_CONTRACT)
        )
        assert result.status is ModuleStatus.PARTIAL
        assert [f.asset_key for f in result.findings] == [f"eth:{OTHER_CONTRACT}"]
        [note] = result.notes
        assert CONTRACT in note

    async def test_nothing_to_read_anywhere_is_partial(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.contract(CONTRACT)
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert len(result.notes) == 1

    async def test_address_without_a_contract(self, make_ctx: Any, chain: FakeChain) -> None:
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.PARTIAL
        assert "no contract" in result.notes[0]

    async def test_another_chain_is_a_note(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.returns_address(CONTRACT, "owner()", SAFE)
        chain.safe(SAFE, [ALICE, BOB, CAROL], 2)
        result = await self.scan(
            make_ctx,
            chain,
            ContractRef(chain="base", address=OTHER_CONTRACT),
            ContractRef(chain="eth", address=CONTRACT),
        )
        assert result.status is ModuleStatus.PARTIAL
        assert len(result.findings) == 1
        assert "base" in result.notes[0]
        assert all(OTHER_CONTRACT.lower() not in json.dumps(r).lower() for r in chain.requests)

    async def test_invalid_address_is_a_note(self, make_ctx: Any, chain: FakeChain) -> None:
        result = await self.scan(make_ctx, chain, ContractRef(address="0x1234"))
        assert result.status is ModuleStatus.PARTIAL
        assert chain.requests == []

    @pytest.mark.parametrize(
        "answer",
        [
            "0x1234",
            "0x" + "f" * 64,  # 32 bytes, but not an address
            "0x" + word(1) * 3,
            "0x" + "00" * 300_000,  # far larger than any honest answer
            "not hex at all",
        ],
    )
    async def test_malformed_and_oversized_answers(
        self, make_ctx: Any, chain: FakeChain, answer: str
    ) -> None:
        chain.answer(CONTRACT, sel("owner()"), answer)
        result = await self.scan(make_ctx, chain)
        assert result.status in (ModuleStatus.PARTIAL, ModuleStatus.FAILED)
        assert result.findings == []
        assert CONTRACT in result.notes[0]

    async def test_malformed_storage(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.contract(CONTRACT)
        chain.storage[(CONTRACT.lower(), contract_control.SLOT_ADMIN)] = "0x" + "f" * 64
        result = await self.scan(make_ctx, chain)
        assert result.findings == []
        assert result.status is ModuleStatus.PARTIAL

    @pytest.mark.parametrize(
        "answer",
        [
            httpx.Response(500, text=f"boom at {RPC}"),
            httpx.Response(401, json={"error": f"bad key in {RPC}"}),
            httpx.Response(200, text=f"<html>{RPC}</html>"),
            httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": RPC}},
            ),
        ],
    )
    async def test_failure_never_reveals_the_rpc_address(
        self, make_ctx: Any, answer: httpx.Response, capsys: pytest.CaptureFixture[str]
    ) -> None:
        target = Target(root_domain=ROOT, contracts=[ContractRef(address=CONTRACT)])
        result = await ContractControl().run(target, make_ctx(handler=lambda request: answer))
        assert result.status is ModuleStatus.FAILED
        assert result.skip_reason
        dumped = result.model_dump_json()
        assert RPC_KEY not in dumped
        assert "rpc.example.org" not in dumped
        captured = capsys.readouterr()
        assert RPC_KEY not in captured.out + captured.err

    async def test_unreachable_endpoint_never_reveals_the_rpc_address(self, make_ctx: Any) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout(f"timed out reaching {request.url}", request=request)

        target = Target(root_domain=ROOT, contracts=[ContractRef(address=CONTRACT)])
        result = await ContractControl().run(target, make_ctx(handler=down))
        assert result.status is ModuleStatus.FAILED
        assert RPC_KEY not in result.model_dump_json()

    async def test_no_endpoint_configured(
        self, make_ctx: Any, chain: FakeChain, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PARAPET_RPC_ETH_MAINNET")
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.FAILED
        assert chain.requests == []


# --- ens_names ---------------------------------------------------------------------

NAME = "acme.eth"


class TestEnsNaming:
    def test_namehash_vectors_from_eip_137(self) -> None:
        assert namehash("") == b"\x00" * 32
        assert (
            namehash("eth").hex()
            == "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
        )
        assert (
            namehash("foo.eth").hex()
            == "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"
        )

    def test_labelhash(self) -> None:
        assert labelhash("foo") == keccak(text="foo")
        assert namehash("foo.eth") == keccak(namehash("eth") + labelhash("foo"))

    @pytest.mark.parametrize("name", ["acme.eth", "app.acme.eth", "a-b.eth", "123.eth", "-x-.eth"])
    def test_names_accepted(self, name: str) -> None:
        assert validate_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "eth",
            ".eth",
            "acme",
            "acme.com",
            "acme.eth.",
            "acme..eth",
            "Acme.eth",
            "acme.ETH",
            " acme.eth",
            "acme.eth\n",
            "ac me.eth",
            "acme_dao.eth",
            "café.eth",
            "\u0430cme.eth",  # the first letter is Cyrillic
            "acme\u200d.eth",  # zero-width joiner
            "🦊.eth",
            "xn--caf-dma.eth",
            "acme.eth/../x",
            "a" * 300 + ".eth",
        ],
    )
    def test_names_refused(self, name: str) -> None:
        with pytest.raises(NameRefused):
            validate_name(name)

    def test_unsupported_characters_are_explained(self) -> None:
        with pytest.raises(NameRefused, match="not supported yet"):
            validate_name("café.eth")

    def test_buckets(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=UTC)

        def bucket(**delta: int) -> str | None:
            return expiry_bucket(now + timedelta(**delta), now)

        assert bucket(days=91) is None
        assert bucket(days=90) == "90d"
        assert bucket(days=31) == "90d"
        assert bucket(days=30) == "30d"
        assert bucket(days=15) == "30d"
        assert bucket(days=14) == "14d"
        assert bucket(days=8) == "14d"
        assert bucket(days=7) == "7d"
        assert bucket(seconds=1) == "7d"
        assert bucket(seconds=0) == "expired"
        assert bucket(days=-200) == "expired"


class TestEnsNames:
    def test_spec(self) -> None:
        spec = EnsNames.spec
        assert spec.mode is ScanMode.PASSIVE
        assert spec.requires_keys == ("PARAPET_RPC_ETH_MAINNET",)
        assert spec.requires_target == ("ens_names",)
        assert kind_info("web3.ens.details").severity is Severity.INFO
        assert kind_info("web3.ens.expiring").severity is Severity.MEDIUM

    def test_contract_addresses_are_well_formed(self) -> None:
        from parapet.safety.domains import validate_eth_address

        for address in (ENS_REGISTRY, BASE_REGISTRAR, NAME_WRAPPER):
            assert validate_eth_address(address) == address, "the checksum must hold"

    def register(
        self,
        chain: FakeChain,
        name: str = NAME,
        *,
        owner: str = ALICE,
        points_to: str | None = BOB,
        days_left: float = 400,
        resolver: str | None = RESOLVER,
    ) -> None:
        node = namehash(name).hex()
        label = labelhash(name.split(".")[-2]).hex()
        chain.answer(ENS_REGISTRY, sel("owner(bytes32)") + node, address_word(owner))
        chain.answer(ENS_REGISTRY, sel("resolver(bytes32)") + node, address_word(resolver or ZERO))
        if resolver and points_to:
            chain.answer(resolver, sel("addr(bytes32)") + node, address_word(points_to))
        expires = int((datetime.now(UTC) + timedelta(days=days_left)).timestamp())
        chain.answer(BASE_REGISTRAR, sel("nameExpires(uint256)") + label, "0x" + word(expires))
        if days_left > 0:
            chain.answer(BASE_REGISTRAR, sel("ownerOf(uint256)") + label, address_word(owner))
        else:
            chain.calls.pop((BASE_REGISTRAR.lower(), sel("ownerOf(uint256)") + label), None)

    async def scan(self, make_ctx: Any, chain: FakeChain, *names: str) -> Any:
        target = Target(root_domain=ROOT, ens_names=list(names) or [NAME])
        result = await EnsNames().run(target, make_ctx(handler=chain))
        assert chain.methods <= READ_ONLY, "only read-only calls are ever made"
        assert set(chain.urls) <= {RPC}
        assert RPC_KEY not in result.model_dump_json()
        return result

    async def test_details(self, make_ctx: Any, chain: FakeChain) -> None:
        self.register(chain)
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "web3.ens.details"
        assert finding.severity is Severity.INFO
        assert finding.asset_key == NAME
        assert finding.identity == {}
        assert finding.state["owner"] == ALICE
        assert finding.state["resolver"] == RESOLVER
        assert finding.state["address"] == BOB
        assert finding.evidence["held_in_name_wrapper"] is False
        assert finding.evidence["expires"]
        assert "expires" not in finding.state, "the date would change the state on renewal"
        [asset] = result.assets
        assert asset.key == NAME

    async def test_the_right_contracts_are_asked(self, make_ctx: Any, chain: FakeChain) -> None:
        self.register(chain, "foo.eth")
        await self.scan(make_ctx, chain, "foo.eth")
        asked = {(r["params"][0]["to"], r["params"][0]["data"]) for r in chain.requests}
        node = "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"
        assert (ENS_REGISTRY, "0x02571be3" + node) in asked
        assert (ENS_REGISTRY, "0x0178b8bf" + node) in asked
        assert (RESOLVER, "0x3b3b57de" + node) in asked
        assert (BASE_REGISTRAR, "0xd6e4fa86" + keccak(text="foo").hex()) in asked

    async def test_changes_alter_the_state(self, make_ctx: Any, chain: FakeChain) -> None:
        self.register(chain)
        seen = [(await self.scan(make_ctx, chain)).findings[0]]
        self.register(chain, owner=CAROL)
        seen.append((await self.scan(make_ctx, chain)).findings[0])
        self.register(chain, owner=CAROL, points_to=SAFE)
        seen.append((await self.scan(make_ctx, chain)).findings[0])
        self.register(chain, owner=CAROL, points_to=SAFE, resolver=OTHER_CONTRACT)
        seen.append((await self.scan(make_ctx, chain)).findings[0])
        for before, after in pairwise(seen):
            assert (before.asset_key, before.identity) == (after.asset_key, after.identity)
            assert before.state != after.state

    async def test_renewal_does_not_alter_the_details(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        self.register(chain, days_left=100)
        before = (await self.scan(make_ctx, chain)).findings[0]
        self.register(chain, days_left=465)
        after = (await self.scan(make_ctx, chain)).findings[0]
        assert before.state == after.state

    async def test_name_without_a_resolver(self, make_ctx: Any, chain: FakeChain) -> None:
        self.register(chain, resolver=None)
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state["resolver"] is None
        assert finding.state["address"] is None

    async def test_resolver_that_holds_no_address(self, make_ctx: Any, chain: FakeChain) -> None:
        self.register(chain, points_to=None)
        chain.contract(RESOLVER)  # addr() reverts
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.OK
        assert result.findings[0].state["address"] is None

    async def test_wrapped_name(self, make_ctx: Any, chain: FakeChain) -> None:
        self.register(chain, owner=NAME_WRAPPER)
        chain.answer(
            NAME_WRAPPER, sel("ownerOf(uint256)") + namehash(NAME).hex(), address_word(CAROL)
        )
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state["owner"] == NAME_WRAPPER
        assert finding.state["wrapped_owner"] == CAROL
        assert finding.evidence["held_in_name_wrapper"] is True
        assert "Name Wrapper" in finding.evidence["note"]

    @pytest.mark.parametrize(
        ("days_left", "bucket", "severity"),
        [
            (89.5, "90d", Severity.MEDIUM),
            (29.5, "30d", Severity.MEDIUM),
            (13.5, "14d", Severity.HIGH),
            (6.5, "7d", Severity.HIGH),
            (-5, "expired", Severity.HIGH),
            (-120, "expired", Severity.HIGH),
        ],
    )
    async def test_expiring(
        self, make_ctx: Any, chain: FakeChain, days_left: float, bucket: str, severity: Severity
    ) -> None:
        self.register(chain, days_left=days_left)
        found = by_kind(await self.scan(make_ctx, chain))
        finding = found["web3.ens.expiring"]
        assert finding.state["expires_within"] == bucket
        assert finding.severity is severity
        assert finding.identity == {}
        assert "web3.ens.details" in found
        if bucket == "expired":
            assert finding.state["in_grace_period"] is (days_left > -90)
            wording = "can still be renewed" if days_left > -90 else "registered by anyone"
            assert wording in finding.title
        else:
            assert "in_grace_period" not in finding.state

    async def test_state_is_the_same_within_a_bucket(self, make_ctx: Any, chain: FakeChain) -> None:
        self.register(chain, days_left=29)
        today = by_kind(await self.scan(make_ctx, chain))["web3.ens.expiring"]
        self.register(chain, days_left=28)
        tomorrow = by_kind(await self.scan(make_ctx, chain))["web3.ens.expiring"]
        assert today.state == tomorrow.state
        assert today.evidence["expires"] != tomorrow.evidence["expires"]

    async def test_far_from_expiry(self, make_ctx: Any, chain: FakeChain) -> None:
        self.register(chain, days_left=91)
        assert "web3.ens.expiring" not in by_kind(await self.scan(make_ctx, chain))

    async def test_a_name_below_another_depends_on_its_parent(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        self.register(chain, "app.acme.eth", days_left=10)
        found = by_kind(await self.scan(make_ctx, chain, "app.acme.eth"))
        expiring = found["web3.ens.expiring"]
        assert expiring.asset_key == "app.acme.eth"
        assert expiring.evidence["registered_name"] == "acme.eth"
        assert "acme.eth, which app.acme.eth depends on" in expiring.title

    async def test_unregistered_name(self, make_ctx: Any, chain: FakeChain) -> None:
        node = namehash(NAME).hex()
        chain.answer(ENS_REGISTRY, sel("owner(bytes32)") + node, address_word(ZERO))
        chain.answer(ENS_REGISTRY, sel("resolver(bytes32)") + node, address_word(ZERO))
        chain.answer(
            BASE_REGISTRAR,
            sel("nameExpires(uint256)") + labelhash("acme").hex(),
            "0x" + word(0),
        )
        result = await self.scan(make_ctx, chain)
        [finding] = result.findings
        assert finding.state["owner"] is None
        assert "not registered" in result.notes[0]

    async def test_refused_names_are_notes(self, make_ctx: Any, chain: FakeChain) -> None:
        self.register(chain)
        result = await self.scan(make_ctx, chain, "Acme.eth", "café.eth", "acme.com", NAME)
        assert result.status is ModuleStatus.PARTIAL
        assert len(result.notes) == 3
        assert {f.asset_key for f in result.findings} == {NAME}
        assert "not supported yet" in result.notes[1]

    async def test_only_refused_names_send_nothing(self, make_ctx: Any, chain: FakeChain) -> None:
        result = await self.scan(make_ctx, chain, "\u0430cme.eth")
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert chain.requests == []

    @pytest.mark.parametrize(
        "answer",
        ["0x1234", "0x" + "f" * 64, "0x" + word(1) * 2, "0x" + "00" * 300_000, "junk"],
    )
    async def test_malformed_and_oversized_answers(
        self, make_ctx: Any, chain: FakeChain, answer: str
    ) -> None:
        self.register(chain)
        chain.answer(ENS_REGISTRY, sel("owner(bytes32)") + namehash(NAME).hex(), answer)
        result = await self.scan(make_ctx, chain)
        assert result.status in (ModuleStatus.PARTIAL, ModuleStatus.FAILED)
        assert result.findings == []
        assert NAME in result.notes[0]

    async def test_malformed_answer_from_the_resolver(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        self.register(chain)
        chain.answer(RESOLVER, sel("addr(bytes32)") + namehash(NAME).hex(), "0x" + "f" * 64)
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []

    async def test_impossible_expiry(self, make_ctx: Any, chain: FakeChain) -> None:
        self.register(chain)
        chain.answer(
            BASE_REGISTRAR,
            sel("nameExpires(uint256)") + labelhash("acme").hex(),
            "0x" + "f" * 64,
        )
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []

    @pytest.mark.parametrize(
        "answer",
        [
            httpx.Response(500, text=f"boom at {RPC}"),
            httpx.Response(200, text=f"<html>{RPC}</html>"),
            httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": RPC}},
            ),
        ],
    )
    async def test_failure_never_reveals_the_rpc_address(
        self, make_ctx: Any, answer: httpx.Response, capsys: pytest.CaptureFixture[str]
    ) -> None:
        target = Target(root_domain=ROOT, ens_names=[NAME])
        result = await EnsNames().run(target, make_ctx(handler=lambda request: answer))
        assert result.status is ModuleStatus.FAILED
        dumped = result.model_dump_json()
        assert RPC_KEY not in dumped
        assert "rpc.example.org" not in dumped
        captured = capsys.readouterr()
        assert RPC_KEY not in captured.out + captured.err

    async def test_unreachable_endpoint_never_reveals_the_rpc_address(self, make_ctx: Any) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"cannot connect to {request.url}", request=request)

        target = Target(root_domain=ROOT, ens_names=[NAME])
        result = await EnsNames().run(target, make_ctx(handler=down))
        assert result.status is ModuleStatus.FAILED
        assert RPC_KEY not in result.model_dump_json()
