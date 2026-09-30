"""The Safe set-up check and the check of pointers to website content.

A local stand-in plays the RPC endpoint and a table plays DNS. Nothing touches
the network, and any HTTP request to anywhere but the stand-in fails the test.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import httpx
import pytest
from eth_utils.crypto import keccak

from perimeterwatch.clients import contenthash, ethrpc
from perimeterwatch.core.fingerprint import finding_fingerprint, finding_state_hash
from perimeterwatch.core.models import (
    Asset,
    AssetType,
    Category,
    ModuleResult,
    ModuleStatus,
    SafeRef,
    ScanMode,
    Severity,
    Target,
)
from perimeterwatch.core.severity import kind_info
from perimeterwatch.modules import frontend_pointers, safe_modules
from perimeterwatch.modules.ens_names import ENS_REGISTRY, namehash
from perimeterwatch.modules.frontend_pointers import (
    FrontendPointers,
    decode_bytes,
    parse_dnslink,
)
from perimeterwatch.modules.safe_modules import SafeModules, decode_modules_page
from tests.conftest import ROOT, FakeDns

RPC_KEY = "SECRET-RPC-KEY"
RPC = f"https://rpc.example.org/v2/{RPC_KEY}"
READ_ONLY = {"eth_call", "eth_getStorageAt", "eth_getCode"}

SAFE = "0x8617E340B3D01FA5F11F306F4090FD50E238070D"
OTHER_SAFE = "0x52908400098527886E0F7030069857D2E4169EE7"
ALICE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
BOB = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
CAROL = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
MODULE_A = "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
MODULE_B = "0x27b1fdb04752bbc536007a920d24acb045561c26"
GUARD = "0x3333333333333333333333333333333333333333"
MODULE_GUARD = "0x4444444444444444444444444444444444444444"
HANDLER = "0x5555555555555555555555555555555555555555"
SINGLETON_V1 = "0x1111111111111111111111111111111111111111"
SINGLETON_V2 = "0x2222222222222222222222222222222222222222"
RESOLVER = "0x6666666666666666666666666666666666666666"
SENTINEL = "0x0000000000000000000000000000000000000001"
ZERO = "0x" + "0" * 40
CODE = "0x6080604052"
NAME = "acme.eth"
BLIND_KEY = b"k" * 32

SAFE_KINDS = {
    "web3.safe.modules",
    "web3.safe.guard",
    "web3.safe.fallback_handler",
    "web3.safe.singleton",
}

# Published examples of a contenthash and what it decodes to.
# ENSIP-7, https://docs.ens.domains/ensip/7, section "Example".
ENSIP7_IPFS = "e3010170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f"
ENSIP7_IPFS_TEXT = "QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4"
ENSIP7_SWARM = "e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162"
ENSIP7_SWARM_TEXT = "d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162"
# The IPFS documentation gives the same identifier in both of its forms:
# https://docs.ipfs.tech/concepts/content-addressing/ ("ipfs cid format -v 1 -b base32")
IPFS_DOCS_V0 = "QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR"
IPFS_DOCS_V1 = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
# What contenthash(bytes32) returned on Ethereum mainnet on 2026-09-29.
# uniswap.eth is the well-known case of a domain name stored in place of a key.
UNISWAP_ETH = "e5010170000f6170702e756e69737761702e6f7267"
UNISWAP_ETH_TEXT = "app.uniswap.org"
# esteroids.eth holds an IPNS key.
ESTEROIDS_ETH = (
    "e5010172002408011220950b8f62b925ecc50247cc8de1084b43f854fbc452894d9a1a97d7f27d0addb8"
)
ESTEROIDS_ETH_BASE32 = "bafzaajaiaejcbfilr5rlsjpmyubepten4eeewq7ykt54iuujjwnbvf6x6j6qvxny"

CID_V1 = IPFS_DOCS_V1
CID_V1_OTHER = "bafybeibj6lixxzqtsb45ysdjnupvqkufgdvzqbnvmhw2kf7cfkesy7r7d4"
IPNS_KEY = "k51qzi5uqu5djwbl0zcd4g9onue26a8nq97c0m9wp6kir1gibuyjxpkqpoxwag"


def word(value: int) -> str:
    return f"{value:064x}"


def address_word(address: str) -> str:
    return "0x" + address[2:].lower().rjust(64, "0")


def encode_addresses(addresses: list[str]) -> str:
    body = word(32) + word(len(addresses))
    body += "".join(a[2:].lower().rjust(64, "0") for a in addresses)
    return "0x" + body


def encode_page(addresses: list[str], following: str) -> str:
    body = word(64) + following[2:].lower().rjust(64, "0") + word(len(addresses))
    body += "".join(a[2:].lower().rjust(64, "0") for a in addresses)
    return "0x" + body


def encode_bytes(value: bytes) -> str:
    padded = value + b"\x00" * (-len(value) % 32)
    return "0x" + word(32) + word(len(value)) + padded.hex()


def sel(signature: str) -> str:
    return "0x" + keccak(text=signature)[:4].hex()


def base58_decode(text: str) -> bytes:
    number = 0
    for character in text:
        number = number * 58 + contenthash.BASE58_ALPHABET.index(character)
    return number.to_bytes(34, "big")


PAGINATED = sel("getModulesPaginated(address,uint256)")


class FakeSafe:
    """The list of modules, answered page by page as the real contract does."""

    def __init__(self, modules: list[str], *, old_paging: bool = False) -> None:
        self.modules = [m.lower() for m in modules]
        # Safe up to 1.3.0 names the module after the page; later ones the last of the page.
        self.old_paging = old_paging
        self.page_sizes: list[int] = []
        self.starts: list[str] = []

    def page(self, data: str) -> str | None:
        start = "0x" + data[10 + 24 : 10 + 64]
        size = int(data[10 + 64 : 10 + 128], 16)
        self.starts.append(start)
        self.page_sizes.append(size)
        chain = [SENTINEL, *self.modules, SENTINEL]
        if start not in chain[:-1] or size == 0:
            return None
        rest = chain[chain.index(start) + 1 :]
        page = [m for m in rest[:size] if m != SENTINEL]
        following = rest[len(page)]
        if following != SENTINEL and not self.old_paging:
            following = page[-1]
        return encode_page(page, following)


class FakeChain:
    """A stand-in RPC endpoint. Unknown calls revert; unknown storage and code are empty."""

    def __init__(self) -> None:
        self.code: dict[str, str] = {}
        self.storage: dict[tuple[str, str], str] = {}
        self.calls: dict[tuple[str, str], str] = {}
        self.safes: dict[str, FakeSafe] = {}
        self.requests: list[dict[str, Any]] = []
        self.urls: list[str] = []
        # Set to the number of a request, counted from 0, to make it go wrong.
        self.break_at: int | None = None
        self.break_with: httpx.Response | None = None

    def answer(self, address: str, data: str, result: str) -> None:
        self.code.setdefault(address.lower(), CODE)
        self.calls[(address.lower(), data)] = result

    def slot(self, address: str, slot: str, value: str) -> None:
        self.storage[(address.lower(), slot)] = address_word(value)

    def safe(
        self,
        address: str = SAFE,
        *,
        modules: list[str] | None = None,
        guard: str = ZERO,
        module_guard: str = ZERO,
        handler: str = HANDLER,
        singleton: str = SINGLETON_V1,
        old_paging: bool = False,
        code_at_modules: bool = True,
    ) -> FakeSafe:
        self.answer(address, sel("getThreshold()"), "0x" + word(2))
        self.answer(address, sel("getOwners()"), encode_addresses([ALICE, BOB, CAROL]))
        fake = FakeSafe(modules or [], old_paging=old_paging)
        self.safes[address.lower()] = fake
        self.slot(address, safe_modules.SLOT_SINGLETON, singleton)
        self.slot(address, safe_modules.SLOT_GUARD, guard)
        self.slot(address, safe_modules.SLOT_MODULE_GUARD, module_guard)
        self.slot(address, safe_modules.SLOT_FALLBACK_HANDLER, handler)
        for module in modules or []:
            if code_at_modules:
                self.code[module.lower()] = CODE
        return fake

    def ens(
        self, name: str = NAME, value: bytes | str | None = b"", resolver: str = RESOLVER
    ) -> None:
        """Give a name a resolver and a contenthash. None makes contenthash() revert."""
        node = namehash(name).hex()
        self.answer(ENS_REGISTRY, sel("resolver(bytes32)") + node, address_word(resolver))
        if resolver == ZERO:
            return
        self.code[resolver.lower()] = CODE
        key = (resolver.lower(), sel("contenthash(bytes32)") + node)
        if value is None:
            self.calls.pop(key, None)
        else:
            self.calls[key] = value if isinstance(value, str) else encode_bytes(value)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.urls.append(str(request.url))
        call = json.loads(request.content)
        number = len(self.requests)
        self.requests.append(call)
        method, params = call["method"], call["params"]
        if method not in READ_ONLY:
            raise AssertionError(f"{method} must never be sent")
        if self.break_at is not None and number >= self.break_at:
            if self.break_with is None:
                raise httpx.ConnectError(f"cannot connect to {request.url}", request=request)
            return self.break_with
        result: str | None
        if method == "eth_getCode":
            result = self.code.get(params[0].lower(), "0x")
        elif method == "eth_getStorageAt":
            result = self.storage.get((params[0].lower(), params[1]), "0x" + word(0))
        else:
            to, data = params[0]["to"].lower(), params[0]["data"]
            if data.startswith(PAGINATED) and (to, data) not in self.calls and to in self.safes:
                result = self.safes[to].page(data)
            else:
                result = self.calls.get((to, data))
        if result is None:
            error = {"code": 3, "message": "execution reverted", "data": "0x"}
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": error})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

    @property
    def methods(self) -> set[str]:
        return {r["method"] for r in self.requests}


EMPTY_ANSWER = httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x"})
FAILURES = [
    None,  # the endpoint cannot be reached
    httpx.Response(429, text=f"slow down, {RPC}"),
    httpx.Response(500, text=f"boom at {RPC}"),
    httpx.Response(200, text=f"<html>{RPC}</html>"),
    httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32005, "message": "rate limited"}},
    ),
    httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": 1, "error": {"code": 429, "message": f"too many, {RPC}"}},
    ),
    httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": None}),
    EMPTY_ANSWER,
    httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": "0x" + "00" * 300_000}),
]
FAILURE_NAMES = [
    "unreachable",
    "http-429",
    "http-500",
    "not-json",
    "rate-limited",
    "error-429",
    "null",
    "empty",
    "oversized",
]


@pytest.fixture
def chain() -> FakeChain:
    return FakeChain()


@pytest.fixture(autouse=True)
def rpc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PW_RPC_ETH_MAINNET", RPC)


def by_kind(result: Any) -> dict[str, Any]:
    return {f.kind: f for f in result.findings}


def fingerprint(finding: Any) -> str:
    return finding_fingerprint(ROOT, finding, BLIND_KEY)


def check_result(result: ModuleResult, chain: FakeChain | None = None) -> None:
    """What must hold for every result, whatever happened."""
    if chain is not None:
        assert chain.methods <= READ_ONLY, "only read-only calls are ever made"
        assert set(chain.urls) <= {RPC}, "nothing but the RPC endpoint is contacted"
    dumped = result.model_dump_json()
    assert RPC_KEY not in dumped
    assert "rpc.example.org" not in dumped
    assert "\u2014" not in json.loads(dumped).__repr__(), "no em dashes"


# --- constants ---------------------------------------------------------------------


class TestConstants:
    def test_safe_storage_slots_match_their_labels(self) -> None:
        def slot(label: str) -> str:
            return "0x" + keccak(text=label).hex()

        assert slot("guard_manager.guard.address") == safe_modules.SLOT_GUARD
        assert slot("fallback_manager.handler.address") == safe_modules.SLOT_FALLBACK_HANDLER
        assert slot("module_manager.module_guard.address") == safe_modules.SLOT_MODULE_GUARD
        assert safe_modules.SLOT_SINGLETON == "0x" + word(0)
        assert int(safe_modules.SENTINEL, 16) == 1

    def test_selectors(self) -> None:
        # As published with the contracts: getModulesPaginated in Safe's
        # ModuleManager, and ENSIP-7 gives 0xbc1c58d1 for contenthash.
        assert sel(safe_modules.SIG_MODULES_PAGINATED) == "0xcc2f8452"
        assert safe_modules.GET_THRESHOLD == "0xe75235b8"
        assert safe_modules.GET_OWNERS == "0xa0e67e2b"
        assert safe_modules.GET_MODULES == "0xb2494df3"
        assert sel(frontend_pointers.SIG_CONTENTHASH) == "0xbc1c58d1"
        assert sel(frontend_pointers.SIG_RESOLVER) == "0x0178b8bf"

    def test_the_kinds_exist_and_alert_on_change(self) -> None:
        expected = {
            "web3.safe.modules": (Severity.INFO, Severity.CRITICAL),
            "web3.safe.module_enabled": (Severity.MEDIUM, None),
            "web3.safe.guard": (Severity.INFO, Severity.HIGH),
            "web3.safe.fallback_handler": (Severity.INFO, Severity.HIGH),
            "web3.safe.singleton": (Severity.INFO, Severity.CRITICAL),
            "web3.ens.contenthash": (Severity.INFO, Severity.HIGH),
            "dns.dnslink": (Severity.INFO, Severity.HIGH),
        }
        for kind, (severity, on_change) in expected.items():
            info = kind_info(kind)
            assert info.severity is severity
            assert info.change_severity == on_change

    def test_specs(self) -> None:
        spec = SafeModules.spec
        assert spec.name == "safe_modules"
        assert spec.category is Category.WEB3
        assert spec.mode is ScanMode.PASSIVE
        assert spec.requires_target == ("safes",)
        assert spec.requires_keys == ("PW_RPC_ETH_MAINNET",)
        spec = FrontendPointers.spec
        assert spec.name == "frontend_pointers"
        assert spec.category is Category.SUPPLY_CHAIN
        assert spec.mode is ScanMode.PASSIVE
        assert spec.depends_on == ("subdomains",)
        assert spec.requires_keys == (), "the DNSLink part must run without a key"
        assert spec.optional_keys == ("PW_RPC_ETH_MAINNET",)
        assert spec.requires_target == ()


# --- safe_modules ------------------------------------------------------------------


class TestSafeModules:
    async def scan(self, make_ctx: Any, chain: FakeChain, *safes: SafeRef) -> ModuleResult:
        refs = list(safes) or [SafeRef(chain="eth", address=SAFE)]
        target = Target(root_domain=ROOT, safes=refs)
        result = await SafeModules().run(target, make_ctx(handler=chain))
        check_result(result, chain)
        return result

    async def test_every_finding(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.safe(modules=[MODULE_B, MODULE_A], guard=GUARD)
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.OK
        assert result.notes == []
        found = by_kind(result)
        assert set(found) == SAFE_KINDS | {"web3.safe.module_enabled"}

        modules = found["web3.safe.modules"]
        assert modules.severity is Severity.INFO
        assert modules.asset_type is AssetType.SAFE
        assert modules.asset_key == f"eth:{SAFE}"
        assert modules.identity == {}
        expected = sorted(
            [ethrpc.decode_address(address_word(m)) for m in (MODULE_A, MODULE_B)],
            key=str.lower,
        )
        assert modules.state == {"modules": expected}
        assert "2 modules" in modules.title

        enabled = [f for f in result.findings if f.kind == "web3.safe.module_enabled"]
        assert [f.identity["module"] for f in enabled] == expected
        assert all(f.severity is Severity.MEDIUM for f in enabled)
        assert all(f.evidence["holds_contract_code"] is True for f in enabled)
        assert len({fingerprint(f) for f in enabled}) == 2

        assert found["web3.safe.guard"].state == {"guard": GUARD, "module_guard": "none"}
        assert found["web3.safe.fallback_handler"].state == {"fallback_handler": HANDLER}
        assert found["web3.safe.singleton"].state == {"singleton": SINGLETON_V1}
        for kind in SAFE_KINDS:
            assert found[kind].severity is Severity.INFO
            assert found[kind].identity == {}
        [asset] = result.assets
        assert asset.type is AssetType.SAFE
        assert asset.key == f"eth:{SAFE}".lower()
        assert asset.state == {}
        assert result.stats == {"safes": 1, "modules": 2}

    async def test_the_right_questions_are_asked(self, make_ctx: Any, chain: FakeChain) -> None:
        fake = chain.safe(modules=[MODULE_A])
        await self.scan(make_ctx, chain)
        assert fake.starts == [SENTINEL]
        assert fake.page_sizes == [50]
        slots = {r["params"][1] for r in chain.requests if r["method"] == "eth_getStorageAt"}
        assert slots == {
            "0x" + word(0),
            "0x" + keccak(text="guard_manager.guard.address").hex(),
            "0x" + keccak(text="fallback_manager.handler.address").hex(),
            "0x" + keccak(text="module_manager.module_guard.address").hex(),
        }

    async def test_safe_with_no_modules(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.safe(handler=ZERO)
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.OK
        found = by_kind(result)
        assert set(found) == SAFE_KINDS
        assert found["web3.safe.modules"].state == {"modules": []}
        assert "no modules" in found["web3.safe.modules"].title
        assert found["web3.safe.guard"].state == {"guard": "none", "module_guard": "none"}
        assert found["web3.safe.fallback_handler"].state == {"fallback_handler": "none"}

    async def test_module_without_code(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.safe(modules=[MODULE_A], code_at_modules=False)
        found = by_kind(await self.scan(make_ctx, chain))
        enabled = found["web3.safe.module_enabled"]
        assert enabled.evidence["holds_contract_code"] is False
        assert "no contract code" in enabled.title
        assert found["web3.safe.modules"].evidence["modules"] == [
            {"address": MODULE_A, "holds_contract_code": False}
        ]

    async def test_account_that_delegates_is_not_a_contract(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.safe(modules=[MODULE_A])
        chain.code[MODULE_A.lower()] = "0xef0100" + SINGLETON_V1[2:]
        found = by_kind(await self.scan(make_ctx, chain))
        assert found["web3.safe.module_enabled"].evidence["holds_contract_code"] is False

    async def test_module_guard(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.safe(module_guard=MODULE_GUARD)
        found = by_kind(await self.scan(make_ctx, chain))
        assert found["web3.safe.guard"].state == {"guard": "none", "module_guard": MODULE_GUARD}
        assert "module guard" in found["web3.safe.guard"].title

    async def test_safe_that_names_no_singleton(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.safe(singleton=ZERO)
        found = by_kind(await self.scan(make_ctx, chain))
        assert found["web3.safe.singleton"].state == {"singleton": "none"}

    @pytest.mark.parametrize(
        ("kind", "before", "after"),
        [
            ("web3.safe.modules", {"modules": [MODULE_A]}, {"modules": [MODULE_A, MODULE_B]}),
            ("web3.safe.modules", {"modules": [MODULE_A, MODULE_B]}, {"modules": [MODULE_A]}),
            ("web3.safe.modules", {"modules": [MODULE_A]}, {"modules": []}),
            ("web3.safe.modules", {"modules": [MODULE_A]}, {"modules": [MODULE_B]}),
            ("web3.safe.guard", {}, {"guard": GUARD}),
            ("web3.safe.guard", {"guard": GUARD}, {}),
            ("web3.safe.guard", {}, {"module_guard": MODULE_GUARD}),
            ("web3.safe.fallback_handler", {}, {"handler": GUARD}),
            ("web3.safe.singleton", {}, {"singleton": SINGLETON_V2}),
        ],
    )
    async def test_a_change_alters_the_state_and_not_the_identity(
        self,
        make_ctx: Any,
        kind: str,
        before: dict[str, Any],
        after: dict[str, Any],
    ) -> None:
        first, second = FakeChain(), FakeChain()
        first.safe(**before)
        second.safe(**after)
        old = by_kind(await self.scan(make_ctx, first))
        new = by_kind(await self.scan(make_ctx, second))
        assert fingerprint(old[kind]) == fingerprint(new[kind])
        assert old[kind].state != new[kind].state
        assert finding_state_hash(old[kind]) != finding_state_hash(new[kind])
        for other in SAFE_KINDS - {kind}:
            assert fingerprint(old[other]) == fingerprint(new[other])
            assert finding_state_hash(old[other]) == finding_state_hash(new[other])

    async def test_the_same_safe_twice_gives_the_same_state(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.safe(modules=[MODULE_A, MODULE_B], guard=GUARD)
        first = await self.scan(make_ctx, chain)
        # The order the contract lists them in is not part of the state.
        chain.safe(modules=[MODULE_B, MODULE_A], guard=GUARD)
        second = await self.scan(make_ctx, chain)
        assert [finding_state_hash(f) for f in first.findings] == [
            finding_state_hash(f) for f in second.findings
        ]
        assert [fingerprint(f) for f in first.findings] == [fingerprint(f) for f in second.findings]

    @pytest.mark.parametrize("old_paging", [False, True])
    @pytest.mark.parametrize("count", [49, 50, 51, 100, 101, 120, 499])
    async def test_pagination(
        self, make_ctx: Any, chain: FakeChain, count: int, old_paging: bool
    ) -> None:
        modules = [f"0x{n:040x}" for n in range(0x1000, 0x1000 + count)]
        fake = chain.safe(modules=modules, old_paging=old_paging)
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.OK
        found = by_kind(result)
        listed = found["web3.safe.modules"].state["modules"]
        assert [m.lower() for m in listed] == modules, "none missed and none listed twice"
        assert (len(fake.starts) > 1) is (count > 50)
        assert len(fake.starts) <= 10
        enabled = [f for f in result.findings if f.kind == "web3.safe.module_enabled"]
        assert len(enabled) == count

    @pytest.mark.parametrize("old_paging", [False, True])
    async def test_the_page_cap(self, make_ctx: Any, chain: FakeChain, old_paging: bool) -> None:
        modules = [f"0x{n:040x}" for n in range(0x1000, 0x1000 + 600)]
        fake = chain.safe(modules=modules, old_paging=old_paging)
        result = await self.scan(make_ctx, chain)
        assert len(fake.starts) == 10, "ten pages and no more"
        assert set(fake.page_sizes) == {50}
        # A list that was cut short would look like modules being removed later.
        assert result.findings == []
        assert result.status is ModuleStatus.PARTIAL
        assert "more than 500 modules" in result.notes[0]

    async def test_list_that_goes_round_in_a_circle(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.safe()
        for start in (SENTINEL, MODULE_A, MODULE_B):
            data = ethrpc.encode_call(safe_modules.SIG_MODULES_PAGINATED, int(start, 16), 50)
            following = MODULE_B if start != MODULE_B else MODULE_A
            page = [MODULE_A] if start != MODULE_A else [MODULE_B]
            chain.answer(SAFE, data, encode_page(page if start == SENTINEL else [], following))
        result = await self.scan(make_ctx, chain)
        assert result.findings == []
        assert result.status is ModuleStatus.PARTIAL
        assert len(chain.requests) < 20

    async def test_safe_1_0_0_has_no_pages(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.safe()
        del chain.safes[SAFE.lower()]  # getModulesPaginated reverts
        chain.answer(SAFE, sel("getModules()"), encode_addresses([MODULE_A]))
        found = by_kind(await self.scan(make_ctx, chain))
        assert found["web3.safe.modules"].state == {"modules": [MODULE_A]}

    async def test_address_that_is_not_a_safe(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.code[SAFE.lower()] = CODE  # a contract, but every call reverts
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert result.assets == []
        assert "does not look like a Safe" in result.notes[0]

    @pytest.mark.parametrize(
        ("threshold", "owners"),
        [
            ("0x" + word(0), encode_addresses([ALICE])),
            ("0x" + word(3), encode_addresses([ALICE, BOB])),
            ("0x" + word(1), encode_addresses([])),
            ("0x" + word(1), "0x" + word(7)),
            ("0x1234", encode_addresses([ALICE])),
            ("0x" + word(1) * 2, encode_addresses([ALICE])),
        ],
    )
    async def test_answers_a_safe_would_not_give(
        self, make_ctx: Any, chain: FakeChain, threshold: str, owners: str
    ) -> None:
        chain.safe(modules=[MODULE_A])
        chain.answer(SAFE, sel("getThreshold()"), threshold)
        chain.answer(SAFE, sel("getOwners()"), owners)
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert "does not look like a Safe" in result.notes[0]

    async def test_an_ordinary_account_is_not_a_safe(self, make_ctx: Any, chain: FakeChain) -> None:
        result = await self.scan(make_ctx, chain, SafeRef(address=ALICE))
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []

    async def test_one_good_safe_and_one_that_is_not(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.safe(modules=[MODULE_A])
        result = await self.scan(
            make_ctx, chain, SafeRef(address=OTHER_SAFE), SafeRef(address=SAFE)
        )
        assert result.status is ModuleStatus.PARTIAL
        assert {f.asset_key for f in result.findings} == {f"eth:{SAFE}"}
        assert len(result.notes) == 1

    async def test_another_chain_is_a_note(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.safe()
        result = await self.scan(
            make_ctx, chain, SafeRef(chain="base", address=OTHER_SAFE), SafeRef(address=SAFE)
        )
        assert result.status is ModuleStatus.PARTIAL
        assert "not supported yet" in result.notes[0]
        assert {f.asset_key for f in result.findings} == {f"eth:{SAFE}"}
        assert all(
            r["params"][0] != OTHER_SAFE for r in chain.requests if r["method"] != "eth_call"
        )

    async def test_invalid_address_sends_nothing(self, make_ctx: Any, chain: FakeChain) -> None:
        result = await self.scan(make_ctx, chain, SafeRef(address="0x1234"))
        assert result.status is ModuleStatus.PARTIAL
        assert chain.requests == []
        assert result.findings == []

    async def test_the_same_safe_listed_twice(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.safe()
        result = await self.scan(
            make_ctx, chain, SafeRef(address=SAFE), SafeRef(address=SAFE.lower())
        )
        assert result.status is ModuleStatus.OK
        assert len(result.findings) == len(SAFE_KINDS)

    async def test_no_endpoint_configured(
        self, make_ctx: Any, chain: FakeChain, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PW_RPC_ETH_MAINNET")
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.FAILED
        assert chain.requests == []

    async def test_reverting_module_list_is_not_an_empty_list(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.safe(modules=[MODULE_A])
        del chain.safes[SAFE.lower()]  # both ways of listing modules revert
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert "could not be read" in result.notes[0]

    async def test_revert_part_of_the_way_through_the_list(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        modules = [f"0x{n:040x}" for n in range(0x1000, 0x1000 + 60)]
        fake = chain.safe(modules=modules)
        chain.answer(
            SAFE,
            ethrpc.encode_call(safe_modules.SIG_MODULES_PAGINATED, 1, 50),
            encode_page(modules[:50], modules[49]),
        )
        fake.modules = []  # so the second page, which starts at a module, reverts
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []

    @pytest.mark.parametrize("failure", FAILURES, ids=FAILURE_NAMES)
    async def test_a_failing_endpoint_never_looks_like_a_change(
        self, make_ctx: Any, failure: httpx.Response | None
    ) -> None:
        healthy = FakeChain()
        healthy.safe(modules=[MODULE_A, MODULE_B], guard=GUARD, module_guard=MODULE_GUARD)
        complete = await self.scan(make_ctx, healthy)
        assert complete.status is ModuleStatus.OK
        total = len(healthy.requests)
        assert total >= 9
        truth = {fingerprint(f): finding_state_hash(f) for f in complete.findings}

        for position in range(total):
            chain = FakeChain()
            chain.safe(modules=[MODULE_A, MODULE_B], guard=GUARD, module_guard=MODULE_GUARD)
            chain.break_at = position
            chain.break_with = failure
            result = await self.scan(make_ctx, chain)
            # Whatever is reported must be what a healthy endpoint would have said.
            for finding in result.findings:
                assert truth[fingerprint(finding)] == finding_state_hash(finding)
            asks_for_code = chain.requests[position]["method"] == "eth_getCode"
            if failure is EMPTY_ANSWER and asks_for_code:
                # "0x" is how a node says an address holds no code, so this one
                # answer cannot be told from a true one. Only the evidence of
                # whether a module holds code depends on it, and no state does.
                assert len(result.findings) == len(complete.findings)
                continue
            assert result.status in (ModuleStatus.PARTIAL, ModuleStatus.FAILED), position
            assert result.findings == [], f"request {position} failed and findings were made"
            assert result.assets == []
            assert result.notes

    @pytest.mark.parametrize("failure", FAILURES, ids=FAILURE_NAMES)
    async def test_one_failure_in_the_middle_never_looks_like_a_change(
        self, make_ctx: Any, failure: httpx.Response | None
    ) -> None:
        """The endpoint fails once and then recovers, as a rate limit does."""
        healthy = FakeChain()
        healthy.safe(modules=[MODULE_A, MODULE_B], guard=GUARD, module_guard=MODULE_GUARD)
        complete = await self.scan(make_ctx, healthy)
        truth = {fingerprint(f): finding_state_hash(f) for f in complete.findings}
        for position in range(len(healthy.requests)):
            chain = FakeChain()
            chain.safe(modules=[MODULE_A, MODULE_B], guard=GUARD, module_guard=MODULE_GUARD)
            inner = chain.__call__
            seen = {"count": 0}

            def handler(
                request: httpx.Request,
                position: int = position,
                inner: Any = inner,
                seen: dict[str, int] = seen,
                chain: FakeChain = chain,
            ) -> httpx.Response:
                number = seen["count"]
                seen["count"] += 1
                if number != position:
                    return inner(request)  # type: ignore[no-any-return]
                chain.urls.append(str(request.url))
                if failure is None:
                    raise httpx.ConnectError(f"cannot connect to {request.url}", request=request)
                return failure

            target = Target(root_domain=ROOT, safes=[SafeRef(address=SAFE)])
            result = await SafeModules().run(target, make_ctx(handler=handler))
            check_result(result, chain)
            for finding in result.findings:
                assert truth[fingerprint(finding)] == finding_state_hash(finding)
            if failure is EMPTY_ANSWER and healthy.requests[position]["method"] == "eth_getCode":
                continue  # see the test above
            assert result.status in (ModuleStatus.PARTIAL, ModuleStatus.FAILED), position
            assert result.findings == [], f"request {position} failed and findings were made"

    async def test_endpoint_down_for_every_safe_is_a_failure(self, make_ctx: Any) -> None:
        chain = FakeChain()
        chain.break_at = 0
        result = await self.scan(
            make_ctx, chain, SafeRef(address=SAFE), SafeRef(address=OTHER_SAFE)
        )
        assert result.status is ModuleStatus.FAILED
        assert result.skip_reason
        assert "could not be read" in result.skip_reason
        assert len(result.notes) == 2

    @pytest.mark.parametrize(
        "answer",
        [
            "0x1234",
            "junk",
            "0x" + word(64) + word(1),  # no array at all
            "0x" + word(32) + word(1) + word(0),  # the offset of a plain address[]
            "0x" + word(64) + "f" * 64 + word(0),  # next is not an address
            "0x" + word(64) + word(1) + word(2) + address_word(MODULE_A)[2:],  # claims 2, holds 1
            "0x" + word(64) + word(1) + word(10**6),  # absurd length
            "0x" + word(64) + word(1) + word(1) + "f" * 64,  # the module is not an address
            encode_page([MODULE_A, MODULE_A], SENTINEL),  # listed twice
            encode_page([ZERO], SENTINEL),  # nobody
            encode_page([SENTINEL], SENTINEL),  # the marker itself
            encode_page([MODULE_A], ZERO),  # the list does not end
            encode_page([], MODULE_A),  # an empty page that says there is more
            encode_page([f"0x{n:040x}" for n in range(0x1000, 0x1000 + 51)], SENTINEL),
            encode_page([f"0x{n:040x}" for n in range(0x1000, 0x1000 + 250)], SENTINEL),
            "0x" + "00" * 300_000,
        ],
    )
    async def test_malformed_and_oversized_module_lists(
        self, make_ctx: Any, chain: FakeChain, answer: str
    ) -> None:
        chain.safe(modules=[MODULE_A])
        data = ethrpc.encode_call(safe_modules.SIG_MODULES_PAGINATED, 1, 50)
        chain.answer(SAFE, data, answer)
        result = await self.scan(make_ctx, chain)
        assert result.status in (ModuleStatus.PARTIAL, ModuleStatus.FAILED)
        assert result.findings == []
        assert SAFE in result.notes[0]

    @pytest.mark.parametrize(
        "slot",
        [
            safe_modules.SLOT_SINGLETON,
            safe_modules.SLOT_GUARD,
            safe_modules.SLOT_FALLBACK_HANDLER,
            safe_modules.SLOT_MODULE_GUARD,
        ],
    )
    @pytest.mark.parametrize(
        "value", ["0x", "", "0x" + "f" * 64, "0x" + "0" * 66, "junk", "0x" + "00" * 300_000]
    )
    async def test_malformed_and_oversized_storage(
        self, make_ctx: Any, chain: FakeChain, slot: str, value: str
    ) -> None:
        chain.safe(modules=[MODULE_A], guard=GUARD)
        chain.storage[(SAFE.lower(), slot)] = value
        result = await self.scan(make_ctx, chain)
        assert result.status in (ModuleStatus.PARTIAL, ModuleStatus.FAILED)
        assert result.findings == []

    async def test_storage_with_leading_zeros_left_out(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.safe(guard=GUARD)
        chain.storage[(SAFE.lower(), safe_modules.SLOT_GUARD)] = "0x" + GUARD[2:]
        chain.storage[(SAFE.lower(), safe_modules.SLOT_MODULE_GUARD)] = "0x0"
        found = by_kind(await self.scan(make_ctx, chain))
        assert found["web3.safe.guard"].state == {"guard": GUARD, "module_guard": "none"}

    @pytest.mark.parametrize("value", ["0x123", "junk", "0x" + "00" * 300_000])
    async def test_malformed_code(self, make_ctx: Any, chain: FakeChain, value: str) -> None:
        chain.safe(modules=[MODULE_A])
        chain.code[MODULE_A.lower()] = value
        result = await self.scan(make_ctx, chain)
        assert result.status in (ModuleStatus.PARTIAL, ModuleStatus.FAILED)
        assert result.findings == []

    def test_decoding_a_page(self) -> None:
        assert decode_modules_page(encode_page([], SENTINEL)) == ([], SENTINEL)
        page = decode_modules_page(encode_page([MODULE_A, MODULE_B.lower()], MODULE_B))
        assert page == ([MODULE_A, ethrpc.decode_address(address_word(MODULE_B))], page[1])
        for bad in (None, 12, "", "0x", "0xzz", "0x" + "zz" * 96):
            with pytest.raises(ethrpc.MalformedAnswer):
                decode_modules_page(bad)  # type: ignore[arg-type]


# --- contenthash decoding ----------------------------------------------------------


class TestContenthashDecoding:
    def test_ensip_7_ipfs_example(self) -> None:
        pointer = contenthash.decode(bytes.fromhex(ENSIP7_IPFS))
        assert pointer is not None
        assert pointer.protocol == "ipfs"
        # ENSIP-7 writes the identifier in its older form, which is kept alongside.
        assert pointer.also_written == ENSIP7_IPFS_TEXT
        assert pointer.hash == CID_V1_OTHER
        assert pointer.uri == f"ipfs://{CID_V1_OTHER}"
        # The two are the same bytes: the newer form holds the older one whole.
        assert base58_decode(ENSIP7_IPFS_TEXT) == bytes.fromhex(ENSIP7_IPFS)[4:]

    def test_ensip_7_swarm_example(self) -> None:
        pointer = contenthash.decode(bytes.fromhex(ENSIP7_SWARM))
        assert pointer is not None
        assert (pointer.protocol, pointer.hash) == ("swarm", ENSIP7_SWARM_TEXT)
        assert pointer.uri == f"bzz://{ENSIP7_SWARM_TEXT}"

    def test_the_two_forms_given_in_the_ipfs_documentation(self) -> None:
        multihash = base58_decode(IPFS_DOCS_V0)
        pointer = contenthash.decode(b"\xe3\x01\x01\x70" + multihash)
        assert pointer is not None
        assert (pointer.protocol, pointer.hash) == ("ipfs", IPFS_DOCS_V1)
        assert pointer.also_written == IPFS_DOCS_V0

    def test_cid_v0_is_shown_as_stored(self) -> None:
        pointer = contenthash.decode(b"\xe3\x01" + base58_decode(IPFS_DOCS_V0))
        assert pointer is not None
        assert (pointer.protocol, pointer.hash) == ("ipfs", IPFS_DOCS_V0)
        assert pointer.also_written is None

    def test_uniswap_eth_holds_a_domain_name(self) -> None:
        pointer = contenthash.decode(bytes.fromhex(UNISWAP_ETH))
        assert pointer is not None
        assert (pointer.protocol, pointer.hash) == ("ipns", UNISWAP_ETH_TEXT)
        assert pointer.also_written is not None
        assert pointer.also_written.startswith("b")

    def test_an_ipns_key(self) -> None:
        pointer = contenthash.decode(bytes.fromhex(ESTEROIDS_ETH))
        assert pointer is not None
        assert (pointer.protocol, pointer.hash) == ("ipns", ESTEROIDS_ETH_BASE32)
        # Base32 of the stored bytes, worked out again with the standard library.
        import base64

        stored = bytes.fromhex(ESTEROIDS_ETH)[2:]
        assert pointer.hash == "b" + base64.b32encode(stored).decode().lower().rstrip("=")
        assert pointer.also_written == IPNS_KEY
        assert int(IPNS_KEY[1:], 36) == int.from_bytes(stored, "big")

    def test_other_content_types_are_still_cids(self) -> None:
        digest = hashlib.sha256(b"x").digest()
        pointer = contenthash.decode(b"\xe3\x01\x01\x55\x12\x20" + digest)  # raw, not dag-pb
        assert pointer is not None
        assert pointer.protocol == "ipfs"
        assert pointer.hash.startswith("bafkrei")
        assert pointer.also_written is None, "only dag-pb has an older form"

    def test_empty(self) -> None:
        assert contenthash.decode(b"") is None

    @pytest.mark.parametrize(
        "raw",
        [
            "bc03" + "00" * 10,  # onion
            "bd03" + "00" * 35,  # onion3
            "90b2c605" + "11" * 32,  # skynet
            "90b2ca05" + "11" * 32,  # arweave
            "00",
            "01",
            "e2" + "11" * 32,
            "ff",  # a number that never ends
            "ffffffffffffffffffff01",  # a number that is too long
            "e30101701220",  # no hash at all
            "e381000170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f",
        ],
    )
    def test_unknown_codecs_are_never_guessed_at(self, raw: str) -> None:
        pointer = contenthash.decode(bytes.fromhex(raw))
        assert pointer is not None
        assert pointer.protocol == "unknown"
        assert pointer.hash == raw[:128]
        assert pointer.sha256 == hashlib.sha256(bytes.fromhex(raw)).hexdigest()
        assert pointer.uri is None

    @pytest.mark.parametrize("vector", [ENSIP7_IPFS, ENSIP7_SWARM, UNISWAP_ETH, ESTEROIDS_ETH])
    def test_truncated_bytes(self, vector: str) -> None:
        raw = bytes.fromhex(vector)
        for length in range(1, len(raw)):
            pointer = contenthash.decode(raw[:length])
            assert pointer is not None
            assert pointer.protocol == "unknown", length
            assert pointer.hash == raw[:length].hex()
        pointer = contenthash.decode(raw + b"\x00")
        assert pointer is not None
        assert pointer.protocol == "unknown", "bytes after the end are not ignored"

    @pytest.mark.parametrize(
        "raw",
        [
            "e30201701220" + "11" * 32,  # CID version 2
            "e3010170121f" + "11" * 31,  # sha2-256 of 31 bytes
            "e30101701b20" + "11" * 32 + "00",  # longer than it says
            "e301017000" + "",  # an empty inlined value
            "e30101700003616263",  # content inlined, not named by a hash
            "e40101701220" + "11" * 32,  # swarm, but not a swarm manifest
            "e40101fa011220" + "11" * 32,  # swarm, but not keccak-256
            "e4" + "1220" + "11" * 32,  # swarm has no older form
        ],
    )
    def test_values_that_break_their_own_rules(self, raw: str) -> None:
        pointer = contenthash.decode(bytes.fromhex(raw))
        assert pointer is not None
        assert pointer.protocol == "unknown"

    @pytest.mark.parametrize(
        "text",
        [
            b"<script>alert(1)</script>.org",
            b"../../etc/passwd",
            b"APP.UNISWAP.ORG",
            b"app uniswap.org",
            b"app.uniswap.org\n",
            b"app..uniswap.org",
            b"-app.uniswap.org",
            b"localhost",
            b"caf\xc3\xa9.org",
            b"\x00\x01\x02\x03.org",
        ],
    )
    def test_inlined_text_that_is_not_a_domain_name_is_not_shown(self, text: bytes) -> None:
        raw = b"\xe5\x01\x01\x70\x00" + bytes([len(text)]) + text
        pointer = contenthash.decode(raw)
        assert pointer is not None
        assert pointer.protocol == "ipns"
        assert pointer.hash.startswith("b")
        assert pointer.hash.isalnum()

    def test_oversized(self) -> None:
        raw = b"\xe3\x01\x01\x70\x00\xff" + b"a" * 600
        pointer = contenthash.decode(raw)
        assert pointer is not None
        assert pointer.protocol == "unknown"
        assert len(pointer.hash) == 128
        assert pointer.raw_length == len(raw)

    def test_encodings(self) -> None:
        # Test vectors of RFC 4648, section 10, in lower case and without padding.
        assert contenthash.base32_encode(b"foobar") == "mzxw6ytboi"
        assert contenthash.base32_encode(b"fo") == "mzxq"
        # Leading zero bytes are kept.
        assert contenthash.base58_encode(b"\x00\x00\x01") == "112"
        assert contenthash.base36_encode(b"\x00\x24") == "010"
        assert contenthash.read_varint(b"\xe3\x01") == (0xE3, 2)
        assert contenthash.read_varint(b"\x7f") == (0x7F, 1)

    def test_decoding_abi_bytes(self) -> None:
        assert decode_bytes(encode_bytes(b"")) == b""
        assert decode_bytes(encode_bytes(b"\x01" * 32)) == b"\x01" * 32
        assert decode_bytes(encode_bytes(bytes.fromhex(ENSIP7_IPFS))).hex() == ENSIP7_IPFS
        bad: list[Any] = [
            None,
            "",
            "0x",
            "junk",
            "0x" + word(32),
            "0x" + word(64) + word(0),  # the wrong offset
            "0x" + word(32) + word(38),  # says 38 bytes and holds none
            "0x" + word(32) + word(38) + "00" * 32,  # says 38 bytes and holds 32
            "0x" + word(32) + word(1) + "00" * 64,  # holds more than it says
            "0x" + word(32) + word(2**255),
            "0x" + word(32) + word(513) + "00" * 544,  # longer than any real contenthash
            "0x" + word(32) + word(4) + "zz" * 32,
            "0x" + word(32) + word(4) + "00" * 31,
        ]
        for data in bad:
            with pytest.raises(ethrpc.MalformedAnswer):
                decode_bytes(data)


# --- frontend_pointers: ENS --------------------------------------------------------


class TestEnsContenthash:
    async def scan(
        self, make_ctx: Any, chain: FakeChain, *names: str, root: str = ROOT
    ) -> ModuleResult:
        target = Target(root_domain=root, ens_names=list(names) or [NAME])
        result = await FrontendPointers().run(target, make_ctx(handler=chain, root=root))
        check_result(result, chain)
        return result

    async def test_ipfs(self, make_ctx: Any, chain: FakeChain, dns: FakeDns) -> None:
        chain.ens(value=bytes.fromhex(ENSIP7_IPFS))
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.kind == "web3.ens.contenthash"
        assert finding.category is Category.SUPPLY_CHAIN
        assert finding.severity is Severity.INFO
        assert finding.asset_type is AssetType.ENS_NAME
        assert finding.asset_key == NAME
        assert finding.identity == {}
        assert finding.state == {"protocol": "ipfs", "hash": CID_V1_OTHER}
        assert finding.evidence["also_written"] == ENSIP7_IPFS_TEXT
        assert finding.evidence["uri"] == f"ipfs://{CID_V1_OTHER}"
        assert finding.evidence["resolver"] == RESOLVER
        assert "note" not in finding.evidence
        assert result.stats["ens_contenthashes"] == 1

    async def test_the_right_contracts_are_asked(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.ens("foo.eth", bytes.fromhex(ENSIP7_IPFS))
        await self.scan(make_ctx, chain, "foo.eth")
        asked = [(r["params"][0]["to"], r["params"][0]["data"]) for r in chain.requests]
        # The namehash of foo.eth is given in EIP-137.
        node = "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"
        assert asked == [(ENS_REGISTRY, "0x0178b8bf" + node), (RESOLVER, "0xbc1c58d1" + node)]

    async def test_swarm(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.ens(value=bytes.fromhex(ENSIP7_SWARM))
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state == {"protocol": "swarm", "hash": ENSIP7_SWARM_TEXT}
        assert finding.evidence["uri"] == f"bzz://{ENSIP7_SWARM_TEXT}"

    @pytest.mark.parametrize(
        ("vector", "shown"),
        [(UNISWAP_ETH, UNISWAP_ETH_TEXT), (ESTEROIDS_ETH, ESTEROIDS_ETH_BASE32)],
    )
    async def test_ipns_carries_a_warning(
        self, make_ctx: Any, chain: FakeChain, vector: str, shown: str
    ) -> None:
        chain.ens(value=bytes.fromhex(vector))
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state == {"protocol": "ipns", "hash": shown}
        assert "cannot be seen" in finding.evidence["note"]

    async def test_a_change_alters_the_state_and_not_the_identity(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        seen = []
        values: list[bytes | None] = [
            bytes.fromhex(ENSIP7_IPFS),
            b"\xe3\x01\x01\x70" + base58_decode(IPFS_DOCS_V0),
            bytes.fromhex(ESTEROIDS_ETH),
            bytes.fromhex(ENSIP7_SWARM),
            bytes.fromhex("90b2c605" + "11" * 32),
            bytes.fromhex("90b2c605" + "22" * 32),
            b"",
        ]
        for value in values:
            chain.ens(value=value)
            [finding] = (await self.scan(make_ctx, chain)).findings
            seen.append(finding)
        assert len({fingerprint(f) for f in seen}) == 1
        assert len({finding_state_hash(f) for f in seen}) == len(values)

    async def test_a_change_beyond_what_is_shown_is_still_a_change(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.ens(value=bytes.fromhex("90b2c605") + b"\x11" * 100 + b"\x01")
        [before] = (await self.scan(make_ctx, chain)).findings
        chain.ens(value=bytes.fromhex("90b2c605") + b"\x11" * 100 + b"\x02")
        [after] = (await self.scan(make_ctx, chain)).findings
        assert before.state["hash"] == after.state["hash"]
        assert len(before.state["hash"]) == 128
        assert finding_state_hash(before) != finding_state_hash(after)

    async def test_the_same_value_twice_gives_the_same_state(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        chain.ens(value=bytes.fromhex(ENSIP7_IPFS))
        [first] = (await self.scan(make_ctx, chain)).findings
        [second] = (await self.scan(make_ctx, chain)).findings
        assert finding_state_hash(first) == finding_state_hash(second)

    async def test_empty_contenthash(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.ens(value=b"")
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.state == {"protocol": "none", "hash": None}
        assert "does not point to any website content" in finding.title
        assert "empty" in finding.evidence["note"]

    async def test_resolver_without_a_contenthash(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.ens(value=None)  # contenthash() reverts
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.state == {"protocol": "none", "hash": None}
        assert "does not hold a contenthash" in finding.evidence["note"]

    async def test_name_without_a_resolver(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.ens(resolver=ZERO)
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.state == {"protocol": "none", "hash": None}
        assert len(chain.requests) == 1

    async def test_unknown_codec(self, make_ctx: Any, chain: FakeChain) -> None:
        raw = "90b2c605" + "11" * 32
        chain.ens(value=bytes.fromhex(raw))
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state == {
            "protocol": "unknown",
            "hash": raw,
            "sha256": hashlib.sha256(bytes.fromhex(raw)).hexdigest(),
        }
        assert "not recognised" in finding.title
        assert "uri" not in finding.evidence

    async def test_truncated_contenthash(self, make_ctx: Any, chain: FakeChain) -> None:
        raw = bytes.fromhex(ENSIP7_IPFS)[:20]
        chain.ens(value=raw)
        [finding] = (await self.scan(make_ctx, chain)).findings
        assert finding.state["protocol"] == "unknown"
        assert finding.state["hash"] == raw.hex()

    async def test_hostile_text_in_a_contenthash_is_not_shown(
        self, make_ctx: Any, chain: FakeChain
    ) -> None:
        text = b"<script>alert(1)</script>"
        chain.ens(value=b"\xe5\x01\x01\x70\x00" + bytes([len(text)]) + text)
        result = await self.scan(make_ctx, chain)
        assert "<script" not in result.model_dump_json()
        assert result.findings[0].state["protocol"] == "ipns"

    @pytest.mark.parametrize(
        "answer",
        [
            "0x1234",
            "junk",
            "0x" + word(32),
            "0x" + word(64) + word(0),
            "0x" + word(32) + word(38) + "00" * 32,
            "0x" + word(32) + word(2**200),
            "0x" + word(32) + word(600) + "00" * 608,
            "0x" + "00" * 300_000,
        ],
    )
    async def test_malformed_and_oversized_answers(
        self, make_ctx: Any, chain: FakeChain, answer: str
    ) -> None:
        chain.ens(value=answer)
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []
        assert NAME in result.notes[0]

    @pytest.mark.parametrize("answer", ["0x1234", "0x" + "f" * 64, "0x" + word(1) * 2, "junk"])
    async def test_malformed_resolver(self, make_ctx: Any, chain: FakeChain, answer: str) -> None:
        chain.ens(value=bytes.fromhex(ENSIP7_IPFS))
        chain.answer(ENS_REGISTRY, sel("resolver(bytes32)") + namehash(NAME).hex(), answer)
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []

    async def test_registry_that_does_not_answer(self, make_ctx: Any, chain: FakeChain) -> None:
        # The registry always answers, so a revert from it says the endpoint is
        # not to be believed. It must not look like a name with no content.
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.PARTIAL
        assert result.findings == []

    @pytest.mark.parametrize("failure", FAILURES, ids=FAILURE_NAMES)
    @pytest.mark.parametrize("position", [0, 1])
    async def test_a_failing_endpoint_never_looks_like_a_change(
        self, make_ctx: Any, chain: FakeChain, failure: httpx.Response | None, position: int
    ) -> None:
        chain.ens(value=bytes.fromhex(ENSIP7_IPFS))
        chain.break_at = position
        chain.break_with = failure
        result = await self.scan(make_ctx, chain)
        if position == 1 and failure is not None and failure.status_code == 200:
            body = json.loads(failure.content) if failure.content[:1] == b"{" else {}
            if body.get("result", 1) in (None, "0x"):
                # An empty answer to eth_call is how a node says a contract has no
                # such function. It cannot be told apart from a resolver that has
                # no contenthash, and the shared client treats it as such.
                assert [f.state["protocol"] for f in result.findings] == ["none"]
                return
        assert result.status in (ModuleStatus.PARTIAL, ModuleStatus.FAILED)
        assert result.findings == []
        assert "could not be read" in result.notes[0]

    async def test_endpoint_down_and_dns_down_is_a_failure(
        self, make_ctx: Any, chain: FakeChain, dns: FakeDns
    ) -> None:
        chain.break_at = 0
        dns.errors.add(f"_dnslink.{ROOT}")
        result = await self.scan(make_ctx, chain)
        assert result.status is ModuleStatus.FAILED
        assert result.findings == []

    async def test_refused_names_are_notes(self, make_ctx: Any, chain: FakeChain) -> None:
        chain.ens(value=bytes.fromhex(ENSIP7_IPFS))
        result = await self.scan(make_ctx, chain, "Acme.eth", "café.eth", "acme.com", NAME, NAME)
        assert result.status is ModuleStatus.PARTIAL
        assert len(result.notes) == 3
        assert [f.asset_key for f in result.findings] == [NAME]

    async def test_names_without_a_key_are_not_checked(
        self, make_ctx: Any, chain: FakeChain, dns: FakeDns, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PW_RPC_ETH_MAINNET")
        dns.add(f"_dnslink.{ROOT}", "TXT", [f"dnslink=/ipfs/{CID_V1}"])
        result = await self.scan(make_ctx, chain)
        assert chain.requests == []
        # Partial, so that a contenthash found earlier is not taken to be gone.
        assert result.status is ModuleStatus.PARTIAL
        assert "PW_RPC_ETH_MAINNET" in result.notes[0]
        assert [f.kind for f in result.findings] == ["dns.dnslink"]


# --- frontend_pointers: DNSLink ----------------------------------------------------


def host_assets(*hosts: str) -> ModuleResult:
    return ModuleResult(
        module="subdomains",
        status=ModuleStatus.OK,
        assets=[
            Asset(type=AssetType.DOMAIN if h == ROOT else AssetType.SUBDOMAIN, key=h) for h in hosts
        ],
    )


HOSTILE = [
    "dnslink=/ipfs/<script>alert(1)</script>",
    "dnslink=/ipns/<script>alert(1)</script>.org",
    "dnslink=/ipfs/../../etc/passwd",
    "dnslink=/ipfs/" + CID_V1 + "/../../secret",
    "dnslink=/ipns/../app.example.org",
    "dnslink=/ipns/app..example.org",
    "dnslink=/ipns/.example.org",
    "dnslink=/ipns/-app.example.org",
    "dnslink=/ipfs/" + "a" * 129,
    "dnslink=/ipfs/" + "a" * 100_000,
    "dnslink=/ipns/" + ".".join(["a" * 60] * 5) + ".org",
    "dnslink=/ipns/" + "a" * 64 + ".org",
    "dnslink=/ipfs/" + CID_V1 + "\x00",
    "dnslink=/ipfs/" + CID_V1 + "\n",
    "dnslink=/ipfs/" + CID_V1 + "\r\nSet-Cookie: x=1",
    "dnslink=/ipfs/\x1b[31m" + CID_V1,
    "dnslink=/ipfs/" + CID_V1 + " ",
    "dnslink=/ipfs/" + CID_V1 + "?x=1",
    "dnslink=/ipfs/" + CID_V1 + "#x",
    "dnslink=/ipfs/" + CID_V1 + "/index.html",
    "dnslink=/ipfs/Qm%2e%2e",
    "dnslink=/ipfs/",
    "dnslink=/ipfs/short",
    "dnslink=/ipns/localhost",
    "dnslink=/ipns/café.org",
    "dnslink=/ipns/\u0430pp.example.org",
    "dnslink=/ipns/APP.EXAMPLE.ORG",
    "dnslink=/swarm/" + "a" * 64,
    "dnslink=/IPFS/" + CID_V1,
    "dnslink=ipfs/" + CID_V1,
    "dnslink=",
    "dnslink=javascript:alert(1)",
    "dnslink=https://evil.example/" + CID_V1,
]


class TestDnsLink:
    async def scan(
        self,
        make_ctx: Any,
        *hosts: str,
        ens_names: list[str] | None = None,
        root: str = ROOT,
    ) -> ModuleResult:
        # No handler is given, so any HTTP request at all fails the test.
        ctx = make_ctx(root=root)
        if hosts:
            ctx.assets.add(host_assets(*hosts))
        target = Target.model_construct(root_domain=root, ens_names=ens_names or [])
        result = await FrontendPointers().run(target, ctx)
        check_result(result)
        return result

    async def test_ipfs_on_the_root_domain(
        self, make_ctx: Any, dns: FakeDns, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PW_RPC_ETH_MAINNET")  # this part needs no key
        dns.add(f"_dnslink.{ROOT}", "TXT", [f"dnslink=/ipfs/{CID_V1}"])
        result = await self.scan(make_ctx)
        assert result.status is ModuleStatus.OK
        assert result.notes == []
        [finding] = result.findings
        assert finding.kind == "dns.dnslink"
        assert finding.category is Category.SUPPLY_CHAIN
        assert finding.severity is Severity.INFO
        assert finding.asset_type is AssetType.DOMAIN
        assert finding.asset_key == ROOT
        assert finding.identity == {}
        assert finding.state == {"protocol": "ipfs", "target": CID_V1}
        assert finding.evidence["points_to"] == f"/ipfs/{CID_V1}"
        assert finding.evidence["record"] == f"_dnslink.{ROOT}"
        assert dns.queries == [(f"_dnslink.{ROOT}", "TXT")]
        assert result.stats == {
            "ens_contenthashes": 0,
            "dnslink_records": 1,
            "hostnames_checked": 1,
        }

    @pytest.mark.parametrize(
        ("value", "protocol", "target"),
        [
            (f"dnslink=/ipfs/{CID_V1}", "ipfs", CID_V1),
            (f"dnslink=/ipfs/{IPFS_DOCS_V0}", "ipfs", IPFS_DOCS_V0),
            (f"dnslink=/ipns/{IPNS_KEY}", "ipns", IPNS_KEY),
            ("dnslink=/ipns/app.example.org", "ipns", "app.example.org"),
            ("dnslink=/ipns/_x.my-app.example.org", "ipns", "_x.my-app.example.org"),
        ],
    )
    async def test_valid_values(
        self, make_ctx: Any, dns: FakeDns, value: str, protocol: str, target: str
    ) -> None:
        assert parse_dnslink(value) == frontend_pointers.DnsLink(protocol, target)
        dns.add(f"_dnslink.app.{ROOT}", "TXT", [value])
        result = await self.scan(make_ctx, f"app.{ROOT}")
        assert result.status is ModuleStatus.OK
        [finding] = result.findings
        assert finding.asset_type is AssetType.SUBDOMAIN
        assert finding.asset_key == f"app.{ROOT}"
        assert finding.state == {"protocol": protocol, "target": target}
        if protocol == "ipns":
            assert "cannot be seen" in finding.evidence["note"]
        else:
            assert "note" not in finding.evidence

    async def test_every_host_in_scope_is_looked_up(self, make_ctx: Any, dns: FakeDns) -> None:
        dns.add(f"_dnslink.app.{ROOT}", "TXT", [f"dnslink=/ipfs/{CID_V1}"])
        dns.add("_dnslink.app.elsewhere.org", "TXT", [f"dnslink=/ipfs/{CID_V1}"])
        result = await self.scan(
            make_ctx,
            ROOT,
            f"app.{ROOT}",
            f"APP.{ROOT}.",
            f"docs.{ROOT}",
            "app.elsewhere.org",
            f"not{ROOT}",
            f"*.{ROOT}",
            f"bad host.{ROOT}",
            f"<script>.{ROOT}",
            f"{'a' * 64}.{ROOT}",
        )
        assert result.status is ModuleStatus.OK
        assert sorted(dns.queries) == [
            (f"_dnslink.{ROOT}", "TXT"),
            (f"_dnslink.app.{ROOT}", "TXT"),
            (f"_dnslink.docs.{ROOT}", "TXT"),
        ]
        assert [f.asset_key for f in result.findings] == [f"app.{ROOT}"]

    async def test_works_when_no_hostnames_were_found(self, make_ctx: Any, dns: FakeDns) -> None:
        result = await self.scan(make_ctx)
        assert result.status is ModuleStatus.OK
        assert result.findings == []
        assert dns.queries == [(f"_dnslink.{ROOT}", "TXT")]

    async def test_other_txt_records_are_ignored(self, make_ctx: Any, dns: FakeDns) -> None:
        dns.add(
            f"_dnslink.{ROOT}",
            "TXT",
            ["v=spf1 -all", "google-site-verification=abc", "DNSLINK=/ipfs/" + CID_V1, ""],
        )
        result = await self.scan(make_ctx)
        assert result.status is ModuleStatus.OK
        assert result.findings == []

    async def test_a_change_alters_the_state_and_not_the_identity(
        self, make_ctx: Any, dns: FakeDns
    ) -> None:
        seen = []
        values = [
            f"dnslink=/ipfs/{CID_V1}",
            f"dnslink=/ipfs/{CID_V1_OTHER}",
            f"dnslink=/ipns/{IPNS_KEY}",
            "dnslink=/ipns/app.example.org",
            "dnslink=/ipns/app.example.net",
            f"dnslink=/ipfs/{CID_V1}/index.html",
            f"dnslink=/ipfs/{CID_V1}/other.html",
        ]
        for value in values:
            dns.add(f"_dnslink.{ROOT}", "TXT", [value])
            [finding] = (await self.scan(make_ctx)).findings
            seen.append(finding)
        assert len({fingerprint(f) for f in seen}) == 1
        assert len({finding_state_hash(f) for f in seen}) == len(values)

    async def test_the_same_record_twice_gives_the_same_state(
        self, make_ctx: Any, dns: FakeDns
    ) -> None:
        dns.add(f"_dnslink.{ROOT}", "TXT", [f"dnslink=/ipfs/{CID_V1}"])
        [first] = (await self.scan(make_ctx)).findings
        [second] = (await self.scan(make_ctx)).findings
        assert finding_state_hash(first) == finding_state_hash(second)

    @pytest.mark.parametrize("value", HOSTILE)
    async def test_hostile_values(self, make_ctx: Any, dns: FakeDns, value: str) -> None:
        link = parse_dnslink(value)
        assert link is not None
        assert link.protocol == "unrecognised"
        digest = hashlib.sha256(value.encode()).hexdigest()
        assert link.target == f"sha256:{digest}"

        dns.add(f"_dnslink.{ROOT}", "TXT", [value])
        result = await self.scan(make_ctx)
        [finding] = result.findings
        # The record is there, so it is reported, but nothing of it is repeated.
        assert finding.state == {"protocol": "unrecognised", "target": f"sha256:{digest}"}
        assert "points_to" not in finding.evidence
        dumped = result.model_dump_json()
        for fragment in ("script", "passwd", "..", "Set-Cookie", "javascript", "evil", "aaaaaaaa"):
            assert fragment not in dumped
        for character in ("\\u0000", "\\n", "\\r", "\\u001b", "%2e"):
            assert character not in dumped

    async def test_a_hostile_record_beside_a_good_one(self, make_ctx: Any, dns: FakeDns) -> None:
        dns.add(
            f"_dnslink.{ROOT}",
            "TXT",
            ["dnslink=/ipfs/<script>alert(1)</script>", f"dnslink=/ipfs/{CID_V1}"],
        )
        result = await self.scan(make_ctx)
        [finding] = result.findings
        assert finding.state["protocol"] == "ipfs"
        assert finding.state["target"] == CID_V1
        [other] = finding.state["other_records"]
        assert other.startswith("unrecognised:sha256:")
        assert "script" not in result.model_dump_json()

    async def test_several_records(self, make_ctx: Any, dns: FakeDns) -> None:
        values = [f"dnslink=/ipfs/{CID_V1_OTHER}", f"dnslink=/ipfs/{CID_V1}"]
        dns.add(f"_dnslink.{ROOT}", "TXT", values)
        [first] = (await self.scan(make_ctx)).findings
        dns.add(f"_dnslink.{ROOT}", "TXT", values[::-1] + values)
        [second] = (await self.scan(make_ctx)).findings
        assert first.state == second.state, "the order of the answer does not matter"
        assert first.state["target"] == min(CID_V1, CID_V1_OTHER)
        assert len(first.state["other_records"]) == 1

    async def test_very_many_records(self, make_ctx: Any, dns: FakeDns) -> None:
        values = [f"dnslink=/ipfs/{CID_V1}{n:04d}" for n in range(500)]
        dns.add(f"_dnslink.{ROOT}", "TXT", values)
        [finding] = (await self.scan(make_ctx)).findings
        assert len(finding.state["other_records"]) == 19

    async def test_dns_errors_are_not_absence(self, make_ctx: Any, dns: FakeDns) -> None:
        dns.add(f"_dnslink.app.{ROOT}", "TXT", [f"dnslink=/ipfs/{CID_V1}"])
        dns.errors.add(f"_dnslink.{ROOT}")
        result = await self.scan(make_ctx, f"app.{ROOT}")
        # Partial, so that a record found earlier on the root is not taken to be gone.
        assert result.status is ModuleStatus.PARTIAL
        assert "could not be looked up" in result.notes[0]
        assert "1 of 2" in result.notes[0]
        assert [f.asset_key for f in result.findings] == [f"app.{ROOT}"]
        assert result.stats["hostnames_checked"] == 1

    async def test_dns_down_altogether_is_a_failure(self, make_ctx: Any, dns: FakeDns) -> None:
        dns.errors.update({f"_dnslink.{ROOT}", f"_dnslink.app.{ROOT}"})
        result = await self.scan(make_ctx, f"app.{ROOT}")
        assert result.status is ModuleStatus.FAILED
        assert result.findings == []
        assert result.skip_reason

    async def test_name_that_exists_without_a_record(self, make_ctx: Any, dns: FakeDns) -> None:
        dns.nodata.add(f"_dnslink.{ROOT}")
        result = await self.scan(make_ctx)
        assert result.status is ModuleStatus.OK
        assert result.findings == []

    async def test_too_many_hostnames(self, make_ctx: Any, dns: FakeDns) -> None:
        hosts = [f"h{n}.{ROOT}" for n in range(600)]
        result = await self.scan(make_ctx, *hosts)
        assert len(dns.queries) == 500
        assert dns.queries[0] == (f"_dnslink.{ROOT}", "TXT")
        assert result.status is ModuleStatus.PARTIAL
        assert "first 500" in result.notes[0]

    async def test_skipped_when_neither_part_applies(
        self, make_ctx: Any, dns: FakeDns, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A root that is not a hostname leaves nothing to look up.
        result = await self.scan(make_ctx, root="not a hostname")
        assert result.status is ModuleStatus.SKIPPED
        assert result.skip_reason
        assert result.hint
        assert dns.queries == []

        monkeypatch.delenv("PW_RPC_ETH_MAINNET")
        result = await self.scan(make_ctx, root="not a hostname", ens_names=[NAME])
        assert result.status is ModuleStatus.SKIPPED
        assert result.hint is not None
        assert "PW_RPC_ETH_MAINNET" in result.hint
        assert dns.queries == []


# --- both parts together -----------------------------------------------------------


class TestBothParts:
    async def test_both_parts_in_one_run(
        self, make_ctx: Any, chain: FakeChain, dns: FakeDns
    ) -> None:
        chain.ens(value=bytes.fromhex(ENSIP7_IPFS))
        dns.add(f"_dnslink.{ROOT}", "TXT", [f"dnslink=/ipfs/{CID_V1}"])
        ctx = make_ctx(handler=chain)
        target = Target(root_domain=ROOT, ens_names=[NAME])
        result = await FrontendPointers().run(target, ctx)
        check_result(result, chain)
        assert result.status is ModuleStatus.OK
        assert sorted(f.kind for f in result.findings) == ["dns.dnslink", "web3.ens.contenthash"]
        # The content is never fetched: two calls to the RPC endpoint and nothing else.
        assert len(chain.requests) == 2
        assert set(chain.urls) == {RPC}
        for finding in result.findings:
            shown = json.dumps([finding.title, finding.state, finding.evidence])
            for gateway in ("ipfs.io", "dweb.link", "http://", "https://"):
                assert gateway not in shown

    async def test_ens_part_alone_when_the_root_gives_no_hostname(
        self, make_ctx: Any, chain: FakeChain, dns: FakeDns
    ) -> None:
        chain.ens(value=bytes.fromhex(ENSIP7_IPFS))
        target = Target.model_construct(root_domain="not a hostname", ens_names=[NAME])
        result = await FrontendPointers().run(
            target, make_ctx(handler=chain, root="not a hostname")
        )
        assert result.status is ModuleStatus.OK
        assert [f.kind for f in result.findings] == ["web3.ens.contenthash"]
        assert dns.queries == []

    async def test_one_part_failing_leaves_the_other(
        self, make_ctx: Any, chain: FakeChain, dns: FakeDns
    ) -> None:
        chain.break_at = 0
        dns.add(f"_dnslink.{ROOT}", "TXT", [f"dnslink=/ipfs/{CID_V1}"])
        target = Target(root_domain=ROOT, ens_names=[NAME])
        result = await FrontendPointers().run(target, make_ctx(handler=chain))
        check_result(result, chain)
        assert result.status is ModuleStatus.PARTIAL
        assert [f.kind for f in result.findings] == ["dns.dnslink"]

    def test_neither_module_can_fetch_content(self) -> None:
        """Neither module holds the address of a gateway or asks for a web page."""
        import inspect

        for module in (frontend_pointers, contenthash, safe_modules):
            source = inspect.getsource(module)
            code = "\n".join(
                line.split("#")[0]
                for line in source.splitlines()
                if not line.strip().startswith("#")
            )
            # Docstrings name their sources, so only calls are looked for.
            for call in ("ctx.http", ".get(", ".post(", "httpx", "urlopen", "requests."):
                if call == ".get(" and module is contenthash:
                    continue  # a dictionary lookup
                assert call not in code, f"{module.__name__} uses {call}"
