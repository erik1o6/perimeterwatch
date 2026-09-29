"""Who can sign for the organisation's Safe, read straight from the chain.

Two read-only contract calls per Safe. No third-party API and no transaction.
"""

from __future__ import annotations

from typing import Any

import httpx
from eth_utils.address import to_checksum_address

from perimeterwatch.core.context import ScanContext
from perimeterwatch.core.models import (
    Asset,
    AssetType,
    Category,
    Confidence,
    Finding,
    ModuleResult,
    ModuleStatus,
    SafeRef,
    ScanMode,
    Target,
)
from perimeterwatch.core.module import ModuleSpec, ScanModule, register

GET_OWNERS = "0xa0e67e2b"  # getOwners()
GET_THRESHOLD = "0xe75235b8"  # getThreshold()
RPC_SECRET = {"eth": "PW_RPC_ETH_MAINNET"}
MAX_OWNERS = 200


class RpcError(Exception):
    pass


def decode_uint(data: str) -> int:
    body = data.removeprefix("0x")
    if len(body) != 64:
        raise RpcError("unexpected response length")
    return int(body, 16)


def decode_addresses(data: str) -> list[str]:
    """Decode an ABI-encoded address[] return value."""
    body = data.removeprefix("0x")
    if len(body) < 128 or len(body) % 64:
        raise RpcError("unexpected response length")
    words = [body[i : i + 64] for i in range(0, len(body), 64)]
    offset = int(words[0], 16)
    if offset % 32 or offset // 32 >= len(words):
        raise RpcError("unexpected array offset")
    start = offset // 32
    count = int(words[start], 16)
    if count > MAX_OWNERS or start + 1 + count > len(words):
        raise RpcError("unexpected array length")
    owners = []
    for word in words[start + 1 : start + 1 + count]:
        if int(word[:24], 16) != 0:
            raise RpcError("value is not an address")
        owners.append(str(to_checksum_address("0x" + word[24:])))
    return owners


async def eth_call(ctx: ScanContext, rpc_url: str, to: str, data: str) -> str:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"],
    }
    try:
        response = await ctx.http.post(rpc_url, json=payload)
    except httpx.TransportError as exc:
        # The URL usually holds an API key, so it is never put in a message.
        raise RpcError(f"the RPC endpoint could not be reached ({type(exc).__name__})") from exc
    if response.status_code != 200:
        raise RpcError(f"the RPC endpoint answered HTTP {response.status_code}")
    try:
        body: dict[str, Any] = response.json()
    except ValueError as exc:
        raise RpcError("the RPC endpoint did not answer with JSON") from exc
    if "error" in body:
        raise RpcError("the contract call was rejected")
    result = body.get("result")
    if not isinstance(result, str) or result in ("0x", ""):
        raise RpcError("no contract answered at that address")
    return result


@register
class SafeMultisig(ScanModule):
    spec = ModuleSpec(
        name="safe_multisig",
        title="Safe multisig signers",
        category=Category.WEB3,
        mode=ScanMode.PASSIVE,
        description="Owners and signing threshold of your Safe, read from the chain.",
        requires_target=("safes",),
        requires_keys=("PW_RPC_ETH_MAINNET",),
        contacts=("your Ethereum RPC endpoint",),
        default_timeout_s=120,
    )

    async def run(self, target: Target, ctx: ScanContext) -> ModuleResult:
        assets: list[Asset] = []
        findings: list[Finding] = []
        notes: list[str] = []
        failed = 0
        for safe in target.safes:
            rpc_url = ctx.secret(RPC_SECRET.get(safe.chain, ""))
            if not rpc_url:
                failed += 1
                notes.append(f"No RPC endpoint is configured for chain '{safe.chain}'.")
                continue
            try:
                owners = decode_addresses(await eth_call(ctx, rpc_url, safe.address, GET_OWNERS))
                threshold = decode_uint(await eth_call(ctx, rpc_url, safe.address, GET_THRESHOLD))
            except RpcError as exc:
                failed += 1
                notes.append(f"{safe.address} could not be read: {exc}.")
                continue
            if not owners or not 1 <= threshold <= len(owners):
                failed += 1
                notes.append(f"{safe.address} does not look like a Safe.")
                continue
            found = self._assess(safe, sorted(owners), threshold)
            findings.extend(found)
            assets.append(
                self.asset(
                    AssetType.SAFE,
                    f"{safe.chain}:{safe.address}",
                    attributes={"owners": sorted(owners)},
                    state={"threshold": threshold, "owner_count": len(owners)},
                )
            )
        if failed and not assets:
            return self.result(ModuleStatus.FAILED, skip_reason=notes[0], notes=notes)
        return self.result(
            ModuleStatus.PARTIAL if failed else ModuleStatus.OK,
            assets=assets,
            findings=findings,
            notes=notes,
            stats={"safes": len(assets)},
        )

    def _assess(self, safe: SafeRef, owners: list[str], threshold: int) -> list[Finding]:
        key = f"{safe.chain}:{safe.address}"
        policy = f"{threshold} of {len(owners)}"
        evidence = {"signatures_needed": policy, "owners": owners}
        findings = [
            self.finding(
                "web3.safe.owners",
                AssetType.SAFE,
                key,
                f"Safe {safe.address[:10]}… needs {policy} signatures",
                # Any change to owners or threshold shows up as a changed finding.
                state={"owners": owners, "threshold": threshold},
                evidence=evidence,
                confidence=Confidence.CONFIRMED,
            )
        ]
        if threshold == 1:
            findings.append(
                self.finding(
                    "web3.safe.low_threshold",
                    AssetType.SAFE,
                    key,
                    f"Safe {safe.address[:10]}… can be controlled by a single key",
                    evidence=evidence,
                    confidence=Confidence.CONFIRMED,
                )
            )
        if len(owners) < 3:
            findings.append(
                self.finding(
                    "web3.safe.few_owners",
                    AssetType.SAFE,
                    key,
                    f"Safe {safe.address[:10]}… has only {len(owners)} owner(s)",
                    evidence=evidence,
                    confidence=Confidence.CONFIRMED,
                )
            )
        elif threshold == len(owners):
            findings.append(
                self.finding(
                    "web3.safe.threshold_equals_owners",
                    AssetType.SAFE,
                    key,
                    f"Safe {safe.address[:10]}… needs every owner to sign",
                    evidence=evidence,
                    confidence=Confidence.CONFIRMED,
                )
            )
        return findings
