"""A small read-only Ethereum JSON-RPC client, with hand-written ABI decoding.

Only methods that read from the chain can be sent. The address of the RPC
endpoint usually holds an API key, so it never appears in a message raised or
returned from here, and nothing here writes to the log.

Every value that comes back is treated as untrusted: sizes and shapes are
checked before anything is decoded.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

import httpx
from eth_utils.address import to_checksum_address
from eth_utils.crypto import keccak

if TYPE_CHECKING:
    from perimeterwatch.core.context import ScanContext

# The only methods this client will send. None of them can change anything.
READ_ONLY_METHODS = frozenset({"eth_call", "eth_getStorageAt", "eth_getCode"})

# A contract is at most 24,576 bytes (EIP-170), which is about 49,000 hex
# characters. Anything much larger than that is not an honest answer.
MAX_RESPONSE_BYTES = 262_144
MAX_ARRAY_ITEMS = 200
ZERO_ADDRESS = "0x" + "0" * 40

_HEX = re.compile(r"0x[0-9a-fA-F]*")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
# What nodes say when a contract call fails inside the contract, as opposed to
# the endpoint itself refusing or failing. Geth and Erigon use code 3 or
# -32000 with "execution reverted"; Nethermind uses -32015 "VM execution error".
_REVERT_WORDS = ("revert", "vm execution error", "invalid opcode", "bad instruction")
_REVERT_CODES = frozenset({3, -32015})


class RpcError(Exception):
    """The endpoint failed, or answered with something that cannot be trusted."""


class MalformedAnswer(RpcError):
    """An answer arrived, but not in the form the function should return."""


class NoAnswer(RpcError):
    """The call reverted or returned nothing: the contract has no such function."""


def selector(signature: str) -> str:
    """The four-byte selector of a function, e.g. selector("owner()")."""
    return "0x" + keccak(text=signature)[:4].hex()


def encode_call(signature: str, *words: bytes | int) -> str:
    """Call data for a function whose arguments are all single 32-byte words."""
    data = selector(signature)
    for value in words:
        if isinstance(value, int):
            if not 0 <= value < 2**256:
                raise ValueError("argument does not fit in 32 bytes")
            data += f"{value:064x}"
        else:
            if len(value) != 32:
                raise ValueError("argument is not 32 bytes long")
            data += value.hex()
    return data


def _body(data: str, what: str = "answer") -> str:
    if not isinstance(data, str) or not _HEX.fullmatch(data):
        raise MalformedAnswer(f"the {what} is not hexadecimal")
    return data[2:].lower()


def decode_bytes32(data: str) -> bytes:
    body = _body(data)
    if len(body) != 64:
        raise MalformedAnswer("unexpected response length")
    return bytes.fromhex(body)


def decode_uint256(data: str) -> int:
    return int.from_bytes(decode_bytes32(data), "big")


def _word_to_address(word: str) -> str:
    if int(word[:24], 16) != 0:
        raise MalformedAnswer("value is not an address")
    return str(to_checksum_address("0x" + word[24:]))


def decode_address(data: str) -> str:
    """Decode one ABI-encoded address. The result is EIP-55 checksummed."""
    return _word_to_address(decode_bytes32(data).hex())


def decode_addresses(data: str) -> list[str]:
    """Decode an ABI-encoded address[] return value."""
    body = _body(data)
    if len(body) < 128 or len(body) % 64:
        raise MalformedAnswer("unexpected response length")
    words = [body[i : i + 64] for i in range(0, len(body), 64)]
    offset = int(words[0], 16)
    if offset % 32 or offset // 32 >= len(words):
        raise MalformedAnswer("unexpected array offset")
    start = offset // 32
    count = int(words[start], 16)
    if count > MAX_ARRAY_ITEMS or start + 1 + count > len(words):
        raise MalformedAnswer("unexpected array length")
    return [_word_to_address(word) for word in words[start + 1 : start + 1 + count]]


def is_zero_address(address: str | None) -> bool:
    return address is None or int(address, 16) == 0


def _is_revert(error: Any) -> bool:
    if not isinstance(error, dict):
        return False
    if error.get("code") in _REVERT_CODES:
        return True
    message = error.get("message")
    return isinstance(message, str) and any(w in message.lower() for w in _REVERT_WORDS)


async def call(ctx: ScanContext, rpc_url: str, method: str, params: list[Any]) -> Any:
    """Send one read-only JSON-RPC request and return its `result`.

    Raises NoAnswer if the contract call reverted, and RpcError for anything
    else that went wrong. No message ever contains the endpoint's address or
    any text supplied by the endpoint.
    """
    if method not in READ_ONLY_METHODS:
        raise RpcError(f"{method} is not a read-only method and will not be sent")
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    try:
        async with ctx.http.stream("POST", rpc_url, json=payload) as response:
            status = response.status_code
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                raw += chunk
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise RpcError("the RPC endpoint sent an answer that is too large")
    except httpx.HTTPError as exc:
        # The URL usually holds an API key, so it is never put in a message,
        # and the original exception (which may name it) is not chained.
        raise RpcError(f"the RPC endpoint could not be reached ({type(exc).__name__})") from None
    except httpx.InvalidURL:
        raise RpcError("the RPC endpoint address is not a valid URL") from None
    if status != 200:
        raise RpcError(f"the RPC endpoint answered HTTP {status}")
    try:
        body = json.loads(raw)
    except ValueError:
        raise RpcError("the RPC endpoint did not answer with JSON") from None
    if not isinstance(body, dict):
        raise RpcError("the RPC endpoint sent an unexpected answer")
    if body.get("error") is not None:
        if method == "eth_call" and _is_revert(body["error"]):
            raise NoAnswer("the contract call was rejected")
        raise RpcError("the RPC endpoint reported an error")
    if "result" not in body:
        raise RpcError("the RPC endpoint sent an unexpected answer")
    return body["result"]


def _check_address(address: str) -> str:
    if not _ADDRESS.fullmatch(address):
        raise RpcError("that is not an Ethereum address")
    return address


async def eth_call(ctx: ScanContext, rpc_url: str, to: str, data: str) -> str:
    """Call a contract function without sending a transaction.

    Returns the answer as hexadecimal. Raises NoAnswer if the call reverted or
    returned nothing, which normally means the contract has no such function.
    """
    params = [{"to": _check_address(to), "data": "0x" + _body(data, "call data")}, "latest"]
    result = await call(ctx, rpc_url, "eth_call", params)
    if result in ("0x", "", None):
        raise NoAnswer("the contract did not answer")
    return "0x" + _body(result)


async def get_storage_at(ctx: ScanContext, rpc_url: str, address: str, slot: str) -> str:
    """One 32-byte storage slot of a contract, as hexadecimal."""
    if len(_body(slot, "slot")) != 64:
        raise RpcError("a storage slot is 32 bytes long")
    params = [_check_address(address), slot, "latest"]
    result = await call(ctx, rpc_url, "eth_getStorageAt", params)
    body = _body(result)
    # Most nodes answer with all 32 bytes. A few strip leading zeros.
    if len(body) > 64:
        raise RpcError("unexpected response length")
    return "0x" + body.rjust(64, "0")


async def get_code(ctx: ScanContext, rpc_url: str, address: str) -> str:
    """The code at an address. "0x" means an ordinary account with no code."""
    result = await call(ctx, rpc_url, "eth_getCode", [_check_address(address), "latest"])
    body = _body(result)
    if len(body) % 2:
        raise RpcError("unexpected response length")
    return "0x" + body
