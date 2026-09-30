"""Decoding of the ENS contenthash field, and the few encodings it needs.

The field holds a protocol code followed by a content identifier (CID).
Source: ENSIP-7, https://docs.ens.domains/ensip/7
    <protoCode uvarint><cid-version><multicodec-content-type><multihash-content-address>
Protocol and hash codes are from the multicodec table:
https://github.com/multiformats/multicodec/blob/master/table.csv

Nothing here touches the network. The bytes come from a contract anyone may
have written, so every length is checked, and anything that is not understood
in full is reported as "unknown" with its raw bytes rather than guessed at.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

# Protocol codes (multicodec table, tag "namespace").
IPFS_NS = 0xE3
SWARM_NS = 0xE4
IPNS_NS = 0xE5
PROTOCOLS = {IPFS_NS: "ipfs", IPNS_NS: "ipns", SWARM_NS: "swarm"}

# Content types and hash functions (multicodec table).
DAG_PB = 0x70
LIBP2P_KEY = 0x72
SWARM_MANIFEST = 0xFA
IDENTITY = 0x00
SHA2_256 = 0x12
KECCAK_256 = 0x1B
# Hash functions whose length is fixed. Any other length is not an honest value.
DIGEST_LENGTHS = {SHA2_256: 32, KECCAK_256: 32}

MAX_CONTENTHASH_BYTES = 512
MAX_RAW_HEX = 128
# An unsigned varint is at most nine bytes long.
# Source: https://github.com/multiformats/unsigned-varint
MAX_VARINT_BYTES = 9

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE36_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"

PROTOCOL_UNKNOWN = "unknown"

# Some names, uniswap.eth among them, hold a plain domain name in place of an
# IPNS key: the text is stored whole under the "identity" hash, which hashes
# nothing. Only text that is plainly a domain name is shown as one.
_DOMAIN = re.compile(
    rb"(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
)


class NotUnderstood(Exception):
    """The bytes do not have the form they claim to have."""


@dataclass(frozen=True)
class ContentPointer:
    protocol: str
    # The content identifier as text. For an unknown protocol, the raw bytes in
    # hexadecimal, cut to MAX_RAW_HEX characters.
    hash: str
    # The same identifier in the other form people commonly see, if there is one.
    also_written: str | None = None
    # Set for an unknown protocol only: a digest of all the bytes, so that a
    # change beyond the part shown is still a change.
    sha256: str | None = None
    raw_length: int = 0

    @property
    def known(self) -> bool:
        return self.protocol != PROTOCOL_UNKNOWN

    @property
    def uri(self) -> str | None:
        if not self.known:
            return None
        scheme = "bzz" if self.protocol == "swarm" else self.protocol
        return f"{scheme}://{self.hash}"


def read_varint(data: bytes, start: int = 0) -> tuple[int, int]:
    """Read one unsigned varint. Returns the number and the position after it."""
    value = 0
    for count in range(MAX_VARINT_BYTES):
        position = start + count
        if position >= len(data):
            raise NotUnderstood("the value ends in the middle of a number")
        byte = data[position]
        value |= (byte & 0x7F) << (7 * count)
        if not byte & 0x80:
            if count and byte == 0:
                raise NotUnderstood("a number is not written in its shortest form")
            return value, position + 1
    raise NotUnderstood("a number is too long")


def base58_encode(data: bytes) -> str:
    """Base58 with the Bitcoin alphabet, as used for CIDv0."""
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 58)
        out = BASE58_ALPHABET[remainder] + out
    zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * zeros + out


def base32_encode(data: bytes) -> str:
    """Lower-case base32 without padding (RFC 4648), as used for CIDv1."""
    return base64.b32encode(data).decode("ascii").lower().rstrip("=")


def base36_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 36)
        out = BASE36_ALPHABET[remainder] + out
    zeros = len(data) - len(data.lstrip(b"\x00"))
    return "0" * zeros + out


@dataclass(frozen=True)
class Cid:
    version: int
    codec: int
    hash_code: int
    digest: bytes
    raw: bytes

    @property
    def multihash(self) -> bytes:
        return self.raw if self.version == 0 else self.raw[-self._multihash_length :]

    @property
    def _multihash_length(self) -> int:
        return len(_varint(self.hash_code)) + len(_varint(len(self.digest))) + len(self.digest)

    def text(self) -> str:
        """CIDv0 in base58, CIDv1 in base32 with its "b" prefix."""
        if self.version == 0:
            return base58_encode(self.raw)
        return "b" + base32_encode(self.raw)


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _read_multihash(data: bytes, start: int) -> tuple[int, bytes]:
    hash_code, position = read_varint(data, start)
    length, position = read_varint(data, position)
    digest = data[position:]
    if len(digest) != length:
        raise NotUnderstood("the hash is not as long as it says it is")
    if not digest and hash_code != IDENTITY:
        raise NotUnderstood("the hash is empty")
    expected = DIGEST_LENGTHS.get(hash_code)
    if expected is not None and length != expected:
        raise NotUnderstood("the hash has the wrong length for its kind")
    return hash_code, digest


def parse_cid(data: bytes) -> Cid:
    """Read a binary CID, which must take up all of `data`."""
    if len(data) == 34 and data[0] == SHA2_256 and data[1] == 32:
        # CIDv0 is a bare sha2-256 multihash, and always dag-pb.
        return Cid(0, DAG_PB, SHA2_256, data[2:], data)
    version, position = read_varint(data)
    if version != 1:
        raise NotUnderstood("the CID version is not supported")
    codec, position = read_varint(data, position)
    hash_code, digest = _read_multihash(data, position)
    return Cid(1, codec, hash_code, digest, data)


def _unknown(raw: bytes) -> ContentPointer:
    return ContentPointer(
        protocol=PROTOCOL_UNKNOWN,
        hash=raw.hex()[:MAX_RAW_HEX],
        sha256=hashlib.sha256(raw).hexdigest(),
        raw_length=len(raw),
    )


def _decode_known(protocol: str, value: bytes) -> ContentPointer:
    cid = parse_cid(value)
    if protocol == "swarm":
        if cid.version != 1 or cid.codec != SWARM_MANIFEST or cid.hash_code != KECCAK_256:
            raise NotUnderstood("not a Swarm manifest hash")
        return ContentPointer(protocol, cid.digest.hex())
    also: str | None = None
    if protocol == "ipfs":
        if cid.hash_code == IDENTITY:
            raise NotUnderstood("the content is inlined rather than named by a hash")
        if cid.version == 1 and cid.codec == DAG_PB and cid.hash_code == SHA2_256:
            # The older way of writing the same identifier, starting "Qm".
            also = base58_encode(cid.multihash)
    elif cid.hash_code == IDENTITY and _DOMAIN.fullmatch(cid.digest):
        return ContentPointer(protocol, cid.digest.decode("ascii"), also_written=cid.text())
    elif cid.version == 1 and cid.codec == LIBP2P_KEY:
        # How IPNS names are usually shown: base36, starting "k".
        also = "k" + base36_encode(cid.raw)
    return ContentPointer(protocol, cid.text(), also_written=also)


def decode(raw: bytes) -> ContentPointer | None:
    """Decode a contenthash value. None means the field is empty.

    Never raises. Anything that cannot be read in full comes back with the
    protocol "unknown".
    """
    if not raw:
        return None
    if len(raw) > MAX_CONTENTHASH_BYTES:
        return _unknown(raw)
    try:
        code, position = read_varint(raw)
        protocol = PROTOCOLS.get(code)
        if protocol is None:
            return _unknown(raw)
        pointer = _decode_known(protocol, raw[position:])
    except NotUnderstood:
        return _unknown(raw)
    return ContentPointer(
        pointer.protocol, pointer.hash, also_written=pointer.also_written, raw_length=len(raw)
    )
