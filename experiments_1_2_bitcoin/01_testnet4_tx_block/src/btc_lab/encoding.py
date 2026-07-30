from __future__ import annotations

import hashlib

from .models import ByteReader, ParseError


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    return sha256(sha256(data))


def hash160(data: bytes) -> bytes:
    digest = hashlib.new("ripemd160")
    digest.update(sha256(data))
    return digest.digest()


def encode_compact_size(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("CompactSize value out of range")
    if value <= 252:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def read_compact_size(reader: ByteReader, field_path: str) -> int:
    prefix = reader.peek(1)[0]
    if prefix < 253:
        reader.read(1, field_path, decoded_value=prefix, endian="single byte", notes="CompactSize")
        return prefix
    reader.read(1, f"{field_path}.prefix", decoded_value=f"0x{prefix:02x}", notes="CompactSize prefix")
    width = {253: 2, 254: 4, 255: 8}[prefix]
    raw = reader.peek(width)
    value = int.from_bytes(raw, "little")
    minimum = {2: 253, 4: 0x10000, 8: 0x100000000}[width]
    if value < minimum:
        raise ParseError(f"non-canonical CompactSize encoding at offset {reader.pos - 1}")
    reader.read(width, f"{field_path}.value", decoded_value=value, endian="little", notes="CompactSize payload")
    return value


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i, generator in enumerate(generators):
            if (top >> i) & 1:
                chk ^= generator
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def convertbits(data: bytes, from_bits: int, to_bits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    result: list[int] = []
    maxv = (1 << to_bits) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise ValueError("invalid value for convertbits")
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((acc >> bits) & maxv)
    if pad:
        if bits:
            result.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        raise ValueError("invalid incomplete group")
    return result


def encode_segwit_address(hrp: str, witness_version: int, program: bytes) -> str:
    if not 0 <= witness_version <= 16:
        raise ValueError("invalid witness version")
    if not 2 <= len(program) <= 40 or (witness_version == 0 and len(program) not in (20, 32)):
        raise ValueError("invalid witness program")
    values = [witness_version] + convertbits(program, 8, 5)
    constant = 1 if witness_version == 0 else 0x2BC830A3
    polymod_values = _hrp_expand(hrp) + values + [0] * 6
    polymod = _bech32_polymod(polymod_values) ^ constant
    checksum = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[value] for value in values + checksum)


def p2wpkh_script(pubkey: bytes) -> bytes:
    return b"\x00\x14" + hash160(pubkey)


def p2pkh_script(pubkey_hash: bytes) -> bytes:
    if len(pubkey_hash) != 20:
        raise ValueError("P2PKH requires a 20-byte public-key hash")
    return b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"

