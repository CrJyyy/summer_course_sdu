from __future__ import annotations

from typing import Any

from .encoding import read_compact_size, sha256d
from .models import ByteReader, ParseError, assert_complete_coverage
from .transaction import _parse_transaction


def compact_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if bits & 0x00800000:
        return -1
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def merkle_root_from_txids(txids: list[str]) -> str:
    if not txids:
        raise ValueError("a block must contain at least one transaction")
    level = [bytes.fromhex(txid)[::-1] for txid in txids]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0][::-1].hex()


def decode_coinbase_height(script_sig_hex: str) -> int | None:
    script = bytes.fromhex(script_sig_hex)
    if not script or not 1 <= script[0] <= 5 or len(script) < 1 + script[0]:
        return None
    raw = bytearray(script[1 : 1 + script[0]])
    negative = bool(raw[-1] & 0x80)
    raw[-1] &= 0x7F
    value = int.from_bytes(raw, "little")
    return -value if negative else value


def parse_block(raw: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if len(raw) < 81:
        raise ParseError("serialized block is shorter than header plus transaction count")
    reader = ByteReader(raw)
    header_start = reader.pos
    version = reader.read_uint(4, "block.header.version", signed=True)
    prev_internal = reader.peek(32)
    reader.read(
        32,
        "block.header.previous_block_hash",
        decoded_value=prev_internal[::-1].hex(),
        endian="internal little-endian hash order",
    )
    merkle_internal = reader.peek(32)
    reader.read(
        32,
        "block.header.merkle_root",
        decoded_value=merkle_internal[::-1].hex(),
        endian="internal little-endian hash order",
    )
    timestamp = reader.read_uint(4, "block.header.timestamp")
    bits = reader.read_uint(4, "block.header.bits")
    nonce = reader.read_uint(4, "block.header.nonce")
    header_end = reader.pos
    header = raw[header_start:header_end]
    header_digest = sha256d(header)
    block_hash = header_digest[::-1].hex()
    target = compact_target(bits)
    hash_integer = int.from_bytes(header_digest, "little")
    transaction_count = read_compact_size(reader, "block.transaction_count")
    transactions: list[dict[str, Any]] = []
    for index in range(transaction_count):
        transactions.append(_parse_transaction(reader, f"block.transactions[{index}]"))
    if reader.remaining() != 0:
        raise ParseError(f"{reader.remaining()} trailing bytes after declared block transactions")
    coverage = assert_complete_coverage(reader.records, 0, len(raw))
    txids = [transaction["txid"] for transaction in transactions]
    calculated_merkle = merkle_root_from_txids(txids)
    coinbase = transactions[0] if transactions else None
    coinbase_height = None
    witness_commitment = None
    if coinbase and coinbase["inputs"]:
        first_input = coinbase["inputs"][0]
        if first_input["prev_txid"] == "00" * 32 and first_input["prev_vout"] == 0xFFFFFFFF:
            coinbase_height = decode_coinbase_height(first_input["script_sig"])
        for output in coinbase["outputs"]:
            script = bytes.fromhex(output["script_pubkey"])
            if len(script) >= 38 and script[:6] == bytes.fromhex("6a24aa21a9ed"):
                witness_commitment = script[6:38].hex()
                break
    parsed = {
        "block_hash": block_hash,
        "size": len(raw),
        "header": {
            "version": version,
            "previous_block_hash": prev_internal[::-1].hex(),
            "merkle_root": merkle_internal[::-1].hex(),
            "timestamp": timestamp,
            "bits": bits,
            "bits_hex": f"{bits:08x}",
            "nonce": nonce,
            "target_hex": f"{target:064x}" if target >= 0 else "negative",
            "hash_integer_hex": f"{hash_integer:064x}",
            "pow_valid": target > 0 and hash_integer <= target,
        },
        "transaction_count": transaction_count,
        "transactions": transactions,
        "calculated_merkle_root": calculated_merkle,
        "merkle_root_valid": calculated_merkle == merkle_internal[::-1].hex(),
        "coinbase_height": coinbase_height,
        "witness_commitment": witness_commitment,
        "byte_coverage": coverage,
    }
    return parsed, [record.to_dict() for record in reader.records]

